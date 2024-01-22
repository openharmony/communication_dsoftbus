/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_connection.h"

#include <securec.h>

#include "auth_common.h"
#include "auth_log.h"
#include "auth_tcp_connection.h"
#include "lnn_async_callback_utils.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"

#define AUTH_CONN_DATA_HEAD_SIZE           24
#define AUTH_CONN_CONNECT_TIMEOUT_MS       10000
#define AUTH_REPEAT_DEVICE_ID_HANDLE_DELAY 1000
#define AUTH_CONN_MAX_RETRY_TIMES          1
#define AUTH_CONN_RETRY_DELAY_MILLIS       3000

typedef struct {
    uint32_t requestId;
    AuthConnInfo connInfo;
    uint32_t retryTimes;
} ConnCmdInfo;

typedef struct {
    uint32_t requestId;
    int32_t fd;
    AuthConnInfo connInfo;
    uint32_t retryTimes;
    ListNode node;
} ConnRequest;

static ListNode g_connRequestList = { &g_connRequestList, &g_connRequestList };
static AuthConnListener g_listener = { 0 };
static bool g_enahnceP2pModuleIdStatics[AUTH_ENHANCED_P2P_NUM];

void __attribute__((weak)) RouteBuildClientAuthManager(int32_t cfd)
{
    (void)cfd;
}
void __attribute__((weak)) RouteClearAuthChannelId(int32_t cfd)
{
    (void)cfd;
}

static bool IsEnhanceP2pModuleId(ListenerModule moduleId)
{
    if (moduleId >= AUTH_ENHANCED_P2P_START && moduleId <= AUTH_ENHANCED_P2P_END) {
        return true;
    }
    return false;
}

static ListenerModule AllocateWfiDirectListenerModuleId(void)
{
    for (int32_t i = 0; i < AUTH_ENHANCED_P2P_NUM; i++) {
        if (!g_enahnceP2pModuleIdStatics[i]) {
            g_enahnceP2pModuleIdStatics[i] = true;
            return (ListenerModule)(AUTH_ENHANCED_P2P_START + i);
        }
    }
    return (ListenerModule)SOFTBUS_ERR;
}

static void FreeWifiDirectListenerModuleId(ListenerModule moduleId)
{
    if (IsEnhanceP2pModuleId(moduleId)) {
        g_enahnceP2pModuleIdStatics[moduleId - AUTH_ENHANCED_P2P_START] = false;
    }
}

uint64_t GenConnId(int32_t connType, int32_t id)
{
    uint64_t connId = (uint64_t)connType;
    connId = (connId << INT32_BIT_NUM) & MASK_UINT64_H32;
    connId |= (((uint64_t)id) & MASK_UINT64_L32);
    return connId;
}

int32_t GetConnType(uint64_t connId)
{
    return (int32_t)((connId >> INT32_BIT_NUM) & MASK_UINT64_L32);
}

const char *GetConnTypeStr(uint64_t connId)
{
    int32_t type = GetConnType(connId);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return "wifi/eth";
        case AUTH_LINK_TYPE_BR:
            return "br";
        case AUTH_LINK_TYPE_BLE:
            return "ble";
        case AUTH_LINK_TYPE_P2P:
            return "p2p";
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            return "enhanced_p2p";
        default:
            break;
    }
    return "unknown";
}

uint32_t GetConnId(uint64_t connId)
{
    return (uint32_t)(connId & MASK_UINT64_L32);
}

int32_t GetFd(uint64_t connId)
{
    return (int32_t)(connId & MASK_UINT64_L32);
}

void UpdateFd(uint64_t *connId, int32_t id)
{
    CHECK_NULL_PTR_RETURN_VOID(connId);
    *connId &= MASK_UINT64_H32;
    *connId |= (((uint64_t)id) & MASK_UINT64_L32);
}

/* Conn Request */
static int32_t AddConnRequest(const AuthConnInfo *connInfo, uint32_t requestId, int32_t fd)
{
    ConnRequest *item = (ConnRequest *)SoftBusMalloc(sizeof(ConnRequest));
    if (item == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc ConnRequest fail");
        return SOFTBUS_MALLOC_ERR;
    }
    item->fd = fd;
    item->requestId = requestId;
    if (memcpy_s(&item->connInfo, sizeof(item->connInfo), connInfo, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_CONN, "set AuthConnInfo fail");
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    ListTailInsert(&g_connRequestList, &item->node);
    return SOFTBUS_OK;
}

static ConnRequest *FindConnRequestByFd(int32_t fd)
{
    ConnRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_connRequestList, ConnRequest, node) {
        if (item->fd == fd) {
            return item;
        }
    }
    return NULL;
}

static ConnRequest *FindConnRequestByRequestId(uint32_t requestId)
{
    ConnRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_connRequestList, ConnRequest, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    return NULL;
}

static void DelConnRequest(ConnRequest *item)
{
    CHECK_NULL_PTR_RETURN_VOID(item);
    ListDelete(&item->node);
    SoftBusFree(item);
}

static void ClearConnRequest(void)
{
    ConnRequest *item = NULL;
    ConnRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_connRequestList, ConnRequest, node) {
        DelConnRequest(item);
    }
}

/* Notify Conn Listener */

static void NotifyClientConnected(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo)
{
    if (g_listener.onConnectResult != NULL) {
        g_listener.onConnectResult(requestId, connId, result, connInfo);
    }
}

static void NotifyDisconnected(uint64_t connId, const AuthConnInfo *connInfo)
{
    if (g_listener.onDisconnected != NULL) {
        g_listener.onDisconnected(connId, connInfo);
    }
}


static void NotifyDataReceived(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (g_listener.onDataReceived != NULL) {
        g_listener.onDataReceived(connId, connInfo, fromServer, head, data);
    }
}

/* AuthData */
uint32_t GetAuthDataSize(uint32_t len)
{
    return AUTH_CONN_DATA_HEAD_SIZE + len;
}

int32_t PackAuthData(const AuthDataHead *head, const uint8_t *data,
    uint8_t *buf, uint32_t size)
{
    if (size < GetAuthDataSize(head->len)) {
        return SOFTBUS_NO_ENOUGH_DATA;
    }
    uint32_t offset = 0;
    *(uint32_t *)buf = SoftBusHtoLl(head->dataType);
    offset += sizeof(uint32_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl((uint32_t)head->module);
    offset += sizeof(uint32_t);
    *(uint64_t *)(buf + offset) = SoftBusHtoLll((uint64_t)head->seq);
    offset += sizeof(uint64_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl((uint32_t)head->flag);
    offset += sizeof(uint32_t);
    *(uint32_t *)(buf + offset) = SoftBusHtoLl(head->len);
    offset += sizeof(uint32_t);

    if (memcpy_s(buf + offset, size - offset, data, head->len) != EOK) {
        AUTH_LOGE(AUTH_CONN, "pack AuthData fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const uint8_t *UnpackAuthData(const uint8_t *data, uint32_t len, AuthDataHead *head)
{
    if (len < GetAuthDataSize(0)) {
        AUTH_LOGE(AUTH_CONN, "head not enough");
        return NULL;
    }
    uint32_t offset = 0;
    head->dataType = SoftBusLtoHl(*(uint32_t *)data);
    offset += sizeof(uint32_t);
    head->module = (int32_t)SoftBusLtoHl(*(uint32_t *)(data + offset));
    offset += sizeof(uint32_t);
    head->seq = (int64_t)SoftBusLtoHll(*(uint64_t *)(data + offset));
    offset += sizeof(uint64_t);
    head->flag = (int32_t)SoftBusLtoHl(*(uint32_t *)(data + offset));
    offset += sizeof(uint32_t);
    head->len = SoftBusLtoHl(*(uint32_t *)(data + offset));
    offset += sizeof(uint32_t);
    uint32_t dataLen = GetAuthDataSize(head->len);
    if (len < dataLen || dataLen < GetAuthDataSize(0)) {
        AUTH_LOGE(AUTH_CONN, "data not enough");
        return NULL;
    }
    return (data + offset);
}

/* EVENT_CONNECT_TIMEOUT */
static void HandleConnConnectTimeout(const void *para)
{
    CHECK_NULL_PTR_RETURN_VOID(para);
    uint32_t requestId = *(uint32_t *)(para);
    AUTH_LOGE(AUTH_CONN, "connect timeout, requestId=%{public}u", requestId);
    ConnRequest *item = FindConnRequestByRequestId(requestId);
    if (item != NULL) {
        SocketDisconnectDevice(AUTH, item->fd);
        DelConnRequest(item);
    }
    NotifyClientConnected(requestId, 0, SOFTBUS_AUTH_CONN_TIMEOUT, NULL);
}

static void PostConnConnectTimeout(uint32_t requestId)
{
    PostAuthEvent(
        EVENT_CONNECT_TIMEOUT, HandleConnConnectTimeout, &requestId, sizeof(requestId), AUTH_CONN_CONNECT_TIMEOUT_MS);
}

static int32_t RemoveFunc(const void *obj, void *param)
{
    CHECK_NULL_PTR_RETURN_VALUE(obj, SOFTBUS_ERR);
    CHECK_NULL_PTR_RETURN_VALUE(param, SOFTBUS_ERR);
    return ((*(uint32_t *)(obj) == *(uint32_t *)(param)) ? SOFTBUS_OK : SOFTBUS_ERR);
}

static void RemoveConnConnectTimeout(uint32_t requestId)
{
    RemoveAuthEvent(EVENT_CONNECT_TIMEOUT, RemoveFunc, (void *)(&requestId));
}

/* EVENT_CONNECT_CMD */
static void HandleConnConnectCmd(const void *para)
{
    CHECK_NULL_PTR_RETURN_VOID(para);
    ConnCmdInfo *info = (ConnCmdInfo *)para;
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGE(AUTH_CONN, "invalid connType=%{public}d", info->connInfo.type);
        return;
    }
    int32_t fd = SocketConnectDevice(info->connInfo.info.ipInfo.ip, info->connInfo.info.ipInfo.port, false);
    if (fd < 0) {
        AUTH_LOGE(AUTH_CONN, "SocketConnectDevice fail");
        RemoveConnConnectTimeout(info->requestId);
        NotifyClientConnected(info->requestId, 0, SOFTBUS_AUTH_CONN_FAIL, NULL);
        return;
    }
    (void)AddConnRequest(&info->connInfo, info->requestId, fd);
}

/* EVENT_CONNECT_RESULT */
static void HandleConnConnectResult(const void *para)
{
    CHECK_NULL_PTR_RETURN_VOID(para);
    int32_t fd = *(int32_t *)(para);
    RouteBuildClientAuthManager(fd);
    ConnRequest *item = FindConnRequestByFd(fd);
    if (item == NULL) {
        AUTH_LOGE(AUTH_CONN, "ConnRequest not found, fd=%{public}d", fd);
        return;
    }
    uint64_t connId = GenConnId(AUTH_LINK_TYPE_WIFI, fd);
    RemoveConnConnectTimeout(item->requestId);
    NotifyClientConnected(item->requestId, connId, SOFTBUS_OK, &item->connInfo);
    DelConnRequest(item);
}

/* WiFi Connection */
static void OnWiFiConnected(ListenerModule module, int32_t fd, bool isClient)
{
    AUTH_LOGI(AUTH_CONN, "OnWiFiConnected: fd=%{public}d, side=%{public}s", fd,
        isClient ? "client" : "server(ignored)");
    if (!isClient) {
        /* do nothing, wait auth message. */
        return;
    }
    (void)PostAuthEvent(EVENT_CONNECT_RESULT, HandleConnConnectResult, &fd, sizeof(fd), 0);
}

static void OnWiFiDisconnected(int32_t fd)
{
    AUTH_LOGI(AUTH_CONN, "OnWiFiDisconnected: fd=%{public}d", fd);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    NotifyDisconnected(GenConnId(connInfo.type, fd), &connInfo);
    RouteClearAuthChannelId(fd);
}

static void OnWiFiDataReceived(ListenerModule module, int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    CHECK_NULL_PTR_RETURN_VOID(head);
    CHECK_NULL_PTR_RETURN_VOID(data);

    if (module != AUTH && module != AUTH_P2P && !IsEnhanceP2pModuleId(module)) {
        return;
    }
    bool fromServer = false;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (SocketGetConnInfo(fd, &connInfo, &fromServer) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get connInfo fail, fd=%{public}d", fd);
        return;
    }
    NotifyDataReceived(GenConnId(connInfo.type, fd), &connInfo, fromServer, head, data);
}

static int32_t InitWiFiConn(void)
{
    SocketCallback socketCb = {
        .onConnected = OnWiFiConnected,
        .onDisconnected = OnWiFiDisconnected,
        .onDataReceived = OnWiFiDataReceived,
    };
    return SetSocketCallback(&socketCb);
}

/* BR/BLE/P2P Connection */
static void OnCommConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    AUTH_LOGI(AUTH_CONN, "(ignored)OnCommConnected: connectionId=%{public}u", connectionId);
}

DiscoveryType ConvertToDiscoveryType(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return DISCOVERY_TYPE_WIFI;
        case AUTH_LINK_TYPE_BLE:
            return DISCOVERY_TYPE_BLE;
        case AUTH_LINK_TYPE_BR:
            return DISCOVERY_TYPE_BR;
        case AUTH_LINK_TYPE_P2P:
            return DISCOVERY_TYPE_P2P;
        default:
            break;
    }
    return DISCOVERY_TYPE_UNKNOWN;
}

static void OnCommDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    AUTH_LOGI(AUTH_CONN, "connectionId=%{public}u", connectionId);
    CHECK_NULL_PTR_RETURN_VOID(info);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)ConvertToAuthConnInfo(info, &connInfo);
    NotifyDisconnected(GenConnId(connInfo.type, connectionId), &connInfo);
}

int32_t GetConnInfoByConnectionId(uint32_t connectionId, AuthConnInfo *connInfo)
{
    ConnectionInfo info = { 0 };
    int32_t ret = ConnGetConnectionInfo(connectionId, &info);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "GetConnectionInfo err=%{public}d, connectionId=%{public}u", ret, connectionId);
        return ret;
    }
    return ConvertToAuthConnInfo(&info, connInfo);
}

static void OnCommDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    if (data == NULL || moduleId != MODULE_DEVICE_AUTH || len <= 0) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    bool fromServer = ((seq % SEQ_INTERVAL) != 0);
    AUTH_LOGI(AUTH_CONN,
        "connectionId=%{public}u, module=%{public}d, seq=%{public}" PRId64 ", len=%{public}d, from=%{public}s",
        connectionId, moduleId, seq, len, GetAuthSideStr(fromServer));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (GetConnInfoByConnectionId(connectionId, &connInfo) != SOFTBUS_OK) {
        return;
    }
    AuthDataHead head = { 0 };
    const uint8_t *body = UnpackAuthData((const uint8_t *)data, (uint32_t)len, &head);
    if (body == NULL) {
        AUTH_LOGE(AUTH_CONN, "empty body");
        return;
    }
    NotifyDataReceived(GenConnId(connInfo.type, connectionId), &connInfo, fromServer, &head, body);
}

static void AsyncCallDeviceIdReceived(void *para)
{
    RepeatDeviceIdData *recvData = (RepeatDeviceIdData *)para;
    if (recvData == NULL) {
        return;
    }
    AUTH_LOGI(AUTH_CONN, "Delay handle connectionId=%{public}" PRIu64 ", len=%{public}d, from=%{public}s",
        recvData->connId, recvData->len, GetAuthSideStr(recvData->fromServer));
    NotifyDataReceived(recvData->connId, &recvData->connInfo, recvData->fromServer, &recvData->head, recvData->data);
    SoftBusFree(para);
}

void HandleRepeatDeviceIdDataDelay(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    RepeatDeviceIdData *request = (RepeatDeviceIdData *)SoftBusCalloc(sizeof(RepeatDeviceIdData) + head->len);
    if (request == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc RepeatDeviceIdData fail");
        return;
    }
    request->len = head->len;
    if (data != NULL && head->len > 0 && memcpy_s(request->data, head->len, data, head->len) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy data fail");
        SoftBusFree(request);
        return;
    }
    request->connId = connId;
    request->connInfo = *connInfo;
    request->fromServer = fromServer;
    request->head = *head;
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), AsyncCallDeviceIdReceived, request,
        AUTH_REPEAT_DEVICE_ID_HANDLE_DELAY) != SOFTBUS_OK) {
        SoftBusFree(request);
    }
}

static int32_t InitCommConn(void)
{
    ConnectCallback connCb = {
        .OnConnected = OnCommConnected,
        .OnDisconnected = OnCommDisconnected,
        .OnDataReceived = OnCommDataReceived,
    };
    return ConnSetConnectCallback(MODULE_DEVICE_AUTH, &connCb);
}

static void OnCommConnectSucc(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    AuthConnInfo connInfo;
    AUTH_LOGI(AUTH_CONN, "requestId=%{public}u, connectionId=%{public}u", requestId, connectionId);
    CHECK_NULL_PTR_RETURN_VOID(info);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)ConvertToAuthConnInfo(info, &connInfo);
    RemoveConnConnectTimeout(requestId);
    uint64_t connId = GenConnId(connInfo.type, connectionId);
    NotifyClientConnected(requestId, connId, SOFTBUS_OK, &connInfo);
}

static void OnCommConnectFail(uint32_t requestId, int32_t reason)
{
    AUTH_LOGI(AUTH_CONN, "requestId=%{public}u, reason=%{public}d", requestId, reason);
    RemoveConnConnectTimeout(requestId);
    NotifyClientConnected(requestId, 0, SOFTBUS_CONN_FAIL, NULL);
}

static int32_t ConnectCommDevice(const AuthConnInfo *info, uint32_t requestId, ConnSideType sideType)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = ConvertToConnectOption(info, &option);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ConvertToConnectOption fail=%{public}d", ret);
        return ret;
    }
    if (option.type == CONNECT_BR) {
        option.brOption.sideType = sideType;
    }
    ConnectResult result = {
        .OnConnectSuccessed = OnCommConnectSucc,
        .OnConnectFailed = OnCommConnectFail,
    };
    ret = ConnConnectDevice(&option, requestId, &result);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ConnConnectDevice fail=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t PostCommData(uint32_t connectionId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    uint32_t size = ConnGetHeadSize() + GetAuthDataSize(head->len);
    uint8_t *buf = (uint8_t *)SoftBusMalloc(size);
    if (buf == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = PackAuthData(head, data, buf + ConnGetHeadSize(), size - ConnGetHeadSize());
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "pack data fail=%{public}d", ret);
        SoftBusFree(buf);
        return ret;
    }
    ConnPostData connData = {
        .module = MODULE_DEVICE_AUTH,
        .seq = GenSeq(!toServer),
        .flag = CONN_HIGH,
        .pid = 0,
        .len = size,
        .buf = (char *)buf,
    };
    AUTH_LOGI(AUTH_CONN,
        "dataSeq=%{public}" PRId64 ", dataLen=%{public}u, "
        "connId=%{public}u, connSeq=%{public}" PRId64 ", connLen=%{public}u}",
        head->seq, head->len, connectionId, connData.seq, connData.len);
    return ConnPostBytes(connectionId, &connData);
}

int32_t AuthConnInit(const AuthConnListener *listener)
{
    CHECK_NULL_PTR_RETURN_VALUE(listener, SOFTBUS_INVALID_PARAM);
    g_listener = *listener;
    ListInit(&g_connRequestList);
    if (InitCommConn() != SOFTBUS_OK) {
        (void)memset_s(&g_listener, sizeof(g_listener), 0, sizeof(AuthConnListener));
        AUTH_LOGE(AUTH_CONN, "init br/ble/p2p conn fail");
        return SOFTBUS_AUTH_CONN_INIT_FAIL;
    }
    if (InitWiFiConn() != SOFTBUS_OK) {
        (void)memset_s(&g_listener, sizeof(g_listener), 0, sizeof(AuthConnListener));
        AUTH_LOGE(AUTH_CONN, "init wifi conn fail");
        return SOFTBUS_AUTH_CONN_INIT_FAIL;
    }
    return SOFTBUS_OK;
}

void AuthConnDeinit(void)
{
    UnsetSocketCallback();
    ConnUnSetConnectCallback(MODULE_DEVICE_AUTH);
    ClearConnRequest();
    (void)memset_s(&g_listener, sizeof(g_listener), 0, sizeof(AuthConnListener));
}

int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    AUTH_LOGI(AUTH_CONN, "requestId=%{public}u, connType=%{public}d, sideType=%{public}d", requestId,
        connInfo->type, sideType);
    PostConnConnectTimeout(requestId);
    int32_t ret = 0;
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_WIFI: {
            ConnCmdInfo info = {
                .requestId = requestId,
                .connInfo = *connInfo,
                .retryTimes = 0,
            };
            ret = PostAuthEvent(EVENT_CONNECT_CMD, HandleConnConnectCmd, &info, sizeof(ConnCmdInfo), 0);
            break;
        }
        case AUTH_LINK_TYPE_BLE:
            __attribute__((fallthrough));
        case AUTH_LINK_TYPE_BR:
            if (SoftBusGetBtState() != BLE_ENABLE) {
                ret = SOFTBUS_AUTH_CONN_FAIL;
                break;
            }
            __attribute__((fallthrough));
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            ret = ConnectCommDevice(connInfo, requestId, sideType);
            break;
        default:
            ret = SOFTBUS_OK;
            break;
    }
    if (ret != SOFTBUS_OK) {
        RemoveConnConnectTimeout(requestId);
        AUTH_LOGE(AUTH_CONN, "ConnectDevice fail, requestId=%{public}u", requestId);
    }
    return ret;
}

void UpdateAuthDevicePriority(uint64_t connId)
{
    if (GetConnType(connId) != AUTH_LINK_TYPE_BLE) {
        return;
    }
    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_BALANCED,
        }
    };
    int32_t ret = ConnUpdateConnection(GetConnId(connId), &option);
    AUTH_LOGI(AUTH_CONN, "update connecton priority to balanced, connType=%{public}d, id=%{public}u, ret=%{public}d",
        GetConnType(connId), GetConnId(connId), ret);
}

void DisconnectAuthDevice(uint64_t *connId)
{
    if (connId == NULL) {
        AUTH_LOGW(AUTH_CONN, "connId nulptr");
        return;
    }
    AUTH_LOGI(AUTH_CONN, "connType=%{public}d, connectionId=%{public}u", GetConnType(*connId), GetConnId(*connId));
    switch (GetConnType(*connId)) {
        case AUTH_LINK_TYPE_WIFI:
            SocketDisconnectDevice(AUTH, GetFd(*connId));
            UpdateFd(connId, AUTH_INVALID_FD);
            break;
        case AUTH_LINK_TYPE_BLE:
            __attribute__((fallthrough));
        case AUTH_LINK_TYPE_BR:
            ConnDisconnectDevice(GetConnId(*connId));
            __attribute__((fallthrough));
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            break;
        default:
            AUTH_LOGI(AUTH_CONN, "unknown connType");
            break;
    }
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    CHECK_NULL_PTR_RETURN_VALUE(head, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    AUTH_LOGI(AUTH_CONN,
        "auth post dataType=0x%{public}x, dataModule=%{public}d, dataSeq=%{public}" PRId64 ", "
        "dataFlag=%{public}d, dataLen=%{public}u, " CONN_INFO ", toServer=%{public}s",
        head->dataType, head->module, head->seq, head->flag, head->len, CONN_DATA(connId),
        GetAuthSideStr(toServer));
    switch (GetConnType(connId)) {
        case AUTH_LINK_TYPE_WIFI:
            return SocketPostBytes(GetFd(connId), head, data);
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            return PostCommData(GetConnId(connId), toServer, head, data);
        default:
            AUTH_LOGI(AUTH_CONN, "unknown connType");
            break;
    }
    return SOFTBUS_AUTH_SEND_FAIL;
}

ConnSideType GetConnSideType(uint64_t connId)
{
    if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGE(AUTH_CONN, "WiFi not supported, " CONN_INFO, CONN_DATA(connId));
        return CONN_SIDE_ANY;
    }
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    if (ConnGetConnectionInfo(GetConnId(connId), &info)) {
        AUTH_LOGE(AUTH_CONN, "ConnGetConnectionInfo fail, " CONN_INFO, CONN_DATA(connId));
        return CONN_SIDE_ANY;
    }
    if (!info.isAvailable) {
        AUTH_LOGE(AUTH_CONN, "connection not available, " CONN_INFO, CONN_DATA(connId));
    }
    return info.isServer ? CONN_SIDE_SERVER : CONN_SIDE_CLIENT;
}

bool CheckActiveAuthConnection(const AuthConnInfo *connInfo)
{
    ConnectOption connOpt;
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, false);
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    if (ConvertToConnectOption(connInfo, &connOpt) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert to connect option fail, connType=%{public}d.", connInfo->type);
        return false;
    }
    return CheckActiveConnection(&connOpt);
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    if (ip == NULL) {
        AUTH_LOGW(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_LOGI(AUTH_CONN, "start auth listening, linkType=%{public}d, port=%{public}d", type, port);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI: {
            LocalListenerInfo info = {
                .type = CONNECT_TCP,
                .socketOption = {
                    .addr = "",
                    .port = port,
                    .moduleId = AUTH,
                    .protocol = LNN_PROTOCOL_IP,
                },
            };

            if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ip) != EOK) {
                AUTH_LOGE(AUTH_CONN, "strcpy_s ip fail");
                return SOFTBUS_MEM_ERR;
            }
            return StartSocketListening(AUTH, &info);
        }
        default:
            AUTH_LOGE(AUTH_CONN, "unsupport linkType=%{public}d", type);
            break;
    }
    return SOFTBUS_INVALID_PARAM;
}

void AuthStopListening(AuthLinkType type)
{
    AUTH_LOGI(AUTH_CONN, "stop auth listening, linkType=%{public}d", type);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            StopSocketListening();
            break;
        default:
            AUTH_LOGE(AUTH_CONN, "unsupport linkType=%{public}d", type);
            break;
    }
}

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(ip != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "ip is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(moduleId != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "moduleId is null");

    LocalListenerInfo local;
    local.type = CONNECT_TCP;
    local.socketOption.port = port;
    local.socketOption.protocol = LNN_PROTOCOL_IP;
    int32_t ret = strcpy_s(local.socketOption.addr, sizeof(local.socketOption.addr), ip);
    AUTH_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, AUTH_CONN, "copy ip failed");

    if (type == AUTH_LINK_TYPE_P2P) {
        local.socketOption.moduleId = AUTH_P2P;
    } else if (type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        local.socketOption.moduleId = AllocateWfiDirectListenerModuleId();
        AUTH_CHECK_AND_RETURN_RET_LOGE(local.socketOption.moduleId > 0, SOFTBUS_ERR, AUTH_CONN,
                                       "alloc listener module id failed");
    } else {
        AUTH_LOGE(AUTH_CONN, "type invalid. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t realPort = ConnStartLocalListening(&local);
    AUTH_CHECK_AND_RETURN_RET_LOGE(realPort > 0, SOFTBUS_ERR, AUTH_CONN, "start local listening failed");
    AUTH_LOGI(AUTH_CONN, "moduleId=%{public}u, port=%{public}d", local.socketOption.moduleId, realPort);
    *moduleId = local.socketOption.moduleId;
    return realPort;
}

void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId)
{
    AUTH_CHECK_AND_RETURN_LOGE(type == AUTH_LINK_TYPE_P2P || type == AUTH_LINK_TYPE_ENHANCED_P2P, AUTH_CONN,
                               "type invalid. type=%{public}d", type);
    LocalListenerInfo local = {
        .type = CONNECT_TCP,
        .socketOption = {
            .moduleId = moduleId,
            .protocol = LNN_PROTOCOL_IP,
        },
    };

    FreeWifiDirectListenerModuleId(moduleId);
    if (ConnStopLocalListening(&local) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ConnStopLocalListening fail");
    }
}