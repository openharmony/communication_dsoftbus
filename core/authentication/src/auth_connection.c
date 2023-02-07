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
#include "auth_tcp_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"

#define AUTH_CONN_DATA_HEAD_SIZE 24
#define AUTH_CONN_CONNECT_TIMEOUT_MS 10000

typedef struct {
    uint32_t requestId;
    AuthConnInfo connInfo;
} ConnCmdInfo;

typedef struct {
    uint32_t requestId;
    int32_t fd;
    AuthConnInfo connInfo;
    ListNode node;
} ConnRequest;

static ListNode g_connRequestList = { &g_connRequestList, &g_connRequestList };
static AuthConnListener g_listener = {0};

static uint64_t GenConnId(int32_t connType, int32_t id)
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
        default:
            break;
    }
    return "unknown";
}

uint32_t GetConnId(uint64_t connId)
{
    return (uint32_t)(connId & MASK_UINT64_L32);
}

static int32_t GetFd(uint64_t connId)
{
    return (int32_t)(connId & MASK_UINT64_L32);
}

/* Conn Request */
static int32_t AddConnRequest(const AuthConnInfo *connInfo, uint32_t requestId, int32_t fd)
{
    ConnRequest *item = (ConnRequest *)SoftBusMalloc(sizeof(ConnRequest));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConn: malloc ConnRequest fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->fd = fd;
    item->requestId = requestId;
    if (memcpy_s(&item->connInfo, sizeof(item->connInfo), connInfo, sizeof(AuthConnInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConn: set AuthConnInfo fail.");
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

static void NotifyDataReceived(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack AuthData fail.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

const uint8_t *UnpackAuthData(const uint8_t *data, uint32_t len, AuthDataHead *head)
{
    if (len < GetAuthDataSize(0)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthData: head not enough.");
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthData: data not enough.");
        return NULL;
    }
    return (data + offset);
}

/* EVENT_CONNECT_TIMEOUT */
static void HandleConnConnectTimeout(const void *para)
{
    CHECK_NULL_PTR_RETURN_VOID(para);
    uint32_t requestId = *(uint32_t *)(para);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConn: connect timeout, requestId=%u.", requestId);
    ConnRequest *item = FindConnRequestByRequestId(requestId);
    if (item != NULL) {
        SocketDisconnectDevice(item->fd);
        DelConnRequest(item);
    }
    NotifyClientConnected(requestId, 0, SOFTBUS_AUTH_CONN_TIMEOUT, NULL);
}

static void PostConnConnectTimeout(uint32_t requestId)
{
    PostAuthEvent(EVENT_CONNECT_TIMEOUT, HandleConnConnectTimeout,
        &requestId, sizeof(requestId), AUTH_CONN_CONNECT_TIMEOUT_MS);
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "AuthConn: invalid connType(=%d).", info->connInfo.type);
        return;
    }
    int32_t fd = SocketConnectDevice(info->connInfo.info.ipInfo.ip, info->connInfo.info.ipInfo.port, false);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConn: SocketConnectDevice fail.");
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
    ConnRequest *item = FindConnRequestByFd(fd);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnRequest not found, fd=%d.", fd);
        return;
    }
    RemoveConnConnectTimeout(item->requestId);
    NotifyClientConnected(item->requestId, GenConnId(AUTH_LINK_TYPE_WIFI, fd), SOFTBUS_OK, &item->connInfo);
    DelConnRequest(item);
}

/* WiFi Connection */
static void OnWiFiConnected(int32_t fd, bool isClient)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "OnWiFiConnected: fd=%d, side=%s.", fd, isClient ? "client" : "server(ignored)");
    if (!isClient) {
        /* do nothing, wait auth message. */
        return;
    }
    (void)PostAuthEvent(EVENT_CONNECT_RESULT, HandleConnConnectResult, &fd, sizeof(fd), 0);
}

static void OnWiFiDisconnected(int32_t fd)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "OnWiFiDisconnected: fd=%d.", fd);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    NotifyDisconnected(GenConnId(connInfo.type, fd), &connInfo);
}

static void OnWiFiDataReceived(int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    CHECK_NULL_PTR_RETURN_VOID(head);
    CHECK_NULL_PTR_RETURN_VOID(data);
    bool fromServer = false;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (SocketGetConnInfo(fd, &connInfo, &fromServer) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get connInfo fail, fd=%d.", fd);
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
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "(ignored)OnCommConnected: connectionId=%u.", connectionId);
}

static void OnCommDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "OnCommDisconnected: connectionId=%u.", connectionId);
    CHECK_NULL_PTR_RETURN_VOID(info);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)ConvertToAuthConnInfo(info, &connInfo);
    NotifyDisconnected(GenConnId(connInfo.type, connectionId), &connInfo);
}

int32_t GetConnInfoByConnectionId(uint32_t connectionId, AuthConnInfo *connInfo)
{
    ConnectionInfo info = {0};
    int32_t ret = ConnGetConnectionInfo(connectionId, &info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "GetConnectionInfo fail(=%d), connectionId=%u.", ret, connectionId);
        return SOFTBUS_ERR;
    }
    return ConvertToAuthConnInfo(&info, connInfo);
}

static void OnCommDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    if (data == NULL || moduleId != MODULE_DEVICE_AUTH || len <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "RecvCommData: invalid param.");
        return;
    }
    bool fromServer = ((seq % SEQ_INTERVAL) != 0);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "RecvCommData: connectionId=%u, module=%d, seq=%" PRId64
        ", len=%d, from=%s.", connectionId, moduleId, seq, len, GetAuthSideStr(fromServer));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    if (GetConnInfoByConnectionId(connectionId, &connInfo) != SOFTBUS_OK) {
        return;
    }
    AuthDataHead head = {0};
    const uint8_t *body = UnpackAuthData((const uint8_t *)data, (uint32_t)len, &head);
    if (body == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "RecvCommData: empty body.");
        return;
    }
    NotifyDataReceived(GenConnId(connInfo.type, connectionId), &connInfo, fromServer, &head, body);
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
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "OnCommConnectSucc: requestId=%u, connectionId=%u.", requestId, connectionId);
    CHECK_NULL_PTR_RETURN_VOID(info);
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)ConvertToAuthConnInfo(info, &connInfo);
    RemoveConnConnectTimeout(requestId);
    NotifyClientConnected(requestId, GenConnId(connInfo.type, connectionId), SOFTBUS_OK, &connInfo);
}

static void OnCommConnectFail(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "OnCommConnectFail: requestId=%u, reason=%d.", requestId, reason);
    RemoveConnConnectTimeout(requestId);
    NotifyClientConnected(requestId, 0, SOFTBUS_CONN_FAIL, NULL);
}

static int32_t ConnectCommDevice(const AuthConnInfo *info, uint32_t requestId, ConnSideType sideType)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = ConvertToConnectOption(info, &option);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConvertToConnectOption fail(=%d).", ret);
        return SOFTBUS_ERR;
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnConnectDevice fail(=%d).", ret);
        return SOFTBUS_CONN_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t PostCommData(uint32_t connectionId, bool toServer,
    const AuthDataHead *head, const uint8_t *data)
{
    uint32_t size = ConnGetHeadSize() + GetAuthDataSize(head->len);
    uint8_t *buf = (uint8_t *)SoftBusMalloc(size);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "PostCommData: malloc fail.");
        return SOFTBUS_ERR;
    }
    int32_t ret = PackAuthData(head, data, buf + ConnGetHeadSize(), size - ConnGetHeadSize());
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "PostCommData: pack data fail(=%d).", ret);
        SoftBusFree(buf);
        return ret;
    }
    ConnPostData connData = {
        .module = MODULE_DEVICE_AUTH,
        .seq = GenSeq(!toServer),
        .flag = CONN_HIGH,
        .pid = 0,
        .buf = (char *)buf,
        .len = size,
    };
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "PostCommData: data{seq=%"PRId64", len=%u} conn{id=%u, seq=%"PRId64", len=%u}",
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
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "init br/ble/p2p conn fail.");
        return SOFTBUS_ERR;
    }
    if (InitWiFiConn() != SOFTBUS_OK) {
        (void)memset_s(&g_listener, sizeof(g_listener), 0, sizeof(AuthConnListener));
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "init wifi conn fail.");
        return SOFTBUS_ERR;
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
    int32_t ret;
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "ConnectDevice: requestId=%u, connType=%d, sideType=%d.", requestId, connInfo->type, sideType);
    PostConnConnectTimeout(requestId);
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_WIFI: {
            ConnCmdInfo info = {
                .requestId = requestId,
                .connInfo = *connInfo
            };
            ret = PostAuthEvent(EVENT_CONNECT_CMD, HandleConnConnectCmd, &info, sizeof(ConnCmdInfo), 0);
            break;
        }
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_P2P:
            ret = ConnectCommDevice(connInfo, requestId, sideType);
            break;
        default:
            break;
    }
    if (ret != SOFTBUS_OK) {
        RemoveConnConnectTimeout(requestId);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnectDevice fail, requestId=%u.", requestId);
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
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "update connecton priority to balanced, connType=%d, id=%u, ret: %d",
        GetConnType(connId), GetConnId(connId), ret);
}
void DisconnectAuthDevice(uint64_t connId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "DisconnectDevice: connType=%d, id=%u.", GetConnType(connId), GetConnId(connId));
    switch (GetConnType(connId)) {
        case AUTH_LINK_TYPE_WIFI:
            SocketDisconnectDevice(GetFd(connId));
            break;
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_P2P:
            ConnDisconnectDevice(GetConnId(connId));
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "unknown connType.");
            break;
    }
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    CHECK_NULL_PTR_RETURN_VALUE(head, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(data, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth post data{type=0x%x, module=%d, seq=%"PRId64", flag=%d, len=%u} " CONN_INFO " to[%s]",
        head->dataType, head->module, head->seq, head->flag, head->len, CONN_DATA(connId), GetAuthSideStr(toServer));
    switch (GetConnType(connId)) {
        case AUTH_LINK_TYPE_WIFI:
            return SocketPostBytes(GetFd(connId), head, data);
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_P2P:
            return PostCommData(GetConnId(connId), toServer, head, data);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "unknown connType.");
            break;
    }
    return SOFTBUS_ERR;
}

ConnSideType GetConnSideType(uint64_t connId)
{
    if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "WiFi not supported, " CONN_INFO, CONN_DATA(connId));
        return CONN_SIDE_ANY;
    }
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    if (ConnGetConnectionInfo(GetConnId(connId), &info)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "ConnGetConnectionInfo fail, " CONN_INFO, CONN_DATA(connId));
        return CONN_SIDE_ANY;
    }
    if (!info.isAvailable) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "connection not available, " CONN_INFO, CONN_DATA(connId));
    }
    return info.isServer ? CONN_SIDE_SERVER : CONN_SIDE_CLIENT;
}

bool CheckActiveAuthConnection(const AuthConnInfo *connInfo)
{
    ConnectOption connOpt;
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, false);
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    if (ConvertToConnectOption(connInfo, &connOpt) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "convert to connect option fail, connType=%d.", connInfo->type);
        return false;
    }
    return CheckActiveConnection(&connOpt);
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    if (ip == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "start auth listening, type=%d, port=%d.", type, port);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return StartSocketListening(ip, port);
        case AUTH_LINK_TYPE_P2P: {
            LocalListenerInfo local = {
                .type = CONNECT_TCP,
                .socketOption = {
                    .addr = "",
                    .port = port,
                    .moduleId = AUTH_P2P,
                    .protocol = LNN_PROTOCOL_IP
                }
            };
            if (strcpy_s(local.socketOption.addr, sizeof(local.socketOption.addr), ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s ip fail.");
                return SOFTBUS_MEM_ERR;
            }
            return ConnStartLocalListening(&local);
        }
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport link type:%d.", type);
            break;
    }
    return SOFTBUS_INVALID_PARAM;
}

void AuthStopListening(AuthLinkType type)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "stop auth listening, type=%d.", type);
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            StopSocketListening();
            break;
        case AUTH_LINK_TYPE_P2P: {
            LocalListenerInfo local = {
                .type = CONNECT_TCP,
                .socketOption = {
                    .moduleId = AUTH_P2P,
                    .protocol = LNN_PROTOCOL_IP
                }
            };
            if (ConnStopLocalListening(&local) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ConnStopLocalListening fail.");
            }
            break;
        }
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport link type:%d.", type);
            break;
    }
}
