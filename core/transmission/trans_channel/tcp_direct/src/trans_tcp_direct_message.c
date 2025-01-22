/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "trans_tcp_direct_message.h"

#include <securec.h>
#include <string.h>

#include "access_control.h"
#include "anonymizer.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "data_bus_native.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_link.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_app_info.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "trans_bind_request_manager.h"
#include "trans_channel_common.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_listener.h"
#include "wifi_direct_manager.h"

#define MAX_PACKET_SIZE (64 * 1024)
#define MIN_META_LEN 6
#define META_SESSION "IShare"
#define MAX_ERRDESC_LEN 128

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t fd;
    uint32_t size;
    char *data;
    char *w;
} ServerDataBuf;

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static SoftBusList *g_tcpSrvDataList = NULL;

static void PackTdcPacketHead(TdcPacketHead *data)
{
    data->magicNumber = SoftBusHtoLl(data->magicNumber);
    data->module = SoftBusHtoLl(data->module);
    data->seq = SoftBusHtoLll(data->seq);
    data->flags = SoftBusHtoLl(data->flags);
    data->dataLen = SoftBusHtoLl(data->dataLen);
}

static void UnpackTdcPacketHead(TdcPacketHead *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return;
    }
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->module = SoftBusLtoHl(data->module);
    data->seq = SoftBusLtoHll(data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

int32_t TransSrvDataListInit(void)
{
    if (g_tcpSrvDataList != NULL) {
        return SOFTBUS_OK;
    }
    g_tcpSrvDataList = CreateSoftBusList();
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "creat list failed");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

static void TransSrvDestroyDataBuf(void)
{
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpSrvDataList is null");
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mutex lock failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpSrvDataList->cnt--;
    }
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
}

void TransSrvDataListDeinit(void)
{
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_BYTES, "g_tcpSrvDataList is null");
        return;
    }
    TransSrvDestroyDataBuf();
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = NULL;
}

int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd)
{
#define MAX_DATA_BUF 4096
    ServerDataBuf *node = (ServerDataBuf *)SoftBusCalloc(sizeof(ServerDataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create server data buf node fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = MAX_DATA_BUF;
    node->data = (char *)SoftBusCalloc(MAX_DATA_BUF);
    if (node->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create server data buf fail.");
        SoftBusFree(node);
        return SOFTBUS_MALLOC_ERR;
    }
    node->w = node->data;

    if (SoftBusMutexLock(&(g_tcpSrvDataList->lock)) != SOFTBUS_OK) {
        SoftBusFree(node->data);
        SoftBusFree(node);
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&node->node);
    ListTailInsert(&g_tcpSrvDataList->list, &node->node);
    g_tcpSrvDataList->cnt++;
    SoftBusMutexUnlock(&(g_tcpSrvDataList->lock));

    return SOFTBUS_OK;
}

void TransSrvDelDataBufNode(int32_t channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        TRANS_LOGE(TRANS_BYTES, "g_tcpSrvDataList is null");
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_BYTES, "delete channelId=%{public}d", item->channelId);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpSrvDataList->cnt--;
            break;
        }
    }
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
}

static AuthLinkType SwitchCipherTypeToAuthLinkType(uint32_t cipherFlag)
{
    if (cipherFlag & FLAG_BR) {
        return AUTH_LINK_TYPE_BR;
    }

    if (cipherFlag & FLAG_BLE) {
        return AUTH_LINK_TYPE_BLE;
    }

    if (cipherFlag & FLAG_P2P) {
        return AUTH_LINK_TYPE_P2P;
    }
    if (cipherFlag & FLAG_ENHANCE_P2P) {
        return AUTH_LINK_TYPE_ENHANCED_P2P;
    }
    return AUTH_LINK_TYPE_WIFI;
}

static int32_t PackBytes(int32_t channelId, const char *data, TdcPacketHead *packetHead,
    char *buffer, uint32_t bufLen)
{
    AuthHandle authHandle = { 0 };
    if (GetAuthHandleByChanId(channelId, &authHandle) != SOFTBUS_OK ||
        authHandle.authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_BYTES, "PackBytes get auth id fail");
        return SOFTBUS_NOT_FIND;
    }

    uint8_t *encData = (uint8_t *)buffer + DC_MSG_PACKET_HEAD_SIZE;
    uint32_t encDataLen = bufLen - DC_MSG_PACKET_HEAD_SIZE;
    if (AuthEncrypt(&authHandle, (const uint8_t *)data, packetHead->dataLen, encData, &encDataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "PackBytes encrypt fail");
        return SOFTBUS_ENCRYPT_ERR;
    }
    packetHead->dataLen = encDataLen;

    TRANS_LOGI(TRANS_BYTES, "PackBytes: flag=%{public}u, seq=%{public}" PRIu64,
        packetHead->flags, packetHead->seq);
    PackTdcPacketHead(packetHead);
    if (memcpy_s(buffer, bufLen, packetHead, sizeof(TdcPacketHead)) != EOK) {
        TRANS_LOGE(TRANS_BYTES, "memcpy_s buffer fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void SendFailToFlushDevice(SessionConn *conn)
{
    if (conn->appInfo.routeType == WIFI_STA) {
        char *tmpId = NULL;
        Anonymize(conn->appInfo.peerData.deviceId, &tmpId);
        TRANS_LOGE(TRANS_CTRL, "send data fail, do Authflushdevice deviceId=%{public}s", AnonymizeWrapper(tmpId));
        AnonymizeFree(tmpId);
        if (AuthFlushDevice(conn->appInfo.peerData.deviceId) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "tcp flush failed, wifi will offline");
            LnnRequestLeaveSpecific(conn->appInfo.peerNetWorkId, CONNECTION_ADDR_WLAN);
        }
    }
}

int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data)
{
    if (data == NULL || packetHead == NULL || packetHead->dataLen == 0) {
        TRANS_LOGE(TRANS_BYTES, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthHandle authHandle = { 0 };
    if (GetAuthHandleByChanId(channelId, &authHandle) != SOFTBUS_OK ||
        authHandle.authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_BYTES, "get auth id fail, channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED;
    }
    uint32_t bufferLen = AuthGetEncryptSize(authHandle.authId, packetHead->dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = (char *)SoftBusCalloc(bufferLen);
    if (buffer == NULL) {
        TRANS_LOGE(TRANS_BYTES, "buffer malloc error.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PackBytes(channelId, data, packetHead, buffer, bufferLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "Pack Bytes error.");
        SoftBusFree(buffer);
        return SOFTBUS_ENCRYPT_ERR;
    }
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        TRANS_LOGE(TRANS_BYTES, "malloc conn fail");
        SoftBusFree(buffer);
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetSessionConnById(channelId, conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "Get SessionConn fail");
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    (void)memset_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), 0, sizeof(conn->appInfo.sessionKey));
    int fd = conn->appInfo.fd;
    SetIpTos(fd, FAST_MESSAGE_TOS);
    if (ConnSendSocketData(fd, buffer, bufferLen, 0) != (int)bufferLen) {
        SendFailToFlushDevice(conn);
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return GetErrCodeBySocketErr(SOFTBUS_TCP_SOCKET_ERR);
    }
    SoftBusFree(conn);
    SoftBusFree(buffer);
    return SOFTBUS_OK;
}

static void GetChannelInfoFromConn(ChannelInfo *info, SessionConn *conn, int32_t channelId)
{
    info->channelId = channelId;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->isServer = conn->serverSide;
    info->isEnabled = true;
    info->fd = conn->appInfo.fd;
    info->sessionKey = conn->appInfo.sessionKey;
    info->myHandleId = conn->appInfo.myHandleId;
    info->peerHandleId = conn->appInfo.peerHandleId;
    info->peerSessionName = conn->appInfo.peerData.sessionName;
    info->groupId = conn->appInfo.groupId;
    info->isEncrypt = true;
    info->keyLen = SESSION_KEY_LENGTH;
    info->peerUid = conn->appInfo.peerData.uid;
    info->peerPid = conn->appInfo.peerData.pid;
    info->routeType = conn->appInfo.routeType;
    info->businessType = conn->appInfo.businessType;
    info->autoCloseTime = conn->appInfo.autoCloseTime;
    info->peerIp = conn->appInfo.peerData.addr;
    info->peerPort = conn->appInfo.peerData.port;
    info->linkType = conn->appInfo.linkType;
    info->dataConfig = conn->appInfo.myData.dataConfig;
}

static int32_t GetServerSideIpInfo(const AppInfo *appInfo, char *ip, uint32_t len)
{
    char myIp[IP_LEN] = { 0 };
    if (appInfo->routeType == WIFI_STA) {
        if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "NotifyChannelOpened get local ip fail");
            return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
        }
    } else if (appInfo->routeType == WIFI_P2P) {
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        if (mgr == NULL || mgr->getLocalIpByRemoteIp == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetWifiDirectManager failed");
            return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
        }

        int32_t ret = mgr->getLocalIpByRemoteIp(appInfo->peerData.addr, myIp, sizeof(myIp));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret=%{public}d", ret);
            return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
        }

        if (LnnSetLocalStrInfo(STRING_KEY_P2P_IP, myIp) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide set local p2p ip fail");
        }
        if (LnnSetDLP2pIp(appInfo->peerData.deviceId, CATEGORY_UUID, appInfo->peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide set peer p2p ip fail");
        }
    }
    if (strcpy_s(ip, len, myIp) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy str failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetClientSideIpInfo(const AppInfo *appInfo, char *ip, uint32_t len)
{
    if (appInfo->routeType == WIFI_P2P) {
        if (LnnSetLocalStrInfo(STRING_KEY_P2P_IP, appInfo->myData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client set local p2p ip fail");
        }
        if (LnnSetDLP2pIp(appInfo->peerData.deviceId, CATEGORY_UUID, appInfo->peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client set peer p2p ip fail");
        }
    }
    if (strcpy_s(ip, len, appInfo->myData.addr) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy str failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t NotifyChannelOpened(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    ChannelInfo info = { 0 };
    GetChannelInfoFromConn(&info, &conn, channelId);
    char myIp[IP_LEN] = { 0 };
    int32_t ret = conn.serverSide ? GetServerSideIpInfo(&conn.appInfo, myIp, IP_LEN)
                                  : GetClientSideIpInfo(&conn.appInfo, myIp, IP_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get ip failed, ret=%{public}d.", ret);
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        return ret;
    }
    info.myIp = myIp;

    char buf[NETWORK_ID_BUF_LEN] = { 0 };
    ret = LnnGetNetworkIdByUuid(conn.appInfo.peerData.deviceId, buf, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get networkId failed, ret=%{public}d", ret);
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        return ret;
    }
    info.peerDeviceId = buf;
    info.timeStart = conn.appInfo.timeStart;
    info.linkType = conn.appInfo.linkType;
    info.connectType = conn.appInfo.connectType;
    info.osType = conn.appInfo.osType;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    ret = TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");

    int32_t uid = 0;
    int32_t pid = 0;
    if (TransTdcGetUidAndPid(conn.appInfo.myData.sessionName, &uid, &pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get uid and pid fail.");
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        return SOFTBUS_TRANS_GET_PID_FAILED;
    }
    if (conn.appInfo.fastTransDataSize > 0) {
        info.isFastData = true;
    }
    TransGetLaneIdByChannelId(channelId, &info.laneId);
    info.isSupportTlv = GetCapabilityBit(&conn.appInfo.channelCapability, TRANS_CAPABILITY_TLV_OFFSET);
    GetOsTypeByNetworkId(info.peerDeviceId, &info.osType);
    ret = TransTdcOnChannelOpened(pkgName, pid, conn.appInfo.myData.sessionName, &info);
    (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
    conn.status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    SetSessionConnStatusById(channelId, conn.status);
    return ret;
}

static int32_t NotifyChannelBind(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify channel bind, get tdcInfo is null channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    (void)memset_s(&conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));

    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");

    ret = TransTdcOnChannelBind(pkgName, conn.appInfo.myData.pid, channelId);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

static int32_t NotifyChannelClosed(const AppInfo *appInfo, int32_t channelId)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    int32_t ret = TransTdcGetPkgName(appInfo->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");
    ret = TransTdcOnChannelClosed(pkgName, appInfo->myData.pid, channelId);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

int32_t NotifyChannelOpenFailedBySessionConn(const SessionConn *conn, int32_t errCode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(conn != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    int64_t timeStart = conn->appInfo.timeStart;
    int64_t timeDiff = GetSoftbusRecordTimeMillis() - timeStart;
    char localUdid[UDID_BUF_LEN] = { 0 };
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, sizeof(localUdid));
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = conn->appInfo.myData.pkgName,
        .channelId = conn->channelId,
        .peerNetworkId = conn->appInfo.peerNetWorkId,
        .socketName = conn->appInfo.myData.sessionName,
        .linkType = conn->appInfo.connectType,
        .costTime = timeDiff,
        .errcode = errCode,
        .osType = (conn->appInfo.osType < 0) ? UNKNOW_OS_TYPE : (conn->appInfo.osType),
        .localUdid = localUdid,
        .peerUdid = conn->appInfo.peerUdid,
        .peerDevVer = conn->appInfo.peerVersion,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    extra.deviceState = TransGetDeviceState(conn->appInfo.peerNetWorkId);
    int32_t sceneCommand = conn->serverSide ? EVENT_SCENE_OPEN_CHANNEL_SERVER : EVENT_SCENE_OPEN_CHANNEL;
    TRANS_EVENT(sceneCommand, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransAlarmExtra extraAlarm = {
        .conflictName = NULL,
        .conflictedName = NULL,
        .occupyedName = NULL,
        .permissionName = NULL,
        .linkType = conn->appInfo.linkType,
        .errcode = errCode,
        .sessionName = conn->appInfo.myData.sessionName,
    };
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
    SoftbusRecordOpenSessionKpi(conn->appInfo.myData.pkgName,
        conn->appInfo.linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, timeDiff);
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    int32_t ret = TransTdcGetPkgName(conn->appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");
    if (!(conn->serverSide)) {
        ret = TransTdcOnChannelOpenFailed(
            conn->appInfo.myData.pkgName, conn->appInfo.myData.pid, conn->channelId, errCode);
        TRANS_LOGW(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", conn->channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }

    (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
    return NotifyChannelOpenFailedBySessionConn(&conn, errCode);
}

static int32_t TransTdcPostFastData(SessionConn *conn)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    uint32_t outLen = 0;
    char *buf = TransTdcPackFastData(&(conn->appInfo), &outLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (outLen != conn->appInfo.fastTransDataSize + FAST_TDC_EXT_DATA_SIZE) {
        TRANS_LOGE(TRANS_CTRL, "pack bytes len error, outLen=%{public}d", outLen);
        SoftBusFree(buf);
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t tos = (conn->appInfo.businessType == BUSINESS_TYPE_BYTE) ? FAST_BYTE_TOS : FAST_MESSAGE_TOS;
    if (SetIpTos(conn->appInfo.fd, tos) != SOFTBUS_OK) {
        SoftBusFree(buf);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    ssize_t ret = ConnSendSocketData(conn->appInfo.fd, buf, outLen, 0);
    if (ret != (ssize_t)outLen) {
        TRANS_LOGE(TRANS_CTRL, "failed to send tcp data. ret=%{public}zd", ret);
        SoftBusFree(buf);
        return GetErrCodeBySocketErr(SOFTBUS_TRANS_SEND_TCP_DATA_FAILED);
    }
    SoftBusFree(buf);
    buf = NULL;
    return SOFTBUS_OK;
}

static const ConfigTypeMap g_configTypeMap[] = {
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_BYTE, SOFTBUS_INT_MAX_BYTES_NEW_LENGTH},
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH},
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    uint32_t size = (uint32_t)(sizeof(g_configTypeMap) / sizeof(ConfigTypeMap));
    for (uint32_t i = 0; i < size; i++) {
        if ((g_configTypeMap[i].channelType == channelType) &&
            (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

static int32_t TransGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Invalid channelType=%{public}d, businessType=%{public}d",
            channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen = 0;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d.", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    *len = maxLen;
    TRANS_LOGI(TRANS_CTRL, "get local config len=%{public}d.", *len);
    return SOFTBUS_OK;
}

static int32_t TransTdcProcessDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        TRANS_LOGI(TRANS_CTRL, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        appInfo->myData.dataConfig = MIN(appInfo->myData.dataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_CTRL, "process dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_MAX_BYTES_LENGTH : SOFTBUS_INT_MAX_MESSAGE_LENGTH;
    int32_t ret = SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "process dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

// the channel open failed while be notified when function OpenDataBusReply return ERR
static int32_t OpenDataBusReply(int32_t channelId, uint64_t seq, const cJSON *reply)
{
    (void)seq;
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, seq=%{public}" PRIu64, channelId, seq);
    SessionConn conn;
    (void)memset_s(&conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetSessionConnById(channelId, &conn) == SOFTBUS_OK,
        SOFTBUS_TRANS_GET_SESSION_CONN_FAILED, TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
    int32_t errCode = SOFTBUS_OK;
    if (UnpackReplyErrCode(reply, &errCode) == SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "receive err reply msg channelId=%{public}d, errCode=%{public}d, seq=%{public}" PRIu64,
            channelId, errCode, seq);
        if (errCode == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) {
            (void)TransAddTimestampToList(
                conn.appInfo.myData.sessionName, conn.appInfo.peerData.sessionName,
                conn.appInfo.peerNetWorkId, SoftBusGetSysTimeMs());
        }
        return errCode;
    }

    uint16_t fastDataSize = 0;
    TRANS_CHECK_AND_RETURN_RET_LOGE(UnpackReply(reply, &conn.appInfo, &fastDataSize) == SOFTBUS_OK,
        SOFTBUS_TRANS_UNPACK_REPLY_FAILED, TRANS_CTRL, "UnpackReply failed");

    int32_t ret = TransTdcProcessDataConfig(&conn.appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "Trans Tdc process data config failed.");

    ret = SetAppInfoById(channelId, &conn.appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "set app info by id failed.");

    if ((fastDataSize > 0 && (conn.appInfo.fastTransDataSize == fastDataSize)) || conn.appInfo.fastTransDataSize == 0) {
        ret = NotifyChannelOpened(channelId);
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "notify channel open failed");
    } else {
        ret = TransTdcPostFastData(&conn);
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "tdc send fast data failed");
        ret = NotifyChannelOpened(channelId);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "notify channel open failed");
    }
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = channelId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

static inline int32_t TransTdcPostReplyMsg(int32_t channelId, uint64_t seq, uint32_t flags, char *reply)
{
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = seq,
        .flags = (FLAG_REPLY | flags),
        .dataLen = strlen(reply),
    };
    return TransTdcPostBytes(channelId, &packetHead, reply);
}

static int32_t OpenDataBusRequestReply(const AppInfo *appInfo, int32_t channelId, uint64_t seq, uint32_t flags)
{
    char *reply = PackReply(appInfo);
    if (reply == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get pack reply err");
        return SOFTBUS_TRANS_GET_PACK_REPLY_FAILED;
    }

    int32_t ret = TransTdcPostReplyMsg(channelId, seq, flags, reply);
    cJSON_free(reply);
    return ret;
}

static int32_t OpenDataBusRequestError(int32_t channelId, uint64_t seq, char *errDesc, int32_t errCode, uint32_t flags)
{
    char *reply = PackError(errCode, errDesc);
    if (reply == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get pack reply err");
        return SOFTBUS_TRANS_GET_PACK_REPLY_FAILED;
    }
    int32_t ret = TransTdcPostReplyMsg(channelId, seq, flags, reply);
    cJSON_free(reply);
    return ret;
}

static int32_t GetUuidByChanId(int32_t channelId, char *uuid, uint32_t len)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "get authId fail");
        return SOFTBUS_TRANS_GET_AUTH_ID_FAILED;
    }
    return AuthGetDeviceUuid(authId, uuid, len);
}

static void OpenDataBusRequestOutSessionName(const char *mySessionName, const char *peerSessionName)
{
    char *tmpMyName = NULL;
    char *tmpPeerName = NULL;
    Anonymize(mySessionName, &tmpMyName);
    Anonymize(peerSessionName, &tmpPeerName);
    TRANS_LOGI(TRANS_CTRL, "OpenDataBusRequest: mySessionName=%{public}s, peerSessionName=%{public}s",
        AnonymizeWrapper(tmpMyName), AnonymizeWrapper(tmpPeerName));
    AnonymizeFree(tmpMyName);
    AnonymizeFree(tmpPeerName);
}

static SessionConn* GetSessionConnFromDataBusRequest(int32_t channelId, const cJSON *request)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "conn calloc failed");
        return NULL;
    }
    if (GetSessionConnById(channelId, conn) != SOFTBUS_OK) {
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "get session conn failed");
        return NULL;
    }
    if (UnpackRequest(request, &conn->appInfo) != SOFTBUS_OK) {
        (void)memset_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), 0, sizeof(conn->appInfo.sessionKey));
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "UnpackRequest error");
        return NULL;
    }
    return conn;
}

static void NotifyFastDataRecv(SessionConn *conn, int32_t channelId)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    TransReceiveData receiveData;
    receiveData.data = (void*)conn->appInfo.fastTransData;
    receiveData.dataLen = conn->appInfo.fastTransDataSize + FAST_TDC_EXT_DATA_SIZE;
    if (conn->appInfo.businessType == BUSINESS_TYPE_MESSAGE) {
        receiveData.dataType = TRANS_SESSION_MESSAGE;
    } else {
        receiveData.dataType = TRANS_SESSION_BYTES;
    }
    if (TransTdcOnMsgReceived(conn->appInfo.myData.pkgName, conn->appInfo.myData.pid,
        channelId, &receiveData) != SOFTBUS_OK) {
        conn->appInfo.fastTransDataSize = 0;
        TRANS_LOGE(TRANS_CTRL, "err");
        return;
    }
    TRANS_LOGD(TRANS_CTRL, "ok");
}

static int32_t TransTdcFillDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (appInfo->businessType != BUSINESS_TYPE_BYTE && appInfo->businessType != BUSINESS_TYPE_MESSAGE) {
        TRANS_LOGI(TRANS_CTRL, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        int32_t ret = TransGetLocalConfig(CHANNEL_TYPE_TCP_DIRECT, appInfo->businessType, &localDataConfig);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get local config fail");
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_CTRL, "fill dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_MAX_BYTES_LENGTH : SOFTBUS_INT_MAX_MESSAGE_LENGTH;
    int32_t ret = SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "fill dataConfig=%{public}d", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static bool IsMetaSession(const char *sessionName)
{
    if (strlen(sessionName) < MIN_META_LEN || strncmp(sessionName, META_SESSION, MIN_META_LEN)) {
        return false;
    }
    return true;
}

static void ReleaseSessionConn(SessionConn *chan)
{
    if (chan == NULL) {
        return;
    }
    if (chan->appInfo.fastTransData != NULL) {
        SoftBusFree((void*)chan->appInfo.fastTransData);
    }
    SoftBusFree(chan);
}

static void ReportTransEventExtra(
    TransEventExtra *extra, int32_t channelId, SessionConn *conn, NodeInfo *nodeInfo, char *peerUuid)
{
    extra->socketName = conn->appInfo.myData.sessionName;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->channelId = channelId;
    extra->peerChannelId = conn->appInfo.peerData.channelId;
    extra->socketFd = conn->appInfo.fd;
    extra->result = EVENT_STAGE_RESULT_OK;
    bool peerRet = GetUuidByChanId(channelId, peerUuid, DEVICE_ID_SIZE_MAX) == SOFTBUS_OK &&
        LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, nodeInfo) == SOFTBUS_OK;
    if (peerRet) {
        extra->peerUdid = nodeInfo->deviceInfo.deviceUdid;
        extra->peerDevVer = nodeInfo->deviceInfo.deviceVersion;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nodeInfo->masterUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra->localUdid = nodeInfo->masterUdid;
    }
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, *extra);
}

static int32_t CheckServerPermission(AppInfo *appInfo, char *ret)
{
    if (appInfo->callingTokenId != TOKENID_NOT_SET &&
        TransCheckServerAccessControl(appInfo->callingTokenId) != SOFTBUS_OK) {
        ret = (char *)"Server check acl failed";
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }

    if (CheckSecLevelPublic(appInfo->myData.sessionName, appInfo->peerData.sessionName) != SOFTBUS_OK) {
        ret = (char *)"Server check session name failed";
        return SOFTBUS_PERMISSION_SERVER_DENIED;
    }

    return SOFTBUS_OK;
}

static int32_t TransTdcCheckCollabRelation(const AppInfo *appInfo, int32_t channelId, char *ret)
{
    OpenDataBusRequestOutSessionName(appInfo->myData.sessionName, appInfo->peerData.sessionName);
    TRANS_LOGI(TRANS_CTRL, "OpenDataBusRequest: myPid=%{public}d, peerPid=%{public}d",
        appInfo->myData.pid, appInfo->peerData.pid);
    
    char *errDesc = NULL;
    int32_t errCode = CheckCollabRelation(appInfo, channelId, CHANNEL_TYPE_TCP_DIRECT);
    if (errCode == SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION) {
        errCode = NotifyChannelOpened(channelId);
        if (errCode != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "Notify SDK Channel Opened Failed, ret=%{public}d", errCode);
            errDesc = (char *)"Notify SDK Channel Opened Failed";
            goto ERR_EXIT;
        }
    } else if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "CheckCollabRelation Failed, ret=%{public}d", errCode);
        errDesc = (char *)"CheckCollabRelation Failed";
        goto ERR_EXIT;
    }
    return SOFTBUS_OK;
ERR_EXIT:
    if (strcpy_s(ret, MAX_ERRDESC_LEN, errDesc) != EOK) {
        TRANS_LOGW(TRANS_CTRL, "strcpy failed");
    }
    return errCode;
}

static int32_t TransTdcFillAppInfoAndNotifyChannel(AppInfo *appInfo, int32_t channelId, char *errDesc)
{
    char *ret = NULL;
    int32_t errCode = SOFTBUS_OK;
    errCode = CheckServerPermission(appInfo, ret);
    if (errCode != SOFTBUS_OK) {
        goto ERR_EXIT;
    }

    if (TransTdcGetUidAndPid(appInfo->myData.sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        errCode = SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        ret = (char *)"Peer Device Session Not Create";
        goto ERR_EXIT;
    }

    errCode = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Auth: Get Uuid By ChanId failed.");
        ret = (char *)"Get Uuid By ChanId failed";
        goto ERR_EXIT;
    }

    errCode = TransTdcFillDataConfig(appInfo);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill data config failed.");
        ret = (char *)"fill data config failed";
        goto ERR_EXIT;
    }
    appInfo->myHandleId = 0;
    errCode = SetAppInfoById(channelId, appInfo);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set app info by id failed.");
        ret = (char *)"Set App Info By Id Failed";
        goto ERR_EXIT;
    }

    errCode = TransTdcCheckCollabRelation(appInfo, channelId, ret);
    if (errCode != SOFTBUS_OK) {
        goto ERR_EXIT;
    }

    return SOFTBUS_OK;
ERR_EXIT:
    if (strcpy_s(errDesc, MAX_ERRDESC_LEN, ret) != EOK) {
        TRANS_LOGW(TRANS_CTRL, "strcpy failed");
    }
    return errCode;
}

static int32_t HandleDataBusReply(
    SessionConn *conn, int32_t channelId, TransEventExtra *extra, uint32_t flags, uint64_t seq)
{
    int32_t ret = OpenDataBusRequestReply(&conn->appInfo, channelId, seq, flags);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequest reply err");
        (void)NotifyChannelClosed(&conn->appInfo, channelId);
        return ret;
    } else {
        extra->result = EVENT_STAGE_RESULT_OK;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, *extra);
    }

    if (conn->appInfo.routeType == WIFI_P2P) {
        if (LnnGetNetworkIdByUuid(conn->appInfo.peerData.deviceId,
            conn->appInfo.peerNetWorkId, DEVICE_ID_SIZE_MAX) == SOFTBUS_OK) {
            TRANS_LOGI(TRANS_CTRL, "get networkId by uuid");
            LaneUpdateP2pAddressByIp(conn->appInfo.peerData.addr, conn->appInfo.peerNetWorkId);
        }
    }
    return SOFTBUS_OK;
}

static int32_t OpenDataBusRequest(int32_t channelId, uint32_t flags, uint64_t seq, const cJSON *request)
{
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, seq=%{public}" PRIu64, channelId, seq);
    SessionConn *conn = GetSessionConnFromDataBusRequest(channelId, request);
    TRANS_CHECK_AND_RETURN_RET_LOGE(conn != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "conn is null");

    TransEventExtra extra;
    char peerUuid[DEVICE_ID_SIZE_MAX] = { 0 };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ReportTransEventExtra(&extra, channelId, conn, &nodeInfo, peerUuid);

    if ((flags & FLAG_AUTH_META) != 0 && !IsMetaSession(conn->appInfo.myData.sessionName)) {
        char *tmpName = NULL;
        Anonymize(conn->appInfo.myData.sessionName, &tmpName);
        TRANS_LOGI(TRANS_CTRL,
            "Request denied: session is not a meta session. sessionName=%{public}s", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        (void)memset_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), 0, sizeof(conn->appInfo.sessionKey));
        ReleaseSessionConn(conn);
        return SOFTBUS_TRANS_NOT_META_SESSION;
    }
    char errDesc[MAX_ERRDESC_LEN] = { 0 };
    int32_t errCode = TransTdcFillAppInfoAndNotifyChannel(&conn->appInfo, channelId, errDesc);
    if (errCode != SOFTBUS_OK) {
        if (OpenDataBusRequestError(channelId, seq, errDesc, errCode, flags) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequestError error");
        }
        (void)memset_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), 0, sizeof(conn->appInfo.sessionKey));
        (void)TransDelTcpChannelInfoByChannelId(channelId);
        TransDelSessionConnById(channelId);
        ReleaseSessionConn(conn);
    }
    return errCode;
}

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const char *msg, uint32_t dataLen)
{
    int32_t ret;
    cJSON *json = cJSON_ParseWithLength(msg, dataLen);
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "json parse failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (flags & FLAG_REPLY) {
        ret = OpenDataBusReply(channelId, seq, json);
    } else {
        ret = OpenDataBusRequest(channelId, flags, seq, json);
    }
    cJSON_Delete(json);
    AppInfo appInfo;
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetAppInfoById(channelId, &appInfo) == SOFTBUS_OK, ret,
        TRANS_CTRL, "get appInfo fail");
    char *tmpNetWorkId = NULL;
    char *tmpUdid = NULL;
    Anonymize(appInfo.peerNetWorkId, &tmpNetWorkId);
    Anonymize(appInfo.peerUdid, &tmpUdid);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, peerNetWorkId=%{public}s, peerUdid=%{public}s, ret=%{public}d",
        channelId, AnonymizeWrapper(tmpNetWorkId), AnonymizeWrapper(tmpUdid), ret);
    AnonymizeFree(tmpNetWorkId);
    AnonymizeFree(tmpUdid);
    return ret;
}

static ServerDataBuf *TransSrvGetDataBufNodeById(int32_t channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpSrvDataList is null");
        return NULL;
    }

    ServerDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpSrvDataList->list), ServerDataBuf, node) {
        if (item->channelId == channelId) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "srv tcp direct channelId=%{public}d not exist.", channelId);
    return NULL;
}

static int32_t GetAuthIdByChannelInfo(int32_t channelId, uint64_t seq, uint32_t cipherFlag, AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        TRANS_LOGE(TRANS_CTRL, "authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetAuthHandleByChanId(channelId, authHandle) == SOFTBUS_OK && authHandle->authId != AUTH_INVALID_ID) {
        TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 " is not AUTH_INVALID_ID", authHandle->authId);
        return SOFTBUS_OK;
    }

    AppInfo appInfo;
    int32_t ret = GetAppInfoById(channelId, &appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get appInfo fail");

    bool fromAuthServer = ((seq & AUTH_CONN_SERVER_SIDE) != 0);
    char uuid[UUID_BUF_LEN] = {0};
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr == NULL || mgr->getRemoteUuidByIp == NULL) {
        TRANS_LOGE(TRANS_CTRL, "GetWifiDirectManager failed");
        return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
    }
    ret = mgr->getRemoteUuidByIp(appInfo.peerData.addr, uuid, sizeof(uuid));
    (void)memset_s(appInfo.sessionKey, sizeof(appInfo.sessionKey), 0, sizeof(appInfo.sessionKey));
    if (ret != SOFTBUS_OK) {
        AuthConnInfo connInfo;
        connInfo.type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, appInfo.peerData.addr) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "copy ip addr fail");
            return SOFTBUS_MEM_ERR;
        }
        char *tmpPeerIp = NULL;
        Anonymize(appInfo.peerData.addr, &tmpPeerIp);
        TRANS_LOGE(TRANS_CTRL, "channelId=%{public}d get remote uuid by Ip=%{public}s failed",
            channelId, AnonymizeWrapper(tmpPeerIp));
        AnonymizeFree(tmpPeerIp);
        authHandle->type = connInfo.type;
        authHandle->authId = AuthGetIdByConnInfo(&connInfo, !fromAuthServer, false);
        return SOFTBUS_OK;
    }

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    TRANS_LOGI(TRANS_CTRL, "get auth linkType=%{public}d, flag=0x%{public}x", linkType, cipherFlag);
    bool isAuthMeta = (cipherFlag & FLAG_AUTH_META) ? true : false;
    authHandle->type = linkType;
    authHandle->authId = AuthGetIdByUuid(uuid, linkType, !fromAuthServer, isAuthMeta);
    return SOFTBUS_OK;
}

static int32_t DecryptMessage(int32_t channelId, const TdcPacketHead *pktHead, const uint8_t *pktData,
    uint8_t **outData, uint32_t *outDataLen)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    int32_t ret = GetAuthIdByChannelInfo(channelId, pktHead->seq, pktHead->flags, &authHandle);
    if (ret != SOFTBUS_OK || (authHandle.authId == AUTH_INVALID_ID && pktHead->flags == FLAG_P2P)) {
        TRANS_LOGW(TRANS_CTRL, "get p2p authId fail, peer device may be legacyOs, retry hml");
        // we don't know peer device is legacyOs or not, so retry hml when flag is p2p and get auth failed
        ret = GetAuthIdByChannelInfo(channelId, pktHead->seq, FLAG_ENHANCE_P2P, &authHandle);
    }
    if (ret != SOFTBUS_OK || authHandle.authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: get authId fail.");
        return SOFTBUS_NOT_FIND;
    }
    ret = SetAuthHandleByChanId(channelId, &authHandle);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "srv process recv data: set authId fail.");

    uint32_t decDataLen = AuthGetDecryptSize(pktHead->dataLen) + 1;
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (AuthDecrypt(&authHandle, pktData, pktHead->dataLen, decData, &decDataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: decrypt fail.");
        SoftBusFree(decData);
        return SOFTBUS_DECRYPT_ERR;
    }
    *outData = decData;
    *outDataLen = decDataLen;
    return SOFTBUS_OK;
}

static int32_t ProcessReceivedData(int32_t channelId, int32_t type)
{
    uint64_t seq;
    uint32_t flags;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL || node->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "node is null.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_TRANS_NODE_IS_NULL;
    }
    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    uint8_t *pktData = (uint8_t *)(node->data + sizeof(TdcPacketHead));
    if (pktHead->module != MODULE_SESSION) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: illegal module.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_TRANS_ILLEGAL_MODULE;
    }
    seq = pktHead->seq;
    flags = pktHead->flags;

    TRANS_LOGI(TRANS_CTRL,
        "recv tdc packet. channelId=%{public}d, flags=%{public}d, seq=%{public}" PRIu64,
        channelId, flags, seq);
    if (DecryptMessage(channelId, pktHead, pktData, &data, &dataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: decrypt fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }

    char *end = node->data + sizeof(TdcPacketHead) + pktHead->dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusFree(data);
        TRANS_LOGE(TRANS_CTRL, "memmove fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - sizeof(TdcPacketHead) - pktHead->dataLen;
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    int32_t ret = ProcessMessage(channelId, flags, seq, (char *)data, dataLen);
    SoftBusFree(data);
    return ret;
}

static int32_t TransTdcSrvProcData(ListenerModule module, int32_t channelId, int32_t type)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_tcpSrvDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is NULL");
    int32_t ret = SoftBusMutexLock(&g_tcpSrvDataList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock failed.");

    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv can not get buf node. listenerModule=%{public}d, "
            "channelId=%{public}d, type=%{public}d", (int32_t)module, channelId, type);
        return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED;
    }

    uint32_t bufLen = node->w - node->data;
    if (bufLen < DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv head not enough, recv next time. listenerModule=%{public}d, bufLen=%{public}u "
            "channelId=%{public}d, type=%{public}d", (int32_t)module, bufLen, channelId, type);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    UnpackTdcPacketHead(pktHead);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv recv invalid packet head listenerModule=%{public}d, "
            "channelId=%{public}d, type=%{public}d", (int32_t)module, channelId, type);
        return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED;
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > node->size - DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv out of recv dataLen=%{public}u, listenerModule=%{public}d, "
            "channelId=%{public}d, type=%{public}d", dataLen, (int32_t)module, channelId, type);
        return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED;
    }

    if (bufLen < dataLen + DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv data not enough, recv next time. bufLen=%{public}u, dataLen=%{public}u, headLen=%{public}d "
            "listenerModule=%{public}d, channelId=%{public}d, type=%{public}d",
            bufLen, dataLen, (int32_t)DC_MSG_PACKET_HEAD_SIZE, (int32_t)module, channelId, type);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    DelTrigger(module, node->fd, READ_TRIGGER);
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    return ProcessReceivedData(channelId, type);
}

static int32_t TransTdcGetDataBufInfoByChannelId(int32_t channelId, int32_t *fd, size_t *len)
{
    if (fd == NULL || len == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tcp srv data list empty.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    ServerDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpSrvDataList->list), ServerDataBuf, node) {
        if (item->channelId == channelId) {
            *fd = item->fd;
            *len = item->size - (item->w - item->data);
            (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    TRANS_LOGI(TRANS_CTRL, "trans tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TCP_DATABUF_NOT_FOUND;
}

static int32_t TransTdcUpdateDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "srv data list empty.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    ServerDataBuf *item = NULL;
    ServerDataBuf *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &(g_tcpSrvDataList->list), ServerDataBuf, node) {
        if (item->channelId != channelId) {
            continue;
        }
        int32_t freeLen = (int32_t)(item->size) - (item->w - item->data);
        if (recvLen > freeLen) {
            (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
            TRANS_LOGE(TRANS_CTRL,
                "trans tdc. recvLen=%{public}d, freeLen=%{public}d.", recvLen, freeLen);
            return SOFTBUS_TRANS_RECV_DATA_OVER_LEN;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
            TRANS_LOGE(TRANS_CTRL, "memcpy_s trans tdc failed. channelId=%{public}d", channelId);
            return SOFTBUS_MEM_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    TRANS_LOGE(TRANS_CTRL, "trans update tdc databuf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TCP_DATABUF_NOT_FOUND;
}

static int32_t TransRecvTdcSocketData(int32_t channelId, char *buffer, int32_t bufferSize)
{
    int32_t fd = -1;
    size_t len = 0;
    int32_t ret = TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, TRANS_CTRL, "get info failed, ret=%{public}d", ret);
    TRANS_CHECK_AND_RETURN_RET_LOGE(len >= (size_t)bufferSize, SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, TRANS_CTRL,
        "freeBufferLen=%{public}zu less than bufferSize=%{public}d. channelId=%{public}d", len, bufferSize, channelId);

    int32_t totalRecvLen = 0;
    while (totalRecvLen < bufferSize) {
        int32_t recvLen = ConnRecvSocketData(fd, buffer, bufferSize - totalRecvLen, 0);
        if (recvLen < 0) {
            TRANS_LOGE(TRANS_CTRL, "recv tcp data fail, channelId=%{public}d, retLen=%{public}d, total=%{public}d, "
                "totalRecv=%{public}d", channelId, recvLen, bufferSize, totalRecvLen);
            return GetErrCodeBySocketErr(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);
        } else if (recvLen == 0) {
            TRANS_LOGE(TRANS_CTRL, "recv tcp data fail, retLen=0, channelId=%{public}d, total=%{public}d, "
                "totalRecv=%{public}d", channelId, bufferSize, totalRecvLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        if (TransTdcUpdateDataBufWInfo(channelId, buffer, recvLen) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "update channel data buf failed. channelId=%{public}d", channelId);
            return SOFTBUS_TRANS_UPDATE_DATA_BUF_FAILED;
        }
        buffer += recvLen;
        totalRecvLen += recvLen;
    }

    return SOFTBUS_OK;
}

/*
 * The negotiation message may be unpacked, and when obtaining the message,
 * it is necessary to first check whether the buffer of the channel already has data.
*/
static int32_t TransReadDataLen(int32_t channelId, int32_t *pktDataLen, int32_t module, int32_t type)
{
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tcp srv data list empty channelId=%{public}d %{public}d.", channelId, module);
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed channelId=%{public}d %{public}d.", channelId, module);
        return SOFTBUS_LOCK_ERR;
    }

    ServerDataBuf *dataBuf = TransSrvGetDataBufNodeById(channelId);
    if (dataBuf == NULL) {
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_TRANS_TCP_DATABUF_NOT_FOUND;
    }

    const uint32_t headSize = sizeof(TdcPacketHead);
    uint32_t bufDataLen = dataBuf->w - dataBuf->data;
    const uint32_t maxDataLen = dataBuf->size - headSize;

    TdcPacketHead *pktHeadPtr = NULL;
    // channel buffer already has header data
    if (bufDataLen >= headSize) {
        bufDataLen -= headSize;
        pktHeadPtr = (TdcPacketHead *)(dataBuf->data);
        // obtain the remaining length of data to be read
        *pktDataLen = pktHeadPtr->dataLen - bufDataLen;
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    TdcPacketHead pktHead;
    (void)memset_s(&pktHead, sizeof(pktHead), 0, sizeof(pktHead));
    int32_t ret = TransRecvTdcSocketData(channelId, (char *)&pktHead, headSize);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    UnpackTdcPacketHead(&pktHead);
    if (pktHead.magicNumber != MAGIC_NUMBER || pktHead.dataLen > maxDataLen || pktHead.dataLen == 0) {
        TRANS_LOGE(TRANS_CTRL, "invalid packet head module=%{public}d, channelId=%{public}d, type=%{public}d, "
            "magic=%{public}x, len=%{public}d", module, channelId, type, pktHead.magicNumber, pktHead.dataLen);
        return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED;
    }
    *pktDataLen = pktHead.dataLen;

    return SOFTBUS_OK;
}

int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId, int32_t type)
{
    int32_t dataSize = 0;
    int32_t ret = TransReadDataLen(channelId, &dataSize, (int32_t)module, type);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED,
        TRANS_CTRL, "read dataLen failed, ret=%{public}d", ret);

    char *dataBuffer = (char *)SoftBusCalloc(dataSize);
    if (dataBuffer == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc failed. channelId=%{public}d, len=%{public}d", channelId, dataSize);
        return SOFTBUS_MALLOC_ERR;
    }
    ret = TransRecvTdcSocketData(channelId, dataBuffer, dataSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(dataBuffer);
        return ret;
    }
    SoftBusFree(dataBuffer);

    return TransTdcSrvProcData(module, channelId, type);
}

static int32_t TransSrvGetSeqAndFlagsByChannelId(uint64_t *seq, uint32_t *flags, int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_tcpSrvDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is null");

    int32_t ret = SoftBusMutexLock(&g_tcpSrvDataList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_CTRL, "lock mutex fail!");
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL || node->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "node is null.");
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_TRANS_NODE_IS_NULL;
    }
    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    *seq = pktHead->seq;
    *flags = pktHead->flags;
    TRANS_LOGI(TRANS_CTRL, "flags=%{public}d, seq=%{public}" PRIu64, *flags, *seq);
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    return SOFTBUS_OK;
}

static void TransCleanTdcSource(int32_t channelId)
{
    (void)TransDelTcpChannelInfoByChannelId(channelId);
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
}

static void TransProcessAsyncOpenTdcChannelFailed(
    SessionConn *conn, int32_t openResult, uint64_t seq, uint32_t flags)
{
    char errDesc[MAX_ERRDESC_LEN] = { 0 };
    char *desc = (char *)"Tdc channel open failed";
    if (strcpy_s(errDesc, MAX_ERRDESC_LEN, desc) != EOK) {
        TRANS_LOGW(TRANS_CTRL, "strcpy failed");
    }
    if (OpenDataBusRequestError(conn->channelId, seq, errDesc, openResult, flags) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequestError error");
    }
    (void)memset_s(conn->appInfo.sessionKey, sizeof(conn->appInfo.sessionKey), 0, sizeof(conn->appInfo.sessionKey));
    TransCleanTdcSource(conn->channelId);
    CloseTcpDirectFd(conn->listenMod, conn->appInfo.fd);
}

int32_t TransDealTdcChannelOpenResult(int32_t channelId, int32_t openResult)
{
    SessionConn conn;
    (void)memset_s(&conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    int32_t ret = GetSessionConnById(channelId, &conn);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get sessionConn failed, ret=%{public}d", ret);
    ret = TransTdcUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    uint32_t flags = 0;
    uint64_t seq = 0;
    ret = TransSrvGetSeqAndFlagsByChannelId(&seq, &flags, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get seqs and flags failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    char peerUuid[DEVICE_ID_SIZE_MAX] = { 0 };
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ReportTransEventExtra(&extra, channelId, &conn, &nodeInfo, peerUuid);
    if (openResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Tdc channel open failed, openResult=%{public}d", openResult);
        TransProcessAsyncOpenTdcChannelFailed(&conn, openResult, seq, flags);
        return SOFTBUS_OK;
    }
    if (conn.appInfo.fastTransDataSize > 0 && conn.appInfo.fastTransData != NULL) {
        NotifyFastDataRecv(&conn, channelId);
    }
    ret = HandleDataBusReply(&conn, channelId, &extra, flags, seq);
    CloseTcpDirectFd(conn.listenMod, conn.appInfo.fd);
    if (ret != SOFTBUS_OK) {
        (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
        goto ERR_EXIT;
    }
    ret = NotifyChannelBind(channelId);
    (void)memset_s(conn.appInfo.sessionKey, sizeof(conn.appInfo.sessionKey), 0, sizeof(conn.appInfo.sessionKey));
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
    return SOFTBUS_OK;
ERR_EXIT:
    TransCleanTdcSource(channelId);
    return ret;
}

void TransAsyncTcpDirectChannelTask(int32_t channelId)
{
    int32_t curCount = 0;
    int32_t ret = TransCheckTdcChannelOpenStatus(channelId, &curCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "check tdc channel statue failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount == CHANNEL_OPEN_SUCCESS) {
        TRANS_LOGI(TRANS_CTRL, "Open tdc channel success, channelId=%{public}d", channelId);
        return;
    }
    SessionConn connInfo;
    (void)memset_s(&connInfo, sizeof(SessionConn), 0, sizeof(SessionConn));
    ret = GetSessionConnById(channelId, &connInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount >= LOOPER_REPLY_CNT_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Open Tdc channel timeout, channelId=%{public}d", channelId);
        uint32_t flags = 0;
        uint64_t seq = 0;
        ret = TransSrvGetSeqAndFlagsByChannelId(&seq, &flags, channelId);
        if (ret != SOFTBUS_OK) {
            CloseTcpDirectFd(connInfo.listenMod, connInfo.appInfo.fd);
            TRANS_LOGE(TRANS_CTRL, "get seqs and flags failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
            return;
        }
        char errDesc[MAX_ERRDESC_LEN] = { 0 };
        char *desc = (char *)"Open tdc channel time out!";
        if (strcpy_s(errDesc, MAX_ERRDESC_LEN, desc) != EOK) {
            TRANS_LOGW(TRANS_CTRL, "strcpy failed");
        }
        if (OpenDataBusRequestError(
            channelId, seq, errDesc, SOFTBUS_TRANS_OPEN_CHANNEL_NEGTIATE_TIMEOUT, flags) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequestError error");
        }
        (void)memset_s(
            connInfo.appInfo.sessionKey, sizeof(connInfo.appInfo.sessionKey), 0, sizeof(connInfo.appInfo.sessionKey));
        (void)NotifyChannelClosed(&connInfo.appInfo, channelId);
        TransCleanTdcSource(channelId);
        CloseTcpDirectFd(connInfo.listenMod, connInfo.appInfo.fd);
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "Open channelId=%{public}d not finished, generate new task and waiting", channelId);
    uint32_t delayTime = (curCount <= LOOPER_SEPARATE_CNT) ? FAST_INTERVAL_MILLISECOND : SLOW_INTERVAL_MILLISECOND;
    TransCheckChannelOpenToLooperDelay(channelId, CHANNEL_TYPE_TCP_DIRECT, delayTime);
}

static int32_t TransTdcPostErrorMsg(uint64_t *seq, uint32_t *flags, int32_t channelId, int32_t errCode)
{
    int32_t ret = TransSrvGetSeqAndFlagsByChannelId(seq, flags, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get seq and flags by channelId=%{public}d failed.", channelId);
        return ret;
    }
    char *desc = (char *)"Open tdc channel failed.";
    if (OpenDataBusRequestError(channelId, *seq, desc, errCode, *flags) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_CTRL, "OpenDataBusRequestError failed.");
    }
    return SOFTBUS_OK;
}

int32_t TransDealTdcCheckCollabResult(int32_t channelId, int32_t checkResult)
{
    uint32_t tranFlags = 0;
    uint64_t seq = 0;
    SessionConn conn = { 0 };
    int32_t ret = GetSessionConnById(channelId, &conn);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn by channelId=%{public}d failed.", channelId);
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    ret = TransTdcUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update waitOpenReplyCnt failed, channelId=%{public}d.", channelId);
        goto ERR_EXIT;
    }
    // Remove old check tasks.
    TransCheckChannelOpenRemoveFromLooper(channelId);
    if (checkResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "check Collab relation failed, checkResult=%{public}d.", checkResult);
        ret = checkResult;
        goto ERR_EXIT;
    }
    // Reset the check count to 0.
    ret = TransTdcResetReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        goto ERR_EXIT;
    }
    ret = NotifyChannelOpened(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Notify sdk channelId=%{public}d opened failed ret=%{public}d.", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;

ERR_EXIT:
    ret = TransTdcPostErrorMsg(&seq, &tranFlags, channelId, ret);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    CloseTcpDirectFd(conn.listenMod, conn.appInfo.fd);
    TransDelSessionConnById(channelId);
    return ret;
}
