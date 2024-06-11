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
#include "softbus_app_info.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "wifi_direct_manager.h"

#define MAX_PACKET_SIZE (64 * 1024)
#define MIN_META_LEN 6
#define META_SESSION "IShare"
#define MAX_DATA_BUF 4096
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
    if (g_tcpSrvDataList ==  NULL) {
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
        TRANS_LOGI(TRANS_BYTES, "g_tcpSrvDataList is null");
        return;
    }
    TransSrvDestroyDataBuf();
    DestroySoftBusList(g_tcpSrvDataList);
    g_tcpSrvDataList = NULL;
}

int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd)
{
    ServerDataBuf *node = (ServerDataBuf *)SoftBusCalloc(sizeof(ServerDataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create server data buf node fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = MAX_DATA_BUF;
    node->data = (char*)SoftBusCalloc(MAX_DATA_BUF);
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

void TransSrvDelDataBufNode(int channelId)
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
        TRANS_LOGE(TRANS_CTRL, "send data fail, do Authflushdevice deviceId=%{public}s", tmpId);
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
    uint32_t bufferLen = AuthGetEncryptSize(packetHead->dataLen) + DC_MSG_PACKET_HEAD_SIZE;
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
    if (GetSessionConnById(channelId, conn) == NULL) {
        TRANS_LOGE(TRANS_BYTES, "Get SessionConn fail");
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    int fd = conn->appInfo.fd;
    if (ConnSendSocketData(fd, buffer, bufferLen, 0) != (int)bufferLen) {
        SendFailToFlushDevice(conn);
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return SOFTBUS_TCP_SOCKET_ERR;
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

static int32_t GetServerSideIpInfo(SessionConn *conn, char *ip, uint32_t len)
{
    char myIp[IP_LEN] = { 0 };
    if (conn->appInfo.routeType == WIFI_STA) {
        if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "NotifyChannelOpened get local ip fail");
            return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
        }
    } else if (conn->appInfo.routeType == WIFI_P2P) {
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        if (mgr == NULL || mgr->getLocalIpByRemoteIp == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetWifiDirectManager failed");
            return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
        }

        int32_t ret = mgr->getLocalIpByRemoteIp(conn->appInfo.peerData.addr, myIp, sizeof(myIp));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret = %{public}d", ret);
            return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
        }

        if (LnnSetLocalStrInfo(STRING_KEY_P2P_IP, myIp) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide set local p2p ip fail");
        }
        if (LnnSetDLP2pIp(conn->appInfo.peerData.deviceId, CATEGORY_UUID,
            conn->appInfo.peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide set peer p2p ip fail");
        }
    }
    if (strcpy_s(ip, len, myIp)) {
        TRANS_LOGE(TRANS_CTRL, "copy str failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetClientSideIpInfo(SessionConn *conn, char *ip, uint32_t len)
{
    char myIp[IP_LEN] = { 0 };
    if (conn->appInfo.routeType == WIFI_STA) {
        if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "NotifyChannelOpened get local ip fail");
            return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED;
        }
    } else if (conn->appInfo.routeType == WIFI_P2P) {
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        if (mgr == NULL || mgr->getLocalIpByRemoteIp == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetWifiDirectManager failed");
            return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
        }

        int32_t ret = mgr->getLocalIpByRemoteIp(conn->appInfo.peerData.addr, myIp, sizeof(myIp));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret = %{public}d", ret);
            return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
        }

        if (LnnSetLocalStrInfo(STRING_KEY_P2P_IP, myIp) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client set local p2p ip fail");
        }
        if (LnnSetDLP2pIp(conn->appInfo.peerData.deviceId, CATEGORY_UUID,
            conn->appInfo.peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client set peer p2p ip fail");
        }
    }
    if (strcpy_s(ip, len, conn->appInfo.myData.addr)) {
        TRANS_LOGE(TRANS_CTRL, "copy str failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t NotifyChannelOpened(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    ChannelInfo info = { 0 };
    GetChannelInfoFromConn(&info, &conn, channelId);
    char myIp[IP_LEN] = { 0 };
    int32_t ret = conn.serverSide ? GetServerSideIpInfo(&conn, myIp, IP_LEN) : GetClientSideIpInfo(&conn, myIp, IP_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get ip failed, ret=%{public}d.", ret);
        return ret;
    }
    info.myIp = myIp;

    char buf[NETWORK_ID_BUF_LEN] = {0};
    ret = LnnGetNetworkIdByUuid(conn.appInfo.peerData.deviceId, buf, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get info networkId fail.");
        return ret;
    }
    info.peerDeviceId = buf;
    info.timeStart = conn.appInfo.timeStart;
    info.linkType = conn.appInfo.linkType;
    info.connectType = conn.appInfo.connectType;
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    ret = TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");

    int uid = 0;
    int pid = 0;
    if (TransTdcGetUidAndPid(conn.appInfo.myData.sessionName, &uid, &pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get uid and pid fail.");
        return SOFTBUS_TRANS_GET_PID_FAILED;
    }
    if (conn.appInfo.fastTransDataSize > 0) {
        info.isFastData = true;
    }
    TransGetLaneIdByChannelId(channelId, &info.laneId);
    ret = TransTdcOnChannelOpened(pkgName, pid, conn.appInfo.myData.sessionName, &info);
    conn.status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    SetSessionConnStatusById(channelId, conn.status);
    return ret;
}

static int32_t NotifyChannelBind(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel bind, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }

    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");

    ret = TransTdcOnChannelBind(pkgName, conn.appInfo.myData.pid, channelId);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

static int32_t NotifyChannelClosed(const AppInfo *appInfo, int32_t channelId)
{
    AppInfoData myData = appInfo->myData;
    int ret = TransTdcOnChannelClosed(myData.pkgName, myData.pid, channelId);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

int32_t NotifyChannelOpenFailedBySessionConn(const SessionConn *conn, int32_t errCode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(conn != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    int64_t timeStart = conn->appInfo.timeStart;
    int64_t timediff = GetSoftbusRecordTimeMillis() - timeStart;
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = conn->appInfo.myData.pkgName,
        .channelId = conn->channelId,
        .peerNetworkId = conn->appInfo.peerNetWorkId,
        .socketName = conn->appInfo.myData.sessionName,
        .linkType = conn->appInfo.connectType,
        .costTime = timediff,
        .errcode = errCode,
        .osType = (conn->appInfo.osType < 0) ? UNKNOW_OS_TYPE : (conn->appInfo.osType),
        .peerUdid = conn->appInfo.peerUdid,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    if (!conn->serverSide) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
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
        conn->appInfo.linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, timediff);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = TransTdcGetPkgName(conn->appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get pkg name fail.");
    if (!(conn->serverSide)) {
        const AppInfoData *myData = &conn->appInfo.myData;
        if (myData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "myData is null");
            return SOFTBUS_INVALID_PARAM;
        }
        int ret = TransTdcOnChannelOpenFailed(myData->pkgName, myData->pid, conn->channelId, errCode);
        TRANS_LOGW(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", conn->channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }

    return NotifyChannelOpenFailedBySessionConn(&conn, errCode);
}

static int TransTdcPostFisrtData(SessionConn *conn)
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
        return SOFTBUS_TRANS_SEND_TCP_DATA_FAILED;
    }
    SoftBusFree(buf);
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

static int32_t OpenDataBusReply(int32_t channelId, uint64_t seq, const cJSON *reply)
{
    (void)seq;
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d", channelId);
    SessionConn conn;
    (void)memset_s(&conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetSessionConnById(channelId, &conn) != NULL,
        SOFTBUS_TRANS_GET_SESSION_CONN_FAILED, TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
    int32_t errCode = SOFTBUS_OK;
    if (UnpackReplyErrCode(reply, &errCode) == SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = channelId,
            .errcode = errCode,
            .result = EVENT_STAGE_RESULT_FAILED };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        TRANS_LOGE(TRANS_CTRL, "receive err reply msg");
        int32_t status = NotifyChannelOpenFailed(channelId, errCode);
        TRANS_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, status, TRANS_CTRL, "channel open failed.");
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
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "notify channel open failed");
    } else {
        ret = TransTdcPostFisrtData(&conn);
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
        .result = EVENT_STAGE_RESULT_OK };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

static inline int TransTdcPostReplyMsg(int32_t channelId, uint64_t seq, uint32_t flags, char *reply)
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
        tmpMyName, tmpPeerName);
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
    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "get session conn failed");
        return NULL;
    }
    if (UnpackRequest(request, &conn->appInfo) != SOFTBUS_OK) {
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

static void CheckStrcpy(char *dest, const int32_t destSize, const char *src)
{
    if (strcpy_s(dest, destSize, src) != EOK) {
        TRANS_LOGW(TRANS_CTRL, "strcpy failed");
    }
    return;
}

static int32_t CheckAndFillAppInfo(AppInfo *appInfo, int32_t channelId, char *errDesc)
{
    char *ret = NULL;
    int32_t errCode = SOFTBUS_OK;
    if (appInfo->callingTokenId != TOKENID_NOT_SET &&
        TransCheckServerAccessControl(appInfo->callingTokenId) != SOFTBUS_OK) {
        ret = (char *)"Server check acl failed";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }

    if (TransTdcGetUidAndPid(appInfo->myData.sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        errCode = SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        ret = (char *)"Peer Device Session Not Create";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return errCode;
    }

    errCode = GetUuidByChanId(channelId, appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Auth: Get Uuid By ChanId failed.");
        ret = (char *)"Get Uuid By ChanId failed";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return errCode;
    }

    errCode = TransTdcFillDataConfig(appInfo);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill data config failed.");
        ret = (char *)"fill data config failed";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return errCode;
    }
    appInfo->myHandleId = 0;
    errCode = SetAppInfoById(channelId, appInfo);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set app info by id failed.");
        ret = (char *)"Set App Info By Id Failed";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return errCode;
    }

    OpenDataBusRequestOutSessionName(appInfo->myData.sessionName, appInfo->peerData.sessionName);
    TRANS_LOGI(TRANS_CTRL, "OpenDataBusRequest: myPid=%{public}d, peerPid=%{public}d",
        appInfo->myData.pid, appInfo->peerData.pid);

    errCode = NotifyChannelOpened(channelId);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Notify SDK Channel Opened Failed");
        ret = (char *)"Notify SDK Channel Opened Failed";
        CheckStrcpy(errDesc, MAX_ERRDESC_LEN, ret);
        return errCode;
    }

    return SOFTBUS_OK;
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
            "Request denied: session is not a meta session. sessionName=%{public}s", tmpName);
        AnonymizeFree(tmpName);
        ReleaseSessionConn(conn);
        return SOFTBUS_TRANS_NOT_META_SESSION;
    }
    char errDesc[MAX_ERRDESC_LEN] = { 0 };
    int32_t errCode = CheckAndFillAppInfo(&conn->appInfo, channelId, errDesc);
    if (errCode != SOFTBUS_OK) {
        if (OpenDataBusRequestError(channelId, seq, errDesc, errCode, flags) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequestError error");
        }
        ReleaseSessionConn(conn);
        return errCode;
    }

    if (conn->appInfo.fastTransDataSize > 0 && conn->appInfo.fastTransData != NULL) {
        NotifyFastDataRecv(conn, channelId);
    }

    errCode = HandleDataBusReply(conn, channelId, &extra, flags, seq);
    if (errCode != SOFTBUS_OK) {
        ReleaseSessionConn(conn);
        return errCode;
    }

    errCode = NotifyChannelBind(channelId);
    ReleaseSessionConn(conn);
    return errCode;
}
    

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const char *msg)
{
    int32_t ret;
    cJSON *json = cJSON_Parse(msg);
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
    TRANS_LOGI(TRANS_CTRL, "ret=%{public}d", ret);
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
    TRANS_LOGE(TRANS_CTRL, "srv tcp direct channel id not exist.");
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
    if (ret != SOFTBUS_OK) {
        AuthConnInfo connInfo;
        connInfo.type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, appInfo.peerData.addr) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "copy ip addr fail");
            return SOFTBUS_MEM_ERR;
        }
        TRANS_LOGE(TRANS_CTRL, "get Local Ip fail");
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

    TRANS_LOGI(TRANS_CTRL, "recv tdc packet, flags=%{public}d, seq=%{public}" PRIu64, flags, seq);
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

    int32_t ret = ProcessMessage(channelId, flags, seq, (char *)data);
    SoftBusFree(data);
    return ret;
}

static int32_t TransTdcSrvProcData(ListenerModule module, int32_t channelId, int32_t type)
{
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_tcpSrvDataList is NULL");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL, "srv can not get buf node.");
        return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED;
    }
    uint32_t bufLen = node->w - node->data;
    if (bufLen < DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL, "srv head not enough, recv next time.");
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    UnpackTdcPacketHead(pktHead);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL, "srv recv invalid packet head");
        return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED;
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > node->size - DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL, "srv out of recv dataLen=%{public}d", dataLen);
        return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED;
    }

    if (bufLen < dataLen + DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        TRANS_LOGE(TRANS_CTRL,
            "srv data not enough, recv next time. bufLen=%{public}d, dataLen=%{public}d, headLen=%{public}d",
            bufLen, dataLen, DC_MSG_PACKET_HEAD_SIZE);
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

int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId, int32_t type)
{
    int32_t fd = -1;
    size_t len = 0;
    if (TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get info failed");
        return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED;
    }
    if (len == 0) {
        TRANS_LOGE(TRANS_CTRL, "trans free databuf less zero. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TCP_DATABUF_LESS_ZERO;
    }
    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "trans malloc failed. channelId=%{public}d, len%{public}zu", channelId, len);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (recvLen < 0) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_CTRL, " recv tcp data fail, channelId=%{public}d, retLen=%{public}d.", channelId, recvLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    } else if (recvLen == 0) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_CTRL, "recv tcp data fail, retLen=0, channelId=%{public}d", channelId);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    if (TransTdcUpdateDataBufWInfo(channelId, recvBuf, recvLen) != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_CTRL, "update channel data buf failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_UPDATE_DATA_BUF_FAILED;
    }
    SoftBusFree(recvBuf);

    return TransTdcSrvProcData(module, channelId, type);
}
