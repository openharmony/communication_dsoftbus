/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "trans_log.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "wifi_direct_manager.h"

#define MAX_PACKET_SIZE (64 * 1024)
#define MIN_META_LEN 6
#define META_SESSION "IShare"
#define MAX_DATA_BUF 4096

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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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
            TRANS_LOGI(TRANS_BYTES, "delete channelId = %{public}d", item->channelId);
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
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_BYTES, "PackBytes get auth id fail");
        return SOFTBUS_NOT_FIND;
    }

    uint8_t *encData = (uint8_t *)buffer + DC_MSG_PACKET_HEAD_SIZE;
    uint32_t encDataLen = bufLen - DC_MSG_PACKET_HEAD_SIZE;
    if (AuthEncrypt(authId, (const uint8_t *)data, packetHead->dataLen, encData, &encDataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_BYTES, "PackBytes encrypt fail");
        return SOFTBUS_ENCRYPT_ERR;
    }
    packetHead->dataLen = encDataLen;

    TRANS_LOGI(TRANS_BYTES, "PackBytes: flag=%{public}u, seq=%{public}" PRIu64,
        packetHead->flags, packetHead->seq);

    PackTdcPacketHead(packetHead);
    if (memcpy_s(buffer, bufLen, packetHead, sizeof(TdcPacketHead)) != EOK) {
        TRANS_LOGE(TRANS_BYTES, "buffer copy fail");
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
        return SOFTBUS_ERR;
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
        if (LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, myIp) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide wifi set local ip fail");
        }
        if (LnnSetDLP2pIp(conn->appInfo.peerData.deviceId, CATEGORY_UUID,
            conn->appInfo.peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "ServerSide wifi set peer ip fail");
        }
    } else if (conn->appInfo.routeType == WIFI_P2P) {
        if (GetWifiDirectManager()->getLocalIpByRemoteIp(conn->appInfo.peerData.addr, myIp, sizeof(myIp)) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "NotifyChannelOpened get p2p ip fail");
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
        return SOFTBUS_ERR;
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
        if (LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, myIp) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client wifi set local ip fail");
        }
        if (LnnSetDLP2pIp(conn->appInfo.peerData.deviceId, CATEGORY_UUID,
            conn->appInfo.peerData.addr) != SOFTBUS_OK) {
            TRANS_LOGW(TRANS_CTRL, "Client wifi set peer ip fail");
        }
    } else if (conn->appInfo.routeType == WIFI_P2P) {
        if (GetWifiDirectManager()->getLocalIpByRemoteIp(conn->appInfo.peerData.addr, myIp, sizeof(myIp)) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "NotifyChannelOpened get p2p ip fail");
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
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t NotifyChannelOpened(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    info.peerDeviceId = buf;
    info.timeStart = conn.appInfo.timeStart;
    info.linkType = conn.appInfo.linkType;
    info.connectType = conn.appInfo.connectType;
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    int uid = 0;
    int pid = 0;
    if (TransTdcGetUidAndPid(conn.appInfo.myData.sessionName, &uid, &pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get uid and pid fail.");
        return SOFTBUS_TRANS_GET_PID_FAILED;
    }
    if (conn.appInfo.fastTransDataSize > 0) {
        info.isFastData = true;
    }
    ret = TransTdcOnChannelOpened(pkgName, pid, conn.appInfo.myData.sessionName, &info);
    conn.status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    SetSessionConnStatusById(channelId, conn.status);
    return ret;
}

static int32_t NotifyChannelClosed(const AppInfo *appInfo, int32_t channelId)
{
    AppInfoData myData = appInfo->myData;
    int ret = TransTdcOnChannelClosed(myData.pkgName, myData.pid, channelId);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
    return ret;
}

int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }
    int64_t timeStart = conn.appInfo.timeStart;
    int64_t timediff = GetSoftbusRecordTimeMillis() - timeStart;
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = conn.appInfo.myData.pkgName,
        .channelId = conn.appInfo.myData.channelId,
        .peerNetworkId = conn.appInfo.peerNetWorkId,
        .socketName = conn.appInfo.myData.sessionName,
        .linkType = conn.appInfo.connectType,
        .costTime = timediff,
        .errcode = errCode,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    if (!conn.serverSide) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
    TransAlarmExtra extraAlarm = {
        .conflictName = NULL,
        .conflictedName = NULL,
        .occupyedName = NULL,
        .permissionName = NULL,
        .linkType = conn.appInfo.linkType,
        .errcode = errCode,
        .sessionName = conn.appInfo.myData.sessionName,
    };
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);

    SoftbusRecordOpenSessionKpi(conn.appInfo.myData.pkgName,
        conn.appInfo.linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, timediff);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    if (!(conn.serverSide)) {
        AppInfoData *myData = &conn.appInfo.myData;
        if (myData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "myData is null");
            return SOFTBUS_INVALID_PARAM;
        }
        int ret = TransTdcOnChannelOpenFailed(myData->pkgName, myData->pid, channelId, errCode);
        TRANS_LOGW(TRANS_CTRL, "channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
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
        return SOFTBUS_ERR;
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
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_ERR;
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
    if (GetSessionConnById(channelId, &conn) == NULL) {
        TRANS_LOGE(TRANS_CTRL, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED;
    }
    int errCode = SOFTBUS_OK;
    if (UnpackReplyErrCode(reply, &errCode) == SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = channelId,
            .errcode = errCode,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
        TRANS_LOGE(TRANS_CTRL, "receive err reply msg");
        if (NotifyChannelOpenFailed(channelId, errCode) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "channel open failed");
            return SOFTBUS_ERR;
        }
        return errCode;
    }
    uint16_t fastDataSize = 0;
    if (UnpackReply(reply, &conn.appInfo, &fastDataSize) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "UnpackReply failed");
        return SOFTBUS_TRANS_UNPACK_REPLY_FAILED;
    }
    int32_t ret = SOFTBUS_ERR;
    ret = TransTdcProcessDataConfig(&conn.appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Trans Tdc process data config failed.");
        return ret;
    }
    ret = SetAppInfoById(channelId, &conn.appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set app info by id failed.");
        return ret;
    }
    if ((fastDataSize > 0 && (conn.appInfo.fastTransDataSize == fastDataSize)) || conn.appInfo.fastTransDataSize == 0) {
        ret = NotifyChannelOpened(channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "notify channel open failed");
            return SOFTBUS_ERR;
        }
    } else {
        ret = TransTdcPostFisrtData(&conn);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "tdc send fast data failed");
            return ret;
        }
        ret = NotifyChannelOpened(channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "notify channel open failed");
            return ret;
        }
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

static int32_t OpenDataBusRequestReply(const AppInfo *appInfo, int32_t channelId, uint64_t seq,
    uint32_t flags)
{
    char *reply = PackReply(appInfo);
    if (reply == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get pack reply err");
        return SOFTBUS_ERR;
    }
    int32_t ret = TransTdcPostReplyMsg(channelId, seq, flags, reply);
    cJSON_free(reply);
    return ret;
}

static int32_t OpenDataBusRequestError(int32_t channelId, uint64_t seq, char *errDesc,
    int32_t errCode, uint32_t flags)
{
    char *reply = PackError(errCode, errDesc);
    if (reply == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get pack reply err");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    if (appInfo->businessType != BUSINESS_TYPE_BYTE && appInfo->businessType != BUSINESS_TYPE_MESSAGE) {
        TRANS_LOGI(TRANS_CTRL, "invalid businessType=%{public}d", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        if (TransGetLocalConfig(CHANNEL_TYPE_TCP_DIRECT, appInfo->businessType, &localDataConfig) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        TRANS_LOGI(TRANS_CTRL, "fill dataConfig succ. dataConfig=%{public}u", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_MAX_BYTES_LENGTH : SOFTBUS_INT_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get config failed, configType=%{public}d", configType);
        return SOFTBUS_ERR;
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

static int32_t OpenDataBusRequest(int32_t channelId, uint32_t flags, uint64_t seq, const cJSON *request)
{
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, seq=%{public}" PRIu64, channelId, seq);
    SessionConn *conn = GetSessionConnFromDataBusRequest(channelId, request);
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "conn is null");
        return SOFTBUS_INVALID_PARAM;
    }

    TransEventExtra extra = {
        .socketName = conn->appInfo.myData.sessionName,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = channelId,
        .peerChannelId = conn->appInfo.peerData.channelId,
        .socketFd = conn->appInfo.fd,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, extra);
    if ((flags & FLAG_AUTH_META) != 0 && !IsMetaSession(conn->appInfo.myData.sessionName)) {
        char *tmpName = NULL;
        Anonymize(conn->appInfo.myData.sessionName, &tmpName);
        TRANS_LOGI(TRANS_CTRL,
            "Request denied: session is not a meta session. sessionName=%{public}s", tmpName);
        AnonymizeFree(tmpName);
        return SOFTBUS_TRANS_NOT_META_SESSION;
    }
    char *errDesc = NULL;
    int32_t errCode;
    int myHandleId;
    if (TransTdcGetUidAndPid(conn->appInfo.myData.sessionName,
        &conn->appInfo.myData.uid, &conn->appInfo.myData.pid) != SOFTBUS_OK) {
        errCode = SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        errDesc = (char *)"Peer Device Session Not Create";
        goto ERR_EXIT;
    }
    if (GetUuidByChanId(channelId, conn->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Get Uuid By ChanId failed.");
        errCode = SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
        errDesc = (char *)"Get Uuid By ChanId failed";
        goto ERR_EXIT;
    }
    if (TransTdcFillDataConfig(&conn->appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill data config failed.");
        errCode = SOFTBUS_INVALID_PARAM;
        errDesc = (char *)"fill data config failed";
        goto ERR_EXIT;
    }
    if (SetAppInfoById(channelId, &conn->appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set app info by id failed.");
        errCode = SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
        errDesc = (char *)"Set App Info By Id Failed";
        goto ERR_EXIT;
    }

    OpenDataBusRequestOutSessionName(conn->appInfo.myData.sessionName,
        conn->appInfo.peerData.sessionName);
    TRANS_LOGI(TRANS_CTRL, "OpenDataBusRequest: myPid=%{public}d, peerPid=%{public}d",
        conn->appInfo.myData.pid, conn->appInfo.peerData.pid);
    if (NotifyChannelOpened(channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Notify App Channel Opened Failed");
        errCode = SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED;
        errDesc = (char *)"Notify App Channel Opened Failed";
        goto ERR_EXIT;
    }
    if (conn->appInfo.fastTransDataSize > 0 && conn->appInfo.fastTransData != NULL) {
        NotifyFastDataRecv(conn, channelId);
    }
    myHandleId = NotifyNearByUpdateHandleId(channelId);
    if (myHandleId != SOFTBUS_ERR) {
        TRANS_LOGE(TRANS_CTRL, "update handId notify failed");
        conn->appInfo.myHandleId = myHandleId;
    }
    (void)SetAppInfoById(channelId, &conn->appInfo);

    if (OpenDataBusRequestReply(&conn->appInfo, channelId, seq, flags) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequest reply err");
        (void)NotifyChannelClosed(&conn->appInfo, channelId);
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    } else {
        extra.result = EVENT_STAGE_RESULT_OK;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, extra);
    }

    if (conn->appInfo.routeType == WIFI_P2P) {
        if (LnnGetNetworkIdByUuid(conn->appInfo.peerData.deviceId,
            conn->appInfo.peerNetWorkId, DEVICE_ID_SIZE_MAX) == SOFTBUS_OK) {
            TRANS_LOGI(TRANS_CTRL, "get networkId by uuid");
            LaneUpdateP2pAddressByIp(conn->appInfo.peerData.addr, conn->appInfo.peerNetWorkId);
        }
    }

    SoftBusFree(conn);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;

ERR_EXIT:
    if (OpenDataBusRequestError(channelId, seq, errDesc, errCode, flags) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenDataBusRequestError error");
    }
    SoftBusFree(conn);
    return errCode;
}

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const char *msg)
{
    int32_t ret = SOFTBUS_ERR;
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

static int64_t GetAuthIdByChannelInfo(int32_t channelId, uint64_t seq, uint32_t cipherFlag)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId != AUTH_INVALID_ID) {
        TRANS_LOGI(TRANS_CTRL, "authId is not AUTH_INVALID_ID");
        return authId;
    }
    AppInfo appInfo;
    if (GetAppInfoById(channelId, &appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get appInfo fail");
        return AUTH_INVALID_ID;
    }
    bool fromAuthServer = ((seq & AUTH_CONN_SERVER_SIDE) != 0);
    char uuid[UUID_BUF_LEN] = {0};
    if (GetWifiDirectManager()->getRemoteUuidByIp(appInfo.peerData.addr, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        AuthConnInfo connInfo;
        connInfo.type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, appInfo.peerData.addr) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "copy ip addr fail");
            return AUTH_INVALID_ID;
        }
        return AuthGetIdByConnInfo(&connInfo, !fromAuthServer, false);
    }

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    TRANS_LOGI(TRANS_CTRL, "get auth linkType=%{public}d, flag=0x%{public}x", linkType, cipherFlag);
    bool isAuthMeta = (cipherFlag & FLAG_AUTH_META) ? true : false;
    return AuthGetIdByUuid(uuid, linkType, !fromAuthServer, isAuthMeta);
}

static int32_t DecryptMessage(int32_t channelId, const TdcPacketHead *pktHead, const uint8_t *pktData,
    uint8_t **outData, uint32_t *outDataLen)
{
    int64_t authId = GetAuthIdByChannelInfo(channelId, pktHead->seq, pktHead->flags);
    if (authId == AUTH_INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: get authId fail.");
        return SOFTBUS_NOT_FIND;
    }
    if (SetAuthIdByChanId(channelId, authId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: set authId fail.");
        return SOFTBUS_ERR;
    }

    uint32_t decDataLen = AuthGetDecryptSize(pktHead->dataLen) + 1;
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (AuthDecrypt(authId, pktData, pktHead->dataLen, decData, &decDataLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: decrypt fail.");
        SoftBusFree(decData);
        return SOFTBUS_DECRYPT_ERR;
    }
    *outData = decData;
    *outDataLen = decDataLen;
    return SOFTBUS_OK;
}

static int32_t ProcessReceivedData(int32_t channelId)
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
        return SOFTBUS_ERR;
    }
    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    uint8_t *pktData = (uint8_t *)(node->data + sizeof(TdcPacketHead));
    if (pktHead->module != MODULE_SESSION) {
        TRANS_LOGE(TRANS_CTRL, "srv process recv data: illegal module.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
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

static int32_t TransTdcSrvProcData(ListenerModule module, int32_t channelId)
{
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
    return ProcessReceivedData(channelId);
}

static int32_t TransTdcGetDataBufInfoByChannelId(int32_t channelId, int32_t *fd, size_t *len)
{
    if (fd == NULL || len == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tcp srv data list empty.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_ERR;
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
    return SOFTBUS_ERR;
}

static int32_t TransTdcUpdateDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (g_tcpSrvDataList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "srv data list empty.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed.");
        return SOFTBUS_ERR;
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
            return SOFTBUS_ERR;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
            TRANS_LOGE(TRANS_CTRL, "trans tdc memcpy failed. channelId=%{public}d", channelId);
            return SOFTBUS_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    TRANS_LOGE(TRANS_CTRL, "trans update tdc databuf not found. channelId=%{public}d", channelId);
    return SOFTBUS_ERR;
}

int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId)
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
        return SOFTBUS_ERR;
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

    return TransTdcSrvProcData(module, channelId);
}