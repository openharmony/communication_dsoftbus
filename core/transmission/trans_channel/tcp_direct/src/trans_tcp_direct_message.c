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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "softbus_app_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_log.h"
#include "softbus_message_open_channel.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "wifi_direct_manager.h"
#include "data_bus_native.h"
#include "lnn_lane_link.h"
#include "lnn_net_builder.h"

#define MAX_PACKET_SIZE (64 * 1024)

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
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void TransSrvDestroyDataBuf(void)
{
    if (g_tcpSrvDataList ==  NULL) {
        return;
    }

    ServerDataBuf *item = NULL;
    ServerDataBuf *next = NULL;
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpSrvDataList->list, ServerDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpSrvDataList->cnt--;
    }
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    return;
}

void TransSrvDataListDeinit(void)
{
    if (g_tcpSrvDataList == NULL) {
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create server data buf node fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = MAX_DATA_BUF;
    node->data = (char*)SoftBusCalloc(MAX_DATA_BUF);
    if (node->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create server data buf fail.");
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
    return AUTH_LINK_TYPE_WIFI;
}

static int32_t PackBytes(int32_t channelId, const char *data, TdcPacketHead *packetHead,
    char *buffer, uint32_t bufLen)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackBytes get auth id fail");
        return SOFTBUS_NOT_FIND;
    }

    uint8_t *encData = (uint8_t *)buffer + DC_MSG_PACKET_HEAD_SIZE;
    uint32_t encDataLen = bufLen - DC_MSG_PACKET_HEAD_SIZE;
    if (AuthEncrypt(authId, (const uint8_t *)data, packetHead->dataLen, encData, &encDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackBytes encrypt fail");
        return SOFTBUS_ENCRYPT_ERR;
    }
    packetHead->dataLen = encDataLen;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "PackBytes: flag=0x%x, seq=%" PRIu64,
        packetHead->flags, packetHead->seq);

    PackTdcPacketHead(packetHead);
    if (memcpy_s(buffer, bufLen, packetHead, sizeof(TdcPacketHead)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void SendFailToFlushDevice(SessionConn *conn)
{
    if (conn->appInfo.routeType == WIFI_STA) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send data fail, do Authflushdevice uuid:%s",
            AnonymizesNetworkID(conn->appInfo.peerData.deviceId));
        if (AuthFlushDevice(conn->appInfo.peerData.deviceId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp flush failed, wifi will offline");
            LnnRequestLeaveSpecific(conn->appInfo.peerNetWorkId, CONNECTION_ADDR_WLAN);
        }
    }
}

int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data)
{
    if (data == NULL || packetHead == NULL || packetHead->dataLen == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t bufferLen = AuthGetEncryptSize(packetHead->dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = (char *)SoftBusMalloc(bufferLen);
    if (buffer == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "buffer malloc error.");
        return SOFTBUS_MALLOC_ERR;
    }
    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "TransTdcPostBytes, data: ", data, packetHead->dataLen);
    if (PackBytes(channelId, data, packetHead, buffer, bufferLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pack Bytes error.");
        SoftBusFree(buffer);
        return SOFTBUS_ENCRYPT_ERR;
    }
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc conn fail");
        SoftBusFree(buffer);
        return SOFTBUS_ERR;
    }

    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get SessionConn fail");
        SoftBusFree(buffer);
        SoftBusFree(conn);
        return SOFTBUS_ERR;
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

static int32_t NotifyChannelOpened(int32_t channelId)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }
    ChannelInfo info = {0};
    info.channelId = channelId;
    info.channelType = CHANNEL_TYPE_TCP_DIRECT;
    info.isServer = conn.serverSide;
    info.isEnabled = true;
    info.fd = conn.appInfo.fd;
    info.sessionKey = conn.appInfo.sessionKey;
    info.myHandleId = conn.appInfo.myHandleId;
    info.peerHandleId = conn.appInfo.peerHandleId;
    info.peerSessionName = conn.appInfo.peerData.sessionName;
    info.groupId = conn.appInfo.groupId;
    info.isEncrypt = true;
    info.keyLen = SESSION_KEY_LENGTH;
    info.peerUid = conn.appInfo.peerData.uid;
    info.peerPid = conn.appInfo.peerData.pid;
    info.routeType = conn.appInfo.routeType;
    info.businessType = conn.appInfo.businessType;
    info.autoCloseTime = conn.appInfo.autoCloseTime;
    info.peerIp = conn.appInfo.peerData.addr;
    info.peerPort = conn.appInfo.peerData.port;
    info.linkType = conn.appInfo.linkType;
    info.dataConfig = conn.appInfo.myData.dataConfig;
    char myIp[IP_LEN] = {0};
    if (conn.serverSide) {
        if (conn.appInfo.routeType == WIFI_STA) {
            if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, myIp, sizeof(myIp)) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "NotifyChannelOpened get local ip fail");
                return SOFTBUS_ERR;
            }
        } else if (conn.appInfo.routeType == WIFI_P2P) {
            if (GetWifiDirectManager()->getLocalIpByUuid(conn.appInfo.peerData.deviceId, myIp,
                sizeof(myIp)) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "NotifyChannelOpened get p2p ip fail");
                return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
            }
        }
        info.myIp = myIp;
    } else {
        info.myIp = conn.appInfo.myData.addr;
    }
    char buf[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(conn.appInfo.peerData.deviceId, buf, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get info networkId fail.");
        return SOFTBUS_ERR;
    }
    info.peerDeviceId = buf;
    info.timeStart = conn.appInfo.timeStart;
    info.linkType = conn.appInfo.linkType;
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    int uid = 0;
    int pid = 0;
    if (TransTdcGetUidAndPid(conn.appInfo.myData.sessionName, &uid, &pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get uid and pid fail.");
        return SOFTBUS_ERR;
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channelId = %d, ret = %d", channelId, ret);
    return ret;
}
int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }
    int64_t timeStart = conn.appInfo.timeStart;
    int64_t timediff = GetSoftbusRecordTimeMillis() - timeStart;
    SoftbusRecordOpenSessionKpi(conn.appInfo.myData.pkgName,
        conn.appInfo.linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, timediff);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if (TransTdcGetPkgName(conn.appInfo.myData.sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }

    if (conn.serverSide == false) {
        AppInfoData *myData = &conn.appInfo.myData;
        int ret = TransTdcOnChannelOpenFailed(myData->pkgName, myData->pid, channelId, errCode);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "channelId = %d, ret = %d", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int TransTdcPostFisrtData(SessionConn *conn)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "begin TransTdcPostFisrtData");
    uint32_t outLen;
    char *buf = TransTdcPackFastData(&(conn->appInfo), &outLen);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (outLen != conn->appInfo.fastTransDataSize + FAST_TDC_EXT_DATA_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack bytes len error, len: %d", outLen);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to send tcp data. ret: %d", ret);
        SoftBusFree(buf);
        return SOFTBUS_ERR;
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
    for (uint32_t i = 0; i < sizeof(g_configTypeMap) / sizeof(ConfigTypeMap); i++) {
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid channelType: %d, businessType: %d",
            channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType: %d.", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }

    *len = maxLen;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local config = %d.", *len);
    return SOFTBUS_OK;
}

static int32_t TransTdcProcessDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "appInfo is null");
        return SOFTBUS_ERR;
    }
    if (appInfo->businessType != BUSINESS_TYPE_MESSAGE && appInfo->businessType != BUSINESS_TYPE_BYTE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "invalid businessType[%d]", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        appInfo->myData.dataConfig = MIN(appInfo->myData.dataConfig, appInfo->peerData.dataConfig);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process dataConfig[%u] succ", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_MAX_BYTES_LENGTH : SOFTBUS_INT_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType[%d]", configType);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process data config value[%d]", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static int32_t OpenDataBusReply(int32_t channelId, uint64_t seq, const cJSON *reply)
{
    (void)seq;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusReply: channelId=%d", channelId);
    SessionConn conn;
    if (GetSessionConnById(channelId, &conn) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open failed, get tdcInfo is null");
        return SOFTBUS_ERR;
    }

    int errCode = SOFTBUS_OK;
    if (UnpackReplyErrCode(reply, &errCode) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "receive err reply msg");
        if (NotifyChannelOpenFailed(channelId, errCode) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        return errCode;
    }

    uint16_t fastDataSize = 0;
    if (UnpackReply(reply, &conn.appInfo, &fastDataSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackReply failed");
        return SOFTBUS_ERR;
    }

    if (TransTdcProcessDataConfig(&conn.appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Trans Tdc process data config failed.");
        return SOFTBUS_ERR;
    }

    if (SetAppInfoById(channelId, &conn.appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set app info by id failed.");
        return SOFTBUS_ERR;
    }
    if ((fastDataSize > 0 && (conn.appInfo.fastTransDataSize == fastDataSize)) || conn.appInfo.fastTransDataSize == 0) {
        if (NotifyChannelOpened(channelId) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
    } else {
        if (TransTdcPostFisrtData(&conn) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tdc send fast data failed");
            return SOFTBUS_ERR;
        }
        if (NotifyChannelOpened(channelId) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusReply ok");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequestReply get pack reply err");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequestError get pack reply err");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetUuidByChanId get authId fail");
        return SOFTBUS_ERR;
    }
    return AuthGetDeviceUuid(authId, uuid, len);
}

static void OpenDataBusRequestOutSessionName(const char *mySessionName, const char *peerSessionName)
{
    char *anonyOutMy = NULL;
    char *anonyOutPeer = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: mySessionName=%s, peerSessionName=%s",
        AnonyDevId(&anonyOutMy, mySessionName), AnonyDevId(&anonyOutPeer, peerSessionName));
    SoftBusFree(anonyOutMy);
    SoftBusFree(anonyOutPeer);
}

static SessionConn* GetSessionConnFromDataBusRequest(int32_t channelId, const cJSON *request)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        return NULL;
    }
    if (GetSessionConnById(channelId, conn) == NULL) {
        SoftBusFree(conn);
        return NULL;
    }
    if (UnpackRequest(request, &conn->appInfo) != SOFTBUS_OK) {
        SoftBusFree(conn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UnpackRequest error");
        return NULL;
    }
    return conn;
}

static void NotifyFastDataRecv(SessionConn *conn, int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NotifyFastDataRecv begin");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NotifyFastDataRecv err");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NotifyFastDataRecv end");
    return;
}

static int32_t TransTdcFillDataConfig(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "appInfo is null");
        return SOFTBUS_ERR;
    }
    if (appInfo->businessType != BUSINESS_TYPE_BYTE && appInfo->businessType != BUSINESS_TYPE_MESSAGE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "invalid businessType[%d]", appInfo->businessType);
        return SOFTBUS_OK;
    }
    if (appInfo->peerData.dataConfig != 0) {
        uint32_t localDataConfig = 0;
        if (TransGetLocalConfig(CHANNEL_TYPE_TCP_DIRECT, appInfo->businessType, &localDataConfig) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        appInfo->myData.dataConfig = MIN(localDataConfig, appInfo->peerData.dataConfig);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fill dataConfig[%u] succ", appInfo->myData.dataConfig);
        return SOFTBUS_OK;
    }
    ConfigType configType = appInfo->businessType == BUSINESS_TYPE_BYTE ?
        SOFTBUS_INT_MAX_BYTES_LENGTH : SOFTBUS_INT_MAX_MESSAGE_LENGTH;
    if (SoftbusGetConfig(configType, (unsigned char *)&appInfo->myData.dataConfig,
        sizeof(appInfo->myData.dataConfig)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config failed, configType[%d]", configType);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "fill data config value[%d]", appInfo->myData.dataConfig);
    return SOFTBUS_OK;
}

static int32_t OpenDataBusRequest(int32_t channelId, uint32_t flags, uint64_t seq, const cJSON *request)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest channelId=%d, seq=%d.", channelId, seq);
    SessionConn *conn = GetSessionConnFromDataBusRequest(channelId, request);
    if (conn == NULL) {
        return SOFTBUS_ERR;
    }

    char *errDesc = NULL;
    int32_t errCode;
    if (TransTdcGetUidAndPid(conn->appInfo.myData.sessionName,
        &conn->appInfo.myData.uid, &conn->appInfo.myData.pid) != SOFTBUS_OK) {
        errCode = SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
        errDesc = (char *)"Peer Device Session Not Create";
        goto ERR_EXIT;
    }

    if (GetUuidByChanId(channelId, conn->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Get Uuid By ChanId failed.");
        errCode = SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
        errDesc = (char *)"Get Uuid By ChanId failed";
        goto ERR_EXIT;
    }

    if (TransTdcFillDataConfig(&conn->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fill data config failed.");
        errCode = SOFTBUS_INVALID_PARAM;
        errDesc = (char *)"fill data config failed";
        goto ERR_EXIT;
    }

    if (SetAppInfoById(channelId, &conn->appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set app info by id failed.");
        errCode = SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
        errDesc = (char *)"Set App Info By Id Failed";
        goto ERR_EXIT;
    }

    OpenDataBusRequestOutSessionName(conn->appInfo.myData.sessionName, conn->appInfo.peerData.sessionName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest: myPid=%d, peerPid=%d",
        conn->appInfo.myData.pid, conn->appInfo.peerData.pid);

    if (NotifyChannelOpened(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Notify App Channel Opened Failed");
        errCode = SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED;
        errDesc = (char *)"Notify App Channel Opened Failed";
        goto ERR_EXIT;
    }
    if (conn->appInfo.fastTransDataSize > 0 && conn->appInfo.fastTransData != NULL) {
        NotifyFastDataRecv(conn, channelId);
    }
    int myHandleId = NotifyNearByUpdateHandleId(channelId);
    if (myHandleId != SOFTBUS_ERR) {
        conn->appInfo.myHandleId = myHandleId;
    }
    (void)SetAppInfoById(channelId, &conn->appInfo);

    if (OpenDataBusRequestReply(&conn->appInfo, channelId, seq, flags) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenDataBusRequest reply err");
        (void)NotifyChannelClosed(&conn->appInfo, channelId);
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    if (conn->appInfo.routeType == WIFI_P2P) {
        if (LnnGetNetworkIdByUuid(conn->appInfo.peerData.deviceId,
            conn->appInfo.peerNetWorkId, DEVICE_ID_SIZE_MAX) == SOFTBUS_OK) {
            LaneUpdateP2pAddressByIp(conn->appInfo.peerData.addr, conn->appInfo.peerNetWorkId);
        }
    }

    SoftBusFree(conn);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequest ok");
    return SOFTBUS_OK;

ERR_EXIT:
    if (OpenDataBusRequestError(channelId, seq, errDesc, errCode, flags) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenDataBusRequestError error");
    }
    SoftBusFree(conn);
    return SOFTBUS_ERR;
}

static int32_t ProcessMessage(int32_t channelId, uint32_t flags, uint64_t seq, const char *msg)
{
    int32_t ret = SOFTBUS_ERR;
    cJSON *json = cJSON_Parse(msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ProcessMessage: json parse failed.");
        return SOFTBUS_ERR;
    }
    if (flags & FLAG_REPLY) {
        ret = OpenDataBusReply(channelId, seq, json);
    } else {
        ret = OpenDataBusRequest(channelId, flags, seq, json);
    }
    cJSON_Delete(json);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessMessage: ret = [%d]", ret);
    return ret;
}

static ServerDataBuf *TransSrvGetDataBufNodeById(int32_t channelId)
{
    if (g_tcpSrvDataList ==  NULL) {
        return NULL;
    }

    ServerDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpSrvDataList->list), ServerDataBuf, node) {
        if (item->channelId == channelId) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv tcp direct channel id not exist.");
    return NULL;
}

static int64_t GetAuthIdByChannelInfo(int32_t channelId, uint64_t seq, uint32_t cipherFlag)
{
    int64_t authId = GetAuthIdByChanId(channelId);
    if (authId != AUTH_INVALID_ID) {
        return authId;
    }

    AppInfo appInfo;
    if (GetAppInfoById(channelId, &appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get appInfo fail");
        return AUTH_INVALID_ID;
    }

    bool fromAuthServer = ((seq & AUTH_CONN_SERVER_SIDE) != 0);
    char uuid[UUID_BUF_LEN] = {0};
    if (GetWifiDirectManager()->getRemoteUuidByIp(appInfo.peerData.addr, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        AuthConnInfo connInfo;
        connInfo.type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, appInfo.peerData.addr) != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy ip addr fail");
            return AUTH_INVALID_ID;
        }
        return AuthGetIdByConnInfo(&connInfo, !fromAuthServer, false);
    }

    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "get auth linktype %d flag 0x%x", linkType, cipherFlag);
    bool isAuthMeta = (cipherFlag & FLAG_AUTH_META) ? true : false;
    return AuthGetIdByUuid(uuid, linkType, !fromAuthServer, isAuthMeta);
}

static int32_t DecryptMessage(int32_t channelId, const TdcPacketHead *pktHead, const uint8_t *pktData,
    uint8_t **outData, uint32_t *outDataLen)
{
    int64_t authId = GetAuthIdByChannelInfo(channelId, pktHead->seq, pktHead->flags);
    if (authId == AUTH_INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: get authId fail.");
        return SOFTBUS_NOT_FIND;
    }
    if (SetAuthIdByChanId(channelId, authId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: set authId fail.");
        return SOFTBUS_ERR;
    }

    uint32_t decDataLen = AuthGetDecryptSize(pktHead->dataLen) + 1;
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: malloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (AuthDecrypt(authId, pktData, pktHead->dataLen, decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: decrypt fail.");
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] lock failed.", __func__);
        return SOFTBUS_ERR;
    }
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL || node->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "node is null.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }
    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    uint8_t *pktData = (uint8_t *)(node->data + sizeof(TdcPacketHead));
    if (pktHead->module != MODULE_SESSION) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: illegal module.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_ERR;
    }
    seq = pktHead->seq;
    flags = pktHead->flags;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "rev tdc packet, flags=%d, seq=%d", flags, seq);
    if (DecryptMessage(channelId, pktHead, pktData, &data, &dataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv process recv data: decrypt fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }

    char *end = node->data + sizeof(TdcPacketHead) + pktHead->dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusFree(data);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memmove fail.");
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - sizeof(TdcPacketHead) - pktHead->dataLen;
    SoftBusMutexUnlock(&g_tcpSrvDataList->lock);

    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "TdcProcessReceivedData, data: ", (char *)data, dataLen);
    int32_t ret = ProcessMessage(channelId, flags, seq, (char *)data);
    SoftBusFree(data);
    return ret;
}

static int32_t TransTdcSrvProcData(ListenerModule module, int32_t channelId)
{
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] lock failed.", __func__);
        return SOFTBUS_ERR;
    }
    ServerDataBuf *node = TransSrvGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv can not get buf node.");
        return SOFTBUS_ERR;
    }

    uint32_t bufLen = node->w - node->data;
    if (bufLen < DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv head not enough, recv next time.");
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    TdcPacketHead *pktHead = (TdcPacketHead *)(node->data);
    UnpackTdcPacketHead(pktHead);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv recv invalid packet head");
        return SOFTBUS_ERR;
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > node->size - DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "srv out of recv buf size[%d]", dataLen);
        return SOFTBUS_ERR;
    }

    if (bufLen < dataLen + DC_MSG_PACKET_HEAD_SIZE) {
        SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "srv data not enough, recv next time.[%d][%d][%d]",
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    if (g_tcpSrvDataList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] tcp srv data list empty.", __func__);
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] lock failed.", __func__);
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans tdc[%d] data buf not found.", channelId);
    return SOFTBUS_ERR;
}

static int32_t TransTdcUpdateDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    if (g_tcpSrvDataList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] srv data list empty.", __func__);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpSrvDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s] lock failed.", __func__);
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "trans tdc recv=%d override free=%d.", recvLen, freeLen);
            return SOFTBUS_ERR;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans tdc channel=%d memcpy failed.", channelId);
            return SOFTBUS_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpSrvDataList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans update tdcchannel=%d databuf not found.", channelId);
    return SOFTBUS_ERR;
}

int32_t TransTdcSrvRecvData(ListenerModule module, int32_t channelId)
{
    int32_t fd = -1;
    size_t len = 0;
    if (TransTdcGetDataBufInfoByChannelId(channelId, &fd, &len) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans channel=%d free databuf less zero.", channelId);
        return SOFTBUS_ERR;
    }

    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans channel=%d malloc [%zu] failed..", channelId, len);
        return SOFTBUS_ERR;
    }

    int32_t recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (recvLen < 0) {
        SoftBusFree(recvBuf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] recv tcp data fail,ret=%d.", channelId, recvLen);
        return SOFTBUS_ERR;
    } else if (recvLen == 0) {
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    if (TransTdcUpdateDataBufWInfo(channelId, recvBuf, recvLen) != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] update channel data buf failed.", channelId);
        return SOFTBUS_ERR;
    }
    SoftBusFree(recvBuf);

    return TransTdcSrvProcData(module, channelId);
}
