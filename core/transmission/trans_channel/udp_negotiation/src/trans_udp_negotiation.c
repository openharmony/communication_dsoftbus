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

#include "trans_udp_negotiation.h"

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "p2plink_interface.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "trans_lane_pending_ctl.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation_exchange.h"

#define MAX_CHANNEL_ID_COUNT 20
#define ID_NOT_USED 0
#define ID_USED 1
#define INVALID_ID (-1)
#define IVALID_SEQ (-1)
#define SEQ_OFFSET 2

#define FLAG_REQUEST 0
#define FLAG_REPLY 1

static int64_t g_seq = 0;
static uint64_t g_channelIdFlagBitsMap = 0;
static IServerChannelCallBack *g_channelCb = NULL;
static SoftBusMutex g_udpNegLock;

static int32_t GenerateUdpChannelId(void)
{
    if (SoftBusMutexLock(&g_udpNegLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate udp channel id lock failed");
        return INVALID_ID;
    }
    for (uint32_t id = 0; id < MAX_CHANNEL_ID_COUNT; id++) {
        if (((g_channelIdFlagBitsMap >> id) & ID_USED) == ID_NOT_USED) {
            g_channelIdFlagBitsMap |= (ID_USED << id);
            SoftBusMutexUnlock(&g_udpNegLock);
            return (int32_t)id;
        }
    }
    SoftBusMutexUnlock(&g_udpNegLock);
    return INVALID_ID;
}

void ReleaseUdpChannelId(int32_t channelId)
{
    if (SoftBusMutexLock(&g_udpNegLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "release udp channel id lock failed");
        return;
    }
    uint32_t id = (uint32_t)channelId;
    g_channelIdFlagBitsMap &= (~(ID_USED << id));
    SoftBusMutexUnlock(&g_udpNegLock);
}

static int64_t GenerateSeq(bool isServer)
{
    if (SoftBusMutexLock(&g_udpNegLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate seq lock failed");
        return IVALID_SEQ;
    }
    if (g_seq > INT64_MAX - SEQ_OFFSET) {
        g_seq = 0;
    }
    int64_t seq = g_seq + SEQ_OFFSET;
    g_seq += SEQ_OFFSET;
    if (isServer) {
        seq++;
    }
    SoftBusMutexUnlock(&g_udpNegLock);
    return seq;
}

static int32_t NotifyUdpChannelOpened(const AppInfo *appInfo, bool isServerSide)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel opened.");
    ChannelInfo info = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    info.channelId = appInfo->myData.channelId;
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = isServerSide;
    info.businessType = appInfo->businessType;
    info.myIp = (char*)appInfo->myData.addr;
    info.sessionKey = (char*)appInfo->sessionKey;
    info.keyLen = SESSION_KEY_LENGTH;
    info.groupId = (char*)appInfo->groupId;
    if (LnnGetNetworkIdByUuid((const char *)appInfo->peerData.deviceId, networkId,
        NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get network id by uuid failed.");
        return SOFTBUS_ERR;
    }
    info.peerDeviceId = (char*)networkId;
    info.peerSessionName = (char*)appInfo->peerData.sessionName;
    info.routeType = (int32_t)appInfo->routeType;
    info.streamType = (int32_t)appInfo->streamType;
    info.isUdpFile = appInfo->fileProtocal == APP_INFO_UDP_FILE_PROTOCAL ? true : false;
    if (!isServerSide) {
        info.peerPort = appInfo->peerData.port;
        info.peerIp = (char*)appInfo->peerData.addr;
    }
    int32_t ret = g_channelCb->GetPkgNameBySessionName(appInfo->myData.sessionName,
        (char *)&appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    return g_channelCb->OnChannelOpened((const char *)&appInfo->myData.pkgName, appInfo->myData.sessionName, &info);
}

int32_t NotifyUdpChannelClosed(const AppInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel closed, pkg[%s].", info->myData.pkgName);
    int32_t ret = g_channelCb->OnChannelClosed(info->myData.pkgName,
        (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "on channel closed failed, ret=%d.", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t NotifyUdpChannelOpenFailed(const AppInfo *info, int32_t errCode)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel open failed.");
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(info->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    ret = g_channelCb->OnChannelOpenFailed(pkgName, (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP, errCode);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify udp channel open failed err.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t NotifyUdpQosEvent(const AppInfo *info, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp qos eventId[%d].", eventId);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(info->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    QosParam param;
    param.channelId = (int32_t)(info->myData.channelId);
    param.channelType = CHANNEL_TYPE_UDP;
    param.eventId = eventId;
    param.tvCount = tvCount;
    param.tvList = tvList;
    return g_channelCb->OnQosEvent(pkgName, &param);
}

static UdpChannelInfo *NewUdpChannelByAppInfo(const AppInfo *info)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (newChannel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "new udp channel failed.");
        return NULL;
    }

    if (memcpy_s(&(newChannel->info), sizeof(newChannel->info), info, sizeof(AppInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
        SoftBusFree(newChannel);
        return NULL;
    }
    return newChannel;
}

static int32_t AcceptUdpChannelAsServer(AppInfo *appInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process udp channel open state[as server].");
    appInfo->myData.channelId = GenerateUdpChannelId();
    int32_t udpPort = NotifyUdpChannelOpened(appInfo, true);
    if (udpPort <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udp listen port failed[port = %d].", udpPort);
        ReleaseUdpChannelId(appInfo->myData.channelId);
        return SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED;
    }
    appInfo->myData.port = udpPort;
    UdpChannelInfo *newChannel = NewUdpChannelByAppInfo(appInfo);
    if (newChannel == NULL) {
        ReleaseUdpChannelId(appInfo->myData.channelId);
        return SOFTBUS_MEM_ERR;
    }
    newChannel->seq = GenerateSeq(true);
    newChannel->status = UDP_CHANNEL_STATUS_INIT;
    if (TransAddUdpChannel(newChannel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add new udp channel failed.");
        ReleaseUdpChannelId(appInfo->myData.channelId);
        SoftBusFree(newChannel);
        return SOFTBUS_TRANS_UDP_SERVER_ADD_CHANNEL_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t AcceptUdpChannelAsClient(AppInfo *appInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process udp channel open state[as client].");
    if (NotifyUdpChannelOpened(appInfo, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify app udp channel opened failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CloseUdpChannel(AppInfo *appInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "process udp channel close state");
    if (TransDelUdpChannel(appInfo->myData.channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "delete udp channel failed.");
        return SOFTBUS_ERR;
    }
    if (NotifyUdpChannelClosed(appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "notify app udp channel closed failed.");
    }
    return SOFTBUS_OK;
}

static int32_t ProcessUdpChannelState(AppInfo *appInfo, bool isServerSide)
{
    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            if (isServerSide) {
                return AcceptUdpChannelAsServer(appInfo);
            }
            return AcceptUdpChannelAsClient(appInfo);
        case TYPE_UDP_CHANNEL_CLOSE:
            (void)CloseUdpChannel(appInfo);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t sendUdpInfo(cJSON *replyMsg, int64_t authId, int64_t seq)
{
    char *msgStr = cJSON_PrintUnformatted(replyMsg);
    if (msgStr == NULL) {
        return SOFTBUS_ERR;
    }
    AuthTransData dataInfo = {
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REPLY,
        .seq = seq,
        .len = strlen(msgStr) + 1,
        .data = (const uint8_t *)msgStr,
    };

    int32_t ret = SOFTBUS_OK;
    if (AuthPostTransData(authId, &dataInfo) != SOFTBUS_OK) {
        ret = SOFTBUS_ERR;
    }
    cJSON_free(msgStr);
    return ret;
}

static int32_t SendReplyErrInfo(int errCode, char* errDesc, int64_t authId, int64_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp send reply info in.");
    cJSON *replyMsg = cJSON_CreateObject();
    if (replyMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create cjson object failed.");
        return SOFTBUS_ERR;
    }

    if (TransPackReplyErrInfo(replyMsg, errCode, errDesc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack request udp info failed.");
        cJSON_Delete(replyMsg);
        return SOFTBUS_ERR;
    }

    if (sendUdpInfo(replyMsg, authId, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendReplyeErrInfo failed.");
        cJSON_Delete(replyMsg);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(replyMsg);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp send reply error info out.");
    return SOFTBUS_OK;
}

static int32_t SendReplyUdpInfo(AppInfo *appInfo, int64_t authId, int64_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp send reply info in.");
    cJSON *replyMsg = cJSON_CreateObject();
    if (replyMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create cjson object failed.");
        return SOFTBUS_ERR;
    }

    if (TransPackReplyUdpInfo(replyMsg, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack request udp info failed.");
        cJSON_Delete(replyMsg);
        return SOFTBUS_ERR;
    }

    if (sendUdpInfo(replyMsg, authId, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendReplyeErrInfo failed.");
        cJSON_Delete(replyMsg);
        return SOFTBUS_ERR;
    }

    cJSON_Delete(replyMsg);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp send reply info out.");
    return SOFTBUS_OK;
}

static int32_t SetPeerDeviceIdByAuth(int64_t authId, AppInfo *appInfo)
{
    char peerUuid[UUID_BUF_LEN] = {0};
    int32_t ret = AuthGetDeviceUuid(authId, peerUuid, sizeof(peerUuid));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get peer uuid by auth id failed, ret = %d.", ret);
        return SOFTBUS_ERR;
    }

    if (memcpy_s(appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId),
        peerUuid, sizeof(peerUuid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s network id failed.");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t ParseRequestAppInfo(int64_t authId, const cJSON *msg, AppInfo *appInfo)
{
    if (TransUnpackRequestUdpInfo(msg, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack request udp info failed.");
        return SOFTBUS_ERR;
    }

    int32_t ret = g_channelCb->GetPkgNameBySessionName(appInfo->myData.sessionName,
        appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetPkgNameBySessionName Failed, ret = %d", ret);
        return SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED;
    }

    if (appInfo->udpChannelOptType != TYPE_UDP_CHANNEL_OPEN) {
        return SOFTBUS_OK;
    }

    char localIp[IP_LEN] = {0};
    if (appInfo->udpConnType == UDP_CONN_TYPE_WIFI) {
        appInfo->routeType = WIFI_STA;
        if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, sizeof(localIp)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local ip from lnn failed.");
            return SOFTBUS_ERR;
        }
    } else {
        appInfo->routeType = WIFI_P2P;
        if (P2pLinkGetLocalIp(localIp, sizeof(localIp)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get p2p ip failed.");
            return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
        }
    }
    if (strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), localIp) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
        return SOFTBUS_ERR;
    }

    if (SetPeerDeviceIdByAuth(authId, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get network id by auth id failed.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

/**
 * don't care release resources when close status, after invoking process udp channel status.
 * */
static void ProcessAbnormalUdpChannelState(const AppInfo *info, int32_t errCode, bool needClose)
{
    if (info->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
        (void)NotifyUdpChannelOpenFailed(info, errCode);
        (void)TransDelUdpChannel(info->myData.channelId);
    } else if (needClose) {
        NotifyUdpChannelClosed(info);
        (void)TransDelUdpChannel(info->myData.channelId);
    }
}

static void TransOnExchangeUdpInfoReply(int64_t authId, int64_t seq, const cJSON *msg)
{
    /* receive reply message */
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "receive reply udp negotiation info.");
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(channel), 0, sizeof(channel));

    if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_DONE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel negotiation status done failed.");
        return;
    }
    if (TransGetUdpChannelBySeq(seq, &channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udp channel by seq failed.");
        return;
    }
    int32_t errCode = SOFTBUS_OK;
    if (TransUnpackReplyErrInfo(msg, &errCode) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "receive err reply info");
        ProcessAbnormalUdpChannelState(&(channel.info), errCode, false);
        return;
    }
    if (TransUnpackReplyUdpInfo(msg, &(channel.info)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack reply udp info failed.");
        ProcessAbnormalUdpChannelState(&(channel.info), SOFTBUS_TRANS_HANDSHAKE_ERROR, true);
        return;
    }
    if (ProcessUdpChannelState(&(channel.info), false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process udp channel state failed.");
        ProcessAbnormalUdpChannelState(&(channel.info), SOFTBUS_IPC_ERR, false);
        return;
    }
    TransUpdateUdpChannelInfo(seq, &(channel.info));
}

static void TransOnExchangeUdpInfoRequest(int64_t authId, int64_t seq, const cJSON *msg)
{
    /* receive request message */
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "receive request udp negotiation info.");
    AppInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    char* errDesc = NULL;

    int32_t ret = ParseRequestAppInfo(authId, msg, &info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get appinfo failed. ret = %d", ret);
        errDesc = (char *)"peer device session name not create";
        goto ERR_EXIT;
    }
    ret = ProcessUdpChannelState(&info, true);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process udp channel state failed. ret = %d", ret);
        errDesc = (char *)"notify app error";
        goto ERR_EXIT;
    }
    if (SendReplyUdpInfo(&info, authId, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send reply udp info failed.");
        (void)TransDelUdpChannel(info.myData.channelId);
    }
    return;

ERR_EXIT:
    if (SendReplyErrInfo(ret, errDesc, authId, seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send reply error info failed.");
    }
}
static void TransOnExchangeUdpInfo(int64_t authId, int32_t isReply, int64_t seq, const cJSON *msg)
{
    if (isReply) {
        TransOnExchangeUdpInfoReply(authId, seq, msg);
    } else {
        TransOnExchangeUdpInfoRequest(authId, seq, msg);
    }
}

static int32_t StartExchangeUdpInfo(UdpChannelInfo *channel, int64_t authId, int64_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "start exchange udp info: channelId=%" PRId64 ", authId=%" PRId64 ", streamType=%d",
        channel->info.myData.channelId, authId, channel->info.streamType);
    cJSON *requestMsg = cJSON_CreateObject();
    if (requestMsg == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create cjson object failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (TransPackRequestUdpInfo(requestMsg, &(channel->info)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack request udp info failed.");
        cJSON_Delete(requestMsg);
        return SOFTBUS_ERR;
    }
    char *msgStr = cJSON_PrintUnformatted(requestMsg);
    cJSON_Delete(requestMsg);
    if (msgStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cjson unformatted failed.");
        return SOFTBUS_ERR;
    }
    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "UdpStartExchangeUdpInfo, msgStr: ", msgStr, strlen(msgStr));
    AuthTransData dataInfo = {
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REQUEST,
        .seq = seq,
        .len = strlen(msgStr) + 1,
        .data = (const uint8_t *)msgStr,
    };
    if (AuthPostTransData(authId, &dataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "AuthPostTransData failed.");
        cJSON_free(msgStr);
        return SOFTBUS_ERR;
    }
    cJSON_free(msgStr);
    if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_NEGING) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel negotiation status neging failed.");
    }
    return SOFTBUS_OK;
}

static void UdpOnAuthConnOpened(uint32_t requestId, int64_t authId)
{
    SoftBusLog(
        SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "UdpOnAuthConnOpened: requestId=%u, authId=%" PRId64, requestId, authId);
    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (channel == NULL) {
        goto EXIT_ERR;
    }
    if (TransGetUdpChannelByRequestId(requestId, channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOnAuthConnOpened get channel fail");
        SoftBusFree(channel);
        goto EXIT_ERR;
    }
    if (StartExchangeUdpInfo(channel, authId, channel->seq) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOnAuthConnOpened neg fail");
        ProcessAbnormalUdpChannelState(&channel->info, true, SOFTBUS_TRANS_HANDSHAKE_ERROR);
        SoftBusFree(channel);
        goto EXIT_ERR;
    }

    SoftBusFree(channel);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "UdpOnAuthConnOpened end");
    return;
EXIT_ERR:
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOnAuthConnOpened proc fail");
    AuthCloseConn(authId);
}

static void UdpOnAuthConnOpenFailed(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "UdpOnAuthConnOpenFailed: requestId=%u, reason=%d",
        requestId, reason);
    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOnAuthConnOpenFailed malloc fail");
        return;
    }
    if (TransGetUdpChannelByRequestId(requestId, channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOnAuthConnOpened get channel fail");
        SoftBusFree(channel);
        return;
    }
    ProcessAbnormalUdpChannelState(&channel->info, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED, true);
    SoftBusFree(channel);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "UdpOnAuthConnOpenFailed end");
    return;
}

static int32_t UdpOpenAuthConn(const char *peerUdid, uint32_t requestId, bool isMeta)
{
    AuthConnInfo auth;
    (void)memset_s(&auth, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthConnCallback cb = {0};
    (void)memset_s(&cb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));

    int32_t ret = AuthGetPreferConnInfo(peerUdid, &auth, isMeta);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOpenAuthConn get info fail: ret=%d", ret);
        return ret;
    }

    cb.onConnOpened = UdpOnAuthConnOpened;
    cb.onConnOpenFailed = UdpOnAuthConnOpenFailed;
    ret = AuthOpenConn(&auth, requestId, &cb, isMeta);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UdpOpenAuthConn open fail: ret=%d", ret);
        return ret;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "UdpOpenAuthConn ok: requestId=%u", requestId);
    return SOFTBUS_OK;
}

static int32_t OpenAuthConnForUdpNegotiation(UdpChannelInfo *channel)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthConnForUdpNegotiation");
    if (channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t requestId = AuthGenRequestId();

    if (GetUdpChannelLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *channelObj = TransGetChannelObj(channel->info.myData.channelId);
    if (channelObj == NULL) {
        ReleaseUdpChannelLock();
        return SOFTBUS_NOT_FIND;
    }
    channelObj->requestId = requestId;
    channelObj->status = UDP_CHANNEL_STATUS_OPEN_AUTH;
    channelObj->isMeta = TransGetAuthTypeByNetWorkId(channel->info.peerNetWorkId);
    ReleaseUdpChannelLock();

    if (UdpOpenAuthConn(channel->info.peerData.deviceId, requestId, channelObj->isMeta) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open auth conn fail");
        return SOFTBUS_TRANS_OPEN_AUTH_CHANNANEL_FAILED;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenAuthConnForUdpNegotiation end");
    return SOFTBUS_OK;
}

static int32_t PrepareAppInfoForUdpOpen(const ConnectOption *connOpt, AppInfo *appInfo, int32_t *channelId)
{
    appInfo->peerData.port = connOpt->socketOption.port;
    if (strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), connOpt->socketOption.addr) != EOK) {
        return SOFTBUS_MEM_ERR;
    }

    if (SoftBusGenerateSessionKey(appInfo->sessionKey, sizeof(appInfo->sessionKey)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate session key failed.");
        return SOFTBUS_ERR;
    }

    int32_t connType = connOpt->type;
    switch (connType) {
        case CONNECT_TCP:
            appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
            appInfo->routeType = WIFI_STA;
            if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.addr, sizeof(appInfo->myData.addr)) !=
                SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PrepareAppInfoForUdpOpen get local ip fail");
                return SOFTBUS_ERR;
            }
            appInfo->protocol = connOpt->socketOption.protocol;
            break;
        case CONNECT_P2P:
            appInfo->udpConnType = UDP_CONN_TYPE_P2P;
            appInfo->routeType = WIFI_P2P;
            if (P2pLinkGetLocalIp(appInfo->myData.addr, sizeof(appInfo->myData.addr)) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PrepareAppInfoForUdpOpen get p2p ip fail");
                return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
            }
            appInfo->protocol = connOpt->socketOption.protocol;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid connType.");
            return SOFTBUS_ERR;
    }

    int32_t id = GenerateUdpChannelId();
    if (id == INVALID_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate udp channel id failed.");
        return SOFTBUS_ERR;
    }
    *channelId = id;
    appInfo->myData.channelId = id;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    return SOFTBUS_OK;
}

int32_t TransOpenUdpChannel(AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans open udp channel.");
    if (appInfo == NULL || connOpt == NULL || channelId == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invaild param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t id;
    if (PrepareAppInfoForUdpOpen(connOpt, appInfo, &id) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "prepare app info for opening udp channel.");
        return SOFTBUS_ERR;
    }
    UdpChannelInfo *newChannel = NewUdpChannelByAppInfo(appInfo);
    if (newChannel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "new udp channel failed.");
        ReleaseUdpChannelId(id);
        return SOFTBUS_MEM_ERR;
    }
    newChannel->seq = GenerateSeq(false);
    newChannel->status = UDP_CHANNEL_STATUS_INIT;
    if (TransAddUdpChannel(newChannel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add new udp channel failed.");
        ReleaseUdpChannelId(id);
        SoftBusFree(newChannel);
        return SOFTBUS_ERR;
    }
    if (OpenAuthConnForUdpNegotiation(newChannel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open udp negotiation failed.");
        ReleaseUdpChannelId(id);
        TransDelUdpChannel(id);
        return SOFTBUS_ERR;
    }
    *channelId = id;
    return SOFTBUS_OK;
}

int32_t TransCloseUdpChannel(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans close udp channel.");
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(channel), 0, sizeof(channel));

    if (TransSetUdpChannelOptType(channelId, TYPE_UDP_CHANNEL_CLOSE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel close type failed.");
        return SOFTBUS_ERR;
    }
    if (TransGetUdpChannelById(channelId, &channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udp channel by channel id failed.[id = %d]", channelId);
        return SOFTBUS_ERR;
    }
    if (OpenAuthConnForUdpNegotiation(&channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open udp negotiation failed.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void UdpModuleCb(int64_t authId, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len < 1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "udp module callback enter: module=%d, seq=%" PRId64 ", len=%u.", data->module, data->seq, data->len);
    AnonyPacketPrintout(SOFTBUS_LOG_TRAN, "UdpModuleCb TransOnExchangeUdpInfo: ", (char *)data->data, data->len);
    cJSON *json = cJSON_ParseWithLength((char *)data->data, data->len);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cjson parse failed!");
        return;
    }
    TransOnExchangeUdpInfo(authId, data->flag, data->seq, json);
    cJSON_Delete(json);

    if (data->flag) {
        AuthCloseConn(authId);
    }
}

void TransUdpNodeOffLineProc(const LnnEventBasicInfo *info)
{
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED)) {
        return;
    }

    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo*)info;
    if (onlineStateInfo->isOnline == true) {
        return;
    }

    TransCloseUdpChannelByNetWorkId(onlineStateInfo->networkId);
}

int32_t TransUdpChannelInit(IServerChannelCallBack *callback)
{
    g_channelCb = callback;

    if (SoftBusMutexInit(&g_udpNegLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "g_udpNegLock init failed.");
        return SOFTBUS_ERR;
    }
    if (TransUdpChannelMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans udp channel manager init failed.");
        return SOFTBUS_ERR;
    }
    AuthTransListener transUdpCb = {
        .onDataReceived = UdpModuleCb,
        .onDisconnected = NULL,
    };
    if (RegAuthTransListener(MODULE_UDP_INFO, &transUdpCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register udp callback to auth failed.");
        return SOFTBUS_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, TransUdpNodeOffLineProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register udp Node offLine Proc failed.");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans udp channel init success.");
    return SOFTBUS_OK;
}

void TransUdpChannelDeinit(void)
{
    TransUdpChannelMgrDeinit();
    UnregAuthTransListener(MODULE_UDP_INFO);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, TransUdpNodeOffLineProc);

    g_channelCb = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans udp channel deinit success.");
}

void TransUdpDeathCallback(const char *pkgName)
{
    if (GetUdpChannelLock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    SoftBusList *udpChannelList = GetUdpChannelMgrHead();
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(udpChannelList->list), UdpChannelInfo, node) {
        if (strcmp(udpChannelNode->info.myData.pkgName, pkgName) == 0) {
            udpChannelNode->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
            if (OpenAuthConnForUdpNegotiation(udpChannelNode) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open udp negotiation failed.");
            }
        }
    }
    (void)ReleaseUdpChannelLock();
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransUdpDeathCallback end[pkgName = %s]", pkgName);
    return;
}