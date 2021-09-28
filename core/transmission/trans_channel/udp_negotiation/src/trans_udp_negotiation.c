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
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
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
static pthread_mutex_t g_udpNegLock = PTHREAD_MUTEX_INITIALIZER;

static int32_t GenerateUdpChannelId(void)
{
    if (pthread_mutex_lock(&g_udpNegLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate udp channel id lock failed");
        return INVALID_ID;
    }
    for (uint32_t id = 0; id < MAX_CHANNEL_ID_COUNT; id++) {
        if (((g_channelIdFlagBitsMap >> id) & ID_USED) == ID_NOT_USED) {
            g_channelIdFlagBitsMap |= (ID_USED << id);
            pthread_mutex_unlock(&g_udpNegLock);
            return (int32_t)id;
        }
    }
    pthread_mutex_unlock(&g_udpNegLock);
    return INVALID_ID;
}

void ReleaseUdpChannelId(int32_t channelId)
{
    if (pthread_mutex_lock(&g_udpNegLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "release udp channel id lock failed");
        return;
    }
    uint32_t id = (uint32_t)channelId;
    g_channelIdFlagBitsMap &= (~(ID_USED << id));
    pthread_mutex_unlock(&g_udpNegLock);
}

static int64_t GenerateSeq(bool isServer)
{
    if (pthread_mutex_lock(&g_udpNegLock) != 0) {
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
    pthread_mutex_unlock(&g_udpNegLock);
    return seq;
}

static int32_t NotifyUdpChannelOpened(const AppInfo *appInfo, bool isServerSide)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel opened.");
    ChannelInfo info = {0};
    info.channelId = appInfo->myData.channelId;
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = isServerSide;
    info.businessType = appInfo->businessType;
    info.myIp = (char*)appInfo->myData.ip;
    info.sessionKey = (char*)appInfo->sessionKey;
    info.keyLen = SESSION_KEY_LENGTH;
    info.groupId = (char*)appInfo->groupId;
    info.peerDeviceId = (char*)appInfo->peerData.deviceId;
    info.peerSessionName = (char*)appInfo->peerData.sessionName;
    if (!isServerSide) {
        info.peerPort = appInfo->peerData.port;
        info.peerIp = (char*)appInfo->peerData.ip;
    }
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(appInfo->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    return g_channelCb->OnChannelOpened(pkgName, appInfo->myData.sessionName, &info);
}

int32_t NotifyUdpChannelClosed(const AppInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel closed.");
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(info->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    ret = g_channelCb->OnChannelClosed(pkgName, (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "on channel closed failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t NotifyUdpChannelOpenFailed(const AppInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify udp channel open failed.");
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(info->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail.");
        return SOFTBUS_ERR;
    }
    ret = g_channelCb->OnChannelOpenFailed(pkgName, (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify udp channel open failed err.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
    if (NotifyUdpChannelClosed(appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify app udp channel closed failed.");
        return SOFTBUS_ERR;
    }
    if (TransDelUdpChannel(appInfo->myData.channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "delete udp channel failed.");
        return SOFTBUS_ERR;
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
            return CloseUdpChannel(appInfo);
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid udp channel type.");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static uint8_t *GetEncryptData(const char *data, const ConnectOption *opt, uint32_t *outSize)
{
    uint8_t *encryptData = NULL;
    OutBuf buf = {0};
    uint32_t len = strlen(data) + 1 + AuthGetEncryptHeadLen();
    encryptData = (uint8_t *)SoftBusCalloc(len);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc error!");
        return NULL;
    }
    buf.buf = encryptData;
    buf.bufLen = len;
    AuthSideFlag side;
    if (AuthEncrypt(opt, &side, (uint8_t *)data, strlen(data) + 1, &buf) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "AuthEncrypt error.");
        SoftBusFree(encryptData);
        return NULL;
    }
    if (buf.outLen != len) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "outLen not right.");
    }
    *outSize = buf.outLen;
    return encryptData;
}

static int32_t SendReplyUdpInfo(AppInfo *appInfo, int64_t authId, int64_t seq, const ConnectOption *opt)
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
    char *msgStr = cJSON_PrintUnformatted(replyMsg);
    cJSON_Delete(replyMsg);
    if (msgStr == NULL) {
        return SOFTBUS_ERR;
    }
    uint32_t size;
    uint8_t *encryptData = GetEncryptData(msgStr, opt, &size);
    cJSON_free(msgStr);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "encrypt data failed.");
        return SOFTBUS_ERR;
    }
    AuthDataHead head = {
        .authId = authId,
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REPLY,
        .seq = seq
    };
    if (AuthPostData(&head, encryptData, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "auth post message failed.");
        SoftBusFree(encryptData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(encryptData);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp send reply info out.");
    return SOFTBUS_OK;
}

static int32_t ParseRequestAppInfo(const cJSON *msg, AppInfo *appInfo)
{
    if (TransUnpackRequestUdpInfo(msg, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack request udp info failed.");
        return SOFTBUS_ERR;
    }
    char localIp[IP_LEN] = {0};
    if (appInfo->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN && appInfo->udpConnType == UDP_CONN_TYPE_WIFI) {
        if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, sizeof(localIp)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local ip from lnn failed.");
            return SOFTBUS_ERR;
        }
        appInfo->routeType = WIFI_STA;
        if (strcpy_s(appInfo->myData.ip, IP_LEN, localIp) != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

/**
 * don't care release resources when close status, after invoking process udp channel status.
 * */
static void ProcessAbnormalUdpChannelState(const AppInfo *info, bool needClose)
{
    if (needClose) {
        if (info->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
            (void)NotifyUdpChannelOpenFailed(info);
        } else {
            (void)NotifyUdpChannelClosed(info);
        }
        (void)TransDelUdpChannel(info->myData.channelId);
    } else {
        if (info->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
            (void)NotifyUdpChannelOpenFailed(info);
            (void)TransDelUdpChannel(info->myData.channelId);
        }
    }
}

static void TransOnExchangeUdpInfo(int64_t authId, int32_t isReply, int64_t seq,
    const cJSON *msg, const ConnectOption *opt)
{
    if (isReply) {
        /* receive reply message */
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "receive reply udp negotiation info.");
        UdpChannelInfo channel = {0};
        if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_DONE) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel negotiation status done failed.");
            return;
        }
        if (TransGetUdpChannelBySeq(seq, &channel) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udp channel by seq failed.");
            return;
        }
        if (TransUnpackReplyUdpInfo(msg, &(channel.info)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unpack reply udp info failed.");
            ProcessAbnormalUdpChannelState(&(channel.info), true);
            return;
        }
        if (ProcessUdpChannelState(&(channel.info), false) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process udp channel state failed.");
            ProcessAbnormalUdpChannelState(&(channel.info), false);
        }
        TransUpdateUdpChannelInfo(seq, &(channel.info));
    } else {
        /* receive request message */
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "receive request udp negotiation info.");
        AppInfo info = {0};
        if (ParseRequestAppInfo(msg, &info) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get appinfo failed.");
            return;
        }
        int32_t ret = ProcessUdpChannelState(&info, true);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process udp channel state failed.");
            if (ret == SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED) {
                return;
            }
            ProcessAbnormalUdpChannelState(&info, false);
            return;
        }
        if (SendReplyUdpInfo(&info, authId, seq, opt) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send reply udp info failed.");
            ProcessAbnormalUdpChannelState(&info, false);
        }
    }
}

static int32_t StartExchangeUdpInfo(UdpChannelInfo *channel, int64_t authId, const ConnectOption *opt, int64_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "start exchange udp info.");
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
    uint32_t size;
    uint8_t *encryptData = GetEncryptData(msgStr, opt, &size);
    cJSON_free(msgStr);
    if (encryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "encrypt data failed.");
        return SOFTBUS_ERR;
    }

    AuthDataHead head = {
        .authId = authId,
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REQUEST,
        .seq = seq
    };
    if (AuthPostData(&head, encryptData, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "auth post message failed.");
        SoftBusFree(encryptData);
        return SOFTBUS_ERR;
    }
    if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_NEGING) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel negotiation status neging failed.");
    }
    SoftBusFree(encryptData);
    return SOFTBUS_OK;
}

static int32_t OpenAuthConnForUdpNegotiation(UdpChannelInfo *channel, const ConnectOption *connOpt)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open auth connection for udp negotiation.");
    if (channel == NULL || connOpt == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (connOpt->type == CONNECT_TCP) {
        int64_t authId;
        if (AuthGetIdByOption(connOpt, &authId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get auth id err");
            return SOFTBUS_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "auth info: authid=%lld", authId);

        if (StartExchangeUdpInfo(channel, authId, connOpt, channel->seq) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exchange udp info err");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    } else {
        return SOFTBUS_CONN_INVALID_CONN_TYPE;
    }
}

static int32_t PrepareAppInfoForUdpOpen(const ConnectOption *connOpt, AppInfo *appInfo, int32_t *channelId)
{
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.ip, sizeof(appInfo->myData.ip)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get local ip from lnn failed.");
        return SOFTBUS_ERR;
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
            if (strcpy_s(appInfo->peerData.ip, IP_LEN, connOpt->info.ipOption.ip) != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            appInfo->peerData.port = connOpt->info.ipOption.port;
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
    if (OpenAuthConnForUdpNegotiation(newChannel, connOpt) != SOFTBUS_OK) {
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
    UdpChannelInfo channel = {0};
    ConnectOption connOpt = {0};
    if (TransSetUdpChannelOptType(channelId, TYPE_UDP_CHANNEL_CLOSE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set udp channel close type failed.");
        return SOFTBUS_ERR;
    }
    if (TransGetUdpChannelById(channelId, &channel) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get udp channel by channel id failed.[id = %d]", channelId);
        return SOFTBUS_ERR;
    }
    connOpt.type = CONNECT_TCP;
    if (strcpy_s(connOpt.info.ipOption.ip, IP_LEN, channel.info.peerData.ip) != EOK) {
        return SOFTBUS_ERR;
    }
    connOpt.info.ipOption.port = channel.info.peerData.port;
    if (OpenAuthConnForUdpNegotiation(&channel, &connOpt) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open udp negotiation failed.");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static void UdpModuleCb(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info)
{
    if (option == NULL || info == NULL || info->module != MODULE_UDP_INFO) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp module callback enter.");

    cJSON *json = NULL;
    uint8_t *decryptData = NULL;
    OutBuf buf = {0};
    decryptData = (uint8_t *)SoftBusCalloc(info->len - AuthGetEncryptHeadLen() + 1);
    if (decryptData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt udp negotiation data failed.");
        return;
    }
    buf.buf = decryptData;
    buf.bufLen = info->len - AuthGetEncryptHeadLen();

    if (AuthDecrypt(option, CLIENT_SIDE_FLAG, (uint8_t *)info->data, info->len, &buf) != SOFTBUS_OK) {
        SoftBusFree(decryptData);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt udp negotiation info failed.");
        return;
    }
    json = cJSON_Parse((char *)decryptData);
    SoftBusFree(decryptData);
    decryptData = NULL;
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cjson parse failed!");
        return;
    }

    TransOnExchangeUdpInfo(authId, info->flags, info->seq, json, option);
    cJSON_Delete(json);
}

int32_t TransUdpChannelInit(IServerChannelCallBack *callback)
{
    g_channelCb = callback;
    if (TransUdpChannelMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans udp channel manager init failed.");
        return SOFTBUS_ERR;
    }
    AuthTransCallback transUdpCb = {
        .onTransUdpDataRecv = UdpModuleCb
    };
    if (AuthTransDataRegCallback(TRANS_UDP_DATA, &transUdpCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register udp callback to auth failed.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans udp channel init success.");
    return SOFTBUS_OK;
}

void TransUdpChannelDeinit(void)
{
    TransUdpChannelMgrDeinit();
    g_channelCb = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server trans udp channel deinit success.");
}