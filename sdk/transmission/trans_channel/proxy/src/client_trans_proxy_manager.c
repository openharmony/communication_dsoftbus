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

#include "client_trans_proxy_manager.h"

#include <securec.h>
#include <unistd.h>

#include "anonymizer.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "trans_assemble_tlv.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_proxy_process_data.h"
#include "trans_server_proxy.h"

#define SLICE_LEN (4 * 1024)
#define SHORT_SLICE_LEN (1024)
#define PROXY_ACK_SIZE 4
#define OH_TYPE 10
#define TLV_TYPE_AND_LENTH 2

static IClientSessionCallBack g_sessionCb;

static SoftBusList *g_proxyChannelInfoList = NULL;
static SoftBusList *g_channelSliceProcessorList = NULL;

static void ClientTransProxySliceTimerProc(void);

static int32_t ClientTransProxyListInit()
{
    g_proxyChannelInfoList = CreateSoftBusList();
    if (g_proxyChannelInfoList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    g_channelSliceProcessorList = CreateSoftBusList();
    if (g_channelSliceProcessorList == NULL) {
        DestroySoftBusList(g_proxyChannelInfoList);
        return SOFTBUS_NO_INIT;
    }
    if (RegisterTimeoutCallback(SOFTBUS_PROXYSLICE_TIMER_FUN, ClientTransProxySliceTimerProc) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "register timeout fail");
        DestroySoftBusList(g_proxyChannelInfoList);
        DestroySoftBusList(g_channelSliceProcessorList);
        return SOFTBUS_TIMOUT;
    }
    return SOFTBUS_OK;
}

static void ClientTransProxyListDeinit(void)
{
    if (UnRegisterTimeoutCallback(SOFTBUS_PROXYSLICE_TIMER_FUN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "unregister proxyslice timer failed");
    }
    if (g_proxyChannelInfoList != NULL) {
        DestroySoftBusList(g_proxyChannelInfoList);
        g_proxyChannelInfoList = NULL;
    }
    if (g_channelSliceProcessorList != NULL) {
        DestroySoftBusList(g_channelSliceProcessorList);
        g_channelSliceProcessorList = NULL;
    }
}

int32_t ClientTransProxyInit(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_INIT, "param is null!");
        return SOFTBUS_INVALID_PARAM;
    }

    g_sessionCb = *cb;
    if (ClinetTransProxyFileManagerInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClinetTransProxyFileManagerInit init fail!");
        return SOFTBUS_NO_INIT;
    }
    if (ClientTransProxyListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClinetTransProxyListInit init fail!");
        return SOFTBUS_NO_INIT;
    }

    if (PendingInit(PENDING_TYPE_PROXY) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans proxy pending init failed.");
        return SOFTBUS_NO_INIT;
    }

    TransGetProxyDataBufMaxSize();
    return SOFTBUS_OK;
}

void ClientTransProxyDeinit(void)
{
    ClinetTransProxyFileManagerDeinit();
    PendingDeinit(PENDING_TYPE_PROXY);
    ClientTransProxyListDeinit();
}

int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(ProxyChannelInfoDetail), &item->detail, sizeof(ProxyChannelInfoDetail));
            item->detail.sequence++;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channel by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

int32_t ClientTransProxyGetOsTypeByChannelId(int32_t channelId, int32_t *osType)
{
    if (osType == NULL || g_proxyChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            *osType = item->detail.osType;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientTransProxyGetLinkTypeByChannelId(int32_t channelId, int32_t *linkType)
{
    if (linkType == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            *linkType = item->detail.linkType;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientTransProxyAddChannelInfo(ClientProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == info->channelId) {
            TRANS_LOGE(TRANS_SDK, "client is existed. channelId=%{public}d", item->channelId);
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }

    ListAdd(&g_proxyChannelInfoList->list, &info->node);
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d", info->channelId);
    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    return SOFTBUS_OK;
}

int32_t ClientTransProxyDelChannelInfo(int32_t channelId)
{
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(item);
            DelPendingPacket(channelId, PENDING_TYPE_PROXY);
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channel by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

static ClientProxyChannelInfo *ClientTransProxyCreateChannelInfo(const ChannelInfo *channel)
{
    ClientProxyChannelInfo *info = (ClientProxyChannelInfo *)SoftBusCalloc(sizeof(ClientProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "info is null");
        return NULL;
    }
    info->channelId = channel->channelId;
    info->detail.isEncrypted = channel->isEncrypt;
    info->detail.sequence = 0;
    info->detail.linkType = channel->linkType;
    info->detail.osType = channel->osType;
    info->detail.isD2D = channel->isD2D;
    if (channel->isD2D) {
        info->detail.dataLen = channel->dataLen;
        if (memcpy_s(info->detail.pagingNonce, PAGING_NONCE_LEN, channel->pagingNonce, PAGING_NONCE_LEN) != EOK) {
            SoftBusFree(info);
            TRANS_LOGE(TRANS_SDK, "pagingNonce memcpy fail");
            return NULL;
        }
        if (memcpy_s(info->detail.pagingSessionkey, SHORT_SESSION_KEY_LENGTH, channel->pagingSessionkey,
            SHORT_SESSION_KEY_LENGTH) != EOK) {
            SoftBusFree(info);
            TRANS_LOGE(TRANS_SDK, "pagingSessionkey memcpy fail");
            return NULL;
        }
        if (channel->dataLen > 0 && channel->dataLen < EXTRA_DATA_MAX_LEN &&
            memcpy_s(info->detail.extraData, EXTRA_DATA_MAX_LEN, channel->extraData, channel->dataLen) != EOK) {
            SoftBusFree(info);
            TRANS_LOGE(TRANS_SDK, "extraData memcpy fail");
            return NULL;
        }
        if (channel->isServer &&
            strcpy_s(info->detail.pagingAccountId, ACCOUNT_UID_LEN_MAX, channel->pagingAccountId) != EOK) {
            SoftBusFree(info);
            TRANS_LOGE(TRANS_SDK, "pagingAccountId strcpy fail");
            return NULL;
        }
    } else {
        if (memcpy_s(info->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, channel->keyLen) != EOK) {
            SoftBusFree(info);
            TRANS_LOGE(TRANS_SDK, "sessionKey memcpy fail");
            return NULL;
        }
    }
    return info;
}

int32_t ClientTransProxyOnChannelOpened(
    const char *sessionName, const ChannelInfo *channel, SocketAccessInfo *accessInfo)
{
    if (sessionName == NULL || channel == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    ClientProxyChannelInfo *info = ClientTransProxyCreateChannelInfo(channel);
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "create channel info fail, channelId=%{public}d", channel->channelId);
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = ClientTransProxyAddChannelInfo(info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyAddChannelInfo fail channelId=%{public}d", channel->channelId);
        (void)memset_s(info->detail.sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        SoftBusFree(info);
        return ret;
    }

    SessionType type = TYPE_BUTT;
    switch (channel->businessType) {
        case BUSINESS_TYPE_BYTE:
            type = TYPE_BYTES;
            break;
        case BUSINESS_TYPE_FILE:
            type = TYPE_FILE;
            break;
        case BUSINESS_TYPE_D2D_MESSAGE:
            type = TYPE_D2D_MESSAGE;
            break;
        case BUSINESS_TYPE_D2D_VOICE:
            type = TYPE_D2D_VOICE;
            break;
        default:
            type = TYPE_MESSAGE;
            break;
    }

    ret = g_sessionCb.OnSessionOpened(sessionName, channel, type, accessInfo);
    if (ret != SOFTBUS_OK) {
        (void)ClientTransProxyDelChannelInfo(channel->channelId);
        char *tmpName = NULL;
        Anonymize(sessionName, &tmpName);
        TRANS_LOGE(TRANS_SDK, "notify session open fail, sessionName=%{public}s.", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId, ShutdownReason reason)
{
    (void)ClientTransProxyDelChannelInfo(channelId);
    (void)TransProxyDelSliceProcessorByChannelId(channelId);

    int ret = g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_PROXY, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session closed errCode=%{public}d, channelId=%{public}d.", ret, channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    int ret = g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_PROXY, errCode);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session openfail errCode=%{public}d, channelId=%{public}d.", errCode, channelId);
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t ClientTransProxyDecryptPacketData(int32_t channelId, int32_t seq, ProxyDataInfo *dataInfo)
{
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel Info by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return ret;
    }
    return TransProxyDecryptPacketData(seq, dataInfo, info.sessionKey);
}

int32_t ClientTransProxyPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType);

static void ClientTransProxySendSessionAck(int32_t channelId, int32_t seq)
{
    unsigned char ack[PROXY_ACK_SIZE] = { 0 };
    int32_t tmpSeq = 0;
    ProxyChannelInfoDetail info;
    if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get proxy info err, channelId=%{public}d", channelId);
        return;
    }
    if (info.osType == OH_TYPE) {
        tmpSeq = (int32_t)SoftBusHtoLl((uint32_t)seq);
    } else {
        tmpSeq = (int32_t)SoftBusHtoNl((uint32_t)seq); // convet host order to net order
    }
    if (memcpy_s(ack, PROXY_ACK_SIZE, &tmpSeq, sizeof(int32_t)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy seq err");
        return;
    }
    info.sequence = seq;
    if (ClientTransProxyPackAndSendData(channelId, ack, PROXY_ACK_SIZE, &info, TRANS_SESSION_ACK) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "send ack err, seq=%{public}d", seq);
    }
}

static int32_t ClientTransProxyProcSendMsgAck(int32_t channelId, const char *data, int32_t len,
                                              int32_t dataHeadSeq, uint32_t dataSeq)
{
    if (len != PROXY_ACK_SIZE) {
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    if (data == NULL) {
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    int32_t seq = *(int32_t *)data;
    int32_t hostSeq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, dataHeadSeq=%{public}d, seq=%{public}d, hostSeq=%{public}d",
        channelId, dataHeadSeq, seq, hostSeq);
    if (dataSeq != 0) { // this async process
        int32_t socketId = INVALID_SESSION_ID;
        SessionListenerAdapter sessionCallback;
        bool isServer = false;
        (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
        int32_t ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get socketId failed, channelId=%{public}d", channelId);
            return ret;
        }
        ret = ClientGetSessionCallbackAdapterById(socketId, &sessionCallback, &isServer);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get session callback failed, channelId=%{public}d", channelId);
            return ret;
        }
        ret = DeleteDataSeqInfoList(dataSeq, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "proxychannel delete dataSeqInfoList failed, channelId=%{public}d", channelId);
            return ret;
        }
        if (sessionCallback.socketClient.OnBytesSent == NULL) {
            TRANS_LOGE(TRANS_SDK, "OnBytesSent is null, channelId=%{public}d", channelId);
            return SOFTBUS_INVALID_PARAM;
        }
        sessionCallback.socketClient.OnBytesSent(socketId, dataSeq, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    int32_t ret = SetPendingPacket(channelId, seq, PENDING_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        ret = SetPendingPacket(channelId, hostSeq, PENDING_TYPE_PROXY);
        if (ret == SOFTBUS_OK) {
            TRANS_LOGI(TRANS_SDK, "set pending packet by hostSeq=%{public}d success", hostSeq);
        }
    }
    return ret;
}

static void ClientTransProxySendBytesAck(int32_t channelId, int32_t seq, uint32_t dataSeq, bool needAck)
{
    if (needAck) {
        TRANS_LOGI(TRANS_SDK, "proxy channel server send ack to client");
        unsigned char ack[PROXY_ACK_SIZE] = { 0 };
        int32_t tmpSeq = 0;
        ProxyChannelInfoDetail info;
        if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get proxy info err, channelId=%{public}d", channelId);
            return;
        }
        if (info.osType == OH_TYPE) {
            tmpSeq = (int32_t)SoftBusHtoLl((uint32_t)seq);
        } else {
            tmpSeq = (int32_t)SoftBusHtoNl((uint32_t)seq);
        }
        if (memcpy_s(ack, PROXY_ACK_SIZE, &tmpSeq, sizeof(int32_t)) != EOK) {
            TRANS_LOGE(TRANS_SDK, "memcpy seq err");
            return;
        }
        info.sequence = seq;
        if (TransProxyAsyncPackAndSendData(channelId, ack, PROXY_ACK_SIZE, dataSeq, TRANS_SESSION_ACK) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "send ack err, seq=%{public}d", seq);
            return;
        }
    }
}

static int32_t ClientTransProxyBytesNotifySession(int32_t channelId, const DataHeadTlvPacketHead *dataHead,
    const char *data, uint32_t len)
{
    SessionPktType flags = (SessionPktType)dataHead->flags;
    int32_t seq = dataHead->seq;
    uint32_t dataSeq = dataHead->dataSeq;
    bool needAck = dataHead->needAck;
    switch (flags) {
        case TRANS_SESSION_MESSAGE:
            ClientTransProxySendSessionAck(channelId, seq);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_ACK:
            return ClientTransProxyProcSendMsgAck(channelId, data, len, seq, dataSeq);
        case TRANS_SESSION_BYTES:
            ClientTransProxySendBytesAck(channelId, seq, dataSeq, needAck);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
        case TRANS_SESSION_ASYNC_MESSAGE:
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        default:
            TRANS_LOGE(TRANS_SDK, "invalid flags=%{public}d", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t ClientTransProxyNotifySession(
    int32_t channelId, SessionPktType flags, int32_t seq, const char *data, uint32_t len)
{
    switch (flags) {
        case TRANS_SESSION_MESSAGE:
            ClientTransProxySendSessionAck(channelId, seq);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_ACK:
            return ClientTransProxyProcSendMsgAck(channelId, data, len, seq, 0);
        case TRANS_SESSION_BYTES:
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
        case TRANS_SESSION_ASYNC_MESSAGE:
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        default:
            TRANS_LOGE(TRANS_SDK, "invalid flags=%{public}d", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t ClientTransProxyProcessSessionData(int32_t channelId, const PacketHead *dataHead, const char *data)
{
    ProxyDataInfo dataInfo = { 0 };

    int32_t ret = TransProxyProcessSessionData(&dataInfo, dataHead, data);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = ClientTransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGD(TRANS_SDK, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    if (ClientTransProxyNotifySession(channelId, (SessionPktType)dataHead->flags, dataHead->seq,
                                      (const char *)dataInfo.outData, dataInfo.outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyProcData(int32_t channelId, const DataHeadTlvPacketHead *dataHead, const char *data)
{
    ProxyDataInfo dataInfo = { 0 };
    int32_t ret = TransProxyProcData(&dataInfo, dataHead, data);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = ClientTransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGD(TRANS_SDK, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    if (ClientTransProxyBytesNotifySession(channelId, dataHead, (const char *)dataInfo.outData,
                                           dataInfo.outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyNoSubPacketTlvProc(int32_t channelId, const char *data, uint32_t len)
{
    DataHeadTlvPacketHead pktHead = { 0 };
    uint32_t newPktHeadSize = 0;
    int32_t ret = TransProxyParseTlv(len, data, &pktHead, &newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "proxy channel parse tlv failed, ret=%{public}d", ret);
        return ret;
    }
    ret = TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data failed, channelId=%{public}d, len=%{public}d", channelId, len);
        return ret;
    }
    ret = ClientTransProxyProcData(channelId, &pktHead, data + newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransGenerateRandIv(unsigned char *sessionIv, const uint16_t *nonce, const uint16_t *dataSeq)
{
    uint8_t shortIv[SHORT_SESSION_IV_LENGTH];
    if (memcpy_s(shortIv, NONCE_LEN, nonce, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s nonce fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(shortIv + NONCE_LEN, DATA_SEQ_LEN, dataSeq, DATA_SEQ_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s nonce fail");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusCalcHKDF(shortIv, SHORT_SESSION_IV_LENGTH, sessionIv, GCM_IV_LEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "calc HKDF fail");
        return SOFTBUS_CALC_HKDF_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t TransPackD2DExtraData(ProxyDataInfo *dataInfo, SessionPktType flag, uint16_t dataSeq, uint16_t nonce)
{
    if (memcpy_s(dataInfo->outData + sizeof(PacketD2DHead), NONCE_LEN, &nonce, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy data seq failed");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(dataInfo->outData + sizeof(PacketD2DHead) + NONCE_LEN, DATA_SEQ_LEN, &dataSeq, DATA_SEQ_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy data seq failed");
        return SOFTBUS_MEM_ERR;
    }
    PacketD2DHead *pktHead = (PacketD2DHead *)dataInfo->outData;
    pktHead->flags = flag;
    pktHead->dataLen = (int32_t)((int32_t)dataInfo->outLen - sizeof(PacketD2DHead) - DATA_SEQ_LEN - NONCE_LEN);
    pktHead->flags = (int32_t)SoftBusHtoLl((uint32_t)pktHead->flags);
    pktHead->dataLen = (int32_t)SoftBusHtoLl((uint32_t)pktHead->dataLen);
    return SOFTBUS_OK;
}

static int32_t TransProxyPackAsyncMessage(int32_t channelId, const ProxyChannelInfoDetail *info,
    ProxyDataInfo *dataInfo, SessionPktType flag, uint16_t dataSeq)
{
    if (dataInfo == NULL || info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    uint16_t nonce = 0;
    if (SoftBusGenerateRandomArray((unsigned char *)&nonce, sizeof(uint16_t)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate nonce fail");
        return SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL;
    }
    AesGcm128CipherKey cipherKey = { 0 };
    cipherKey.keyLen = SHORT_SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, info->pagingSessionkey, SHORT_SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key failed");
        return SOFTBUS_MEM_ERR;
    }
    if (TransGenerateRandIv(cipherKey.iv, &nonce, &dataSeq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate iv failed");
        (void)memset_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, 0, SHORT_SESSION_KEY_LENGTH);
        return SOFTBUS_GCM_SET_IV_FAIL;
    }
    dataInfo->outLen = dataInfo->inLen + SHORT_TAG_LEN + DATA_SEQ_LEN + NONCE_LEN + sizeof(PacketD2DHead);
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc failed");
        (void)memset_s(&cipherKey, sizeof(AesGcm128CipherKey), 0, sizeof(AesGcm128CipherKey));
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t outLen = 0;
    char *outData = (char *)dataInfo->outData + DATA_SEQ_LEN + NONCE_LEN + sizeof(PacketD2DHead);
    int32_t ret = SoftBusEncryptDataByGcm128(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcm128CipherKey), 0, sizeof(AesGcm128CipherKey));
    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen + SHORT_TAG_LEN) {
        outData = NULL;
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "encrypt error, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    ret = TransPackD2DExtraData(dataInfo, flag, dataSeq, nonce);
    if (ret != SOFTBUS_OK) {
        outData = NULL;
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "pack extra error, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyAsyncPackAndSendMessage(
    int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq, SessionPktType pktType)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail");

    ProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    ret = TransProxyPackAsyncMessage(channelId, &info, &dataInfo, pktType, dataSeq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransProxyPackAsyncMessage error, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t dataLen = 1;

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SHORT_SLICE_LEN - 1)) / (uint32_t)SHORT_SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        SoftBusFree(dataInfo.outData);
        TRANS_LOGE(TRANS_FILE, "Data overflow, sliceNum=%{public}u, channelId=%{public}d", sliceNum, channelId);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t cnt = 0; cnt < sliceNum; cnt++) {
        uint8_t *sliceData = TransProxyPackD2DData(&dataInfo, sliceNum, pktType, cnt, &dataLen);
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "pack data failed, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }

        int ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);
    TRANS_LOGI(TRANS_SDK, "TransProxyAsyncPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static void ClientTransProxySendD2DAck(int32_t channelId, uint16_t dataSeq)
{
    unsigned char ack[PROXY_ACK_SIZE] = { 0 };
    int32_t tmpSeq = 0;
    ProxyChannelInfoDetail info;
    if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get proxy info err, channelId=%{public}d", channelId);
        return;
    }
    if (info.osType == OH_TYPE) {
        tmpSeq = (int32_t)SoftBusHtoLl((uint32_t)dataSeq);
    } else {
        tmpSeq = (int32_t)SoftBusHtoNl((uint32_t)dataSeq); // convet host order to net order
    }
    if (memcpy_s(ack, PROXY_ACK_SIZE, &tmpSeq, sizeof(int32_t)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy seq err");
        return;
    }
    int32_t businessType;
    if (ClientGetChannelBusinessTypeByChannelId(channelId, &businessType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get businessType, channelId=%{public}d", channelId);
        return;
    }
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        if (TransProxyAsyncPackAndSendMessage(channelId, ack, PROXY_ACK_SIZE, dataSeq,
            TRANS_SESSION_ACK) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "send ack err, dataSeq=%{public}u", dataSeq);
        }
    }
}

static int32_t ClientTransProxyProcD2DAck(int32_t channelId, const char *data, uint32_t len, uint16_t dataSeq)
{
    if (len != PROXY_ACK_SIZE) {
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    if (data == NULL) {
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    if (dataSeq == 0) {
        TRANS_LOGI(TRANS_SDK, "dataSeq invalid");
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    int32_t seq = *(int32_t *)data;
    int32_t hostSeq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, dataHeadSeq=%{public}u, seq=%{public}d, hostSeq=%{public}d", channelId,
        dataSeq, seq, hostSeq);

    int32_t socketId = INVALID_SESSION_ID;
    SessionListenerAdapter sessionCallback;
    bool isServer = false;
    (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
    int32_t ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get socketId failed, channelId=%{public}d", channelId);
        return ret;
    }
    ret = ClientGetSessionCallbackAdapterById(socketId, &sessionCallback, &isServer);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get session callback failed, channelId=%{public}d", channelId);
        return ret;
    }
    ret = DeleteDataSeqInfoList(dataSeq, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "proxychannel delete dataSeqInfoList failed, channelId=%{public}d", channelId);
        return ret;
    }
    if (sessionCallback.socketClient.OnMessageSent == NULL) {
        TRANS_LOGE(TRANS_SDK, "OnMessageSent not implement, channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_REGISTER_LISTENER_FAILED;
    }
    sessionCallback.socketClient.OnMessageSent(socketId, dataSeq, SOFTBUS_OK);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyNotifyD2D(
    int32_t channelId, SessionPktType flags, uint16_t dataSeq, const char *data, uint32_t len)
{
    switch (flags) {
        case TRANS_SESSION_MESSAGE:
            ClientTransProxySendD2DAck(channelId, dataSeq);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_ACK:
            return ClientTransProxyProcD2DAck(channelId, data, len, dataSeq);
        case TRANS_SESSION_BYTES:
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
        case TRANS_SESSION_ASYNC_MESSAGE:
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        default:
            TRANS_LOGE(TRANS_SDK, "invalid flags=%{public}d", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t ClientTransProxyProcD2DData(int32_t channelId, const char *data, const PacketD2DHead *head,
    int32_t businessType, const PacketD2DIvSource *ivSource)
{
    ProxyDataInfo dataInfo = { 0 };

    int32_t ret = TransProxyProcessD2DData(&dataInfo, head, data, businessType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "process d2d data err");
    ProxyChannelInfoDetail info;
    ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get info err");
        SoftBusFree(dataInfo.outData);
        return ret;
    }
    uint8_t sessionCommonIv[GCM_IV_LEN];
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        if (TransGenerateRandIv(sessionCommonIv, &ivSource->nonce, &ivSource->dataSeq) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "generate iv failed");
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_GCM_SET_IV_FAIL;
        }
    } else {
        if (TransGenerateToBytesRandIv(sessionCommonIv, (uint32_t *)&ivSource->nonce) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "generate iv failed");
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_GCM_SET_IV_FAIL;
        }
    }

    ret = TransProxyDecryptD2DData(businessType, &dataInfo, info.pagingSessionkey, sessionCommonIv);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(head->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, head->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGI(TRANS_SDK, "Process D2D Data: outlen=%{public}d, dataseq=%{public}u",
        dataInfo.outLen, ivSource->dataSeq);
    if (ClientTransProxyNotifyD2D(channelId, (SessionPktType)head->flags, ivSource->dataSeq,
        (const char *)dataInfo.outData, dataInfo.outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransParseExtraData(uint16_t *nonce, uint16_t *dataSeq, uint32_t *offSet, const char *data)
{
    if (memcpy_s(nonce, NONCE_LEN, data + *offSet, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy nonce fail");
        return SOFTBUS_MEM_ERR;
    }
    *offSet += NONCE_LEN;
    if (memcpy_s(dataSeq, DATA_SEQ_LEN, data + *offSet, DATA_SEQ_LEN) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy data seq fail");
        return SOFTBUS_MEM_ERR;
    }
    *offSet += DATA_SEQ_LEN;
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyNoSubPacketD2DDataProc(
    int32_t channelId, const char *data, uint32_t len, int32_t businessType)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(data != NULL && len >= sizeof(PacketD2DHead),
        SOFTBUS_INVALID_PARAM, TRANS_SDK, "data null or len error. len=%{public}d", len);
    uint16_t dataSeq = 0;
    uint16_t nonce = 0;
    uint32_t offSet = 0;
    PacketD2DHead head = { 0 };
    if (memcpy_s(&head, sizeof(PacketD2DHead), data, sizeof(PacketD2DHead)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy head fail");
        return SOFTBUS_MEM_ERR;
    }
    head.flags = (int32_t)SoftBusLtoHl((uint32_t)head.flags);
    head.dataLen = (int32_t)SoftBusLtoHl((uint32_t)head.dataLen);
    if (head.dataLen <= 0) {
        TRANS_LOGE(
            TRANS_SDK, "dataLen=%{public}d, channelId=%{public}d, inlen=%{public}d", head.dataLen, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    offSet += sizeof(PacketD2DHead);
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        if (len != NONCE_LEN + DATA_SEQ_LEN + sizeof(PacketD2DHead) + head.dataLen) {
            TRANS_LOGE(
                TRANS_SDK, "dataLen=%{public}d, channelId=%{public}d, inlen=%{public}d", head.dataLen, channelId, len);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        if (ClientTransParseExtraData(&nonce, &dataSeq, &offSet, data) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "parse extra data fail");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        if (len != sizeof(PacketD2DHead) + head.dataLen + NONCE_LEN) {
            TRANS_LOGE(
                TRANS_SDK, "dataLen=%{public}d, channelId=%{public}d, inlen=%{public}d", head.dataLen, channelId, len);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        if (memcpy_s(&nonce, sizeof(uint16_t), data + offSet, NONCE_LEN) != EOK) {
            TRANS_LOGE(TRANS_SDK, "memcpy nonce failed");
            return SOFTBUS_MEM_ERR;
        }
        offSet += NONCE_LEN;
    }
    PacketD2DIvSource ivSource;
    ivSource.dataSeq = dataSeq;
    ivSource.nonce = nonce;
    int32_t ret = ClientTransProxyProcD2DData(channelId, data + offSet, &head, businessType, &ivSource);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
    }
    return ret;
}

static int32_t ClientTransProxyNoSubPacketProc(int32_t channelId, const char *data, uint32_t len)
{
    int32_t businessType;
    int32_t ret = ClientGetChannelBusinessTypeByChannelId(channelId, &businessType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get business type failed, channelId=%{public}d", channelId);
        return ret;
    }
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE || businessType == BUSINESS_TYPE_D2D_VOICE) {
        return ClientTransProxyNoSubPacketD2DDataProc(channelId, data, len, businessType);
    }
    bool supportTlv = false;
    int32_t res = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get support tlv failed, channelId=%{public}d", channelId);
        return ret;
    }
    if (supportTlv) {
        return ClientTransProxyNoSubPacketTlvProc(channelId, data, len);
    }
    PacketHead head = { 0 };
    ret = TransProxyNoSubPacketProc(&head, len, data, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "no sub packet failed, channelId=%{public}d, len=%{public}d", channelId, len);
        return res;
    }

    ret = ClientTransProxyProcessSessionData(channelId, &head, data + sizeof(PacketHead));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err, channelId=%{public}d, len=%{public}d", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static ChannelSliceProcessor *ClientTransProxyGetChannelSliceProcessor(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return processor;
        }
    }

    ChannelSliceProcessor *node = (ChannelSliceProcessor *)SoftBusCalloc(sizeof(ChannelSliceProcessor));
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc err");
        return NULL;
    }
    node->channelId = channelId;
    ListInit(&(node->head));
    ListAdd(&(g_channelSliceProcessorList->list), &(node->head));
    g_channelSliceProcessorList->cnt++;
    TRANS_LOGI(TRANS_SDK, "add new node, channelId=%{public}d", channelId);
    return node;
}

int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId)
{
    ChannelSliceProcessor *node = NULL;
    ChannelSliceProcessor *next = NULL;

    if (g_channelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_INIT, "not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock err");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (node->channelId == channelId) {
            for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
                TransProxyClearProcessor(&(node->processor[i]));
            }
            ListDelete(&(node->head));
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(node);
            g_channelSliceProcessorList->cnt--;
            (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    TransProxyClearProcessor(processor);
    int32_t businessType;
    int32_t ret = ClientGetChannelBusinessTypeByChannelId(channelId, &businessType);
    if (ret == SOFTBUS_OK) {
        if (businessType == BUSINESS_TYPE_D2D_MESSAGE || businessType == BUSINESS_TYPE_D2D_VOICE) {
            return TransProxyD2DFirstSliceProcess(processor, head, data, len, businessType);
        }
    }

    bool supportTlv = false;
    ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get support tlv failed, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t actualDataLen = 0;
    ret = TransGetActualDataLen(head, &actualDataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get actual datalen failed, channelId=%{public}d", channelId);
        return ret;
    }
    return TransProxyFirstSliceProcess(processor, head, data, len, supportTlv);
}

static bool IsValidCheckoutProcess(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return true;
        }
    }

    TRANS_LOGE(TRANS_SDK, "Process not exist.");
    return false;
}

static int32_t ClientTransProxyLastSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    int32_t ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen, (uint32_t)(processor->bufLen - processor->dataLen), data, len) !=
        EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy fail when proc last slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += (int32_t)len;

    ret = ClientTransProxyNoSubPacketProc(channelId, processor->data, (uint32_t)processor->dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process packets err");
        return ret;
    }

    if (IsValidCheckoutProcess(channelId)) {
        TransProxyClearProcessor(processor);
    }

    TRANS_LOGI(TRANS_SDK, "LastSliceProcess ok");
    return ret;
}

static int ClientTransProxySubPacketProc(int32_t channelId, const SliceHead *head, const char *data, uint32_t len)
{
    if (g_channelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_SDK, "TransProxySubPacketProc not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock err");
        return SOFTBUS_LOCK_ERR;
    }
    ChannelSliceProcessor *channelProcessor = ClientTransProxyGetChannelSliceProcessor(channelId);
    if (channelProcessor == NULL) {
        SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    int32_t index = head->priority;
    if (index < PROXY_CHANNEL_PRORITY_MESSAGE || index >= PROXY_CHANNEL_PRORITY_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid index=%{public}d", index);
        SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    }
    int ret;
    SliceProcessor *processor = &(channelProcessor->processor[index]);
    if (head->sliceSeq == 0) {
        ret = ClientTransProxyFirstSliceProcess(processor, head, data, len, channelId);
    } else if (head->sliceNum == head->sliceSeq + 1) {
        ret = ClientTransProxyLastSliceProcess(processor, head, data, len, channelId);
    } else {
        ret = TransProxyNormalSliceProcess(processor, head, data, len);
    }

    SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    if (ret != SOFTBUS_OK) {
        TransProxyClearProcessor(processor);
    }
    return ret;
}

static int32_t ClientTransProxySliceProc(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len <= sizeof(SliceHead)) {
        TRANS_LOGE(TRANS_SDK, "data null or len error. len=%{public}d", len);
        return SOFTBUS_INVALID_PARAM;
    }

    SliceHead headSlice = *(SliceHead *)data;
    TransUnPackSliceHead(&headSlice);
    if (TransProxyCheckSliceHead(&headSlice) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid slihead");
        return SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD;
    }

    uint32_t dataLen = len - sizeof(SliceHead);
    if (headSlice.sliceNum == 1) { // no sub packets
        TRANS_LOGD(TRANS_SDK, "no sub packets proc, channelId=%{public}d", channelId);
        return ClientTransProxyNoSubPacketProc(channelId, data + sizeof(SliceHead), dataLen);
    } else {
        TRANS_LOGI(TRANS_SDK, "sub packets proc sliceNum=%{public}d", headSlice.sliceNum);
        return ClientTransProxySubPacketProc(channelId, &headSlice, data + sizeof(SliceHead), dataLen);
    }
}

static void ClientTransProxySliceTimerProc(void)
{
#define SLICE_PACKET_TIMEOUT 10 // 10s
    ChannelSliceProcessor *removeNode = NULL;
    ChannelSliceProcessor *nextNode = NULL;

    if (g_channelSliceProcessorList == NULL || g_channelSliceProcessorList->cnt == 0) {
        return;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransProxySliceTimerProc lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
            if (removeNode->processor[i].active == true) {
                removeNode->processor[i].timeout++;
                if (removeNode->processor[i].timeout >= SLICE_PACKET_TIMEOUT) {
                    TRANS_LOGE(TRANS_SDK, "timeout=%{public}d", removeNode->processor[i].timeout);
                    TransProxyClearProcessor(&removeNode->processor[i]);
                }
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    return;
}

int32_t ClientTransProxyOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    (void)type;
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyOnDataReceived data null. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    ProxyChannelInfoDetail info;
    if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID;
    }
    if (!info.isEncrypted) {
        return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
    }

    return ClientTransProxySliceProc(channelId, (char *)data, len);
}

void ClientTransProxyCloseChannel(int32_t channelId)
{
    (void)ClientTransProxyDelChannelInfo(channelId);
    (void)TransProxyDelSliceProcessorByChannelId(channelId);
    TRANS_LOGI(TRANS_SDK, "TransCloseProxyChannel, channelId=%{public}d", channelId);
    if (ServerIpcCloseChannel(NULL, channelId, CHANNEL_TYPE_PROXY) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server close err. channelId=%{public}d", channelId);
    }
}

static int32_t ClientTransProxyPackTlvBytes(int32_t channelId, ProxyDataInfo *dataInfo,
    ProxyChannelInfoDetail *info, SessionPktType flag, uint32_t dataSeq)
{
    if (dataInfo == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    bool needAck = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, NULL, &needAck);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get need ack fail");
    DataHeadTlvPacketHead headInfo = {
        .needAck = needAck,
        .dataSeq = dataSeq,
    };
    return TransProxyPackTlvBytes(dataInfo, info->sessionKey, flag, info->sequence, &headInfo);
}

static int32_t ClientTransProxyPackBytes(int32_t channelId, ProxyDataInfo *dataInfo,
    ProxyChannelInfoDetail *info, SessionPktType flag)
{
    if (dataInfo == NULL || info == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    bool supportTlv = false;
    uint32_t dataSeq = 0;
    int32_t res = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(res == SOFTBUS_OK, res, TRANS_SDK, "get support tlv fail");
    if (supportTlv) {
        return ClientTransProxyPackTlvBytes(channelId, dataInfo, info, flag, dataSeq);
    }
    return TransProxyPackBytes(channelId, dataInfo, info->sessionKey, flag, info->sequence);
}

static int32_t TransProxyProcessD2DBytes(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType)
{
    ProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    int32_t ret = TransProxyPackD2DBytes(&dataInfo, info->pagingSessionkey, info->pagingNonce, pktType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "pack d2d bytes error, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t dataLen = 1;

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SHORT_SLICE_LEN - 1)) / (uint32_t)SHORT_SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        TRANS_LOGE(TRANS_SDK, "Data overflow");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t cnt = 0; cnt < sliceNum; cnt++) {
        uint8_t *sliceData = TransProxyPackD2DData(&dataInfo, sliceNum, pktType, cnt, &dataLen);
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "pack data failed, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);

    TRANS_LOGI(TRANS_SDK, "TransProxyPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t TransProxyProcessNormalBytes(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType)
{
    ProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    int32_t ret = ClientTransProxyPackBytes(channelId, &dataInfo, info, pktType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyPackBytes error, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t dataLen = 1;

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SLICE_LEN - 1)) / (uint32_t)SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        TRANS_LOGE(TRANS_SDK, "Data overflow");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t cnt = 0; cnt < sliceNum; cnt++) {
        uint8_t *sliceData = TransProxyPackData(&dataInfo, sliceNum, pktType, cnt, &dataLen);
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "pack data failed, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);

    TRANS_LOGI(TRANS_SDK, "TransProxyPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t ClientTransProxyPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType)
{
    if (data == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t businessType;
    int32_t ret;
    ret = ClientGetChannelBusinessTypeByChannelId(channelId, &businessType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get business type error, channelId=%{public}d", channelId);
    }
    if (businessType == BUSINESS_TYPE_D2D_VOICE) {
        ret = TransProxyProcessD2DBytes(channelId, data, len, info, pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "process d2d bytes error, channelId=%{public}d", channelId);
            return ret;
        }
        return SOFTBUS_OK;
    } else {
        ret = TransProxyProcessNormalBytes(channelId, data, len, info, pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "process d2d bytes error, channelId=%{public}d", channelId);
            return ret;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len, bool needAck)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send bytes: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    if (needAck) {
        ret = AddPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
            return ret;
        }
        ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_BYTES);
        if (ret != SOFTBUS_OK) {
            DelPendingPacketbyChannelId(channelId, info.sequence, PENDING_TYPE_PROXY);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, seq=%{public}d", channelId, info.sequence);
        return ProcPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
    }
    return ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_BYTES);
}

int32_t TransProxyAsyncPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq, SessionPktType pktType)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail");

    ProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    ret = ClientTransProxyPackTlvBytes(channelId, &dataInfo, &info, pktType, dataSeq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyPackTlvBytes error, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t dataLen = 1;

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SLICE_LEN - 1)) / (uint32_t)SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        SoftBusFree(dataInfo.outData);
        TRANS_LOGE(TRANS_FILE, "Data overflow, sliceNum=%{public}u, channelId=%{public}d", sliceNum, channelId);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t cnt = 0; cnt < sliceNum; cnt++) {
        uint8_t *sliceData = TransProxyPackData(&dataInfo, sliceNum, pktType, cnt, &dataLen);
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "pack data failed, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }

        int ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);
    TRANS_LOGI(TRANS_SDK, "TransProxyAsyncPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t TransProxyChannelAsyncSendBytes(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send bytes: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, TRANS_SESSION_BYTES);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "proxy async send data fail!");
    int32_t socketId = 0;
    ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId fail, ret=%{public}d", ret);
        return ret;
    }
    ret = DataSeqInfoListAddItem(dataSeq, channelId, socketId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add dataSeqInfoList fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        // auth channel only can send bytes
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    ret = AddPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
        return ret;
    }
    ret = ClientTransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    if (ret != SOFTBUS_OK) {
        DelPendingPacketbyChannelId(channelId, info.sequence, PENDING_TYPE_PROXY);
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, seq=%{public}d", channelId, info.sequence);
    return ProcPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
}

int32_t ClientTransProxyOnChannelBind(int32_t channelId, int32_t channelType)
{
    if (g_sessionCb.OnChannelBind == NULL) {
        TRANS_LOGE(TRANS_SDK, "OnChannelBind is null, channelId=%{public}d.", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = g_sessionCb.OnChannelBind(channelId, channelType);
    if (ret == SOFTBUS_NOT_NEED_UPDATE) {
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify OnChannelBind openfail channelId=%{public}d.", channelId);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TransProxyChannelAsyncSendMessage(int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = TransProxyAsyncPackAndSendMessage(channelId, data, len, dataSeq, TRANS_SESSION_MESSAGE);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "proxy async send data fail!");
    int32_t socketId = 0;
    ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId fail, ret=%{public}d", ret);
        return ret;
    }
    ret = DataSeqInfoListAddItem(dataSeq, channelId, socketId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add dataSeqInfoList fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}
