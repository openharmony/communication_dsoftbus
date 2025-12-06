/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_message.h"

#include <securec.h>

#include "trans_assemble_tlv.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "trans_event.h"
#include "trans_event_form.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_tcp_process_data.h"
#include "softbus_mintp_socket.h"

#define ACK_SIZE 4

#define BYTE_TOS 0x60
#define COLLABORATE_BYTE_TOS 0x80
#define MESSAGE_TOS 0xC0
#define MAGICNUM_SIZE sizeof(uint32_t)
#define TLVCOUNT_SIZE sizeof(uint8_t)

static SoftBusList *g_tcpDataList = NULL;

static int32_t TransTdcSetPendingPacket(int32_t channelId, const char *data, uint32_t len, uint32_t dataSeq)
{
    if (len != ACK_SIZE) {
        TRANS_LOGE(TRANS_SDK, "recv invalid seq.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataSeq != 0) { // A non-zero value indicates asynchronous. PendingPacket does not need to be set.
        int32_t socketId = INVALID_SESSION_ID;
        SessionListenerAdapter sessionCallback;
        bool isServer = false;
        (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
        int32_t ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_TCP_DIRECT, &socketId, false);
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
            TRANS_LOGE(TRANS_SDK, "tcp delete dataSeqInfoList failed, channelId=%{public}d", channelId);
            return ret;
        }
        if (sessionCallback.socketClient.OnBytesSent == NULL) {
            TRANS_LOGE(TRANS_SDK, "OnBytesSent is null, channelId=%{public}d", channelId);
            return SOFTBUS_INVALID_PARAM;
        }
        sessionCallback.socketClient.OnBytesSent(socketId, dataSeq, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    int32_t seq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    int32_t ret = SetPendingPacket(channelId, seq, PENDING_TYPE_DIRECT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "can not match seq=%{public}d", seq);
        return ret;
    }
    return SOFTBUS_OK;
}

static char *TransTdcPackData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len, int32_t flags,
    DataLenInfo *lenInfo)
{
    bool needAck = false;
    bool supportTlv = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channel->channelId, CHANNEL_TYPE_TCP_DIRECT, &supportTlv, &needAck);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_SDK, "get need ack failed by channelId");
    TransTdcPackDataInfo dataInfo = {
        .needAck = needAck,
        .supportTlv = supportTlv,
        .seq = channel->detail.sequence,
        .len = len,
    };
    return TransTdcPackAllData(&dataInfo, channel->detail.sessionKey, data, flags, lenInfo);
}

static bool CheckCollaborationSessionName(const char *sessionName)
{
    if (strstr(sessionName, "ohos.collaborationcenter") != NULL) {
        return true;
    }
    return false;
}

static int32_t TransTcpSetTos(TcpDirectChannelInfo *channel, int32_t flags)
{
    if (channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char sessionName[SESSION_NAME_SIZE_MAX + 1] = { 0 };
    if (ClientGetSessionNameByChannelId(
        channel->channelId, channel->detail.channelType, sessionName, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to get sessionName, channelId=%{public}d", channel->channelId);
        return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
    }
    uint32_t tos = (flags == FLAG_BYTES) ? BYTE_TOS : MESSAGE_TOS;
    if (CheckCollaborationSessionName(sessionName)) {
        tos = (flags == FLAG_BYTES) ? COLLABORATE_BYTE_TOS : MESSAGE_TOS;
    }
    if (channel->detail.fdProtocol == LNN_PROTOCOL_DETTP || channel->detail.fdProtocol == LNN_PROTOCOL_MINTP) {
        if (SetMintpSocketTos(channel->detail.fd, tos) != SOFTBUS_OK) {
            return SOFTBUS_SOCKET_ERR;
        }
    } else if (channel->detail.fdProtocol != LNN_PROTOCOL_HTP) {
        if (SetIpTos(channel->detail.fd, tos) != SOFTBUS_OK) {
            return SOFTBUS_TCP_SOCKET_ERR;
        }
    }

    return SOFTBUS_OK;
}

static int32_t TransTdcProcessPostData(TcpDirectChannelInfo *channel, const char *data, uint32_t len, int32_t flags)
{
    bool supportTlv = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channel->channelId, channel->detail.channelType, &supportTlv, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to get supprotTlv. channelId=%{public}d", channel->channelId);
        return ret;
    }
    DataLenInfo lenInfo = { 0 };
    char *buf = TransTdcPackData(channel, data, len, flags, &lenInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, SOFTBUS_ENCRYPT_ERR, TRANS_SDK, "failed to pack bytes.");
    ret = TransTcpSetTos(channel, flags);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to set tos. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        return ret;
    }
    if (SoftBusMutexLock(&(channel->detail.fdLock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to lock fd. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        return SOFTBUS_LOCK_ERR;
    }
    ret = TransTdcSendData(&lenInfo, supportTlv, channel->detail.fd, len, buf);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to send data. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        (void)SoftBusMutexUnlock(&(channel->detail.fdLock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(channel->detail.fdLock));
    SoftBusFree(buf);
    buf = NULL;
    return SOFTBUS_OK;
}

int32_t TransTdcSendBytes(int32_t channelId, const char *data, uint32_t len, bool needAck)
{
    if (data == NULL || len == 0) {
        TRANS_LOGE(TRANS_SDK, "param invalid. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoIncFdRefById(channelId, &channel, true) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get info by id failed, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_GET_INFO_FAILED;
    }
    if (needAck) {
        int32_t sequence = channel.detail.sequence;
        int32_t ret = AddPendingPacket(channelId, sequence, PENDING_TYPE_DIRECT);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
            TransUpdateFdState(channel.channelId);
            return ret;
        }
        if (channel.detail.needRelease) {
            TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendBytes, channelId=%{public}d.", channelId);
            TransUpdateFdState(channel.channelId);
            return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
        }
        ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
        TransUpdateFdState(channel.channelId);
        (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
        if (ret != SOFTBUS_OK) {
            DelPendingPacketbyChannelId(channelId, sequence, PENDING_TYPE_DIRECT);
            TRANS_LOGE(TRANS_SDK, "tdc send bytes failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
            return ret;
        }
        return ProcPendingPacket(channelId, sequence, PENDING_TYPE_DIRECT);
    }
    if (channel.detail.needRelease) {
        TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendBytes, channelId=%{public}d.", channelId);
        TransUpdateFdState(channel.channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
    }
    int32_t ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
    TransUpdateFdState(channel.channelId);
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc send bytes failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t TransSetTosSendData(TcpDirectChannelInfo *channel, char *buf, int32_t newPkgHeadSize,
    int32_t flags, uint32_t outLen)
{
    if (channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransTcpSetTos(channel, flags);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to set tos. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        return ret;
    }
    if (SoftBusMutexLock(&(channel->detail.fdLock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to lock fd. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        return SOFTBUS_LOCK_ERR;
    }
    ssize_t res = ConnSendSocketData(channel->detail.fd, buf, outLen + newPkgHeadSize, 0);
    if (res != (ssize_t)outLen + newPkgHeadSize) {
        TRANS_LOGE(TRANS_SDK, "failed to send tcp data. res=%{public}zd", res);
        (void)SoftBusMutexUnlock(&(channel->detail.fdLock));
        SoftBusFree(buf);
        return SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT;
    }
    (void)SoftBusMutexUnlock(&(channel->detail.fdLock));
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

static void BuildTdcSendDataInfo(EncrptyInfo *enInfo, char *finalData, uint32_t inLen, char *out, uint32_t *outLen)
{
    enInfo->in = finalData;
    enInfo->inLen = inLen;
    enInfo->out = out;
    enInfo->outLen = outLen;
}

static int32_t TransTdcNeedAckProcessPostData(TcpDirectChannelInfo *channel, const char *data, uint32_t len,
    int32_t flags, uint32_t dataSeq)
{
    uint32_t outLen = 0;
    int32_t newPkgHeadSize = 0;
    uint32_t dataLen = len + OVERHEAD_LEN;
    char *finalData = (char *)data;
    int32_t finalSeq = channel->detail.sequence;
    uint32_t tmpSeq;
    EncrptyInfo enInfo = { 0 };
    if (flags == FLAG_ACK) {
        finalSeq = *((int32_t *)data);
        tmpSeq = SoftBusHtoNl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }
    DataHead pktHead = { 0 };
    int32_t tlvBufferSize = 0;
    int32_t ret = BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv dataHead error");
    ret = BuildNeedAckTlvData(&pktHead, true, dataSeq, &tlvBufferSize); // asynchronous sendbytes must support reply ack
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv needAck error");
    char *buf = TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);
    if (buf == NULL) {
        ReleaseDataHeadResource(&pktHead);
        TRANS_LOGE(TRANS_SDK, "pack data fail");
        return SOFTBUS_TRANS_PACK_TLV_DATA_FAILED;
    }
    ReleaseDataHeadResource(&pktHead);
    newPkgHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    BuildTdcSendDataInfo(&enInfo, finalData, len, buf + newPkgHeadSize, &outLen);
    ret = TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, &enInfo);
    (void)memset_s(channel->detail.sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "encrypt error");
        SoftBusFree(buf);
        return ret;
    }
    if (outLen != len + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "pack bytes len error, outLen=%{public}d", outLen);
        SoftBusFree(buf);
        return SOFTBUS_ENCRYPT_ERR;
    }
    ret = TransSetTosSendData(channel, buf, newPkgHeadSize, flags, outLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "set tos send data error, channelId=%{public}d", channel->channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcAsyncSendBytes(int32_t channelId, const char *data, uint32_t len, uint32_t dataSeq)
{
    if (data == NULL || len == 0) {
        TRANS_LOGE(TRANS_SDK, "param invalid. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoIncFdRefById(channelId, &channel, true) == NULL) {
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    if (channel.detail.needRelease) {
        TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendBytes, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
    }
    TransUpdateFdState(channel.channelId);
    int32_t ret = TransTdcNeedAckProcessPostData(&channel, data, len, FLAG_BYTES, dataSeq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc async send bytes failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }

    int32_t socketId = 0;
    ret = ClientGetSessionIdByChannelId(channelId, channel.detail.channelType, &socketId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc get sessionId failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }
    ret = DataSeqInfoListAddItem(dataSeq, channelId, socketId, channel.detail.channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc add seqInfoList failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcSendMessage(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        TRANS_LOGE(TRANS_SDK, "param invalid. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoIncFdRefById(channelId, &channel, true) == NULL) {
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    int32_t sequence = channel.detail.sequence;
    int32_t ret = AddPendingPacket(channelId, sequence, PENDING_TYPE_DIRECT);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
        return ret;
    }
    if (channel.detail.needRelease) {
        TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendMessage, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
    }
    ret = TransTdcProcessPostData(&channel, data, len, FLAG_MESSAGE);
    TransUpdateFdState(channel.channelId);
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (ret != SOFTBUS_OK) {
        DelPendingPacketbyChannelId(channelId, sequence, PENDING_TYPE_DIRECT);
        TRANS_LOGE(TRANS_SDK, "tdc send message failed, ret=%{public}d.", ret);
        return ret;
    }
    return ProcPendingPacket(channelId, sequence, PENDING_TYPE_DIRECT);
}

static int32_t TransTdcSendAck(int32_t channelId, int32_t seq)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoIncFdRefById(channelId, &channel, false) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get info by id failed, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_GET_INFO_FAILED;
    }
    if (channel.detail.needRelease) {
        TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendMessage, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
    }
    int32_t ret = TransTdcProcessPostData(&channel, (char *)(&seq), ACK_SIZE, FLAG_ACK);
    TransUpdateFdState(channel.channelId);
    return ret;
}

static int32_t TransTdcNeedSendAck(TcpDirectChannelInfo *channel, int32_t seq, uint32_t dataSeq, bool needAck)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "channel is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (needAck) {
        TRANS_LOGI(TRANS_SDK, "tdc need send ack to client");
        return TransTdcNeedAckProcessPostData(channel, (char *)(&seq), ACK_SIZE, FLAG_ACK, dataSeq);
    }
    return SOFTBUS_OK;
}

int32_t TransAddDataBufNode(int32_t channelId, int32_t fd)
{
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDataList is null.");
        return SOFTBUS_NO_INIT;
    }
    DataBuf *node = (DataBuf *)SoftBusCalloc(sizeof(DataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = TransGetDataBufSize();
    node->data = (char *)SoftBusCalloc(node->size);
    if (node->data == NULL) {
        SoftBusFree(node);
        TRANS_LOGE(TRANS_SDK, "malloc data failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->w = node->data;

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        SoftBusFree(node->data);
        SoftBusFree(node);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_tcpDataList->list, &node->node);
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d", channelId);
    g_tcpDataList->cnt++;
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    return SOFTBUS_OK;
}

int32_t TransDelDataBufNode(int32_t channelId)
{
    if (g_tcpDataList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    DataBuf *item = NULL;
    DataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, DataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpDataList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);

    return SOFTBUS_OK;
}

static int32_t TransDestroyDataBuf(void)
{
    if (g_tcpDataList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    DataBuf *item = NULL;
    DataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, DataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpDataList->cnt--;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);

    return SOFTBUS_OK;
}

static DataBuf *TransGetDataBufNodeById(int32_t channelId)
{
    if (g_tcpDataList ==  NULL) {
        return NULL;
    }

    DataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDataList->list), DataBuf, node) {
        if (item->channelId == channelId) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_SDK, "tcp direct channel not exist. channelId=%{public}d", channelId);
    return NULL;
}

static int32_t TransTdcProcessDataByFlag(
    uint32_t flag, int32_t seqNum, TcpDirectChannelInfo *channel, const char *plain, uint32_t plainLen)
{
    switch (flag) {
        case FLAG_BYTES:
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_BYTES);
        case FLAG_ACK:
            TransTdcSetPendingPacket(channel->channelId, plain, plainLen, 0); // the old message process dataSeq is 0.
            return SOFTBUS_OK;
        case FLAG_MESSAGE:
            TransTdcSendAck(channel->channelId, seqNum);
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_MESSAGE);
        default:
            TRANS_LOGE(TRANS_SDK, "unknown flag=%{public}d.", flag);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t TransTdcProcessBytesDataByFlag(
    TcpDataTlvPacketHead *pktHead, TcpDirectChannelInfo *channel, char *plain, uint32_t plainLen)
{
    uint32_t flag = pktHead->flags;
    int32_t seqNum = pktHead->seq;
    uint32_t dataSeq = pktHead->dataSeq;
    bool needAck = pktHead->needAck;
    switch (flag) {
        case FLAG_BYTES:
            TransTdcNeedSendAck(channel, seqNum, dataSeq, needAck); // this is new sync process and async process
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_BYTES);
        case FLAG_ACK:
            TransTdcSetPendingPacket(channel->channelId, plain, plainLen, dataSeq); // the async or new sync process
            return SOFTBUS_OK;
        case FLAG_MESSAGE:
            TransTdcSendAck(channel->channelId, seqNum);
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_MESSAGE);
        default:
            TRANS_LOGE(TRANS_SDK, "unknown flag=%{public}u.", flag);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t TransTdcProcessTlvData(int32_t channelId, TcpDataTlvPacketHead *pktHead, int32_t pkgHeadSize)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channelInfo failed. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t plainLen = 1;
    DataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "node is null. channelId=%{public}d", channelId);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_SDK, "data received, channelId=%{public}d, dataLen=%{public}u, size=%{public}d, seq=%{public}d",
        channelId, dataLen, node->size, pktHead->seq);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + pkgHeadSize, dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt fail, channelId=%{public}d, dataLen=%{public}u", channel.channelId, dataLen);
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = MoveNode(channel.channelId, node, dataLen, pkgHeadSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    ret = TransTdcProcessBytesDataByFlag(pktHead, &channel, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data fail, channelId=%{public}d, dataLen=%{public}u",
            channel.channelId, dataLen);
    }
    SoftBusFree(plain);
    return ret;
}

static int32_t TransTdcProcessData(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    int32_t ret = TransTdcGetInfoById(channelId, &channel);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, TRANS_SDK,
        "get key fail. channelId=%{public}d ", channelId);
    ret = SoftBusMutexLock(&g_tcpDataList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SDK, "lock failed ");
    uint32_t plainLen = 1;
    DataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "node is null. channelId=%{public}d ", channelId);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    int32_t seqNum = pktHead->seq;
    uint32_t flag = pktHead->flags;
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_SDK, "data received, channelId=%{public}d, len=%{public}u, size=%{public}d, seq=%{public}d"
        ", flags=%{public}d", channelId, dataLen, node->size, seqNum, flag);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ret = TransTdcUnPackData(channelId, channel.detail.sessionKey, plain, &plainLen, node);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "unpack fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    ret = TransTdcProcessDataByFlag(flag, seqNum, &channel, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
    }
    SoftBusFree(plain);
    return ret;
}

static void DfxReceiveRateStatistic(int32_t channelId, uint32_t dataLen)
{
    #define DATA_LEN_1M (1 * 1024 * 1024) // 1MB
    #define SEC_TO_MILLISEC (1000)
    #define FIRST_PKG_USED_TIME 30 // 30ms
    if (dataLen < DATA_LEN_1M) {
        return;
    }
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channelInfo failed. channelId=%{public}d", channelId);
        return;
    }
    uint64_t startTimestamp = channel.timestamp;
    uint64_t endTimestamp = SoftBusGetSysTimeMs();
    uint64_t useTime = startTimestamp > endTimestamp ?
        (UINT64_MAX - startTimestamp + endTimestamp):(endTimestamp - startTimestamp);
    useTime += FIRST_PKG_USED_TIME;
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    extra.channelId = channelId;
    extra.dataLen = dataLen;
    extra.bytesRate = (dataLen * SEC_TO_MILLISEC)/(DATA_LEN_1M * useTime);
    TRANS_EVENT(EVENT_SCENE_TRANS_SEND_DATA, EVENT_STAGE_DATA_SEND_RATE, extra);
}

static int32_t TransTdcProcAllTlvData(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_tcpDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is NULL");
    while (1) {
        TransTdcSetTimestamp(channelId, SoftBusGetSysTimeMs());
        SoftBusMutexLock(&g_tcpDataList->lock);
        TcpDataTlvPacketHead pktHead = { 0 };
        uint32_t newPktHeadSize = 0;
        DataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "can not find data buf node. channelId=%{public}d", channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        bool flag = false;
        int32_t ret = TransTdcUnPackAllTlvData(channelId, &pktHead, &newPktHeadSize, node, &flag);
        if (ret != SOFTBUS_OK || flag == true) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return ret;
        }
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        DfxReceiveRateStatistic(channelId, pktHead.dataLen);
        TransTdcSetTimestamp(channelId, 0);
        ret = TransTdcProcessTlvData(channelId, &pktHead, newPktHeadSize);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "data received failed");
    }
}

static int32_t TransTdcProcAllData(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_tcpDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is NULL");
    while (1) {
        SoftBusMutexLock(&g_tcpDataList->lock);
        DataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "can not find data buf node. channelId=%{public}d", channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        bool flag = false;
        int32_t ret = TransTdcUnPackAllData(channelId, node, &flag);
        if (ret != SOFTBUS_OK || flag == true) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return ret;
        }
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        ret = TransTdcProcessData(channelId);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "data received failed");
    }
}

static int32_t TransClientGetTdcDataBufByChannel(int32_t channelId, int32_t *fd, size_t *len)
{
    if (fd == NULL || len == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "tdc data list empty.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    DataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDataList->list), DataBuf, node) {
        if (item->channelId == channelId) {
            *fd = item->fd;
            *len = item->size - (item->w - item->data);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    TRANS_LOGE(TRANS_SDK, "client get tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

static int32_t TransClientUpdateTdcDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "data list empty.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    DataBuf *item = NULL;
    DataBuf *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &(g_tcpDataList->list), DataBuf, node) {
        if (item->channelId != channelId) {
            continue;
        }
        int32_t freeLen = (int32_t)(item->size) - (item->w - item->data);
        if (recvLen > freeLen) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK,
                "client tdc recvLen override freeLen. recvLen=%{public}d, freeLen=%{public}d", recvLen, freeLen);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "client tdc memcpy failed. channelId=%{public}d", channelId);
            return SOFTBUS_MEM_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        TRANS_LOGD(TRANS_SDK, "client update tdc data success, channelId=%{public}d", channelId);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    TRANS_LOGE(TRANS_SDK, "client update tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

int32_t TransTdcRecvData(int32_t channelId)
{
    int32_t recvLen = 1;
    int32_t fd = -1;
    size_t len = 0;
    int32_t ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get Tdc data buf by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return ret;
    }
    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "client tdc malloc failed. channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_MALLOC_ERR;
    }
    ret = TransTdcRecvFirstData(channelId, recvBuf, &recvLen, fd, len);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        return ret;
    }
    ret = TransClientUpdateTdcDataBufWInfo(channelId, recvBuf, recvLen);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_SDK, "client update data buf failed. channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    SoftBusFree(recvBuf);
    bool supportTlv = false;
    ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_TCP_DIRECT, &supportTlv, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "fail to get support tlv");
    if (supportTlv) {
        return TransTdcProcAllTlvData(channelId);
    }
    return TransTdcProcAllData(channelId);
}

int32_t TransDataListInit(void)
{
    if (g_tcpDataList != NULL) {
        TRANS_LOGI(TRANS_SDK, "g_tcpDataList already init");
        return SOFTBUS_OK;
    }
    int32_t ret = TransGetTdcDataBufMaxSize();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "TransGetTdcDataBufMaxSize failed");

    g_tcpDataList = CreateSoftBusList();
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDataList creat list failed");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

void TransDataListDeinit(void)
{
    if (g_tcpDataList == NULL) {
        return;
    }
    (void)TransDestroyDataBuf();
    DestroySoftBusList(g_tcpDataList);
    g_tcpDataList = NULL;
}
