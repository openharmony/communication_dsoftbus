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

#include "client_trans_tcp_direct_message.h"

#include <securec.h>

#include "client_trans_assemble_tlv.h"
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
#include "trans_log.h"
#include "trans_pending_pkt.h"

#define ACK_SIZE 4
#define DATA_EXTEND_LEN (DC_DATA_HEAD_SIZE + OVERHEAD_LEN)
#define MIN_BUF_LEN (1024 + DATA_EXTEND_LEN)

#define BYTE_TOS 0x60
#define COLLABORATE_BYTE_TOS 0x80
#define MESSAGE_TOS 0xC0
#define TDC_TLV_ELEMENT 5
#define TLV_TYPE_AND_LENTH 2
#define MAGICNUM_SIZE sizeof(uint32_t)
#define TLVCOUNT_SIZE sizeof(uint8_t)

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t fd;
    uint32_t size;
    char *data;
    char *w;
} ClientDataBuf;

typedef struct {
    uint32_t outLen;
    uint32_t tlvHeadLen;
} DataLenInfo;

static uint32_t g_dataBufferMaxLen = 0;
static SoftBusList *g_tcpDataList = NULL;

static void ReleaseDataHeadResource(DataHead *pktHead)
{
    ReleaseTlvValueBuffer(pktHead);
    SoftBusFree(pktHead->tlvElement);
}

static int32_t BuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t dataSeq = SoftBusHtoLl(dataSeqs);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_NEED_ACK, (uint8_t *)&needAck, sizeof(needAck), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tcp channel assemble needAck tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_SEQ, (uint8_t *)&dataSeq, sizeof(dataSeq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tcp channel assemble dataSeq tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    pktHead->tlvElement -= (TDC_TLV_ELEMENT * sizeof(TlvElement));
    return SOFTBUS_OK;
}

static int32_t BuildDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen,
    int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    pktHead->tlvElement = (uint8_t *)SoftBusCalloc(TDC_TLV_ELEMENT * sizeof(TlvElement));
    if (pktHead->tlvElement == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc tlvElement failed");
        return SOFTBUS_MALLOC_ERR;
    }
    pktHead->magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    uint32_t seq = SoftBusHtoLl((uint32_t)finalSeq);
    uint32_t flag = SoftBusHtoLl((uint32_t)flags);
    uint32_t dataLens = SoftBusHtoLl(dataLen);

    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_INNER_SEQ, (uint8_t *)&seq, sizeof(seq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tcp channel assemble seq tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_FLAG, (uint8_t *)&flag, sizeof(flag), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tcp channel assemble flag tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_LEN, (uint8_t *)&dataLens, sizeof(dataLens), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tcp channel assemble dataLen tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcParseTlv(char *data, TcpDataTlvPacketHead *head, uint32_t *newDataHeadSize)
{
    if (data == NULL || head == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    errno_t ret = EOK;
    if (memcpy_s(&head->magicNumber, MAGICNUM_SIZE, data, MAGICNUM_SIZE) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy magicNumber failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&head->tlvCount, TLVCOUNT_SIZE, data + MAGICNUM_SIZE,
        TLVCOUNT_SIZE) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy tlvCount failed.");
        return SOFTBUS_MEM_ERR;
    }
    *newDataHeadSize += MAGICNUM_SIZE + TLVCOUNT_SIZE;
    char *temp = data + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (int index = 0; index < head->tlvCount; index++) {
        uint8_t *type = (uint8_t *)temp;
        uint8_t *length = (uint8_t *)(temp + sizeof(uint8_t));
        temp += (TLV_TYPE_AND_LENTH *sizeof(uint8_t));
        switch (*type) {
            case TLV_TYPE_INNER_SEQ:
                ret = memcpy_s(&head->seq, sizeof(head->seq), temp, *length);
                break;
            case TLV_TYPE_DATA_SEQ:
                ret = memcpy_s(&head->dataSeq, sizeof(head->dataSeq), temp, *length);
                break;
            case TLV_TYPE_FLAG:
                ret = memcpy_s(&head->flags, sizeof(head->flags), temp, *length);
                break;
            case TLV_TYPE_NEED_ACK:
                ret = memcpy_s(&head->needAck, sizeof(head->needAck), temp, *length);
                break;
            case TLV_TYPE_DATA_LEN:
                ret = memcpy_s(&head->dataLen, sizeof(head->dataLen), temp, *length);
                break;
            default:
                TRANS_LOGE(TRANS_SDK, "unknown trans tdc tlv skip, tlvType=%{public}d", *type);
                break;
        }
        temp += *length;
        *newDataHeadSize += (TLV_TYPE_AND_LENTH * sizeof(uint8_t) + *length);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_SDK,
            "parse tlv memcpy failed, tlvType=%{public}d, ret%{public}d", *type, ret);
    }
    return SOFTBUS_OK;
}

static void PackTcpDataPacketHead(TcpDataPacketHead *data)
{
    data->magicNumber = SoftBusHtoLl(data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = SoftBusHtoLl(data->flags);
    data->dataLen = SoftBusHtoLl(data->dataLen);
}

static void TransTcpDataTlvUnpack(TcpDataTlvPacketHead *data)
{
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
    data->dataSeq = SoftBusLtoHl(data->dataSeq);
}

static void UnpackTcpDataPacketHead(TcpDataPacketHead *data)
{
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

static int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusDecryptData(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "SoftBusDecryptData fail ret=%{public}d.", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, const char *in, uint32_t inLen,
    char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen, seqNum);
    if (memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memset cipherKey failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "encrypt error, ret=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

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

static char *TransTdcPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen)
{
    int32_t newDataHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    char *buf = (char *)SoftBusCalloc(dataLen + newDataHeadSize);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc buf failed");
        return NULL;
    }
    if (memcpy_s(buf, dataLen + newDataHeadSize, &pktHead->magicNum, MAGICNUM_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_SDK, "memcpy magicNum failed");
        return NULL;
    }

    if (memcpy_s(buf + MAGICNUM_SIZE, dataLen + newDataHeadSize, &pktHead->tlvCount,
        TLVCOUNT_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_SDK, "memcpy tlvCount failed");
        return NULL;
    }

    char *temp = buf + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (int index = 0; index < pktHead->tlvCount; index++) {
        TlvElement *ement = (TlvElement *)pktHead->tlvElement;

        if (memcpy_s(temp, dataLen + newDataHeadSize, &ement->type, sizeof(ement->type)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment type failed");
            return NULL;
        }

        temp += sizeof(ement->type);
        if (memcpy_s(temp, dataLen + newDataHeadSize, &ement->length, sizeof(ement->length)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment length failed");
            return NULL;
        }

        temp += sizeof(ement->length);
        if (memcpy_s(temp, dataLen + newDataHeadSize, ement->value, ement->length) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment value failed");
            return NULL;
        }
        temp += ement->length;
        pktHead->tlvElement += sizeof(TlvElement);
    }
    return buf;
}

static char *TransPackData(uint32_t dataLen, TcpDataPacketHead pktHead)
{
    char *buf = (char *)SoftBusMalloc(dataLen + DC_DATA_HEAD_SIZE);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, NULL, TRANS_SDK, "malloc failed");
    PackTcpDataPacketHead(&pktHead);
    if (memcpy_s(buf, DC_DATA_HEAD_SIZE, &pktHead, sizeof(TcpDataPacketHead)) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_SDK, "memcpy_s error");
        return NULL;
    }
    return buf;
}

static char *TransTdcPackData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len, int flags,
    DataLenInfo *lenInfo)
{
    uint32_t dataLen = len + OVERHEAD_LEN;
    char *finalData = (char *)data;
    int32_t finalSeq = channel->detail.sequence;
    uint32_t tmpSeq;
    if (flags == FLAG_ACK) {
        finalSeq = *((int32_t *)data);
        tmpSeq = SoftBusHtoNl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }
    bool needAck = false;
    bool supportTlv = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channel->channelId, CHANNEL_TYPE_TCP_DIRECT, &supportTlv, &needAck);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_SDK, "get need ack failed by channelId");
    if (supportTlv) {
        DataHead pktHead;
        int32_t tlvBufferSize = 0;
        int32_t ret = BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_SDK, "build tlv dataHead failed");
        ret = BuildNeedAckTlvData(&pktHead, needAck, 0, &tlvBufferSize); // sync process dataSeq must be zero.
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_SDK, "build tlv needack failed");
        char *buf = TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);
        if (buf == NULL) {
            ReleaseDataHeadResource(&pktHead);
            TRANS_LOGE(TRANS_SDK, "TransTdcPackTlvData fail");
            return NULL;
        }
        ReleaseDataHeadResource(&pktHead);
        lenInfo->tlvHeadLen = (uint32_t)(MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize);
        ret = TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len, buf + lenInfo->tlvHeadLen,
            &lenInfo->outLen);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "encrypt error");
            return NULL;
        }
        return buf;
    }
    TcpDataPacketHead pktHead = {
        .magicNumber = MAGIC_NUMBER,
        .seq = finalSeq,
        .flags = (uint32_t)flags,
        .dataLen = dataLen,
    };
    char *buf = TransPackData(dataLen, pktHead);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, NULL, TRANS_SDK, "TransPackData fail");
    ret = TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len, buf + DC_DATA_HEAD_SIZE,
        &lenInfo->outLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "encrypt error");
        SoftBusFree(buf);
        return NULL;
    }
    return buf;
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
    if (ClientGetSessionNameByChannelId(channel->channelId, channel->detail.channelType,
        sessionName, SESSION_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to get sessionName, channelId=%{public}d", channel->channelId);
        return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
    }
    uint32_t tos = (flags == FLAG_BYTES) ? BYTE_TOS : MESSAGE_TOS;
    if (CheckCollaborationSessionName(sessionName)) {
        tos = (flags == FLAG_BYTES) ? COLLABORATE_BYTE_TOS : MESSAGE_TOS;
    }
    if (SetIpTos(channel->detail.fd, tos) != SOFTBUS_OK) {
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcProcessPostData(TcpDirectChannelInfo *channel, const char *data, uint32_t len, int32_t flags)
{
    DataLenInfo lenInfo = { 0 };
    char *buf = TransTdcPackData(channel, data, len, flags, &lenInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, SOFTBUS_ENCRYPT_ERR, TRANS_SDK, "failed to pack bytes.");
    uint32_t outLen = lenInfo.outLen;
    if (outLen != len + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "pack bytes len error, outLen=%{public}d", outLen);
        SoftBusFree(buf);
        return SOFTBUS_ENCRYPT_ERR;
    }
    int32_t res = TransTcpSetTos(channel, flags);
    if (res != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to set tos. channelId=%{public}d", channel->channelId);
        return res;
    }
    if (SoftBusMutexLock(&(channel->detail.fdLock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to lock fd. channelId=%{public}d", channel->channelId);
        SoftBusFree(buf);
        return SOFTBUS_LOCK_ERR;
    }
    bool supportTlv = false;
    res = GetSupportTlvAndNeedAckById(channel->channelId, channel->detail.channelType, &supportTlv, NULL);
    if (res != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed to get supportTlv. channelId=%{public}d", channel->channelId);
        return res;
    }
    uint32_t tmpHeadLen = DC_DATA_HEAD_SIZE;
    if (supportTlv) {
        TRANS_LOGI(TRANS_SDK, "supportTlv is true");
        tmpHeadLen = lenInfo.tlvHeadLen;
    }
    ssize_t ret = ConnSendSocketData(channel->detail.fd, buf, outLen + tmpHeadLen, 0);
    if (ret != (ssize_t)outLen + (ssize_t)tmpHeadLen) {
        TRANS_LOGE(TRANS_SDK, "send bytes failed to send tcp data. channelId=%{public}d, ret=%{public}zd",
            channel->channelId, ret);
        SoftBusFree(buf);
        (void)SoftBusMutexUnlock(&(channel->detail.fdLock));
        return GetErrCodeBySocketErr(SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT);
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
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoIncFdRefById failed, channelId=%{public}d.", channelId);
        return SOFTBUS_TRANS_TDC_GET_INFO_FAILED;
    }
    if (needAck) {
        int32_t sequence = channel.detail.sequence;
        int32_t ret = AddPendingPacket(channelId, sequence, PENDING_TYPE_DIRECT);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
            return ret;
        }
        if (channel.detail.needRelease) {
            TRANS_LOGE(TRANS_SDK, "trans tdc channel need release, cancel sendBytes, channelId=%{public}d.", channelId);
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
        return SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD;
    }
    int ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
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

static int32_t TransTdcNeedAckProcessPostData(TcpDirectChannelInfo *channel, const char *data, uint32_t len,
    int32_t flags, uint32_t dataSeq)
{
    uint32_t outLen = 0;
    int32_t newPkgHeadSize = 0;
    uint32_t dataLen = len + OVERHEAD_LEN;
    char *finalData = (char *)data;
    int32_t finalSeq = channel->detail.sequence;
    uint32_t tmpSeq;
    if (flags == FLAG_ACK) {
        finalSeq = *((int32_t *)data);
        tmpSeq = SoftBusHtoNl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }
    DataHead pktHead;
    int32_t tlvBufferSize = 0;
    int32_t ret = BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv dataHead error");
    ret = BuildNeedAckTlvData(&pktHead, true, dataSeq, &tlvBufferSize); // asynchronous sendbytes must support reply ack
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv needAck error");
    char *buf = TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);
    if (buf == NULL) {
        ReleaseDataHeadResource(&pktHead);
        TRANS_LOGE(TRANS_SDK, "TransTdcPackTlvData fail");
        return SOFTBUS_TRANS_PACK_TLV_DATA_FAILED;
    }
    ReleaseDataHeadResource(&pktHead);
    newPkgHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    ret = TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len, buf + newPkgHeadSize, &outLen);
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
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoIncFdRefById failed, channelId=%{public}d.", channelId);
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

static uint32_t TransGetDataBufSize(void)
{
    return MIN_BUF_LEN;
}

#define SLICE_HEAD_LEN 16
static int32_t TransGetDataBufMaxSize(void)
{
    uint32_t maxLen = 0;
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen));
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get config err");
    g_dataBufferMaxLen = maxLen + DATA_EXTEND_LEN + SLICE_HEAD_LEN;
    return SOFTBUS_OK;
}

int32_t TransAddDataBufNode(int32_t channelId, int32_t fd)
{
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDataList is null.");
        return SOFTBUS_NO_INIT;
    }
    ClientDataBuf *node = (ClientDataBuf *)SoftBusCalloc(sizeof(ClientDataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = TransGetDataBufSize();
    node->data = (char *)SoftBusCalloc(node->size);
    if (node->data == NULL) {
        SoftBusFree(node);
        TRANS_LOGE(TRANS_SDK, "calloc data failed.");
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
    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
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
    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpDataList->cnt--;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);

    return SOFTBUS_OK;
}

static ClientDataBuf *TransGetDataBufNodeById(int32_t channelId)
{
    if (g_tcpDataList ==  NULL) {
        return NULL;
    }

    ClientDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDataList->list), ClientDataBuf, node) {
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

static int32_t MoveNode(int32_t channelId, ClientDataBuf *node, uint32_t dataLen, int32_t pkgHeadSize)
{
    char *end = node->data + pkgHeadSize + dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memmove fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - pkgHeadSize - dataLen;
    return SOFTBUS_OK;
}

static int32_t TransTdcProcessTlvData(TcpDirectChannelInfo channel, TcpDataTlvPacketHead *pktHead, int32_t pkgHeadSize)
{
    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    ClientDataBuf *node = TransGetDataBufNodeById(channel.channelId);
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "node is null. channelId=%{public}d", channel.channelId);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_SDK, "data received, channelId=%{public}d, dataLen=%{public}u, size=%{public}d, seq=%{public}d",
        channel.channelId, dataLen, node->size, pktHead->seq);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail, channelId=%{public}d, dataLen=%{public}u", channel.channelId, dataLen);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + pkgHeadSize, dataLen, plain, &plainLen);
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
    if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get key fail. channelId=%{public}d ", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    ClientDataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "node is null. channelId=%{public}d ", channelId);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_SDK, "data received, channelId=%{public}d, dataLen=%{public}u, size=%{public}d, seq=%{public}d",
        channelId, dataLen, node->size, pktHead->seq);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int32_t ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + DC_DATA_HEAD_SIZE, dataLen,
        plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = MoveNode(channelId, node, dataLen, DC_DATA_HEAD_SIZE);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    ret = TransTdcProcessDataByFlag(pktHead->flags, pktHead->seq, &channel, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
    }
    SoftBusFree(plain);
    return ret;
}

static int32_t TransResizeDataBuffer(ClientDataBuf *oldBuf, uint32_t pkgLen)
{
    TRANS_LOGI(TRANS_SDK, "Resize Data Buffer channelId=%{public}d, pkgLen=%{public}d",
        oldBuf->channelId, pkgLen);
    char *newBuf = (char *)SoftBusCalloc(pkgLen);
    if (newBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc err pkgLen=%{public}u", pkgLen);
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t bufLen = oldBuf->w - oldBuf->data;
    if (memcpy_s(newBuf, pkgLen, oldBuf->data, bufLen) != EOK) {
        SoftBusFree(newBuf);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(oldBuf->data);
    oldBuf->data = NULL;
    oldBuf->data = newBuf;
    oldBuf->size = pkgLen;
    oldBuf->w = newBuf + bufLen;
    TRANS_LOGI(TRANS_SDK, "TransResizeDataBuffer ok");
    return SOFTBUS_OK;
}

static int32_t TransTdcProcAllTlvData(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_tcpDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is NULL");
    while (1) {
        SoftBusMutexLock(&g_tcpDataList->lock);
        ClientDataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "can not find data buf node. channelId=%{public}d", channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        uint32_t bufLen = node->w - node->data;
        if (bufLen == 0) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_OK;
        }
        TcpDirectChannelInfo channel;
        if (TransTdcGetInfoById(channelId, &channel) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get channelInfo fail. channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
        }
        TcpDataTlvPacketHead pktHead;
        uint32_t newPktHeadSize = 0;
        int32_t ret = TransTdcParseTlv(node->data, &pktHead, &newPktHeadSize);
        if (ret != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return ret;
        }
        TransTcpDataTlvUnpack(&pktHead);
        if (bufLen < newPktHeadSize) {
            TRANS_LOGE(TRANS_SDK,
                "data bufLen not enough, recv biz data next time. channelId=%{public}d, bufLen=%{public}u",
                channelId, bufLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        if (pktHead.magicNumber != MAGIC_NUMBER) {
            TRANS_LOGE(TRANS_SDK, "invalid data packet head. channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        if ((pktHead.dataLen > g_dataBufferMaxLen - newPktHeadSize) || (pktHead.dataLen <= OVERHEAD_LEN)) {
            TRANS_LOGE(TRANS_SDK, "illegal dataLen=%{public}u", pktHead.dataLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        uint32_t pkgLen = pktHead.dataLen + newPktHeadSize;
        if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
            int32_t res = TransResizeDataBuffer(node, pkgLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return res;
        }
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        if (bufLen < pkgLen) {
            TRANS_LOGE(TRANS_SDK, "data bufLen not enough, recv biz data next time. bufLen=%{public}u", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        ret = TransTdcProcessTlvData(channel, &pktHead, newPktHeadSize);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "data received failed");
    }
}

static int32_t TransTdcProcAllData(int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_tcpDataList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is NULL");
    while (1) {
        SoftBusMutexLock(&g_tcpDataList->lock);
        ClientDataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "can not find data buf node. channelId=%{public}d", channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        uint32_t bufLen = node->w - node->data;
        if (bufLen == 0) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_OK;
        }
        if (bufLen < DC_DATA_HEAD_SIZE) {
            TRANS_LOGW(TRANS_SDK,
                "head bufLen not enough, recv biz head next time. channelId=%{public}d, bufLen=%{public}u",
                channelId, bufLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
        UnpackTcpDataPacketHead(pktHead);
        if (pktHead->magicNumber != MAGIC_NUMBER) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_INVALID_DATA_HEAD;
        }
        if ((pktHead->dataLen > g_dataBufferMaxLen - DC_DATA_HEAD_SIZE) || (pktHead->dataLen <= OVERHEAD_LEN)) {
            TRANS_LOGE(TRANS_SDK, "illegal dataLen=%{public}u", pktHead->dataLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        uint32_t pkgLen = pktHead->dataLen + DC_DATA_HEAD_SIZE;

        if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
            int32_t ret = TransResizeDataBuffer(node, pkgLen);
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            return ret;
        }
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);

        if (bufLen < pkgLen) {
            TRANS_LOGE(TRANS_SDK, "data bufLen not enough, recv biz data next time. bufLen=%{public}u", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        int32_t ret = TransTdcProcessData(channelId);
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
    ClientDataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_tcpDataList->list), ClientDataBuf, node) {
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

    ClientDataBuf *item = NULL;
    ClientDataBuf *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &(g_tcpDataList->list), ClientDataBuf, node) {
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
    int32_t fd = -1;
    size_t len = 0;
    int32_t ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get Tdc data buf by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return ret;
    }
    if (len == 0 || len > g_dataBufferMaxLen) {
        TRANS_LOGE(TRANS_SDK,
            "client tdc  free databuf len invalid. channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "client tdc calloc failed. channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_MALLOC_ERR;
    }

    int32_t recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (recvLen < 0) {
        SoftBusFree(recvBuf);
        int32_t socketErrCode = GetErrCodeBySocketErr(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);
        TRANS_LOGE(TRANS_SDK, "client recv data failed, channelId=%{public}d, recvLen=%{public}d, errcode=%{public}d.",
            channelId, recvLen, socketErrCode);
        return socketErrCode;
    } else if (recvLen == 0) {
        SoftBusFree(recvBuf);
        return SOFTBUS_DATA_NOT_ENOUGH;
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
    int32_t ret = TransGetDataBufMaxSize();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "TransGetDataBufMaxSize failed");

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
