/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "trans_tcp_process_data.h"

#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define TDC_TLV_ELEMENT 5
#define TLV_TYPE_AND_LENGTH 2
#define SLICE_HEAD_LEN 16
#define DATA_EXTEND_LEN (DC_DATA_HEAD_SIZE + OVERHEAD_LEN)
#define MIN_BUF_LEN (1024 + DATA_EXTEND_LEN)
#define MAGICNUM_SIZE sizeof(uint32_t)
#define TLVCOUNT_SIZE sizeof(uint8_t)
static uint32_t g_dataBufferMaxLen = 0;

uint32_t TransGetDataBufSize(void)
{
    return MIN_BUF_LEN;
}

int32_t TransGetTdcDataBufMaxSize(void)
{
    uint32_t maxLen = 0;
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen));
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get config err");
    g_dataBufferMaxLen = maxLen + DATA_EXTEND_LEN + SLICE_HEAD_LEN;
    return SOFTBUS_OK;
}

static void UnPackTcpDataPacketHead(TcpDataPacketHead *data)
{
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

static void TransTcpDataTlvUnpack(TcpDataTlvPacketHead *data)
{
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
    data->dataSeq = SoftBusLtoHl(data->dataSeq);
}

static int32_t TransResizeDataBuffer(DataBuf *oldBuf, uint32_t pkgLen)
{
    TRANS_LOGI(TRANS_CTRL, "Resize Data Buffer channelId=%{public}d, pkgLen=%{public}d",
        oldBuf->channelId, pkgLen);
    char *newBuf = (char *)SoftBusCalloc(pkgLen);
    if (newBuf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc err pkgLen=%{public}u", pkgLen);
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
    TRANS_LOGI(TRANS_CTRL, "TransResizeDataBuffer ok");
    return SOFTBUS_OK;
}

int32_t MoveNode(int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize)
{
    if (node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    char *end = node->data + pkgHeadSize + dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memmove fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - pkgHeadSize - dataLen;
    return SOFTBUS_OK;
}

int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    if (sessionKey == NULL || in == NULL || out == NULL || outLen == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusDecryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "dectypt data fail ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcRecvFirstData(int32_t channelId, char *recvBuf, int32_t *recvLen, int32_t fd, size_t len)
{
    if (recvBuf == NULL || recvLen == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len == 0 || len > g_dataBufferMaxLen) {
        TRANS_LOGE(TRANS_CTRL,
            "client tdc free databuf len invalid, channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (*recvLen < 0) {
        int32_t socketErrCode = GetErrCodeBySocketErr(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);
        TRANS_LOGE(TRANS_CTRL, "client recv data failed, channelId=%{public}d, recvlen=%{public}d, errCode=%{public}d",
            channelId, *recvLen, socketErrCode);
        return socketErrCode;
    } else if (*recvLen == 0) {
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcRecvMtpMsg(int32_t channelId, int32_t fd, SoftBusMsgHdr *msg, int32_t *recvLen)
{
    if (msg == NULL || msg->msg_iovlen <= 0 || msg->msg_iov == NULL || recvLen == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (msg->msg_iov->iov_len == 0 || msg->msg_iov->iov_len > g_dataBufferMaxLen) {
        TRANS_LOGE(TRANS_CTRL,
            "len invalid, channelId=%{public}d, len=%{public}zu", channelId, msg->msg_iov->iov_len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *recvLen = ConnRecvSocketMsg(fd, msg, 0, MSG_RX_TIMESTAMP);
    if (*recvLen < 0) {
        int32_t socketErrCode = GetErrCodeBySocketErr(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);
        TRANS_LOGE(TRANS_CTRL, "client recv data failed, channelId=%{public}d, recvlen=%{public}d, errCode=%{public}d",
            channelId, *recvLen, socketErrCode);
        return socketErrCode;
    } else if (*recvLen == 0) {
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcUnPackAllData(int32_t channelId, DataBuf *node, bool *flag)
{
    if (node == NULL || flag == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t bufLen = node->w - node->data;
    if (bufLen == 0) {
        *flag = true;
        return SOFTBUS_OK;
    }
    if (bufLen < DC_DATA_HEAD_SIZE) {
        TRANS_LOGW(TRANS_CTRL,"head bufLen not enough, recv biz head next time\
            channelId=%{public}d, bufLen=%{public}u", channelId, bufLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    UnPackTcpDataPacketHead(pktHead);
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if ((g_dataBufferMaxLen <= DC_DATA_HEAD_SIZE) || (pktHead->dataLen > g_dataBufferMaxLen - DC_DATA_HEAD_SIZE)
        || (pktHead->dataLen <= OVERHEAD_LEN)) {
        TRANS_LOGE(TRANS_CTRL, "illegal dataLen=%{public}u", pktHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t pkgLen = pktHead->dataLen + DC_DATA_HEAD_SIZE;
    if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
        int32_t ret = TransResizeDataBuffer(node, pkgLen);
        *flag = true;
        return ret;
    }
    if (bufLen < pkgLen) {
        TRANS_LOGE(TRANS_CTRL, "data bufLen not enough, recv data next time. bufLen=%{public}u", bufLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcUnPackData(int32_t channelId, const char *sessionKey, char *plain, uint32_t *plainLen, DataBuf *node)
{
    if (sessionKey == NULL || plain == NULL || plainLen == NULL || node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_CTRL, "data received, channelId=%{public}d, dataLen=%{public}u, sizeof=%{public}d, seq=%{public}d",
        channelId, dataLen, node->size, pktHead->seq);
    int32_t ret = TransTdcDecrypt(sessionKey, node->data + DC_DATA_HEAD_SIZE, dataLen, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "decrypt fail, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = MoveNode(channelId, node, dataLen, DC_DATA_HEAD_SIZE);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t CheckBufLenAndCopyData(uint32_t bufLen, uint32_t headSize, char *data, TcpDataTlvPacketHead *head)
{
    if (bufLen <= headSize) {
        TRANS_LOGE(TRANS_CTRL, "data bufLen not enough, bufLen Less than headSize. bufLen=%{public}u", bufLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    if (memcpy_s(&head->magicNumber, MAGICNUM_SIZE, data, MAGICNUM_SIZE) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy magicNumber failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&head->tlvCount, TLVCOUNT_SIZE, data + MAGICNUM_SIZE, TLVCOUNT_SIZE) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy tlvCount failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcParseTlv(uint32_t bufLen, char *data, TcpDataTlvPacketHead *head, uint32_t *headSize)
{
    if (data == NULL || head == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    errno_t ret = EOK;
    *headSize += MAGICNUM_SIZE + TLVCOUNT_SIZE;
    int32_t res = CheckBufLenAndCopyData(bufLen, *headSize, data, head);
    TRANS_CHECK_AND_RETURN_RET_LOGE(res == SOFTBUS_OK, res, TRANS_CTRL, "CheckBufLenAndCopyData failed");
    char *temp = data + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (int32_t index = 0; index < head->tlvCount; index++) {
        uint8_t *type = (uint8_t *)temp;
        if (bufLen < (*headSize + (TLV_TYPE_AND_LENGTH * sizeof(uint8_t)))) {
            TRANS_LOGE(TRANS_CTRL, "check bufLen contains tlv segment data fail, bufLen=%{public}u", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        uint8_t *length = (uint8_t *)(temp + sizeof(uint8_t));
        if (bufLen < (*headSize + (TLV_TYPE_AND_LENGTH * sizeof(uint8_t)) + *length)) {
            TRANS_LOGE(TRANS_CTRL, "data bufLen not enough. bufLen=%{public}u", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        temp += (TLV_TYPE_AND_LENGTH *sizeof(uint8_t));
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
                TRANS_LOGE(TRANS_CTRL, "unknown trans tdc tlv skip, tlvType=%{public}d", *type);
                temp += *length;
                continue;
        }
        temp += *length;
        *headSize += (TLV_TYPE_AND_LENGTH * sizeof(uint8_t) + *length);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL,
            "parse tlv memcpy failed, tlvType=%{public}d, ret%{public}d", *type, ret);
    }
    return SOFTBUS_OK;
}

int32_t TransTdcUnPackAllTlvData(
    int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag)
{
    if (node == NULL || flag == NULL || head == NULL || headSize == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t bufLen = node->w - node->data;
    if (bufLen == 0) {
        *flag = true;
        return SOFTBUS_OK;
    }
    int32_t ret = TransTdcParseTlv(bufLen, node->data, head, headSize);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    TransTcpDataTlvUnpack(head);
    if (bufLen < *headSize) {
        TRANS_LOGW(TRANS_CTRL, "head bufLen not enough, recv biz head next time\
            channelId=%{public}d, bufLen=%{public}u", channelId, bufLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    if (head->magicNumber != MAGIC_NUMBER) {
        TRANS_LOGE(TRANS_CTRL, "invalid data packet head. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if ((g_dataBufferMaxLen <= *headSize) || (head->dataLen > g_dataBufferMaxLen - *headSize)
        || (head->dataLen <= OVERHEAD_LEN)) {
        TRANS_LOGE(TRANS_CTRL, "illegal dataLen=%{public}u", head->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t pkgLen = head->dataLen + *headSize;
    if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
        ret = TransResizeDataBuffer(node, pkgLen);
        *flag = true;
        return ret;
    }
    if (bufLen < pkgLen) {
        TRANS_LOGE(TRANS_CTRL, "data bufLen not enough, recv data next time. bufLen=%{public}u", bufLen);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }
    return SOFTBUS_OK;
}

void ReleaseDataHeadResource(DataHead *pktHead)
{
    ReleaseTlvValueBuffer(pktHead);
    SoftBusFree(pktHead->tlvElement);
    pktHead->tlvElement = NULL;
}

char *TransTdcPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(pktHead != NULL, NULL, TRANS_CTRL, "invalid param");
    int32_t headSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    int32_t bufLen = (int32_t)dataLen + headSize;
    char *buf = (char *)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc buf failed");
        return NULL;
    }
    if (memcpy_s(buf, bufLen, &pktHead->magicNum, MAGICNUM_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "memcpy magicNum failed");
        return NULL;
    }
    if (memcpy_s(buf + MAGICNUM_SIZE, bufLen - MAGICNUM_SIZE, &pktHead->tlvCount, TLVCOUNT_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "memcpy tlvCount failed");
        return NULL;
    }

    char *temp = buf + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    int32_t tempLen = bufLen - MAGICNUM_SIZE - TLVCOUNT_SIZE;
    for (int32_t index = 0; index < pktHead->tlvCount; index++) {
        TlvElement *ement = (TlvElement *)pktHead->tlvElement;
        if (memcpy_s(temp, tempLen, &ement->type, sizeof(ement->type)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_CTRL, "memcpy tlvEment type failed");
            return NULL;
        }
        temp += sizeof(ement->type);
        if (memcpy_s(temp, tempLen - sizeof(ement->type), &ement->length, sizeof(ement->length)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_CTRL, "memcpy tlvEment length failed");
            return NULL;
        }
        temp += sizeof(ement->length);
        if (memcpy_s(temp, tempLen - sizeof(ement->type) - sizeof(ement->length), ement->value, ement->length)
            != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_CTRL, "memcpy tlvEment value failed");
            return NULL;
        }
        temp += ement->length;
        pktHead->tlvElement += sizeof(TlvElement);
    }
    return buf;
}

int32_t BuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize)
{
    if (pktHead == NULL || tlvBufferSize == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t dataSeq = SoftBusHtoLl(dataSeqs);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_NEED_ACK, (uint8_t *)&needAck, sizeof(needAck), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel assemble needAck tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_SEQ, (uint8_t *)&dataSeq, sizeof(dataSeq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel assemble dataSeq tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    pktHead->tlvElement -= (TDC_TLV_ELEMENT * sizeof(TlvElement));
    return SOFTBUS_OK;
}

int32_t BuildDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen,
    int32_t *tlvBufferSize)
{
    if (pktHead == NULL || tlvBufferSize == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    pktHead->tlvElement = (uint8_t *)SoftBusCalloc(TDC_TLV_ELEMENT * sizeof(TlvElement));
    if (pktHead->tlvElement == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc tlvElement failed");
        return SOFTBUS_MALLOC_ERR;
    }
    pktHead->magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    uint32_t seq = SoftBusHtoLl((uint32_t)finalSeq);
    uint32_t flag = SoftBusHtoLl((uint32_t)flags);
    uint32_t dataLens = SoftBusHtoLl(dataLen);

    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_INNER_SEQ, (uint8_t *)&seq, sizeof(seq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel assemble seq tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_FLAG, (uint8_t *)&flag, sizeof(flag), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel assemble flag tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_LEN, (uint8_t *)&dataLens, sizeof(dataLens), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "tcp channel assemble dataLen tlv failed, ret=%{public}d", ret);
        ReleaseDataHeadResource(pktHead);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, EncrptyInfo *info)
{
    if (info == NULL || sessionKey == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char *)info->in, info->inLen,
        (unsigned char *)info->out, info->outLen, seqNum);
    if (memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memset cipherKey failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (ret != SOFTBUS_OK || *info->outLen != info->inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "encrypt error, ret=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
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

static char *TransPackData(uint32_t dataLen, int32_t finalSeq, int32_t flags)
{
    TcpDataPacketHead pktHead = {
        .magicNumber = MAGIC_NUMBER,
        .seq = finalSeq,
        .flags = (uint32_t)flags,
        .dataLen = dataLen,
    };
    char *buf = (char *)SoftBusCalloc(dataLen + DC_DATA_HEAD_SIZE);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, NULL, TRANS_CTRL, "malloc failed");
    PackTcpDataPacketHead(&pktHead);
    if (memcpy_s(buf, DC_DATA_HEAD_SIZE, &pktHead, sizeof(TcpDataPacketHead)) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_CTRL, "memcpy_s error");
        return NULL;
    }
    return buf;
}

static void BuildInnerTdcSendDataInfo(EncrptyInfo *enInfo, char *finalData, uint32_t inLen, char *out, uint32_t *outLen)
{
    enInfo->in = finalData;
    enInfo->inLen = inLen;
    enInfo->out = out;
    enInfo->outLen = outLen;
}

char *TransTdcPackAllData(
    TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo)
{
    if (info == NULL || sessionKey == NULL || data == NULL || lenInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return NULL;
    }
    uint32_t dataLen = info->len + OVERHEAD_LEN;
    char *finalData = (char *)data;
    int32_t finalSeq = info->seq;
    uint32_t tmpSeq = 0;
    EncrptyInfo enInfo = { 0 };
    if (flags == FLAG_ACK) {
        finalSeq = *((int32_t *)data);
        tmpSeq = SoftBusHtoNl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }
    if (info->supportTlv) {
        DataHead pktHead = { 0 };
        int32_t tlvBufferSize = 0;
        int32_t ret = BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_CTRL, "build tlv dataHead failed");
        ret = BuildNeedAckTlvData(&pktHead, info->needAck, 0, &tlvBufferSize); // sync process dataSeq must be zero.
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_CTRL, "build tlv needack failed");
        char *buf = TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);
        if (buf == NULL) {
            ReleaseDataHeadResource(&pktHead);
            TRANS_LOGE(TRANS_CTRL, "pack tlv data fail");
            return NULL;
        }
        ReleaseDataHeadResource(&pktHead);
        lenInfo->tlvHeadLen = (uint32_t)(MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize);
        BuildInnerTdcSendDataInfo(&enInfo, finalData, info->len, buf + lenInfo->tlvHeadLen, &lenInfo->outLen);
        ret = TransTdcEncryptWithSeq(sessionKey, finalSeq, &enInfo);
        if (ret != SOFTBUS_OK) {
            SoftBusFree(buf);
            return NULL;
        }
        return buf;
    }
    char *buf = TransPackData(dataLen, finalSeq, flags);
    TRANS_CHECK_AND_RETURN_RET_LOGE(buf != NULL, NULL, TRANS_CTRL, "trans pack data failed");
    BuildInnerTdcSendDataInfo(&enInfo, finalData, info->len, buf + DC_DATA_HEAD_SIZE, &lenInfo->outLen);
    int32_t ret = TransTdcEncryptWithSeq(sessionKey, finalSeq, &enInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(buf);
        return NULL;
    }
    return buf;
}

int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf)
{
    if (lenInfo == NULL || buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t outLen = lenInfo->outLen;
    if (outLen != len + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t tmpHeadLen = DC_DATA_HEAD_SIZE;
    if (supportTlv) {
        TRANS_LOGD(TRANS_CTRL, "supportTlv is true");
        tmpHeadLen = lenInfo->tlvHeadLen;
    }
    ssize_t ret = ConnSendSocketData(fd, buf, outLen + tmpHeadLen, 0);
    if (ret != (ssize_t)outLen + (ssize_t)tmpHeadLen) {
        TRANS_LOGE(TRANS_CTRL, "send bytes failed to send tcp data. channelId=%{public}d, ret=%{public}zd", fd, ret);
        return GetErrCodeBySocketErr(SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT);
    }
    return SOFTBUS_OK;
}
