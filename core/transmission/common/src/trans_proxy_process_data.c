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

#include "trans_proxy_process_data.h"

#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_assemble_tlv.h"
#include "trans_log.h"

#define SLICE_LEN (4 * 1024)
#define SHORT_SLICE_LEN (1024)
#define PROXY_TLV_ELEMENT 5
#define TLV_TYPE_AND_LENGTH 2
#define PROXY_TLV_PKT_HEAD 32
#define MAGICNUM_SIZE sizeof(uint32_t)
#define TLVCOUNT_SIZE sizeof(uint8_t)
static uint32_t g_proxyMaxByteBufSize = 0;
static uint32_t g_proxyMaxMessageBufSize = 0;
static uint32_t g_proxyMaxD2dVoiceBufSize = 0;
static uint32_t g_proxyMaxD2dMessageBufSize = 0;

void TransGetProxyDataBufMaxSize(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, (unsigned char *)&g_proxyMaxByteBufSize,
                         sizeof(g_proxyMaxByteBufSize)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "get proxy channel max bytes length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH, (unsigned char *)&g_proxyMaxMessageBufSize,
                         sizeof(g_proxyMaxMessageBufSize)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "get proxy channel max message length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_D2D_MAX_VOICE_LENGTH, (unsigned char *)&g_proxyMaxD2dVoiceBufSize,
                         sizeof(g_proxyMaxD2dVoiceBufSize)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "get proxy channel max d2d voice length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_D2D_MAX_MESSAGE_LENGTH, (unsigned char *)&g_proxyMaxD2dMessageBufSize,
                         sizeof(g_proxyMaxD2dMessageBufSize)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "get proxy channel max d2d message length fail");
    }
    TRANS_LOGI(TRANS_INIT, "proxy auth byteSize=%{public}u, mesageSize=%{public}u",
        g_proxyMaxByteBufSize, g_proxyMaxMessageBufSize);
}

void TransUnPackTlvPackHead(DataHeadTlvPacketHead *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid data");
        return;
    }
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->dataSeq = SoftBusLtoHl(data->dataSeq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

static void TransPackSliceHead(SliceHead *data)
{
    data->priority = (int32_t)SoftBusHtoLl((uint32_t)data->priority);
    data->sliceNum = (int32_t)SoftBusHtoLl((uint32_t)data->sliceNum);
    data->sliceSeq = (int32_t)SoftBusHtoLl((uint32_t)data->sliceSeq);
    data->reserved = (int32_t)SoftBusHtoLl((uint32_t)data->reserved);
}

void TransUnPackSliceHead(SliceHead *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid data");
        return;
    }
    data->priority = (int32_t)SoftBusLtoHl((uint32_t)data->priority);
    data->sliceNum = (int32_t)SoftBusLtoHl((uint32_t)data->sliceNum);
    data->sliceSeq = (int32_t)SoftBusLtoHl((uint32_t)data->sliceSeq);
    data->reserved = (int32_t)SoftBusLtoHl((uint32_t)data->reserved);
}

static void TransPackPacketHead(PacketHead *data)
{
    data->magicNumber = (int32_t)SoftBusHtoLl((uint32_t)data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = (int32_t)SoftBusHtoLl((uint32_t)data->flags);
    data->dataLen = (int32_t)SoftBusHtoLl((uint32_t)data->dataLen);
}

static void TransUnPackPacketHead(PacketHead *data)
{
    data->magicNumber = (int32_t)SoftBusLtoHl((uint32_t)data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = (int32_t)SoftBusLtoHl((uint32_t)data->flags);
    data->dataLen = (int32_t)SoftBusLtoHl((uint32_t)data->dataLen);
}

int32_t TransProxyPackBytes(
    int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq)
{
    if (dataInfo == NULL || sessionKey == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketHead);
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc failed");
        return SOFTBUS_MEM_ERR;
    }

    uint32_t outLen = 0;
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key failed");
        SoftBusFree(dataInfo->outData);
        return SOFTBUS_MEM_ERR;
    }
    char *outData = (char *)dataInfo->outData + sizeof(PacketHead);
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    outData = NULL;
    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen + OVERHEAD_LEN) {
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "encrypt error, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    PacketHead *pktHead = (PacketHead *)dataInfo->outData;
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->seq = seq;
    pktHead->flags = flag;
    pktHead->dataLen = (int32_t)((int32_t)dataInfo->outLen - sizeof(PacketHead));
    TransPackPacketHead(pktHead);
    return SOFTBUS_OK;
}

static uint8_t *TransProxyPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(pktHead != NULL, NULL, TRANS_CTRL, "invalid param");
    uint32_t newDataHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    int32_t bufLen = (int32_t)dataLen + newDataHeadSize;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(bufLen);
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
        TRANS_LOGE(TRANS_CTRL, "memcpy tlvCound failed");
        return NULL;
    }
    uint8_t *temp = buf + MAGICNUM_SIZE + TLVCOUNT_SIZE;
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

static int32_t ProxyBuildTlvDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flag,
    uint32_t dataLen, int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    pktHead->tlvElement = (uint8_t *)SoftBusCalloc(PROXY_TLV_ELEMENT * sizeof(TlvElement));
    if (pktHead->tlvElement == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc tlvElement failed");
        return SOFTBUS_MALLOC_ERR;
    }
    pktHead->magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    uint32_t seq = SoftBusHtoLl((uint32_t)finalSeq);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_INNER_SEQ, (uint8_t *)&seq, sizeof(seq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "assemble seq tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        pktHead->tlvElement = NULL;
        return ret;
    }
    uint32_t flags = SoftBusHtoLl((uint32_t)flag);
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_FLAG, (uint8_t *)&flags, sizeof(flags), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "assemble flag tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        pktHead->tlvElement = NULL;
        return ret;
    }
    uint32_t dataLens = SoftBusHtoLl(dataLen);
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_LEN, (uint8_t *)&dataLens, sizeof(dataLens), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "assemble dataLen tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        pktHead->tlvElement = NULL;
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ProxyBuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t dataSeq = SoftBusHtoLl(dataSeqs);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_NEED_ACK, (uint8_t *)&needAck, sizeof(needAck), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "assemble needAck tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        pktHead->tlvElement = NULL;
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_SEQ, (uint8_t *)&dataSeq, sizeof(dataSeq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "assemble dataSeq tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        pktHead->tlvElement = NULL;
        return ret;
    }
    pktHead->tlvElement -= (PROXY_TLV_ELEMENT * sizeof(TlvElement));
    return SOFTBUS_OK;
}

int32_t TransProxyPackTlvBytes(
    ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info)
{
    if (dataInfo == NULL || sessionKey == NULL || info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t dataLen = dataInfo->inLen + OVERHEAD_LEN;
    DataHead pktHead = { 0 };
    int32_t tlvBufferSize = 0;
    int32_t ret = ProxyBuildTlvDataHead(&pktHead, seq, flag, dataLen, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "build tlv dataHead fail");
    ret = ProxyBuildNeedAckTlvData(&pktHead, info->needAck, info->dataSeq, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "build tlv needAck fail");
    dataInfo->outData = TransProxyPackTlvData(&pktHead, tlvBufferSize, dataLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pack tlv data failed");
        ReleaseTlvValueBuffer(&pktHead);
        SoftBusFree(pktHead.tlvElement);
        return ret;
    }
    ReleaseTlvValueBuffer(&pktHead);
    SoftBusFree(pktHead.tlvElement);
    int32_t newDataHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + (uint32_t)newDataHeadSize;

    uint32_t outLen = 0;
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key failed");
        SoftBusFree(dataInfo->outData);
        return SOFTBUS_MEM_ERR;
    }
    char *outData = (char *)dataInfo->outData + newDataHeadSize;
    ret = SoftBusEncryptDataWithSeq(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    outData = NULL;
    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "encrypt failed, ret=%{public}d", ret);
        SoftBusFree(dataInfo->outData);
        dataInfo->outData = NULL;
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SessionPktTypeToProxyIndex(SessionPktType packetType)
{
    switch (packetType) {
        case TRANS_SESSION_MESSAGE:
        case TRANS_SESSION_ASYNC_MESSAGE:
        case TRANS_SESSION_ACK:
            return PROXY_CHANNEL_PRIORITY_MESSAGE;
        case TRANS_SESSION_BYTES:
            return PROXY_CHANNEL_PRIORITY_BYTES;
        default:
            return PROXY_CHANNEL_PRIORITY_FILE;
    }
}

uint8_t *TransProxyPackData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen)
{
    if (dataLen == NULL || dataInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return NULL;
    }
    *dataLen = (cnt == (sliceNum - 1)) ? (dataInfo->outLen - cnt * SLICE_LEN) : SLICE_LEN;
    int32_t offset = (int32_t)(cnt * SLICE_LEN);

    uint8_t *sliceData = (uint8_t *)SoftBusCalloc(*dataLen + sizeof(SliceHead));
    if (sliceData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc sliceData failed");
        return NULL;
    }
    SliceHead *slicehead = (SliceHead *)sliceData;
    slicehead->priority = SessionPktTypeToProxyIndex(pktType);
    slicehead->sliceNum = (int32_t)sliceNum;
    slicehead->sliceSeq = (int32_t)cnt;
    TransPackSliceHead(slicehead);
    if (memcpy_s(sliceData + sizeof(SliceHead), *dataLen, dataInfo->outData + offset, *dataLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy failed");
        SoftBusFree(sliceData);
        return NULL;
    }
    return sliceData;
}

int32_t TransProxyCheckSliceHead(const SliceHead *head)
{
    if (head == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (head->priority < 0 || head->priority >= PROXY_CHANNEL_PRIORITY_BUTT) {
        TRANS_LOGE(TRANS_CTRL, "invalid index=%{public}d", head->priority);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if (head->sliceNum != 1 && head->sliceSeq >= head->sliceNum) {
        TRANS_LOGE(TRANS_CTRL, "sliceNum=%{public}d, sliceSeq=%{public}d", head->sliceNum, head->sliceSeq);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyNoSubPacketProc(PacketHead *head, uint32_t len, const char *data, int32_t channelId)
{
    if (head == NULL || data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (len <= sizeof(PacketHead)) {
        TRANS_LOGE(TRANS_CTRL, "check len failed, len=%{public}d", len);
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(head, sizeof(PacketHead), data, sizeof(PacketHead)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy packetHead failed");
        return SOFTBUS_MEM_ERR;
    }
    TransUnPackPacketHead(head);
    if ((uint32_t)head->magicNumber != MAGIC_NUMBER) {
        TRANS_LOGE(TRANS_CTRL, "invalid magicNumber=%{public}x, channelId=%{public}d, len=%{public}d",
            head->magicNumber, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if (head->dataLen <= 0) {
        TRANS_LOGE(TRANS_CTRL, "invalid dataLen=%{public}d, channelId=%{public}d, len=%{public}d",
            head->dataLen, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    TRANS_LOGD(TRANS_CTRL, "NoSubPacketProc, dataLen=%{public}d, inputLen=%{public}d", head->dataLen, len);
    if (head->dataLen != (int32_t)(len - sizeof(PacketHead))) {
        TRANS_LOGE(TRANS_CTRL, "dataLen error channelId=%{public}d, len=%{public}d, dataLen=%{public}d",
            channelId, len, head->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyProcessSessionData(ProxyDataInfo *dataInfo, const PacketHead *dataHead, const char *data)
{
    if (dataInfo == NULL || data == NULL || dataHead == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataHead->dataLen <= OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "invalid data head dataLen=%{public}d", dataHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    uint32_t outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo->outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when process session out data");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo->inData = (unsigned char *)data;
    dataInfo->inLen = dataHead->dataLen;
    dataInfo->outLen = outLen;
    return SOFTBUS_OK;
}

void TransProxyClearProcessor(SliceProcessor *processor)
{
    if (processor == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return;
    }
    if (processor->data != NULL) {
        SoftBusFree(processor->data);
        processor->data = NULL;
    }
    processor->active = false;
    processor->bufLen = 0;
    processor->dataLen = 0;
    processor->expectedSeq = 0;
    processor->sliceNumber = 0;
    processor->timeout = 0;
}

int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey)
{
    if (dataInfo == NULL || sessionKey == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key failed");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusDecryptDataWithSeq(
        &cipherKey, dataInfo->inData, dataInfo->inLen, dataInfo->outData, &(dataInfo->outLen), seq);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "trans proxy Decrypt Data fail. ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type)
{
    switch (type) {
        case TRANS_SESSION_MESSAGE:
        case TRANS_SESSION_ASYNC_MESSAGE: {
            if (dataLen > g_proxyMaxMessageBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        case TRANS_SESSION_BYTES: {
            if (dataLen > g_proxyMaxByteBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        default: {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransProxyD2dDataLenCheck(uint32_t dataLen, BusinessType type)
{
    switch (type) {
        case BUSINESS_TYPE_D2D_VOICE: {
            if (dataLen > g_proxyMaxD2dVoiceBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        case BUSINESS_TYPE_D2D_MESSAGE: {
            if (dataLen > g_proxyMaxD2dMessageBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        default: {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransProxyFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, bool supportTlv)
{
    if (processor == NULL || head == NULL || data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxDataLen =
        (head->priority == PROXY_CHANNEL_PRIORITY_MESSAGE) ? g_proxyMaxMessageBufSize : g_proxyMaxByteBufSize;
    // The encrypted data length is longer then the actual data length
    maxDataLen += SLICE_LEN;

    if ((head->sliceNum < 0) || ((uint32_t)head->sliceNum > (maxDataLen / SLICE_LEN))) {
        TRANS_LOGE(TRANS_CTRL, "invalid sliceNum=%{public}d", head->sliceNum);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    uint32_t actualDataLen = head->sliceNum * SLICE_LEN;
    uint32_t maxLen = 0;
    if (supportTlv) {
        maxLen = actualDataLen + PROXY_TLV_PKT_HEAD + OVERHEAD_LEN;
    } else {
        maxLen = actualDataLen + sizeof(PacketHead) + OVERHEAD_LEN;
    }
    processor->data = (char *)SoftBusCalloc(maxLen);
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when proc first slice package");
        return SOFTBUS_MALLOC_ERR;
    }
    processor->bufLen = (int32_t)maxLen;
    if (memcpy_s(processor->data, maxLen, data, len) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail when proce first slice package");
        SoftBusFree(processor->data);
        processor->data = NULL;
        return SOFTBUS_MEM_ERR;
    }
    processor->sliceNumber = head->sliceNum;
    processor->expectedSeq = 1;
    processor->dataLen = (int32_t)len;
    processor->active = true;
    processor->timeout = 0;
    TRANS_LOGI(TRANS_CTRL, "FirstSliceProcess ok");
    return SOFTBUS_OK;
}

int32_t TransProxySliceProcessChkPkgIsValid(
    const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    if (processor == NULL || head == NULL || data == NULL || len <= 0) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (head->sliceNum != processor->sliceNumber || head->sliceSeq != processor->expectedSeq) {
        TRANS_LOGE(TRANS_CTRL, "unmatched normal slice received, head sliceNum=%{public}d, sliceSeq=%{public}d,\
            processor sliceNumber=%{public}d, expectedSeq=%{public}d", head->sliceNum, head->sliceSeq,
            processor->sliceNumber, processor->expectedSeq);
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID;
    }
    if (processor->dataLen > processor->bufLen || (int32_t)len > processor->bufLen - processor->dataLen) {
        TRANS_LOGE(TRANS_CTRL, "invalid data len, len=%{public}u, dataLen=%{public}d", len, processor->dataLen);
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH;
    }
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "data NULL");
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    return SOFTBUS_OK;
}

int32_t TransGetActualDataLen(const SliceHead *head, uint32_t *actualDataLen)
{
    if (head == NULL || actualDataLen == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxDataLen =
        (head->priority == PROXY_CHANNEL_PRIORITY_MESSAGE) ? g_proxyMaxMessageBufSize : g_proxyMaxByteBufSize;
    // The encrypted data length is longer than actual data length
    maxDataLen += SLICE_LEN;

    if ((head->sliceNum < 0) || ((uint32_t)head->sliceNum > (maxDataLen / SLICE_LEN))) {
        TRANS_LOGE(TRANS_CTRL, "invalid sliceNum=%{public}d", head->sliceNum);
        return SOFTBUS_INVALID_DATA_HEAD;
    }

    *actualDataLen = head->sliceNum * SLICE_LEN;
    return SOFTBUS_OK;
}

int32_t TransProxyNormalSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    if (processor == NULL || head == NULL || data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen,
        (uint32_t)(processor->bufLen - processor->dataLen), data, len) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail when proc normal slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += (int32_t)len;
    processor->timeout = 0;
    TRANS_LOGI(TRANS_CTRL, "NormalSliceProcess ok");
    return SOFTBUS_OK;
}

static int32_t CheckLenAndCopyData(const char *data, uint32_t len, DataHeadTlvPacketHead *head, uint32_t headSize)
{
    if (len <= headSize) {
        TRANS_LOGE(TRANS_CTRL, "data len not enough, bufLen Less than headSize. len=%{public}u", len);
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

int32_t TransProxyParseTlv(uint32_t len, const char *data, DataHeadTlvPacketHead *head, uint32_t *headSize)
{
    if (data == NULL || head == NULL || headSize == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    *headSize += (MAGICNUM_SIZE + TLVCOUNT_SIZE);
    int32_t res = CheckLenAndCopyData(data, len, head, *headSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(res == SOFTBUS_OK, res, TRANS_CTRL, "checkLenAndCopyData failed");
    errno_t ret = EOK;
    char *temp = (char *)data + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (uint8_t index = 0; index < head->tlvCount; index++) {
        uint8_t *type = (uint8_t *)temp;
        if (len < (*headSize + (TLV_TYPE_AND_LENGTH * sizeof(uint8_t)))) {
            TRANS_LOGE(TRANS_CTRL, "check len contains tlv segment data fail, len=%{public}u", len);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        uint8_t *length = (uint8_t *)(temp + sizeof(uint8_t));
        if (len < (*headSize + (TLV_TYPE_AND_LENGTH * sizeof(uint8_t)) + *length)) {
            TRANS_LOGE(TRANS_CTRL, "data len not enough. len=%{public}u", len);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
        temp += (TLV_TYPE_AND_LENGTH * sizeof(uint8_t));
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
            "parse tlv memcpy failed, tlvType=%{public}d, ret=%{public}d", *type, ret);
    }
    return SOFTBUS_OK;
}

int32_t TransProxyNoSubPacketTlvProc(
    int32_t channelId, uint32_t len, DataHeadTlvPacketHead *pktHead, uint32_t newPktHeadSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    TransUnPackTlvPackHead(pktHead);
    TRANS_LOGD(TRANS_CTRL, "proxy channel parse tlv newPktHeadSize=%{public}d", newPktHeadSize);

    if (pktHead->magicNumber != MAGIC_NUMBER) {
        TRANS_LOGE(TRANS_CTRL, "invalid magicNumber=%{public}x, channelId=%{public}d, len=%{public}u",
            pktHead->magicNumber, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if (pktHead->dataLen == 0) {
        TRANS_LOGE(TRANS_CTRL, "invalid dataLen=%{public}u, channelId=%{public}d, len=%{public}u",
            pktHead->dataLen, channelId, len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    TRANS_LOGD(TRANS_CTRL, "NoSubPacketProc dataLen=%{public}u, inputLen=%{public}u", pktHead->dataLen, len);
    if (len <= newPktHeadSize || (pktHead->dataLen != (len - newPktHeadSize))) {
        TRANS_LOGE(TRANS_CTRL, "dataLen error, channelId=%{public}d, len=%{public}u, dataLen=%{public}u",
            channelId, len, pktHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyProcData(ProxyDataInfo *dataInfo, const DataHeadTlvPacketHead *dataHead, const char *data)
{
    uint32_t outLen = 0;

    if (dataHead->dataLen <= OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_CTRL, "invalid data head dataLen=%{public}d", dataHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo->outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when process session out data.");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo->inData = (unsigned char *)data;
    dataInfo->inLen = dataHead->dataLen;
    dataInfo->outLen = outLen;
    return SOFTBUS_OK;
}

uint8_t *TransProxyPackNewHeadD2DData(
    ProxyDataInfo *dataInfo, uint16_t sliceNum, SessionPktType pktType, uint16_t cnt, uint16_t *dataLen)
{
    if (dataLen == NULL || dataInfo == NULL || sliceNum == 0) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return NULL;
    }
    *dataLen = (cnt == (sliceNum - 1)) ? (dataInfo->outLen - cnt * SHORT_SLICE_LEN) : SHORT_SLICE_LEN;
    int32_t offset = (int32_t)(cnt * SHORT_SLICE_LEN);

    uint8_t *sliceData = (uint8_t *)SoftBusCalloc(*dataLen + sizeof(D2dSliceHead));
    if (sliceData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc sliceData failed");
        return NULL;
    }
    D2dSliceHead *slicehead = (D2dSliceHead *)sliceData;
    slicehead->sliceNum = SoftBusHtoLs(sliceNum);
    slicehead->sliceSeq = SoftBusHtoLs(cnt);
    if (memcpy_s(sliceData + sizeof(D2dSliceHead), *dataLen, dataInfo->outData + offset, *dataLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy failed");
        SoftBusFree(sliceData);
        return NULL;
    }
    return sliceData;
}

uint8_t *TransProxyPackD2DData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen)
{
    if (dataLen == NULL || dataInfo == NULL || sliceNum == 0) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return NULL;
    }
    *dataLen = (cnt == (sliceNum - 1)) ? (dataInfo->outLen - cnt * SHORT_SLICE_LEN) : SHORT_SLICE_LEN;
    int32_t offset = (int32_t)(cnt * SHORT_SLICE_LEN);

    uint8_t *sliceData = (uint8_t *)SoftBusCalloc(*dataLen + sizeof(SliceHead));
    if (sliceData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc sliceData failed");
        return NULL;
    }
    SliceHead *slicehead = (SliceHead *)sliceData;
    slicehead->priority = SessionPktTypeToProxyIndex(pktType);
    slicehead->sliceNum = (int32_t)sliceNum;
    slicehead->sliceSeq = (int32_t)cnt;
    TransPackSliceHead(slicehead);
    if (memcpy_s(sliceData + sizeof(SliceHead), *dataLen, dataInfo->outData + offset, *dataLen) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy failed");
        SoftBusFree(sliceData);
        return NULL;
    }
    return sliceData;
}

int32_t TransProxyProcessD2DData(
    ProxyDataInfo *dataInfo, const PacketD2DHead *dataHead, const char *data, int32_t businessType)
{
    if (dataInfo == NULL || data == NULL || dataHead == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t outLen = 0;
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        if (dataHead->dataLen <= SHORT_TAG_LEN) {
            TRANS_LOGE(TRANS_CTRL, "invalid data head dataLen=%{public}d", dataHead->dataLen);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        outLen = dataHead->dataLen - SHORT_TAG_LEN;
    } else {
        if (dataHead->dataLen <= 0) {
            TRANS_LOGE(TRANS_CTRL, "invalid data head dataLen=%{public}d", dataHead->dataLen);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        outLen = dataHead->dataLen;
    }
    dataInfo->outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when process session out data");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo->inData = (unsigned char *)data;
    dataInfo->inLen = dataHead->dataLen;
    dataInfo->outLen = outLen;
    return SOFTBUS_OK;
}

int32_t TransProxyDecryptD2DData(
    int32_t businessType, ProxyDataInfo *dataInfo, const char *sessionKey, const unsigned char *sessionCommonIv)
{
    if (dataInfo == NULL || sessionKey == NULL || sessionCommonIv == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        AesGcm128CipherKey cipherKey = { 0 };
        cipherKey.keyLen = SHORT_SESSION_KEY_LENGTH;
        if (memcpy_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, sessionKey, SHORT_SESSION_KEY_LENGTH) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy key fail");
            return SOFTBUS_MEM_ERR;
        }
        if (memcpy_s(cipherKey.iv, GCM_IV_LEN, sessionCommonIv, GCM_IV_LEN) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy iv fail");
            (void)memset_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, 0, SHORT_SESSION_KEY_LENGTH);
            return SOFTBUS_MEM_ERR;
        }
        int32_t ret = SoftBusDecryptDataByGcm128(
            &cipherKey, dataInfo->inData, dataInfo->inLen, dataInfo->outData, &(dataInfo->outLen));
        (void)memset_s(&cipherKey, sizeof(AesGcm128CipherKey), 0, sizeof(AesGcm128CipherKey));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "decrypt d2d message fail");
            return ret;
        }
        return SOFTBUS_OK;
    }
    AesCtrCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SHORT_SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, sessionKey, SHORT_SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(cipherKey.iv, SHORT_SESSION_KEY_LENGTH, sessionCommonIv, GCM_IV_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy iv fail");
        (void)memset_s(cipherKey.key, SHORT_SESSION_KEY_LENGTH, 0, SHORT_SESSION_KEY_LENGTH);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret =
        SoftBusDecryptDataByCtr(&cipherKey, dataInfo->inData, dataInfo->inLen, dataInfo->outData, &(dataInfo->outLen));
    (void)memset_s(&cipherKey, sizeof(AesCtrCipherKey), 0, sizeof(AesCtrCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decrypt d2d message fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyD2DFirstNewHeadSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t businessType)
{
    if (processor == NULL || head == NULL || data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t actualDataLen = 0;
    uint32_t maxDataLen =
        (head->priority == PROXY_CHANNEL_PRIORITY_MESSAGE) ? g_proxyMaxD2dMessageBufSize : g_proxyMaxD2dVoiceBufSize;
    // The encrypted data length is longer then the actual data length
    maxDataLen += SHORT_SLICE_LEN;

    if ((head->sliceNum < 0) || ((uint32_t)head->sliceNum > (maxDataLen / SHORT_SLICE_LEN))) {
        TRANS_LOGE(TRANS_CTRL, "invalid sliceNum=%{public}d", head->sliceNum);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    actualDataLen = head->sliceNum * SHORT_SLICE_LEN;
    uint32_t maxLen = 0;
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        maxLen = actualDataLen + sizeof(PacketD2DNewHead) + SHORT_TAG_LEN;
    } else {
        maxLen = actualDataLen + sizeof(PacketD2DNewHead);
    }
    processor->data = (char *)SoftBusCalloc(maxLen);
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when proc first slice package");
        return SOFTBUS_MALLOC_ERR;
    }
    processor->bufLen = (int32_t)maxLen;
    if (memcpy_s(processor->data, maxLen, data, len) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail when proce first slice package");
        SoftBusFree(processor->data);
        processor->data = NULL;
        return SOFTBUS_MEM_ERR;
    }
    processor->sliceNumber = head->sliceNum;
    processor->expectedSeq = 1;
    processor->dataLen = (int32_t)len;
    processor->active = true;
    processor->timeout = 0;
    TRANS_LOGI(TRANS_CTRL, "TransProxyD2DFirstNewHeadSliceProcess ok");
    return SOFTBUS_OK;
}

int32_t TransProxyD2DFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t businessType)
{
    if (processor == NULL || head == NULL || data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t actualDataLen = 0;
    uint32_t maxDataLen =
        (head->priority == PROXY_CHANNEL_PRIORITY_MESSAGE) ? g_proxyMaxMessageBufSize : g_proxyMaxByteBufSize;
    // The encrypted data length is longer then the actual data length
    maxDataLen += SHORT_SLICE_LEN;

    if ((head->sliceNum < 0) || ((uint32_t)head->sliceNum > (maxDataLen / SHORT_SLICE_LEN))) {
        TRANS_LOGE(TRANS_CTRL, "invalid sliceNum=%{public}d", head->sliceNum);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    actualDataLen = head->sliceNum * SHORT_SLICE_LEN;
    uint32_t maxLen = 0;
    if (businessType == BUSINESS_TYPE_D2D_MESSAGE) {
        maxLen = actualDataLen + sizeof(PacketD2DHead) + SHORT_TAG_LEN;
    } else {
        maxLen = actualDataLen + sizeof(PacketD2DHead);
    }
    processor->data = (char *)SoftBusCalloc(maxLen);
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail when proc first slice package");
        return SOFTBUS_MALLOC_ERR;
    }
    processor->bufLen = (int32_t)maxLen;
    if (memcpy_s(processor->data, maxLen, data, len) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail when proce first slice package");
        SoftBusFree(processor->data);
        processor->data = NULL;
        return SOFTBUS_MEM_ERR;
    }
    processor->sliceNumber = head->sliceNum;
    processor->expectedSeq = 1;
    processor->dataLen = (int32_t)len;
    processor->active = true;
    processor->timeout = 0;
    TRANS_LOGI(TRANS_CTRL, "FirstSliceProcess ok");
    return SOFTBUS_OK;
}

int32_t TransGenerateToBytesRandIv(unsigned char *sessionIv, const uint32_t *nonce)
{
    if (sessionIv == NULL || nonce == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t shortIv[SHORT_SESSION_IV_LENGTH];
    if (memcpy_s(shortIv, SHORT_SESSION_IV_LENGTH, nonce, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpys_s nonce failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusCalcHKDF(shortIv, SHORT_SESSION_IV_LENGTH, sessionIv, GCM_IV_LEN) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "calc HKDF failed.");
        return SOFTBUS_CALC_HKDF_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t TransPackNewHeadD2DToBytesExtraData(ProxyDataInfo *dataInfo, SessionPktType flag, uint32_t nonce)
{
    if (dataInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(dataInfo->outData + sizeof(PacketD2DNewHead), NONCE_LEN, &nonce, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy nonce failed.");
        return SOFTBUS_MEM_ERR;
    }
    PacketD2DNewHead *pktHead = (PacketD2DNewHead *)dataInfo->outData;
    pktHead->flags = SoftBusHtoLss(flag);
    pktHead->dataLen = SoftBusHtoLs((uint16_t)((uint16_t)dataInfo->outLen - sizeof(PacketD2DNewHead)- NONCE_LEN));
    return SOFTBUS_OK;
}

static int32_t TransPackD2DToBytesExtraData(ProxyDataInfo *dataInfo, SessionPktType flag, uint32_t nonce)
{
    if (dataInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(dataInfo->outData + sizeof(PacketD2DHead), NONCE_LEN, &nonce, NONCE_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy nonce failed.");
        return SOFTBUS_MEM_ERR;
    }
    PacketD2DHead *pktHead = (PacketD2DHead *)dataInfo->outData;
    pktHead->flags = flag;
    pktHead->dataLen = (int32_t)((int32_t)dataInfo->outLen - sizeof(PacketD2DHead)- NONCE_LEN);
    pktHead->flags = (int32_t)SoftBusHtoLl((uint32_t)pktHead->flags);
    pktHead->dataLen = (int32_t)SoftBusHtoLl((uint32_t)pktHead->dataLen);
    return SOFTBUS_OK;
}

static int32_t TransProxyGenerateIv(const char *sessionKey, uint32_t *nonce, AesCtrCipherKey *cipherKey)
{
    if (sessionKey == NULL || nonce == NULL || cipherKey == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusGenerateRandomArray((unsigned char *)nonce, sizeof(uint32_t)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate nonce failed.");
        return SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL;
    }
    cipherKey->keyLen = SHORT_SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey->key, SHORT_SESSION_KEY_LENGTH, sessionKey, SHORT_SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy key failed");
        return SOFTBUS_MEM_ERR;
    }
    if (TransGenerateToBytesRandIv(cipherKey->iv, nonce) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate iv failed");
        (void)memset_s(cipherKey, sizeof(AesCtrCipherKey), 0, sizeof(AesCtrCipherKey));
        return SOFTBUS_GCM_SET_IV_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyPackD2DBytes(ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, bool isNewHead)
{
    if (dataInfo == NULL || sessionKey == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t nonce = 0;
    AesCtrCipherKey cipherKey = { 0 };
    int32_t ret = TransProxyGenerateIv(sessionKey, &nonce, &cipherKey);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    size_t headSize = isNewHead ? sizeof(PacketD2DNewHead) : sizeof(PacketD2DHead);
    dataInfo->outLen = dataInfo->inLen + NONCE_LEN + headSize;
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc failed");
        (void)memset_s(&cipherKey, sizeof(AesCtrCipherKey), 0, sizeof(AesCtrCipherKey));
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t outLen = 0;
    char *outData = (char *)dataInfo->outData + NONCE_LEN + headSize;
    ret = SoftBusEncryptDataByCtr(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen);
    (void)memset_s(&cipherKey, sizeof(AesCtrCipherKey), 0, sizeof(AesCtrCipherKey));

    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen) {
        outData = NULL;
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "encrypt error, outlen=%{public}d, inlen=%{public}d", outLen, dataInfo->inLen);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    if (isNewHead) {
        ret = TransPackNewHeadD2DToBytesExtraData(dataInfo, flag, nonce);
    } else {
        ret = TransPackD2DToBytesExtraData(dataInfo, flag, nonce);
    }
    if (ret != SOFTBUS_OK) {
        outData = NULL;
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_CTRL, "pack extra error, ret=%{public}d", ret);
    }
    return ret;
}
