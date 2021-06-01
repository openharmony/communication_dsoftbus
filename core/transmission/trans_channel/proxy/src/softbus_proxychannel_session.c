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

#include "softbus_proxychannel_session.h"

#include <securec.h>

#include "softbus_crypto.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_transmission_interface.h"

typedef struct {
    unsigned char *inData;
    uint32_t inLen;
    unsigned char *outData;
    uint32_t outLen;
} ProxyDataInfo;

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} SliceHead;

typedef struct  {
    int32_t magicNumber;
    int32_t seq;
    int32_t flags;
    int32_t dataLen;
} PacketHead;

int32_t NotifyClientMsgReceived(const char *pkgName, int32_t channelId, const char *data, uint32_t len,
    SessionPktType type)
{
    int32_t ret = GetClientProvideInterface()->onChannelMsgReceived(pkgName, channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("notify err(%d)", ret);
    }
    return ret;
}

int32_t ProxyTypeToProxyIndex(ProxyPacketType packetType)
{
    switch (packetType) {
        case PROXY_FLAG_MESSAGE:
        case PROXY_FLAG_ASYNC_MESSAGE:
        case PROXY_FLAG_ACK:
             return PROXY_CHANNEL_PRORITY_MESSAGE;
        case PROXY_FLAG_BYTES:
            return PROXY_CHANNEL_PRORITY_BYTES;
        default:
            return PROXY_CHANNEL_PRORITY_BYTES;
    }
}

ProxyPacketType SessionTypeToPacketType(SessionPktType sessionType)
{
    switch (sessionType) {
        case TRANS_SESSION_BYTES:
            return PROXY_FLAG_BYTES;
        case TRANS_SESSION_MESSAGE:
            return PROXY_FLAG_ASYNC_MESSAGE;
        default:
            return PROXY_FLAG_BYTES;
    }
}

SendPriority ProxyTypeToConnPri(ProxyPacketType proxyType)
{
    switch (proxyType) {
        case PROXY_FLAG_BYTES:
            return CONN_MIDDLE;
        case PROXY_FLAG_ASYNC_MESSAGE:
        case PROXY_FLAG_ACK:
            return CONN_HIGH;
        default:
            return CONN_DEFAULT;
    }
}

int32_t TransProxyEncryptPacketData(int32_t channelId, int32_t seq, ProxyDataInfo *dataInfo)
{
    char sessionKey[SESSION_KEY_LENGTH] = {0};
    AesGcmCipherKey cipherKey = {0};
    uint32_t checkLen;

    if (TransProxyGetSessionKeyByChanId(channelId, sessionKey, sizeof(sessionKey)) != SOFTBUS_OK) {
        LOG_ERR("get channelId(%d) session key err", channelId);
        return SOFTBUS_ERR;
    }

    checkLen = dataInfo->inLen + OVERHEAD_LEN;
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        LOG_ERR("memcpy_s key error.");
        return SOFTBUS_ERR;
    }
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, dataInfo->inData, dataInfo->inLen,
        dataInfo->outData, &(dataInfo->outLen), seq);
    if (ret != SOFTBUS_OK || dataInfo->outLen != checkLen) {
        LOG_ERR("Trans Proxy encrypt error. %d ", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyDecryptPacketData(int32_t channelId, int32_t seq, ProxyDataInfo *dataInfo)
{
    char sessionKey[SESSION_KEY_LENGTH] = {0};
    AesGcmCipherKey cipherKey = {0};
    int ret;

    if (TransProxyGetSessionKeyByChanId(channelId, sessionKey, sizeof(sessionKey)) != SOFTBUS_OK) {
        LOG_ERR("DecryptPacket get chan fail channid %d.", channelId);
        return SOFTBUS_ERR;
    }
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        LOG_ERR("memcpy key error.");
        return SOFTBUS_ERR;
    }
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    ret = SoftBusDecryptDataWithSeq(&cipherKey, dataInfo->inData, dataInfo->inLen,
                                    dataInfo->outData, &(dataInfo->outLen), seq);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("trans proxy Decrypt Data fail. %d ", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyGetPktSeqId(int32_t channelId, ProxyDataInfo *dataInfo, ProxyPacketType flag)
{
    int32_t seq = 0;

    if (flag == PROXY_FLAG_ACK) {
        if (memcpy_s(&seq, sizeof(seq), dataInfo->inData, dataInfo->inLen) == EOK) {
            return seq;
        }
    }

    return TransProxyGetNewChanSeq(channelId);
}

int32_t TransProxyPackBytes(int32_t channelId, ProxyDataInfo *dataInfo, ProxyPacketType flag)
{
#define MAGIC_NUMBER 0xBABEFACE
    uint32_t outBufLen;
    uint8_t *outBuf = NULL;
    PacketHead *pktHead = NULL;
    SliceHead *sliceHead = NULL;
    ProxyDataInfo enDataInfo = {0};
    int32_t seq;

    outBufLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketHead) + sizeof(SliceHead);
    outBuf = SoftBusCalloc(outBufLen);
    if (outBuf == NULL) {
        LOG_ERR("calloc error");
        return SOFTBUS_MEM_ERR;
    }
    seq = TransProxyGetPktSeqId(channelId, dataInfo, flag);
    LOG_INFO("trans proxy send packet seq %d flag %d", seq, flag);
    enDataInfo.outData = outBuf + sizeof(PacketHead) + sizeof(SliceHead);
    enDataInfo.outLen = outBufLen - sizeof(PacketHead) - sizeof(SliceHead);
    enDataInfo.inData = dataInfo->inData;
    enDataInfo.inLen = dataInfo->inLen;
    if (TransProxyEncryptPacketData(channelId, seq, &enDataInfo) != SOFTBUS_OK) {
        SoftBusFree(outBuf);
        LOG_ERR("tran pack encrypt data fail. channid %d", channelId);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }

    sliceHead = (SliceHead*)(outBuf);
    sliceHead->priority = ProxyTypeToProxyIndex(flag);
    sliceHead->sliceNum = 1;
    sliceHead->sliceSeq = 0;

    pktHead = (PacketHead*)(sliceHead + 1);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->seq = seq;
    pktHead->flags = flag;
    pktHead->dataLen = enDataInfo.outLen;

    dataInfo->outData = outBuf;
    dataInfo->outLen = enDataInfo.outLen + sizeof(PacketHead) + sizeof(SliceHead);
    return SOFTBUS_OK;
}

int32_t TransProxyPostPacketData(int32_t channelId, const unsigned char *data, uint32_t len, ProxyPacketType flags)
{
    ProxyDataInfo packDataInfo = {0};
    int32_t ret;

    if (data == NULL) {
        LOG_ERR("invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    packDataInfo.inData = (unsigned char *)data;
    packDataInfo.inLen = len;
    ret = TransProxyPackBytes(channelId, &packDataInfo, flags);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("PackBytes err");
        return ret;
    }
    LOG_INFO("InLen = %u, outLen = %u flags %d", len, packDataInfo.outLen, flags);
    ret = TransProxySendMsg(channelId, (const char *)packDataInfo.outData, packDataInfo.outLen,
                            ProxyTypeToConnPri(flags));
    SoftBusFree(packDataInfo.outData);
    return ret;
}

int32_t TransProxyPostSessionData(int32_t channelId, const unsigned char *data, uint32_t len, SessionPktType flags)
{
    ProxyPacketType type;

    type = SessionTypeToPacketType(flags);
    return TransProxyPostPacketData(channelId, data, len, type);
}
static void TransProxySendSessionAck(int32_t channelId, int32_t seq)
{
#define PROXY_ACK_SIZE 4
    unsigned char ack[PROXY_ACK_SIZE];

    if (memcpy_s(ack, PROXY_ACK_SIZE, &seq, sizeof(int32_t)) != EOK) {
        LOG_ERR("memcpy seq err");
    }
    if (TransProxyPostPacketData(channelId, ack, PROXY_ACK_SIZE, PROXY_FLAG_ACK) != SOFTBUS_OK) {
        LOG_ERR("send ack err, seq = %d", seq);
    }
}

int32_t TransProxyNotifySession(const char *pkgName, int32_t channelId, ProxyPacketType flags, int32_t seq,
    const char *data, uint32_t len)
{
    switch (flags) {
        case PROXY_FLAG_BYTES:
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_BYTES);
        case PROXY_FLAG_MESSAGE:
            TransProxySendSessionAck(channelId, seq);
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_MESSAGE);
        case PROXY_FLAG_ASYNC_MESSAGE:
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_MESSAGE);
        default:
            LOG_ERR("invalid flags(%d)", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

int32_t TransProxySessionDataLenCheck(uint32_t dataLen, ProxyPacketType type)
{
    switch (type) {
        case PROXY_FLAG_MESSAGE:
        case PROXY_FLAG_ASYNC_MESSAGE: {
            if (dataLen > TRANS_MESSAGE_LENGTH_MAX) {
                return SOFTBUS_ERR;
            }
            break;
        }
        case PROXY_FLAG_BYTES: {
            if (dataLen > TRANS_BYTES_LENGTH_MAX) {
                return SOFTBUS_ERR;
            }
            break;
        }
        default: {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyProcessSessionData(const char *pkgName, int32_t channelId, PacketHead *dataHead,
    const char *data)
{
    ProxyDataInfo dataInfo = {0};
    uint32_t outLen;
    int32_t ret;

    if (dataHead->dataLen <= OVERHEAD_LEN) {
        return SOFTBUS_ERR;
    }

    outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo.outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo.outData == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo.inData = (unsigned char *)data;
    dataInfo.inLen = dataHead->dataLen;
    dataInfo.outLen = outLen;

    ret = TransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, dataHead->flags) != SOFTBUS_OK) {
        LOG_ERR("data len is too large %d type %d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_ERR;
    }

    LOG_INFO("ProcessData debug: len %d \n", dataInfo.outLen);
    if (TransProxyNotifySession(pkgName, channelId, (ProxyPacketType)dataHead->flags, dataHead->seq,
        (const char *)dataInfo.outData, dataInfo.outLen) != SOFTBUS_OK) {
        LOG_ERR("process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

void TransProxyNoSubPacketProc(const char *pkgName, int32_t channelId, const char *data, uint32_t len)
{
    PacketHead *head = NULL;

    head = (PacketHead*)data;
    if ((uint32_t)head->magicNumber != MAGIC_NUMBER) {
        LOG_ERR("invalid magicNumber %x", head->magicNumber);
        return;
    }
    if (head->dataLen <= 0) {
        LOG_ERR("invalid dataLen %d", head->dataLen);
        return;
    }
    LOG_ERR("NoSubPacketProc data info %d", head->dataLen);
    int32_t ret = TransProxyProcessSessionData(pkgName, channelId, head, data + sizeof(PacketHead));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("process data err");
        return;
    }
    return;
}

void TransOnNormalMsgReceived(const char *pkgName, int32_t channelId, const char *data, uint32_t len)
{
    SliceHead *head = NULL;

    if (data == NULL || len <= sizeof(SliceHead)) {
        return;
    }
    LOG_ERR("TransOnNormalMsgReceived len %u", len);

    head = (SliceHead*)data;
    if (head->priority < 0 || head->priority >= PROXY_CHANNEL_PRORITY_BUTT) {
        LOG_ERR("invalid index %d", head->priority);
        return;
    }

    if (head->sliceNum != 1 || head->sliceSeq >= head->sliceNum) {
        LOG_ERR("invalid sliceNum %d sliceSeq %d", head->sliceNum, head->sliceSeq);
        return;
    }

    TransProxyNoSubPacketProc(pkgName, channelId, data + sizeof(SliceHead), len - sizeof(SliceHead));
}
