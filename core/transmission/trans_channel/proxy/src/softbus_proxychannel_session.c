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

#include <arpa/inet.h>
#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_property.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_tcp_socket.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_pending_pkt.h"

#define MSG_SLICE_HEAD_LEN (sizeof(SliceHead) + sizeof(ProxyMessageHead))
#define PROXY_ACK_SIZE 4
#define TIME_OUT 10
#define USECTONSEC 1000
#define PACK_HEAD_LEN (sizeof(PacketHead))
#define DATA_HEAD_SIZE (4 * 1024)  // donot knoe bytes 1024 or message (4 * 1024)

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

static SoftBusList *g_channelSliceProcessorList = NULL;
int32_t TransProxyTransDataSendMsg(int32_t channelId, const char *payLoad, int payLoadLen, ProxyPacketType flag);

int32_t NotifyClientMsgReceived(const char *pkgName, int32_t channelId, const char *data, uint32_t len,
    SessionPktType type)
{
    int32_t ret = TransProxyOnMsgReceived(pkgName, channelId, data, len, type);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify err[%d]", ret);
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
            return PROXY_FLAG_MESSAGE;
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

static int32_t TransProxyEncryptPacketData(int32_t channelId, int32_t seq, ProxyDataInfo *dataInfo)
{
    char sessionKey[SESSION_KEY_LENGTH] = {0};
    AesGcmCipherKey cipherKey = {0};
    uint32_t checkLen;

    if (TransProxyGetSessionKeyByChanId(channelId, sessionKey, sizeof(sessionKey)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channelId(%d) session key err", channelId);
        return SOFTBUS_ERR;
    }

    checkLen = dataInfo->inLen + OVERHEAD_LEN;
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s key error.");
        return SOFTBUS_ERR;
    }
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, dataInfo->inData, dataInfo->inLen,
        dataInfo->outData, &(dataInfo->outLen), seq);
    if (ret != SOFTBUS_OK || dataInfo->outLen != checkLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Trans Proxy encrypt error. %d ", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyDecryptPacketData(int32_t channelId, int32_t seq, ProxyDataInfo *dataInfo)
{
    char sessionKey[SESSION_KEY_LENGTH] = {0};
    AesGcmCipherKey cipherKey = {0};
    int ret;

    if (TransProxyGetSessionKeyByChanId(channelId, sessionKey, sizeof(sessionKey)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "DecryptPacket get chan fail channid %d.", channelId);
        return SOFTBUS_ERR;
    }
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    (void)memset_s(sessionKey, sizeof(sessionKey), 0, sizeof(sessionKey));
    ret = SoftBusDecryptDataWithSeq(&cipherKey, dataInfo->inData, dataInfo->inLen,
        dataInfo->outData, &(dataInfo->outLen), seq);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans proxy Decrypt Data fail. %d ", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyGetPktSeqId(int32_t channelId, const ProxyDataInfo *dataInfo, ProxyPacketType flag)
{
    int32_t seq = 0;

    if (flag == PROXY_FLAG_ACK) {
        if (memcpy_s(&seq, sizeof(seq), dataInfo->inData, dataInfo->inLen) == EOK) {
            return seq;
        }
    }
    return TransProxyGetNewChanSeq(channelId);
}

static int32_t TransProxyPackBytes(int32_t channelId, ProxyDataInfo *dataInfo, ProxyPacketType flag, int32_t *outseq)
{
#define MAGIC_NUMBER 0xBABEFACE
    uint32_t outBufLen;
    uint8_t *outBuf = NULL;
    PacketHead *pktHead = NULL;
    ProxyDataInfo enDataInfo = {0};
    int32_t seq;

    outBufLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketHead);
    outBuf = SoftBusCalloc(outBufLen);
    if (outBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc error");
        return SOFTBUS_MEM_ERR;
    }
    seq = TransProxyGetPktSeqId(channelId, dataInfo, flag);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans proxy send packet seq %d flag %d", seq, flag);
    enDataInfo.outData = outBuf + sizeof(PacketHead);
    enDataInfo.outLen = outBufLen - sizeof(PacketHead);

    enDataInfo.inData = dataInfo->inData;
    enDataInfo.inLen = dataInfo->inLen;
    if (TransProxyEncryptPacketData(channelId, seq, &enDataInfo) != SOFTBUS_OK) {
        SoftBusFree(outBuf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tran pack encrypt data fail. channid %d", channelId);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    pktHead = (PacketHead*)outBuf;
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->seq = seq;
    pktHead->flags = flag;
    pktHead->dataLen = enDataInfo.outLen;
    *outseq = seq;
    dataInfo->outData = outBuf;
    dataInfo->outLen = outBufLen;
    return SOFTBUS_OK;
}

static int32_t TransProxyProcSendMsgAck(int32_t channelId, const char *data, int32_t len)
{
    int32_t seq;

    if (len != PROXY_ACK_SIZE) {
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    seq = (int32_t)ntohl(*(uint32_t *)data);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransProxyProcSendMsgAck. chanid %d,seq :%d", channelId, seq);
    return SetPendingPacket(channelId, seq, PENDING_TYPE_PROXY);
}

static int32_t TransProxyTransDataSendSyncMsg(int32_t channelId, const char *payLoad, int payLoadLen,
    ProxyPacketType flag, int32_t seq)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send syncmsg chanid[%d] seq[%d] dataLen[%d] type[%d]",
        channelId, seq, payLoadLen, flag);
    int32_t ret = TransProxyTransDataSendMsg(channelId, payLoad, payLoadLen, flag);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxyTransDataSendSyncMsg err,ret :%d", ret);
        return ret;
    }
    ret = ProcPendingPacket(channelId, seq, PENDING_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "proxy send sync msg fail.[%d]", ret);
    }
    return ret;
}

int32_t TransProxyPostPacketData(int32_t channelId, const unsigned char *data, uint32_t len, ProxyPacketType flags)
{
    ProxyDataInfo packDataInfo = {0};
    int32_t ret;
    int32_t seq;

    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    packDataInfo.inData = (unsigned char *)data;
    packDataInfo.inLen = len;
    ret = TransProxyPackBytes(channelId, &packDataInfo, flags, &seq);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PackBytes err");
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "InLen[%d] seq[%d] outLen[%d] flags[%d]",
        len, seq, packDataInfo.outLen, flags);
    if (flags == PROXY_FLAG_MESSAGE) {
        ret = TransProxyTransDataSendSyncMsg(channelId, (char *)packDataInfo.outData, packDataInfo.outLen, flags, seq);
    } else {
        ret = TransProxyTransDataSendMsg(channelId, (char *)packDataInfo.outData, packDataInfo.outLen, flags);
    }

    SoftBusFree(packDataInfo.outData);
    return ret;
}

int32_t TransProxyPostSessionData(int32_t channelId, const unsigned char *data, uint32_t len, SessionPktType flags)
{
    ProxyPacketType type = SessionTypeToPacketType(flags);
    return TransProxyPostPacketData(channelId, data, len, type);
}
static int32_t TransProxyGetBufLen(void)
{
#define MAX_SEND_LENGTH 1024
    return MAX_SEND_LENGTH;
}

static char *TransProxyPackAppNormalMsg(const ProxyMessageHead *msg, const SliceHead *sliceHead, const char *payLoad,
    int32_t datalen, int32_t *outlen)
{
    char *buf = NULL;
    int bufLen;
    int connHeadLen;
    int dstLen;

    connHeadLen = ConnGetHeadSize();
    bufLen = PROXY_CHANNEL_HEAD_LEN + connHeadLen + sizeof(SliceHead) + datalen;
    buf = (char*)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        return NULL;
    }

    if (memcpy_s(buf + connHeadLen, bufLen - connHeadLen, msg, sizeof(ProxyMessageHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    dstLen = bufLen - connHeadLen - sizeof(ProxyMessageHead);
    if (memcpy_s(buf + connHeadLen + sizeof(ProxyMessageHead), dstLen, sliceHead, sizeof(SliceHead)) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    dstLen = bufLen - connHeadLen - MSG_SLICE_HEAD_LEN;
    if (memcpy_s(buf + connHeadLen + MSG_SLICE_HEAD_LEN, dstLen, payLoad, datalen) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }

    *outlen = bufLen;
    return buf;
}

static int32_t TransProxyTransAppNormalMsg(const ProxyChannelInfo *info, const char *payLoad, int payLoadLen,
    ProxyPacketType flag)
{
    int32_t dataLen;
    int32_t offset;
    int32_t singleLen;
    int32_t sliceNum;

    singleLen = TransProxyGetBufLen();
    if (singleLen <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "getBuflen msg error");
        return SOFTBUS_ERR;
    }
    sliceNum = (payLoadLen + singleLen - 1) / singleLen;
    ProxyMessageHead msgHead = {0};
    msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    msgHead.myId = info->myId;
    msgHead.peerId = info->peerId;
    for (int i = 0; i < sliceNum; i++) {
        char *buf = NULL;
        int bufLen = 0;
        SliceHead slicehead = {0};
        slicehead.priority = ProxyTypeToProxyIndex(flag);
        slicehead.sliceNum = sliceNum;
        slicehead.sliceSeq = i;
        if (sliceNum > 1) {
            dataLen = (i == (sliceNum - 1)) ? (payLoadLen - i * MAX_SEND_LENGTH) : MAX_SEND_LENGTH;
            offset = i * MAX_SEND_LENGTH;
        } else {
            dataLen = payLoadLen;
            offset = 0;
        }

        buf = TransProxyPackAppNormalMsg(&msgHead, &slicehead, payLoad + offset, dataLen, &bufLen);
        if (buf == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg error");
            return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "slice: i:%d", i);
        if (TransProxyTransSendMsg(info->connId, buf, bufLen, ProxyTypeToConnPri(flag)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg error");
            return SOFTBUS_TRANS_PROXY_SENDMSG_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransProxyTransNetWorkMsg(ProxyMessageHead *msghead, const ProxyChannelInfo *info, const char *payLoad,
    int payLoadLen, int priority)
{
    char *buf = NULL;
    int bufLen = 0;

    if (TransProxyPackMessage(msghead, info->connId, payLoad, payLoadLen, &buf, &bufLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg error");
        return SOFTBUS_TRANS_PROXY_PACKMSG_ERR;
    }

    return TransProxyTransSendMsg(info->connId, buf, bufLen, priority);
}

int32_t TransProxyTransDataSendMsg(int32_t channelId, const char *payLoad, int payLoadLen, ProxyPacketType flag)
{
    int ret = SOFTBUS_OK;
    ProxyChannelInfo *info = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail when trans proxy trans data");
        return SOFTBUS_MALLOC_ERR;
    }
    if (TransProxyGetSendMsgChanInfo(channelId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get channelId err %d", channelId);
        ret = SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
        goto EXIT;
    }

    if ((info->status != PROXY_CHANNEL_STATUS_COMPLETED && info->status != PROXY_CHANNEL_STATUS_KEEPLIVEING)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "status is err %d", info->status);
        ret = SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID;
        goto EXIT;
    }
    ret = TransProxyTransAppNormalMsg(info, payLoad, payLoadLen, flag);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack msg error");
        goto EXIT;
    }
EXIT:
    SoftBusFree(info);
    return ret;
}

static void TransProxySendSessionAck(int32_t channelId, int32_t seq)
{
#define PROXY_ACK_SIZE 4
    unsigned char ack[PROXY_ACK_SIZE];
    if (memcpy_s(ack, PROXY_ACK_SIZE, &seq, sizeof(int32_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy seq err");
    }
    if (TransProxyPostPacketData(channelId, ack, PROXY_ACK_SIZE, PROXY_FLAG_ACK) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send ack err, seq = %d", seq);
    }
}

int32_t TransProxyNotifySession(const char *pkgName, int32_t channelId, ProxyPacketType flags, int32_t seq,
    const char *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "flags:%d", flags);
    switch (flags) {
        case PROXY_FLAG_BYTES:
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_BYTES);
        case PROXY_FLAG_MESSAGE:
            TransProxySendSessionAck(channelId, seq);
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_MESSAGE);
        case PROXY_FLAG_ASYNC_MESSAGE:
            return NotifyClientMsgReceived(pkgName, channelId, data, len, TRANS_SESSION_MESSAGE);
        case PROXY_FLAG_ACK:
            return TransProxyProcSendMsgAck(channelId, data, len);
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid flags(%d)", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

int32_t TransProxySessionDataLenCheck(uint32_t dataLen, ProxyPacketType type)
{
#define PROXY_MAX_BYTES_LEN (4 * 1024)
#define PROXY_MAX_MESSAGE_LEN (1 * 1024)
    switch (type) {
        case PROXY_FLAG_MESSAGE:
        case PROXY_FLAG_ASYNC_MESSAGE: {
            if (dataLen > PROXY_MAX_MESSAGE_LEN) {
                return SOFTBUS_ERR;
            }
            break;
        }
        case PROXY_FLAG_BYTES: {
            if (dataLen > PROXY_MAX_BYTES_LEN) {
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

static int32_t TransProxyProcessSessionData(const char *pkgName, int32_t channelId,
    const PacketHead *dataHead, const char *data)
{
    ProxyDataInfo dataInfo = {0};
    uint32_t outLen;
    int32_t ret;

    if (dataHead->dataLen <= OVERHEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid data head len[%d]", dataHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo.outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo.outData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail when process session out data.");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo.inData = (unsigned char *)data;
    dataInfo.inLen = dataHead->dataLen;
    dataInfo.outLen = outLen;

    ret = TransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, dataHead->flags) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data len is too large %d type %d",
            dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ProcessData debug: len %d \n", dataInfo.outLen);
    if (TransProxyNotifySession(pkgName, channelId, (ProxyPacketType)dataHead->flags, dataHead->seq,
        (const char *)dataInfo.outData, dataInfo.outLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t TransProxyNoSubPacketProc(const char *pkgName, int32_t channelId, const char *data, uint32_t len)
{
    PacketHead *head = (PacketHead*)data;
    if ((uint32_t)head->magicNumber != MAGIC_NUMBER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid magicNumber %x", head->magicNumber);
        return SOFTBUS_ERR;
    }
    if (head->dataLen <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid dataLen %d", head->dataLen);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NoSubPacketProc dataLen[%d] inputLen[%d]", head->dataLen,  len);
    int32_t ret = TransProxyProcessSessionData(pkgName, channelId, head, data + sizeof(PacketHead));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process data err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyCheckSliceHead(const SliceHead *head)
{
    if (head == NULL) {
        return SOFTBUS_ERR;
    }
    if (head->priority < 0 || head->priority >= PROXY_CHANNEL_PRORITY_BUTT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid index %d", head->priority);
        return SOFTBUS_ERR;
    }

    if (head->sliceNum != 1 && head->sliceSeq >= head->sliceNum) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sliceNum %d sliceSeq %d", head->sliceNum, head->sliceSeq);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static ChannelSliceProcessor *TransProxyGetChannelSliceProcessor(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return processor;
        }
    }

    ChannelSliceProcessor *node = (ChannelSliceProcessor *)SoftBusCalloc(sizeof(ChannelSliceProcessor));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc err");
        return NULL;
    }
    node->channelId = channelId;
    ListInit(&(node->head));
    ListAdd(&(g_channelSliceProcessorList->list), &(node->head));
    g_channelSliceProcessorList->cnt++;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "add new node, channelId = %d", channelId);
    return node;
}

static void TransProxyClearProcessor(SliceProcessor *processor)
{
    if (processor->data != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "slice processor data not null");
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

static int32_t TransProxyFirstSliceProcess(SliceProcessor *processor, const SliceHead *head,
    const char *data, uint32_t len)
{
    TransProxyClearProcessor(processor);

    uint32_t maxDataLen = (head->priority == PROXY_CHANNEL_PRORITY_MESSAGE) ?
        PROXY_MESSAGE_LENGTH_MAX : PROXY_BYTES_LENGTH_MAX;
    uint32_t maxLen = maxDataLen + DATA_HEAD_SIZE + OVERHEAD_LEN;
    processor->data = (char *)SoftBusCalloc(maxLen);
    if (processor->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail when proc first slice package");
        return SOFTBUS_MALLOC_ERR;
    }
    processor->bufLen = maxLen;
    if (memcpy_s(processor->data, maxLen, data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy fail hen proc first slice package");
        return SOFTBUS_SLICE_ERROR;
    }
    processor->sliceNumber = head->sliceNum;
    processor->expectedSeq = 1;
    processor->dataLen = len;
    processor->active = true;
    processor->timeout = 0;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "FirstSliceProcess ok");
    return SOFTBUS_OK;
}

static int32_t TransProxySliceProcessChkPkgIsValid(const SliceProcessor *processor, const SliceHead *head,
    const char *data, uint32_t len)
{
    if (head->sliceNum != processor->sliceNumber ||
        head->sliceSeq != processor->expectedSeq) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unmatched normal slice received");
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID;
    }
    if ((int32_t)len + processor->dataLen > processor->bufLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data len invalid");
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH;
    }
    if (processor->data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data NULL");
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyNormalSliceProcess(SliceProcessor *processor, const SliceHead *head,
    const char *data, uint32_t len)
{
    int32_t ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen, processor->bufLen - processor->dataLen, data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy fail when proc normal slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += len;
    processor->timeout = 0;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "NormalSliceProcess ok");
    return ret;
}

static int32_t TransProxyLastSliceProcess(SliceProcessor *processor, const SliceHead *head,
    const char *data, uint32_t len, const char *pkgName, int32_t channelId)
{
    int32_t ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen, processor->bufLen - processor->dataLen, data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy fail when proc last slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += len;

    ret = TransProxyNoSubPacketProc(pkgName, channelId, processor->data, processor->dataLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process packets err");
        return ret;
    }
    TransProxyClearProcessor(processor);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "LastSliceProcess ok");
    return ret;
}

static int TransProxySubPacketProc(const char *pkgName, int32_t channelId, const SliceHead *head,
    const char *data, uint32_t len)
{
    if (data == NULL || len <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_channelSliceProcessorList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxySubPacketProc not init");
        return SOFTBUS_NO_INIT;
    }
    if (pthread_mutex_lock(&g_channelSliceProcessorList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock err");
        return SOFTBUS_ERR;
    }

    ChannelSliceProcessor *channelProcessor = TransProxyGetChannelSliceProcessor(channelId);
    if (channelProcessor == NULL) {
        pthread_mutex_unlock(&g_channelSliceProcessorList->lock);
        return SOFTBUS_ERR;
    }

    int ret;
    int32_t index = head->priority;
    SliceProcessor *processor = &(channelProcessor->processor[index]);
    if (head->sliceSeq == 0) {
        ret = TransProxyFirstSliceProcess(processor, head, data, len);
    } else if (head->sliceNum == head->sliceSeq + 1) {
        ret = TransProxyLastSliceProcess(processor, head, data, len, pkgName, channelId);
    } else {
        ret = TransProxyNormalSliceProcess(processor, head, data, len);
    }

    pthread_mutex_unlock(&g_channelSliceProcessorList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Proxy SubPacket Proc end");
    if (ret != SOFTBUS_OK) {
        TransProxyClearProcessor(processor);
    }
    return ret;
}
#define SLICE_HEAD_LEN (sizeof(PacketHead) + sizeof(SliceHead))
int32_t TransOnNormalMsgReceived(const char *pkgName, int32_t channelId, const char *data, uint32_t len)
{
    SliceHead *headSlice = NULL;
    uint32_t dataLen;

    if (data == NULL || len <= SLICE_HEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data null or len %d error", len);
        return SOFTBUS_ERR;
    }

    headSlice = (SliceHead *)data;
    if (TransProxyCheckSliceHead(headSlice)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid slihead");
        return SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD;
    }

    dataLen = len - sizeof(SliceHead);
    if (headSlice->sliceNum == 1) { // no sub packets
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "no sub packets proc");
        return TransProxyNoSubPacketProc(pkgName, channelId, data + sizeof(SliceHead), dataLen);
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "sub packets proc slicecount:%d", headSlice->sliceNum);
        return TransProxySubPacketProc(pkgName, channelId, headSlice, data + sizeof(SliceHead), dataLen);
    }
}

int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId)
{
    ChannelSliceProcessor *node = NULL;
    ChannelSliceProcessor *next = NULL;

    if (g_channelSliceProcessorList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_NO_INIT;
    }
    if (pthread_mutex_lock(&g_channelSliceProcessorList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock err");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (node->channelId == channelId) {
            for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
                TransProxyClearProcessor(&(node->processor[i]));
            }
            ListDelete(&(node->head));
            SoftBusFree(node);
            g_channelSliceProcessorList->cnt--;
            (void)pthread_mutex_unlock(&g_channelSliceProcessorList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_channelSliceProcessorList->lock);
    return SOFTBUS_OK;
}

static void TransProxySliceTimerProc(void)
{
#define SLICE_PACKET_TIMEOUT 10  //  10s
    ChannelSliceProcessor *removeNode = NULL;
    ChannelSliceProcessor *nextNode = NULL;

    if (g_channelSliceProcessorList == 0 || g_channelSliceProcessorList->cnt == 0) {
        return;
    }

    if (pthread_mutex_lock(&g_channelSliceProcessorList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransProxySliceTimerProc lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
            if (removeNode->processor[i].active == true) {
                removeNode->processor[i].timeout++;
                if (removeNode->processor[i].timeout >= SLICE_PACKET_TIMEOUT) {
                    TransProxyClearProcessor(&removeNode->processor[i]);
                }
            }
        }
    }
    (void)pthread_mutex_unlock(&g_channelSliceProcessorList->lock);
    return;
}

int32_t TransSliceManagerInit(void)
{
    g_channelSliceProcessorList = CreateSoftBusList();
    if (g_channelSliceProcessorList == NULL) {
        return SOFTBUS_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_PROXYSLICE_TIMER_FUN, (void *)TransProxySliceTimerProc) != SOFTBUS_OK) {
        DestroySoftBusList(g_channelSliceProcessorList);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransSliceManagerDeInit(void)
{
    if (g_channelSliceProcessorList) {
        DestroySoftBusList(g_channelSliceProcessorList);
    }
    return;
}
