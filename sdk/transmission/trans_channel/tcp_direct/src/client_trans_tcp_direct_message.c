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

#include "client_trans_tcp_direct_message.h"

#include <arpa/inet.h>
#include <securec.h>

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "trans_pending_pkt.h"

#define ACK_SIZE 4
#define DATA_EXTEND_LEN (DC_DATA_HEAD_SIZE + OVERHEAD_LEN)
#define MIN_BUF_LEN (1024 + DATA_EXTEND_LEN)

#define BYTE_TOS 0x60
#define MESSAGE_TOS 0xC0

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t fd;
    uint32_t size;
    char *data;
    char *w;
} ClientDataBuf;

static uint32_t g_dataBufferMaxLen = 0;
static SoftBusList *g_tcpDataList = NULL;

static void PackTcpDataPacketHead(TcpDataPacketHead *data)
{
    data->magicNumber = SoftBusHtoLl(data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = SoftBusHtoLl(data->flags);
    data->dataLen = SoftBusHtoLl(data->dataLen);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    int32_t ret = SoftBusDecryptData(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusDecryptData fail(=%d).", ret);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen, seqNum);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "encrypt error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcSetPendingPacket(int32_t channelId, const char *data, uint32_t len)
{
    if (len != ACK_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv invalid seq.");
        return SOFTBUS_ERR;
    }

    int32_t seq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    if (SetPendingPacket(channelId, seq, PENDING_TYPE_DIRECT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not match seq.[%d]", seq);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *TransTdcPackData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len, int flags,
    uint32_t *outLen)
{
    uint32_t dataLen = len + OVERHEAD_LEN;
    char *buf = (char *)SoftBusMalloc(dataLen + DC_DATA_HEAD_SIZE);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc failed.");
        return NULL;
    }

    char *finalData = (char *)data;
    int32_t finalSeq = channel->detail.sequence;
    uint32_t tmpSeq;
    if (flags == FLAG_ACK) {
        finalSeq = *((int32_t *)data);
        tmpSeq = SoftBusHtoNl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }

    TcpDataPacketHead pktHead = {
        .magicNumber = MAGIC_NUMBER,
        .seq = finalSeq,
        .flags = (uint32_t)flags,
        .dataLen = dataLen,
    };
    PackTcpDataPacketHead(&pktHead);
    if (memcpy_s(buf, DC_DATA_HEAD_SIZE, &pktHead, sizeof(TcpDataPacketHead)) != EOK) {
        SoftBusFree(buf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s error");
        return NULL;
    }
    if (TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len,
        buf + DC_DATA_HEAD_SIZE, outLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "encrypt error");
        SoftBusFree(buf);
        return NULL;
    }
    return buf;
}

static int32_t TransTdcProcessPostData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len,
    int32_t flags)
{
    uint32_t outLen;
    char *buf = TransTdcPackData(channel, data, len, flags, &outLen);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (outLen != len + OVERHEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pack bytes len error, len: %d", outLen);
        SoftBusFree(buf);
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t tos = (flags == FLAG_BYTES) ? BYTE_TOS : MESSAGE_TOS;
    if (SetIpTos(channel->detail.fd, tos) != SOFTBUS_OK) {
        SoftBusFree(buf);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    ssize_t ret = ConnSendSocketData(channel->detail.fd, buf, outLen + DC_DATA_HEAD_SIZE, 0);
    if (ret != (ssize_t)outLen + DC_DATA_HEAD_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to send tcp data. ret: %d", ret);
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    SoftBusFree(buf);
    buf = NULL;
    return SOFTBUS_OK;
}

int32_t TransTdcSendBytes(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s cId[%d] param invalid.", __func__, channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransTdcGetInfoByIdWithIncSeq failed, cId[%d].", channelId);
        return SOFTBUS_ERR;
    }

    int ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] tdc send bytes failed, ret=%d.", channelId, ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TransTdcSendMessage(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s cId[%d] param invalid.", __func__, channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    int32_t ret = TransTdcProcessPostData(&channel, data, len, FLAG_MESSAGE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tdc send message failed, ret=%d.", ret);
        return ret;
    }
    return ProcPendingPacket(channelId, channel.detail.sequence, PENDING_TYPE_DIRECT);
}

static int32_t TransTdcSendAck(const TcpDirectChannelInfo *channel, int32_t seq)
{
    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel is null.");
        return SOFTBUS_ERR;
    }

    return TransTdcProcessPostData(channel, (char*)(&seq), ACK_SIZE, FLAG_ACK);
}

static uint32_t TransGetDataBufSize(void)
{
    return MIN_BUF_LEN;
}

static int32_t TransGetDataBufMaxSize(void)
{
    uint32_t maxLen;
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get config err");
        return SOFTBUS_ERR;
    }
    g_dataBufferMaxLen = maxLen + DATA_EXTEND_LEN;
    return SOFTBUS_OK;
}

int32_t TransAddDataBufNode(int32_t channelId, int32_t fd)
{
    if (g_tcpDataList == NULL) {
        return SOFTBUS_ERR;
    }
    ClientDataBuf *node = (ClientDataBuf *)SoftBusCalloc(sizeof(ClientDataBuf));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s calloc failed.", __func__);
        return SOFTBUS_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = TransGetDataBufSize();
    node->data = (char *)SoftBusCalloc(node->size);
    if (node->data == NULL) {
        SoftBusFree(node);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s calloc data failed.", __func__);
        return SOFTBUS_ERR;
    }
    node->w = node->data;

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        SoftBusFree(node->data);
        SoftBusFree(node);
        return SOFTBUS_ERR;
    }
    ListAdd(&g_tcpDataList->list, &node->node);
    g_tcpDataList->cnt++;
    SoftBusMutexUnlock(&g_tcpDataList->lock);
    return SOFTBUS_OK;
}

int32_t TransDelDataBufNode(int32_t channelId)
{
    if (g_tcpDataList ==  NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        return SOFTBUS_ERR;
    }
    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpDataList->cnt--;
            break;
        }
    }
    SoftBusMutexUnlock(&g_tcpDataList->lock);

    return SOFTBUS_OK;
}

static int32_t TransDestroyDataBuf(void)
{
    if (g_tcpDataList ==  NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        return SOFTBUS_ERR;
    }
    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpDataList->cnt--;
    }
    SoftBusMutexUnlock(&g_tcpDataList->lock);

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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp direct channel id[]%d not exist.", channelId);
    return NULL;
}

static int32_t TransTdcProcessDataByFlag(uint32_t flag, int32_t seqNum, const TcpDirectChannelInfo *channel,
    const char *plain, uint32_t plainLen)
{
    switch (flag) {
        case FLAG_BYTES:
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_BYTES);
        case FLAG_ACK:
            TransTdcSetPendingPacket(channel->channelId, plain, plainLen);
            return SOFTBUS_OK;
        case FLAG_MESSAGE:
            TransTdcSendAck(channel, seqNum);
            return ClientTransTdcOnDataReceived(channel->channelId, plain, plainLen, TRANS_SESSION_MESSAGE);
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unknown flag=%d.", flag);
            return SOFTBUS_ERR;
    }
}

static int32_t TransTdcProcessData(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] get key fail.", channelId);
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        return SOFTBUS_ERR;
    }
    ClientDataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] node is null.", channelId);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_ERR;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    int32_t seqNum = pktHead->seq;
    uint32_t flag = pktHead->flags;
    uint32_t dataLen = pktHead->dataLen;
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail.");
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + DC_DATA_HEAD_SIZE, dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt fail.");
        SoftBusFree(plain);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    char *end = node->data + DC_DATA_HEAD_SIZE + dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memmove fail.");
        SoftBusFree(plain);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - DC_DATA_HEAD_SIZE - dataLen;
    SoftBusMutexUnlock(&g_tcpDataList->lock);

    ret = TransTdcProcessDataByFlag(flag, seqNum, &channel, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "process data fail");
    }
    SoftBusFree(plain);
    return ret;
}

static int32_t TransResizeDataBuffer(ClientDataBuf *oldBuf, uint32_t pkgLen)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransResizeDataBuffer: channelId=%d, pkgLen=%d",
        oldBuf->channelId, pkgLen);
    char *newBuf = (char *)SoftBusCalloc(pkgLen);
    if (newBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransResizeDataBuffer malloc err(%u)", pkgLen);
        return SOFTBUS_MEM_ERR;
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransResizeDataBuffer ok");
    return SOFTBUS_OK;
}

static int32_t TransTdcProcAllData(int32_t channelId)
{
    while (1) {
        SoftBusMutexLock(&g_tcpDataList->lock);
        ClientDataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] can not find data buf node.", channelId);
            return SOFTBUS_ERR;
        }
        uint32_t bufLen = node->w - node->data;
        if (bufLen == 0) {
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_OK;
        }
        if (bufLen < DC_DATA_HEAD_SIZE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "head[%d] not enough, recv biz head next time.", bufLen);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
        UnpackTcpDataPacketHead(pktHead);
        if (pktHead->magicNumber != MAGIC_NUMBER) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "cId[%d] invalid data packet head.", channelId);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_ERR;
        }

        if ((pktHead->dataLen > g_dataBufferMaxLen - DC_DATA_HEAD_SIZE) || (pktHead->dataLen <= OVERHEAD_LEN)) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "illegal data size[%d]", pktHead->dataLen);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_ERR;
        }
        uint32_t pkgLen = pktHead->dataLen + DC_DATA_HEAD_SIZE;

        if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
            int32_t ret = TransResizeDataBuffer(node, pkgLen);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return ret;
        }
        SoftBusMutexUnlock(&g_tcpDataList->lock);

        if (bufLen < pkgLen) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "data[%d] not enough, recv biz data next time.", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        if (TransTdcProcessData(channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data received failed");
            return SOFTBUS_ERR;
        }
    }
}

static int32_t TransClientGetTdcDataBufByChannel(int32_t channelId, int32_t *fd, size_t *len)
{
    if (fd == NULL || len == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s invalid param.", __func__);
        return SOFTBUS_ERR;
    }

    if (g_tcpDataList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s tdc data list empty.", __func__);
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        return SOFTBUS_ERR;
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "client get tdc[%d] data buf not found.", channelId);
    return SOFTBUS_ERR;
}

static int32_t TransClientUpdateTdcDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s invalid param.", __func__);
        return SOFTBUS_ERR;
    }
    if (g_tcpDataList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s data list empty.", __func__);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[client]%s lock failed.", __func__);
        return SOFTBUS_ERR;
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "client tdc recv=%d override free=%d.", recvLen, freeLen);
            return SOFTBUS_ERR;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client tdc[%d] memcpy failed.", channelId);
            return SOFTBUS_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "client update tdc[%d] data buf not found.", channelId);
    return SOFTBUS_ERR;
}

int32_t TransTdcRecvData(int32_t channelId)
{
    int32_t fd = -1;
    size_t len = 0;
    if (TransClientGetTdcDataBufByChannel(channelId, &fd, &len) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (len == 0 || len > g_dataBufferMaxLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "client tdc[%d] free databuf len[%zu] invalid.", channelId, len);
        return SOFTBUS_ERR;
    }

    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client tdc[%d] calloc len[%zu] failed.", channelId, len);
        return SOFTBUS_ERR;
    }

    int32_t recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (recvLen < 0) {
        SoftBusFree(recvBuf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client cId[%d] recv data failed,ret=%d.", channelId, recvLen);
        return SOFTBUS_ERR;
    }

    if (TransClientUpdateTdcDataBufWInfo(channelId, recvBuf, recvLen) != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client cId[%d] update data buf failed.", channelId);
        return SOFTBUS_ERR;
    }
    SoftBusFree(recvBuf);

    return TransTdcProcAllData(channelId);
}

int32_t TransDataListInit(void)
{
    if (g_tcpDataList != NULL) {
        return SOFTBUS_OK;
    }
    if (TransGetDataBufMaxSize() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    g_tcpDataList = CreateSoftBusList();
    if (g_tcpDataList == NULL) {
        return SOFTBUS_ERR;
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
