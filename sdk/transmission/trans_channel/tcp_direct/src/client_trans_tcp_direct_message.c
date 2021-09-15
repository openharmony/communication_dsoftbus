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
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_property.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "trans_pending_pkt.h"

#define ACK_SIZE 4
#define DATA_EXTEND_LEN (DC_DATA_HEAD_SIZE + OVERHEAD_LEN)
#define MIN_BUF_LEN (1024 + DATA_EXTEND_LEN)

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

static int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    return SoftBusDecryptData(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen);
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

    int32_t seq = (int32_t)ntohl(*(uint32_t *)data);
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
        tmpSeq = htonl((uint32_t)finalSeq);
        finalData = (char *)(&tmpSeq);
    }

    TcpDataPacketHead pktHead = {
        .magicNumber = MAGIC_NUMBER,
        .seq = finalSeq,
        .flags = flags,
        .dataLen = dataLen,
    };
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
    if (buf == NULL || outLen != len + OVERHEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t ret = SendTcpData(channel->detail.fd, buf, outLen + DC_DATA_HEAD_SIZE, 0);
    if (ret != outLen + DC_DATA_HEAD_SIZE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to send tcp data.");
        SoftBusFree(buf);
        return SOFTBUS_ERR;
    }
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t TransTdcSendBytes(int32_t channelId, const char *data, uint32_t len)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        return SOFTBUS_ERR;
    }

    int ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "postBytes failed");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TransTdcSendMessage(int32_t channelId, const char *data, uint32_t len)
{
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        return SOFTBUS_ERR;
    }

    int32_t ret = TransTdcProcessPostData(&channel, data, len, FLAG_MESSAGE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "postBytes failed.");
        return ret;
    }

    return ProcPendingPacket(channelId, channel.detail.sequence, PENDING_TYPE_DIRECT);
}

static int32_t TransTdcSendAck(const TcpDirectChannelInfo *channel, int32_t seq)
{
    if (channel == NULL) {
        return SOFTBUS_ERR;
    }

    return TransTdcProcessPostData(channel, (char*)(&seq), ACK_SIZE, FLAG_ACK);
}

static int32_t TransGetDataBufSize(void)
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
        return SOFTBUS_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = TransGetDataBufSize();
    node->data = (char *)SoftBusCalloc(node->size);
    if (node->data == NULL) {
        SoftBusFree(node);
        return SOFTBUS_ERR;
    }
    node->w = node->data;

    pthread_mutex_lock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &node->node);
    g_tcpDataList->cnt++;
    pthread_mutex_unlock(&g_tcpDataList->lock);
    return SOFTBUS_OK;
}

int32_t TransDelDataBufNode(int32_t channelId)
{
    if (g_tcpDataList ==  NULL) {
        return SOFTBUS_ERR;
    }

    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    pthread_mutex_lock(&g_tcpDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_tcpDataList->cnt--;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcpDataList->lock);

    return SOFTBUS_OK;
}

static int32_t TransDestroyDataBuf(void)
{
    if (g_tcpDataList ==  NULL) {
        return SOFTBUS_ERR;
    }

    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    pthread_mutex_lock(&g_tcpDataList->lock);
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_tcpDataList->cnt--;
    }
    pthread_mutex_unlock(&g_tcpDataList->lock);

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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "tcp direct channel id not exist.");
    return NULL;
}

static int32_t TransTdcProcessDataByFlag(int32_t flag, int32_t seqNum, const TcpDirectChannelInfo *channel,
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "unknown flag");
            return SOFTBUS_ERR;
    }
}

static int32_t TransTdcProcessData(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get key fail.");
        return SOFTBUS_ERR;
    }

    pthread_mutex_lock(&g_tcpDataList->lock);
    ClientDataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "node is null.");
        return SOFTBUS_ERR;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    int32_t seqNum = pktHead->seq;
    int32_t flag = pktHead->flags;
    uint32_t dataLen = pktHead->dataLen;
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc fail.");
        pthread_mutex_unlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + DC_DATA_HEAD_SIZE,
        dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt fail.");
        SoftBusFree(plain);
        pthread_mutex_unlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    char *end = node->data + DC_DATA_HEAD_SIZE + dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memmove fail.");
        pthread_mutex_unlock(&g_tcpDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - DC_DATA_HEAD_SIZE - dataLen;
    pthread_mutex_unlock(&g_tcpDataList->lock);

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
    oldBuf->data = newBuf;
    oldBuf->size = pkgLen;
    oldBuf->w = newBuf + bufLen;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransResizeDataBuffer ok");
    return SOFTBUS_OK;
}

static int32_t TransTdcProcAllData(int32_t channelId)
{
    while (1) {
        pthread_mutex_lock(&g_tcpDataList->lock);
        ClientDataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            pthread_mutex_unlock(&g_tcpDataList->lock);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not find data buf node.");
            return SOFTBUS_ERR;
        }
        uint32_t bufLen = node->w - node->data;
        if (bufLen < DC_DATA_HEAD_SIZE) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "head not enough, recv biz head next time.");
            pthread_mutex_unlock(&g_tcpDataList->lock);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
        if (pktHead->magicNumber != MAGIC_NUMBER) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid data packet head");
            pthread_mutex_unlock(&g_tcpDataList->lock);
            return SOFTBUS_ERR;
        }

        uint32_t pkgLen = pktHead->dataLen + DC_DATA_HEAD_SIZE;
        if (pkgLen > g_dataBufferMaxLen) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "out of recv data buf size[%d]", pkgLen);
            pthread_mutex_unlock(&g_tcpDataList->lock);
            return SOFTBUS_ERR;
        }

        if (pkgLen > node->size && pkgLen <= g_dataBufferMaxLen) {
            int32_t ret = TransResizeDataBuffer(node, pkgLen);
            pthread_mutex_unlock(&g_tcpDataList->lock);
            return ret;
        }
        pthread_mutex_unlock(&g_tcpDataList->lock);

        if (bufLen < pkgLen) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "data not enough, recv biz data next time.");
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        if (TransTdcProcessData(channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "data received failed");
            return SOFTBUS_ERR;
        }
    }
}

int32_t TransTdcRecvData(int32_t channelId)
{
    pthread_mutex_lock(&g_tcpDataList->lock);
    ClientDataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        pthread_mutex_unlock(&g_tcpDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "can not find data buf node.");
        return SOFTBUS_ERR;
    }
    int32_t ret = RecvTcpData(node->fd, node->w, node->size - (node->w - node->data), 0);
    if (ret <= 0) {
        pthread_mutex_unlock(&g_tcpDataList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "recv tcp data fail.");
        return SOFTBUS_ERR;
    }
    node->w += ret;
    pthread_mutex_unlock(&g_tcpDataList->lock);

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
