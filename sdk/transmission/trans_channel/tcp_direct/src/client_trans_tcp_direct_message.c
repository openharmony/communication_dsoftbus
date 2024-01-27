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

#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
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
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen, seqNum);
    if (memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memset cipherKey failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "encrypt error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcSetPendingPacket(int32_t channelId, const char *data, uint32_t len)
{
    if (len != ACK_SIZE) {
        TRANS_LOGE(TRANS_SDK, "recv invalid seq.");
        return SOFTBUS_ERR;
    }

    int32_t seq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    if (SetPendingPacket(channelId, seq, PENDING_TYPE_DIRECT) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "can not match seq=%{public}d", seq);
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
        TRANS_LOGE(TRANS_SDK, "malloc failed.");
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
        TRANS_LOGE(TRANS_SDK, "memcpy_s error");
        return NULL;
    }
    if (TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len,
        buf + DC_DATA_HEAD_SIZE, outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "encrypt error");
        SoftBusFree(buf);
        return NULL;
    }
    return buf;
}

static int32_t TransTdcProcessPostData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len,
    int32_t flags)
{
    uint32_t outLen = 0;
    char *buf = TransTdcPackData(channel, data, len, flags, &outLen);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_SDK, "failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (outLen != len + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "pack bytes len error, outLen=%{public}d", outLen);
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
        TRANS_LOGE(TRANS_SDK, "failed to send tcp data. ret=%{public}zd", ret);
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
        TRANS_LOGE(TRANS_SDK, "param invalid. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "TransTdcGetInfoByIdWithIncSeq failed, channelId=%{public}d.", channelId);
        return SOFTBUS_ERR;
    }

    int ret = TransTdcProcessPostData(&channel, data, len, FLAG_BYTES);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc send bytes failed, channelId=%{public}d, ret=%{public}d.", channelId, ret);
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
    if (TransTdcGetInfoByIdWithIncSeq(channelId, &channel) == NULL) {
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }
    int32_t ret = TransTdcProcessPostData(&channel, data, len, FLAG_MESSAGE);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "tdc send message failed, ret=%{public}d.", ret);
        return ret;
    }
    return ProcPendingPacket(channelId, channel.detail.sequence, PENDING_TYPE_DIRECT);
}

static int32_t TransTdcSendAck(const TcpDirectChannelInfo *channel, int32_t seq)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SDK, "channel is null.");
        return SOFTBUS_ERR;
    }

    return TransTdcProcessPostData(channel, (char*)(&seq), ACK_SIZE, FLAG_ACK);
}

static uint32_t TransGetDataBufSize(void)
{
    return MIN_BUF_LEN;
}

#define SLICE_HEAD_LEN 16
static int32_t TransGetDataBufMaxSize(void)
{
    uint32_t maxLen = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get config err");
        return SOFTBUS_ERR;
    }
    g_dataBufferMaxLen = maxLen + DATA_EXTEND_LEN + SLICE_HEAD_LEN;
    return SOFTBUS_OK;
}

int32_t TransAddDataBufNode(int32_t channelId, int32_t fd)
{
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDataList is null.");
        return SOFTBUS_ERR;
    }
    ClientDataBuf *node = (ClientDataBuf *)SoftBusCalloc(sizeof(ClientDataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc failed.");
        return SOFTBUS_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = TransGetDataBufSize();
    node->data = (char *)SoftBusCalloc(node->size);
    if (node->data == NULL) {
        SoftBusFree(node);
        TRANS_LOGE(TRANS_SDK, "calloc data failed.");
        return SOFTBUS_ERR;
    }
    node->w = node->data;

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        SoftBusFree(node->data);
        SoftBusFree(node);
        return SOFTBUS_ERR;
    }
    ListAdd(&g_tcpDataList->list, &node->node);
    TRANS_LOGI(TRANS_SDK, "add channelId = %{public}d", channelId);
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
        TRANS_LOGE(TRANS_SDK, "lock failed.");
        return SOFTBUS_ERR;
    }
    ClientDataBuf *item = NULL;
    ClientDataBuf *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_tcpDataList->list, ClientDataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_SDK, "delete channelId = %{public}d", channelId);
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
        TRANS_LOGE(TRANS_SDK, "lock failed.");
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
    TRANS_LOGE(TRANS_SDK, "tcp direct channel not exist. channelId=%{public}d", channelId);
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
            TRANS_LOGE(TRANS_SDK, "unknown flag=%{public}d.", flag);
            return SOFTBUS_ERR;
    }
}

static int32_t TransTdcProcessData(int32_t channelId)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "get key fail. channelId=%{public}d ", channelId);
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    ClientDataBuf *node = TransGetDataBufNodeById(channelId);
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "node is null. channelId=%{public}d ", channelId);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_ERR;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    int32_t seqNum = pktHead->seq;
    uint32_t flag = pktHead->flags;
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGE(TRANS_SDK, "data has all received, channelId=%{public}d, dataLen=%{public}u", channelId, dataLen);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail.");
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int ret = TransTdcDecrypt(channel.detail.sessionKey, node->data + DC_DATA_HEAD_SIZE, dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt fail.");
        SoftBusFree(plain);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_DECRYPT_ERR;
    }
    char *end = node->data + DC_DATA_HEAD_SIZE + dataLen;
    if (memmove_s(node->data, node->size, end, node->w - end) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memmove fail.");
        SoftBusFree(plain);
        SoftBusMutexUnlock(&g_tcpDataList->lock);
        return SOFTBUS_MEM_ERR;
    }
    node->w = node->w - DC_DATA_HEAD_SIZE - dataLen;
    SoftBusMutexUnlock(&g_tcpDataList->lock);

    ret = TransTdcProcessDataByFlag(flag, seqNum, &channel, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data fail");
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
    TRANS_LOGI(TRANS_SDK, "TransResizeDataBuffer ok");
    return SOFTBUS_OK;
}

static int32_t TransTdcProcAllData(int32_t channelId)
{
    while (1) {
        SoftBusMutexLock(&g_tcpDataList->lock);
        ClientDataBuf *node = TransGetDataBufNodeById(channelId);
        if (node == NULL) {
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "can not find data buf node. channelId=%{public}d", channelId);
            return SOFTBUS_ERR;
        }
        uint32_t bufLen = node->w - node->data;
        if (bufLen == 0) {
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_OK;
        }
        if (bufLen < DC_DATA_HEAD_SIZE) {
            TRANS_LOGW(TRANS_SDK,
                " head bufLen not enough, recv biz head next time. channelId=%{public}d, bufLen=%{public}d", channelId,
                bufLen);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
        UnpackTcpDataPacketHead(pktHead);
        if (pktHead->magicNumber != MAGIC_NUMBER) {
            TRANS_LOGE(TRANS_SDK, "invalid data packet head. channelId=%{public}d", channelId);
            SoftBusMutexUnlock(&g_tcpDataList->lock);
            return SOFTBUS_ERR;
        }

        if ((pktHead->dataLen > g_dataBufferMaxLen - DC_DATA_HEAD_SIZE) || (pktHead->dataLen <= OVERHEAD_LEN)) {
            TRANS_LOGE(TRANS_SDK, "illegal dataLen=%{public}d", pktHead->dataLen);
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
            TRANS_LOGE(TRANS_SDK, "data bufLen not enough, recv biz data next time. bufLen=%{public}d ", bufLen);
            return SOFTBUS_DATA_NOT_ENOUGH;
        }

        if (TransTdcProcessData(channelId) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "data received failed");
            return SOFTBUS_ERR;
        }
    }
}

static int32_t TransClientGetTdcDataBufByChannel(int32_t channelId, int32_t *fd, size_t *len)
{
    if (fd == NULL || len == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_ERR;
    }

    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "tdc data list empty.");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
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
    TRANS_LOGE(TRANS_SDK, "client get tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_ERR;
}

static int32_t TransClientUpdateTdcDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "data list empty.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_tcpDataList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed.");
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
            TRANS_LOGE(TRANS_SDK,
                "client tdc recvLen override freeLen. recvLen=%{public}d, freeLen=%{public}d", recvLen, freeLen);
            return SOFTBUS_ERR;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
            TRANS_LOGE(TRANS_SDK, "client tdc memcpy failed. channelId=%{public}d", channelId);
            return SOFTBUS_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
        TRANS_LOGI(TRANS_SDK, "client update tdc data success, channelId=%{public}d", channelId);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    TRANS_LOGE(TRANS_SDK, "client update tdc data buf not found. channelId=%{public}d", channelId);
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
        TRANS_LOGE(TRANS_SDK,
            "client tdc  free databuf len invalid. channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_ERR;
    }

    char *recvBuf = (char*)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_SDK, "client tdc calloc failed. channelId=%{public}d, len=%{public}zu", channelId, len);
        return SOFTBUS_ERR;
    }

    int32_t recvLen = ConnRecvSocketData(fd, recvBuf, len, 0);
    if (recvLen < 0) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_SDK, "client recv data failed, channelId=%{public}d, recvLen=%{public}d.", channelId, recvLen);
        return SOFTBUS_ERR;
    } else if (recvLen == 0) {
        SoftBusFree(recvBuf);
        return SOFTBUS_DATA_NOT_ENOUGH;
    }

    if (TransClientUpdateTdcDataBufWInfo(channelId, recvBuf, recvLen) != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_SDK, "client update data buf failed. channelId=%{public}d", channelId);
        return SOFTBUS_ERR;
    }
    SoftBusFree(recvBuf);

    return TransTdcProcAllData(channelId);
}

int32_t TransDataListInit(void)
{
    if (g_tcpDataList != NULL) {
        TRANS_LOGI(TRANS_SDK, "g_tcpDataList already init");
        return SOFTBUS_OK;
    }
    if (TransGetDataBufMaxSize() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransGetDataBufMaxSize failed");
        return SOFTBUS_ERR;
    }
    g_tcpDataList = CreateSoftBusList();
    if (g_tcpDataList == NULL) {
        TRANS_LOGE(TRANS_SDK, "g_tcpDataList creat list failed");
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
