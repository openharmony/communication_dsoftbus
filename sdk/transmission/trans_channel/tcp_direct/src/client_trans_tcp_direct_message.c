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

#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_manager.h"
#include "softbus_crypto.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"
#include "trans_pending_pkt.h"

#define ACK_SIZE 4 // Message ACK 4 bytes

static int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        LOG_ERR("memcpy key error.");
        return SOFTBUS_ERR;
    }
    SoftBusDecryptData(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen);
    return SOFTBUS_OK;
}

static int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, const char *in, uint32_t inLen,
    char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        LOG_ERR("memcpy key error.");
        return SOFTBUS_ERR;
    }
    int ret = SoftBusEncryptDataWithSeq(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen, seqNum);
    if (ret != SOFTBUS_OK || *outLen != inLen + OVERHEAD_LEN) {
        LOG_ERR("encrypt error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransTdcSetPendingPacket(int32_t channelId, const char *data, uint32_t len)
{
    if (len != ACK_SIZE) {
        LOG_ERR("recv invalid seq.");
        return SOFTBUS_ERR;
    }

    int32_t seq = (int32_t)ntohl(*(uint32_t *)data);
    if (SetPendingPacket(channelId, seq, PENDING_TYPE_DIRECT) != SOFTBUS_OK) {
        LOG_ERR("can not match seq.");
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
        LOG_ERR("malloc failed.");
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
        LOG_ERR("memcpy_s error");
        return NULL;
    }
    if (TransTdcEncryptWithSeq(channel->detail.sessionKey, finalSeq, finalData, len,
        buf + DC_DATA_HEAD_SIZE, outLen) != SOFTBUS_OK) {
        LOG_ERR("encrypt error");
        SoftBusFree(buf);
        return NULL;
    }
    return buf;
}

static int32_t TransTdcPreProcessPostData(const TcpDirectChannelInfo *channel, const char *data, uint32_t len,
    int32_t flags)
{
    uint32_t outLen;
    char *buf = TransTdcPackData(channel, data, len, flags, &outLen);
    if (buf == NULL || outLen != len + OVERHEAD_LEN) {
        LOG_ERR("failed to pack bytes.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t ret = SendTcpData(channel->detail.fd, buf, outLen + DC_DATA_HEAD_SIZE, 0);
    if (ret != outLen + DC_DATA_HEAD_SIZE) {
        LOG_ERR("failed to send tcp data.");
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

    int ret = TransTdcPreProcessPostData(&channel, data, len, FLAG_BYTES);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("postBytes failed");
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

    int ret = TransTdcPreProcessPostData(&channel, data, len, FLAG_MESSAGE);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("postBytes failed.");
        return ret;
    }

    ret = AddPendingPacket(channelId, channel.detail.sequence, PENDING_TYPE_DIRECT);
    if (ret != SOFTBUS_ERR) {
        DelPendingPacket(channelId, channel.detail.sequence, PENDING_TYPE_DIRECT);
    }
    return ret;
}

static int32_t TransTdcSendAck(const TcpDirectChannelInfo *channel, int32_t seq)
{
    if (channel == NULL) {
        return SOFTBUS_ERR;
    }

    return TransTdcPreProcessPostData(channel, (char*)(&seq), ACK_SIZE, FLAG_ACK);
}

int32_t TransTdcProcessRecvData(int32_t channelId, const char *data)
{
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)data;
    int32_t seqNum = pktHead->seq;

    TcpDirectChannelInfo channel;
    (void)memset_s(&channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        LOG_ERR("get key fail.");
        return SOFTBUS_ERR;
    }

    char *plain = (char *)SoftBusCalloc(pktHead->dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        LOG_ERR("malloc error.");
        return SOFTBUS_MALLOC_ERR;
    }

    uint32_t plainLen;
    int ret = TransTdcDecrypt(channel.detail.sessionKey, data + sizeof(TcpDataPacketHead),
        pktHead->dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("decrypt error.");
        SoftBusFree(plain);
        return SOFTBUS_DECRYPT_ERR;
    }

    switch (pktHead->flags) {
        case FLAG_BYTES:
            TransOnDataReceived(channel.channelId, plain, plainLen, TRANS_SESSION_BYTES);
            break;
        case FLAG_ACK:
            TransTdcSetPendingPacket(channel.channelId, plain, plainLen);
            break;
        case FLAG_MESSAGE:
            TransTdcSendAck(&channel, seqNum);
            TransOnDataReceived(channel.channelId, plain, plainLen, TRANS_SESSION_MESSAGE);
            break;
        default:
            LOG_ERR("unknown flag");
            break;
    }

    SoftBusFree(plain);
    return SOFTBUS_OK;
}

static int32_t TransTdcProcessPackets(int32_t fd, char *data, uint32_t size, uint32_t offset)
{
    if (data == NULL || offset != sizeof(TcpDataPacketHead)) {
        LOG_ERR("invalid input param.");
        return SOFTBUS_ERR;
    }

    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)data;
    if (pktHead->magicNumber != MAGIC_NUMBER) {
        LOG_ERR("invalid packetHead");
        return SOFTBUS_INVALID_DATA_HEAD;
    }

    if (pktHead->flags != FLAG_ACK) {
        if (TransTdcCheckSeq(fd, pktHead->seq) != SOFTBUS_OK) {
            LOG_ERR("cannot get tdc info");
            return SOFTBUS_ERR;
        }
    }

    uint32_t dataLen = pktHead->dataLen;
    if (dataLen > size) {
        LOG_ERR("buffer is not enough");
        return SOFTBUS_INVALID_FD;
    }
    int rc = RecvTcpData(fd, data + offset, dataLen, 0);
    if (rc < 0) {
        LOG_ERR("connection break");
        return SOFTBUS_INVALID_FD;
    }
    if ((uint32_t)rc != dataLen) {
        LOG_ERR("dataPacketRecv failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransTdcPreProcessRecvData(int32_t fd, char *data, uint32_t size)
{
    ssize_t rc = RecvTcpData(fd, data, DC_DATA_HEAD_SIZE, 0);
    if (rc < 0) {
        return SOFTBUS_INVALID_FD;
    }
    if (rc == DC_DATA_HEAD_SIZE) {
        return TransTdcProcessPackets(fd, data, size, rc);
    }

    return SOFTBUS_ERR;
}
