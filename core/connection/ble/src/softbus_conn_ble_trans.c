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

#include "softbus_conn_ble_trans.h"

#include "securec.h"

#include <arpa/inet.h>
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_datahead_transform.h"
#include "softbus_def.h"

static const int32_t MTU_HEADER_SIZE = 3;
static const size_t BLE_TRANS_HEADER_SIZE = sizeof(BleTransHeader);

static ConnBleTransEventListener g_transEventListener = { 0 };

static int32_t UnpackTransHeader(uint8_t *data, uint32_t dataLen, BleTransHeader *header)
{
    if (dataLen < BLE_TRANS_HEADER_SIZE) {
        return SOFTBUS_ERR;
    }
    BleTransHeader *tmp = (BleTransHeader *)data;
    header->seq = ntohl(tmp->seq);
    header->size = ntohl(tmp->size);
    header->offset = ntohl(tmp->offset);
    header->total = ntohl(tmp->total);
    if ((header->size != dataLen - BLE_TRANS_HEADER_SIZE) || (header->total > MAX_DATA_LEN) ||
        (header->size > header->total) || (header->total - header->size < header->offset)) {
        CONN_LOGW(CONN_BLE,
            "unpack ble trans header failed, dataLen=%{public}u, total=%{public}u, currentPacketSize=%{public}u",
            dataLen, header->total, header->size);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DiscardBuffer(ConnBleReadBuffer *buffer, bool quiet)
{
    ConnBlePacket *it = NULL;
    ConnBlePacket *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &buffer->packets, ConnBlePacket, node) {
        if (!quiet) {
            CONN_LOGW(CONN_BLE, "discard packet. Seq=%{public}u, Total=%{public}u, Size=%{public}u, Offset=%{public}u",
                it->header.seq, it->header.total, it->header.size, it->header.offset);
        }
        ListDelete(&it->node);
        SoftBusFree(it->data);
        SoftBusFree(it);
    }
    buffer->seq = 0;
    buffer->total = 0;
    buffer->received = 0;
}

uint8_t *ConnGattTransRecv(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, NULL, CONN_BLE,
        "ble recv packet failed: invalid param, data is null, connectionId=%{public}u", connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(dataLen != 0, NULL, CONN_BLE,
        "ble recv packet failed: invalid param, data len is 0, connectionId=%{public}u", connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(outLen != NULL, NULL, CONN_BLE,
        "ble recv packet failed: invalid param, outLen is null, connectionId=%{public}u", connectionId);

    BleTransHeader header = { 0 };
    CONN_CHECK_AND_RETURN_RET_LOGW(UnpackTransHeader(data, dataLen, &header) == SOFTBUS_OK, NULL, CONN_BLE,
        "unpack ble trans header failed, discard this packet, connectionId=%{public}u, dataLen=%{public}u",
        connectionId, dataLen);

    if (header.size == header.total) {
        if (buffer->seq != 0) {
            CONN_LOGW(CONN_BLE,
                "there is incomple data waitting to receive, but another complete data "
                "received this time, connId=%{public}u, packetDataLen=%{public}u, "
                "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
                "bufferSeq=%{public}u, bufferTotal=%{public}u, bufferReceived=%{public}u",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset,
                buffer->seq, buffer->total, buffer->received);
        }
        uint32_t valueLen = header.total;
        uint8_t *value = SoftBusCalloc(sizeof(uint8_t) * valueLen);
        CONN_CHECK_AND_RETURN_RET_LOGE(value != NULL, NULL, CONN_BLE,
            "calloc value failed, discard this packet. connId=%{public}u, packetDataLen=%{public}u, "
            "Seq=%{public}u, Total=%{public}u, Size=%{public}u, Offset=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        if (memcpy_s(value, valueLen, data + BLE_TRANS_HEADER_SIZE, header.size) != EOK) {
            CONN_LOGE(CONN_BLE,
                "memcpy_s value failed, discard this packet. connId=%{public}u, dataLen=%{public}u, "
                "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset);
            SoftBusFree(value);
            return NULL;
        }
        CONN_LOGI(CONN_BLE,
            "ble recv packet: receive a complete packet. "
            "connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        *outLen = valueLen;
        return value;
    }

    if (buffer->seq != 0 && (buffer->seq != header.seq || buffer->total != header.total)) {
        CONN_LOGW(CONN_BLE,
            "there is incomple data waitting to receive, but another incomplete data received this time or total is "
            "difference, discard all received segmental packet. "
            "connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
            "bufferSeq=%{public}u, bufferTotal=%{public}u, bufferReceived=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
    }

    ConnBlePacket *target = NULL;
    ConnBlePacket *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &buffer->packets, ConnBlePacket, node) {
        if (header.offset < it->header.offset) {
            // mis-order packet received, we try to re-order it
            CONN_LOGE(CONN_BLE,
                "ble recv packet: it received an mis-order packet this time, There may be more times mis-order occured "
                "try to re-order them. "
                "connectionId=%{public}u, dataLen=%{public}u, "
                "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
                "thisSeq=%{public}u, thisTotal=%{public}u, thisSize=%{public}u, thisOffset=%{public}u",
                connectionId, dataLen, it->header.seq, it->header.total, it->header.size, it->header.offset, header.seq,
                header.total, header.size, header.offset);
            target = it;
            break;
        }
        if (header.offset == it->header.offset) {
            CONN_LOGE(CONN_BLE,
                "ble recv packet: it received a duplicate packet this time, just discart this packet, "
                "connId=%{public}u, dataLen=%{public}d, "
                "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
                "cachedSeq=%{public}u, cachedTotal=%{public}u, cachedSize=%{public}u, cachedOffset=%{public}u, ",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, it->header.seq,
                it->header.total, it->header.size, it->header.offset);
            return NULL;
        }
    }

    ConnBlePacket *packet = SoftBusCalloc(sizeof(ConnBlePacket));
    uint8_t *copyData = SoftBusCalloc(dataLen);
    if (packet == NULL || copyData == NULL || memcpy_s(copyData, dataLen, data, dataLen) != EOK) {
        CONN_LOGE(CONN_BLE,
            "ble recv packet failed: calloc ble package or copy data failed, discard all received. "
            "connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
            "bufferSeq=%{public}u, bufferTotal=%{public}u, bufferReceived=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
        SoftBusFree(packet);
        SoftBusFree(copyData);
        return NULL;
    }
    ListInit(&packet->node);
    packet->header = header;
    // MUST NOT free copyData, as its ownship move to packet, it will be free in DiscardBuffer
    packet->data = copyData;
    if (target != NULL) {
        ListAdd(target->node.prev, &packet->node);
    } else {
        ListTailInsert(&buffer->packets, &packet->node);
    }
    buffer->seq = header.seq;
    buffer->received += header.size;
    buffer->total = header.total;
    if (buffer->received < buffer->total) {
        CONN_LOGI(CONN_BLE,
            "ble recv packet: receive a segmental packet. connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        return NULL;
    }

    if (buffer->received > buffer->total) {
        CONN_LOGW(CONN_BLE,
            "ble recv packet failed, receive data length more than expected, discard all received segmental packet"
            "connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
            "bufferSeq=%{public}u, bufferTotal=%{public}u, bufferReceived=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
        return NULL;
    }

    uint32_t valueLen = buffer->total;
    uint8_t *value = SoftBusCalloc(sizeof(uint8_t) * valueLen);
    if (value == NULL) {
        CONN_LOGE(CONN_BLE,
            "calloc out value failed, discard all received segmental packet. connId=%{public}u, dataLen=%{public}u, "
            "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
            "bufferSeq=%{public}u, bufferTotal=%{public}u, bufferReceived=%{public}u",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
    }

    uint32_t offset = 0;
    LIST_FOR_EACH_ENTRY(it, &buffer->packets, ConnBlePacket, node) {
        if (it->header.offset != offset) {
            CONN_LOGE(CONN_BLE,
                "the packet offset is illegal,  is not continous, discard all received segmental packet. "
                "connId=%{public}u, dataLen=%{public}u, "
                "headerSeq=%{public}u, headerTotal=%{public}u, headerSize=%{public}u, headerOffset=%{public}u, "
                "itSeq=%{public}u, itTotal=%{public}d, itSize=%{public}d, itOffset=%{public}u",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, it->header.seq,
                it->header.total, it->header.size, it->header.offset);
            DiscardBuffer(buffer, false);
            SoftBusFree(value);
            return NULL;
        }
        if (memcpy_s(value + offset, valueLen - offset, it->data + BLE_TRANS_HEADER_SIZE, it->header.size) != EOK) {
            CONN_LOGE(CONN_BLE,
                "memcpy_s packet to value failed, discard all received segmental packet. connId=%{public}u, "
                "packetDataLen=%{public}u, Seq=%{public}u, Total=%{public}u, Size=%{public}u, Offset=%{public}u, "
                "valueLen=%{public}u, currentValueOffset=%{public}u",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, valueLen, offset);
            DiscardBuffer(buffer, false);
            SoftBusFree(value);
            return NULL;
        }
        offset += it->header.size;
    }
    DiscardBuffer(buffer, true);
    CONN_LOGI(CONN_BLE,
        "ble recv packet: join segmental packets together. connId=%{public}u, packetDataLen=%{public}u, "
        "Seq=%{public}u, Total=%{public}u, Size=%{public}u, Offset=%{public}u",
        connectionId, dataLen, header.seq, header.total, header.size, header.offset);
    *outLen = valueLen;
    return value;
}

static void FreeSendNode(SendQueueNode *node)
{
    if (node->data != NULL) {
        SoftBusFree(node->data);
    }
    SoftBusFree(node);
}

static int32_t ConnGattTransSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
#define BLE_SEND_PACKET_DELAY_MILLIS 10
    const uint8_t *waitSendData = data;
    uint32_t waitSendLen = dataLen;
    uint32_t offset = 0;
    const uint32_t maxPayload = connection->mtu - MTU_HEADER_SIZE - BLE_TRANS_HEADER_SIZE;
    // the sequence field should Keep the same duaring all segmental packets
    const uint32_t sequence = connection->sequence++;

    while (waitSendLen > 0) {
        uint32_t sendLen = waitSendLen <= maxPayload ? waitSendLen : maxPayload;
        uint8_t *buff = (uint8_t *)SoftBusCalloc(sendLen + BLE_TRANS_HEADER_SIZE);
        if (buff == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(buff + BLE_TRANS_HEADER_SIZE, sendLen, waitSendData, sendLen) != EOK) {
            SoftBusFree(buff);
            return SOFTBUS_MEM_ERR;
        }
        BleTransHeader *header = (BleTransHeader *)buff;
        header->total = htonl(dataLen);
        header->size = htonl(sendLen);
        header->offset = htonl(offset);
        header->seq = htonl(sequence);

        int32_t status = ConnBleSend(connection, buff, sendLen + BLE_TRANS_HEADER_SIZE, module);
        CONN_LOGI(CONN_BLE,
            "ble send packet: connId=%{public}u, module=%{public}d, "
            "Seq=%{public}u, Total=%{public}d, Size=%{public}d, Offset=%{public}u, status=%{public}d",
            connection->connectionId, module, sequence, dataLen, sendLen, offset, status);
        if (status != SOFTBUS_OK) {
            SoftBusFree(buff);
            return status;
        }
        SoftBusFree(buff);
        waitSendData += sendLen;
        waitSendLen -= sendLen;
        offset += sendLen;
        if (waitSendLen > 0) {
            // Temporarily add delay to avoid packet loss
            SoftBusSleepMs(BLE_SEND_PACKET_DELAY_MILLIS);
        }
    }
    return SOFTBUS_OK;
}

int32_t ConnBlePostBytesInner(uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag,
    int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble post bytes failed, invalid param, data is null, connId=%{public}u, pid=%{public}d, "
        "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
        connectionId, pid, dataLen, flag, module, seq);

    if (dataLen == 0 || dataLen > MAX_DATA_LEN) {
        CONN_LOGW(CONN_BLE,
            "invalid param, data len is 0 or exceed max send length, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
            connectionId, pid, dataLen, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_INVALID_PARAM;
    }

    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE,
            "connection not exist, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
            connectionId, pid, dataLen, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR;
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "try to lock failed, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 ", err=%{public}d",
            connectionId, pid, dataLen, flag, module, seq, status);
        ConnBleReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_LOCK_ERR;
    }
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (state != BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO && module != MODULE_CONNECTION && module != MODULE_BLE_NET) {
        CONN_LOGE(CONN_BLE,
            "connection is not ready, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64
            ", connectionState=%{public}d",
            connectionId, pid, dataLen, flag, module, seq, state);
        ConnBleReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR;
    }

    SendQueueNode *node = (SendQueueNode *)SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        CONN_LOGE(CONN_BLE,
            "calloc send node failed, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
            connectionId, pid, dataLen, flag, module, seq);
        ConnBleReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_MALLOC_ERR;
    }
    node->connectionId = connectionId;
    node->pid = pid;
    node->flag = flag;
    node->module = module;
    node->seq = seq;
    node->dataLen = dataLen;
    node->data = data;
    node->onPostBytesFinished = postBytesFinishAction;
    status = ConnBleEnqueueNonBlock((const void *)node);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "enqueue send node failed, connId=%{public}u, pid=%{public}d, "
            "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 ", err=%{public}d",
            connectionId, pid, dataLen, flag, module, seq, status);
        FreeSendNode(node);
        ConnBleReturnConnection(&connection);
        return status;
    }
    ConnBleRefreshIdleTimeout(connection);
    CONN_LOGI(CONN_BLE,
        "ble post bytes: "
        "connId=%{public}u, pid=%{public}d, Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
        connectionId, pid, dataLen, flag, module, seq);
    ConnBleReturnConnection(&connection);
    return SOFTBUS_OK;
}

static int32_t BleCtrlMsgSerializeByJson(BleCtlMessageSerializationContext ctx, char **outData, uint32_t *outDataLen)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (ctx.method == METHOD_NOTIFY_REQUEST) {
        if (!AddNumberToJsonObject(json, CTRL_MSG_KEY_METHOD, CTRL_MSG_METHOD_NOTIFY_REQUEST) ||
            !AddNumberToJsonObject(json, CTRL_MSG_KEY_DELTA, ctx.referenceRequest.delta) ||
            !AddNumberToJsonObject(json, CTRL_MSG_KEY_REF_NUM, ctx.referenceRequest.referenceNumber) ||
            !AddNumber16ToJsonObject(json, CTRL_MSG_KEY_CHALLENGE, ctx.challengeCode)) {
            cJSON_Delete(json);
            return SOFTBUS_CREATE_JSON_ERR;
        }
    } else {
        cJSON_Delete(json);
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    *outData = data;
    *outDataLen = strlen(data) + 1;
    return SOFTBUS_OK;
}

static int64_t ConnBlePackCtrlMsgHeader(ConnPktHead *header, uint32_t dataLen)
{
    static int64_t ctlMsgSeqGenerator = 0;
    int64_t seq = ctlMsgSeqGenerator++;

    header->magic = MAGIC_NUMBER;
    header->module = MODULE_CONNECTION;
    header->seq = seq;
    header->flag = CONN_HIGH;
    header->len = dataLen;
    PackConnPktHead(header);
    return seq;
}

int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outDataLen)
{
    char *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BleCtrlMsgSerializeByJson(ctx, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "ble connecion pack ctl message failed: serialize json bytes failed, "
            "connId=%{public}u, method=%{public}d", ctx.connectionId, ctx.method);
        return ret;
    }

    uint32_t headSize = sizeof(ConnPktHead);
    uint32_t bufLen = dataLen + headSize;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(bufLen);
    if (buf == NULL) {
        cJSON_free(data);
        return SOFTBUS_MALLOC_ERR;
    }
    ConnPktHead *header = (ConnPktHead *)buf;
    int64_t seq = ConnBlePackCtrlMsgHeader(header, dataLen);
    if (memcpy_s(buf + headSize, bufLen - headSize, data, dataLen) != EOK) {
        CONN_LOGE(CONN_BLE,
            "ble connecion pack ctl message failed: memcpy ctl message bytes failed, "
            "connId=%{public}u, method=%{public}d", ctx.connectionId, ctx.method);
        cJSON_free(data);
        SoftBusFree(buf);
        return SOFTBUS_MEM_ERR;
    }
    cJSON_free(data);
    *outData = buf;
    *outDataLen = bufLen;
    return seq;
}

uint8_t *ConnCocTransRecv(uint32_t connectionId, LimitedBuffer *buffer, int32_t *outLen)
{
    uint32_t pktHeadLen = sizeof(ConnPktHead);
    if (buffer->length < pktHeadLen) {
        // not enough for ConnPktHead
        return NULL;
    }
    ConnPktHead *head = (ConnPktHead *)(buffer->buffer);
    UnpackConnPktHead(head);
    if ((uint32_t)(head->magic) != MAGIC_NUMBER) {
        buffer->length = 0;
        CONN_LOGE(CONN_BLE,
            "coc connection received unknown data, just discard. connId=%{public}u, magicError=0x%{public}x",
            connectionId, head->magic);
        return NULL;
    }
    if (buffer->capacity - pktHeadLen < head->len) {
        buffer->length = 0;
        CONN_LOGE(CONN_BLE,
            "coc connection received unexpected data: too big, just discard, connId=%{public}u, module=%{public}d, "
            "seq=%{public}" PRId64 ", datalen=%{public}d", connectionId, head->module, head->seq, head->len);
        return NULL;
    }
    uint32_t packLen = head->len + sizeof(ConnPktHead);
    if (buffer->length < packLen) {
        CONN_LOGI(CONN_BLE, "coc connection received an incomplete packet continue. connId=%{public}u", connectionId);
        return NULL;
    }
    uint8_t *dataCopy = SoftBusCalloc(packLen);
    if (dataCopy == NULL) {
        CONN_LOGE(CONN_BLE,
            "coc connection parse data failed: calloc failed, retry next time, connId=%{public}u, packLen=%{public}u",
            connectionId, packLen);
        return NULL;
    }
    if (memcpy_s(dataCopy, packLen, buffer->buffer, packLen) != EOK) {
        CONN_LOGE(CONN_BLE,
            "coc connection parse data failed: memcpy_s failed, retry next time, "
            "connId=%{public}u, packLen=%{public}u, bufferLen=%{public}u", connectionId, packLen, buffer->length);
        SoftBusFree(dataCopy);
        return NULL;
    }

    if (buffer->length > packLen &&
        memmove_s(buffer->buffer, buffer->length, buffer->buffer + packLen, buffer->length - packLen) != EOK) {
        CONN_LOGE(
            CONN_BLE, "coc connection parse data failed: memmove_s failed, retry next time. connectionId=%{public}u",
            connectionId);
        SoftBusFree(dataCopy);
        return NULL;
    }

    buffer->length -= packLen;
    CONN_LOGI(CONN_BLE, "coc socket read limited buffer: leftLength=%{public}d", buffer->length);
    *outLen = (int32_t)packLen;
    return dataCopy;
}

static int32_t ConnCocTransSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    int32_t status = ConnBleSend(connection, data, dataLen, module);
    CONN_LOGI(CONN_BLE,
        "coc send packet: connId=%{public}u, module=%{public}d, total=%{public}u, status=%{public}d",
        connection->connectionId, module, dataLen, status);
    return status;
}

void *BleSendTask(void *arg)
{
#define WAIT_TIME 10
    SendQueueNode *sendNode = NULL;
    while (true) {
        int32_t status = ConnBleDequeueBlock((void **)(&sendNode));
        if (status != SOFTBUS_OK || sendNode == NULL) {
            CONN_LOGW(CONN_BLE, "deque err=%{public}d", status);
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        ConnBleConnection *connection = ConnBleGetConnectionById(sendNode->connectionId);
        if (connection == NULL) {
            CONN_LOGE(CONN_BLE,
                "connection is not exist, connId=%{public}u, pid=%{public}d, "
                "Len=%{public}u, Flg=%{public}d, Module=%{public}d, Seq=%{public}" PRId64 "",
                sendNode->connectionId, sendNode->pid, sendNode->dataLen, sendNode->flag,
                sendNode->module, sendNode->seq);
            FreeSendNode(sendNode);
            continue;
        }

        switch (connection->protocol) {
            case BLE_GATT:
                status = ConnGattTransSend(connection, sendNode->data, sendNode->dataLen, sendNode->module);
                break;
            case BLE_COC:
                status = ConnCocTransSend(connection, sendNode->data, sendNode->dataLen, sendNode->module);
                break;
            default:
                CONN_LOGE(CONN_BLE, "ble connecion trans send failed, connectionId=%{public}u, protocol=%{public}d",
                    connection->connectionId, connection->protocol);
                break;
        }
        ConnBleReturnConnection(&connection);
        g_transEventListener.onPostBytesFinished(sendNode->connectionId, sendNode->dataLen, sendNode->pid,
            sendNode->flag, sendNode->module, sendNode->seq, status);
        if (sendNode->onPostBytesFinished != NULL) {
            sendNode->onPostBytesFinished(sendNode->connectionId, status);
        }
        FreeSendNode(sendNode);
        sendNode = NULL;
    }
}

int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        listener != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT, "init ble trans failed: invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onPostBytesFinished != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble trans failed: invalid param, listener onPostByteFinshed is null");

    int32_t status = ConnBleInitSendQueue();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        status == SOFTBUS_OK, status, CONN_INIT, "init ble trans failed: init send queue failed, err=%{public}d",
        status);

    status = ConnStartActionAsync(NULL, BleSendTask, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        status == SOFTBUS_OK, status, CONN_INIT, "init ble trans failed: start send task failed, err=%{public}d",
        status);
    g_transEventListener = *listener;
    return SOFTBUS_OK;
}