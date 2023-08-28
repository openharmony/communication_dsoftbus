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

#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_datahead_transform.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

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
        CLOGE("unpack ble trans header failed, dataLen=%u, total=%u, current packet size=%u, current packet len",
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
            CLOGE("discard packet (Seq/Total/Size/Offset)=(%u/%u/%u/%u)", it->header.seq, it->header.total,
                it->header.size, it->header.offset);
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
    CONN_CHECK_AND_RETURN_RET_LOG(
        data != NULL, NULL, "ble recv packet failed: connecttion id=%u, invalid param, data is null", connectionId);
    CONN_CHECK_AND_RETURN_RET_LOG(
        dataLen != 0, NULL, "ble recv packet failed: connecttion id=%u, invalid param, data len is 0", connectionId);
    CONN_CHECK_AND_RETURN_RET_LOG(
        outLen != NULL, NULL, "ble recv packet failed: connecttion id=%u, invalid param, outLen is null", connectionId);

    BleTransHeader header = { 0 };
    CONN_CHECK_AND_RETURN_RET_LOG(UnpackTransHeader(data, dataLen, &header) == SOFTBUS_OK, NULL,
        "connId=%u, unpack ble trans header failed, data len=%u, discard this packet", connectionId, dataLen);

    if (header.size == header.total) {
        if (buffer->seq != 0) {
            CLOGE("connId=%u, there is incomple data waitting to receive, but another complete data received this time,"
                  " this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), incomple payload"
                  "(Seq/Total/Received)=(%u/%u/%u)",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
                buffer->received);
        }
        uint32_t valueLen = header.total;
        uint8_t *value = SoftBusCalloc(sizeof(uint8_t) * valueLen);
        CONN_CHECK_AND_RETURN_RET_LOG(value != NULL, NULL,
            "connId=%u, calloc value failed, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), discard "
            "this packet)",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        if (memcpy_s(value, valueLen, data + BLE_TRANS_HEADER_SIZE, header.size) != EOK) {
            CLOGE("connId=%u, memcpy_s value failed, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), "
                  "discard this packet",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset);
            SoftBusFree(value);
            return NULL;
        }
        CLOGI(
            "ble recv packet: connId=%u, receive a complete packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u)",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        *outLen = valueLen;
        return value;
    }

    if (buffer->seq != 0 && (buffer->seq != header.seq || buffer->total != header.total)) {
        CLOGE("connId=%u, there is incomple data waitting to receive, but another incomplete data received this time "
              "or total is difference, discard all received "
              "segmental packet, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u). incomple payload "
              "(Seq/Total/Received)=(%u/%u/%u)",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
    }

    ConnBlePacket *target = NULL;
    ConnBlePacket *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &buffer->packets, ConnBlePacket, node) {
        if (header.offset < it->header.offset) {
            // mis-order packet received, we try to re-order it
            CLOGE("ble recv packet: connection id=%u, it received an mis-order packet, "
                  "this time, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u) is received early than "
                  "this packet (Seq/Total/Size/Offset)=(%u/%u/%u/%u). There may be more times mis-order occured, "
                  "try to re-order them",
                connectionId, dataLen, it->header.seq, it->header.total, it->header.size, it->header.offset, header.seq,
                header.total, header.size, header.offset);
            target = it;
            break;
        }
        if (header.offset == it->header.offset) {
            CLOGE("ble recv packet: connId=%u, it received a duplicate packet "
                  "this time, this packet data len=%d, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), cached packet "
                  "(Seq/Total/Size/Offset)=(%u/%u/%u/%u), just discart this packet",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, it->header.seq,
                it->header.total, it->header.size, it->header.offset);
            return NULL;
        }
    }

    ConnBlePacket *packet = SoftBusCalloc(sizeof(ConnBlePacket));
    uint8_t *copyData = SoftBusCalloc(dataLen);
    if (packet == NULL || copyData == NULL || memcpy_s(copyData, dataLen, data, dataLen) != EOK) {
        CLOGE("ble recv packet failed: connId=%u, calloc ble package or copy data "
              "failed, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), discard all received "
              "segmental packet, incomple payload (Seq/Total/Received)=(%u/%u/%u)",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
        SoftBusFree(packet);
        SoftBusFree(copyData);
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
        CLOGI("ble recv packet: connId=%u, receive a segmental packet data len=%u, "
              "(Seq/Total/Size/Offset)=(%u/%u/%u/%u)",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset);
        return NULL;
    }

    if (buffer->received > buffer->total) {
        CLOGE("ble recv packet failed: connId=%u, receive data length more than "
              "expected, this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), seq=%u, expected "
              "total len=%u, received len=%u, discard all received segmental packet",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
        return NULL;
    }

    uint32_t valueLen = buffer->total;
    uint8_t *value = SoftBusCalloc(sizeof(uint8_t) * valueLen);
    if (value == NULL) {
        CLOGE("calloc out value failed: connId=%u, this "
              "packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u) seq=%u, total len=%u, received "
              "len=%u, discard all received segmental packet",
            connectionId, dataLen, header.seq, header.total, header.size, header.offset, buffer->seq, buffer->total,
            buffer->received);
        DiscardBuffer(buffer, false);
    }

    uint32_t offset = 0;
    LIST_FOR_EACH_ENTRY(it, &buffer->packets, ConnBlePacket, node) {
        if (it->header.offset != offset) {
            CLOGE("the packet offset is illegal: connId=%u, "
                  "this packet data len=%u, (Seq/Total/Size/Offset)=(%u/%u/%u/%u), packet "
                  "(Seq/Total/Size/Offset)=(%u/%u/%u/%u) is not continous, discard all received segmental packet",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, it->header.seq,
                it->header.total, it->header.size, it->header.offset);
            DiscardBuffer(buffer, false);
            SoftBusFree(value);
            return NULL;
        }
        if (memcpy_s(value + offset, valueLen - offset, it->data + BLE_TRANS_HEADER_SIZE, it->header.size) != EOK) {
            CLOGE("memcpy_s packet to value failed: connId=%u, "
                  "this packet data len=%u (Seq/Total/Size/Offset)=(%u/%u/%u/%u), value len=%u, current "
                  "value offset=%u, discard all received segmental packet",
                connectionId, dataLen, header.seq, header.total, header.size, header.offset, valueLen, offset);
            DiscardBuffer(buffer, false);
            SoftBusFree(value);
            return NULL;
        }
        offset += it->header.size;
    }
    DiscardBuffer(buffer, true);
    CLOGI("ble recv packet: connId=%u, join segmental packets together, this packet data len=%u, "
          "(Seq/Total/Size/Offset)=(%u/%u/%u/%u)",
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

NO_SANITIZE("cfi")
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
        CLOGE("ble send packet: connId=%u, module=%d, (Seq/Total/Size/Offset)=(%u/%d/%d/%u), "
              "status=%d",
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

int32_t ConnBlePostBytesInner(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag, int32_t module, int64_t seq,
    PostBytesFinishAction postBytesFinishAction)
{
    CONN_CHECK_AND_RETURN_RET_LOG(data != NULL, SOFTBUS_INVALID_PARAM,
        "ble post bytes failed, invalid param, data is null, connId=%u, pid=%d, "
        "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
        connectionId, pid, dataLen, flag, module, seq);

    if (dataLen == 0 || dataLen > MAX_DATA_LEN) {
        CLOGE("invalid param, data len is 0 or exceed max send length, connId=%u, "
              "pid=%d, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connectionId, pid, dataLen, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_INVALID_PARAM;
    }

    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("connection not exist, connId=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connectionId, pid, dataLen, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR;
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("try to lock failed, connId=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), err=%d",
            connectionId, pid, dataLen, flag, module, seq, status);
        ConnBleReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_LOCK_ERR;
    }
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (state != BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO && module != MODULE_CONNECTION && module != MODULE_BLE_NET) {
        CLOGE("connection is not ready, connId=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), connection state=%d",
            connectionId, pid, dataLen, flag, module, seq, state);
        ConnBleReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR;
    }

    SendQueueNode *node = (SendQueueNode *)SoftBusCalloc(sizeof(SendQueueNode));
    if (node == NULL) {
        CLOGE("calloc send node failed, connId=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
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
        CLOGE("enqueue send node failed, connId=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), err=%d",
            connectionId, pid, dataLen, flag, module, seq, status);
        FreeSendNode(node);
        ConnBleReturnConnection(&connection);
        return status;
    }
    ConnBleRefreshIdleTimeout(connection);
    CLOGE("ble post bytes: connId=%u, pid=%d, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")", connectionId, pid,
        dataLen, flag, module, seq);
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
            !AddNumberToJsonObject(json, CTRL_MSG_KEY_REF_NUM, ctx.referenceRequest.referenceNumber)) {
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
        CLOGE("ble connecion %u pack ctl message failed: serialize json bytes failed, method: %d", ctx.connectionId,
            ctx.method);
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
        CLOGE("ble connecion %u pack ctl message failed: memcpy ctl message bytes failed, method: %d", ctx.connectionId,
            ctx.method);
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
        CLOGE("coc connection %u received unknown data: magic error 0x%x, just discard", connectionId, head->magic);
        return NULL;
    }
    if (buffer->capacity - pktHeadLen < head->len) {
        buffer->length = 0;
        CLOGE("coc connection %u received unexpected data: too big, just discard, module=%d, seq=%" PRId64
              ", datalen=%d",
            connectionId, head->module, head->seq, head->len);
        return NULL;
    }
    uint32_t packLen = head->len + sizeof(ConnPktHead);
    if (buffer->length < packLen) {
        CLOGI("coc connection %u received an incomplete packet, continue", connectionId);
        return NULL;
    }
    uint8_t *dataCopy = SoftBusCalloc(packLen);
    if (dataCopy == NULL) {
        CLOGE("coc connection %u parse data failed: calloc failed, retry next time, packLen=%u", connectionId, packLen);
        return NULL;
    }
    if (memcpy_s(dataCopy, packLen, buffer->buffer, packLen) != EOK) {
        CLOGE("coc connection %u parse data failed: memcpy_s failed, retry next time, packLen=%u, bufferLen=%u",
            connectionId, packLen, buffer->length);
        SoftBusFree(dataCopy);
        return NULL;
    }

    if (buffer->length > packLen &&
        memmove_s(buffer->buffer, buffer->length, buffer->buffer + packLen, buffer->length - packLen) != EOK) {
        CLOGE("coc connection %u parse data failed: memmove_s failed, retry next time", connectionId);
        SoftBusFree(dataCopy);
        return NULL;
    }

    buffer->length -= packLen;
    CLOGI("coc socket read limited buffer: left length=%d", buffer->length);
    *outLen = packLen;
    return dataCopy;
}

NO_SANITIZE("cfi")
static int32_t ConnCocTransSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    int32_t status = ConnBleSend(connection, data, dataLen, module);
    CLOGE("coc send packet: connId=%u, module=%d, payload (Total=%u), status=%d", connection->connectionId, module,
        dataLen, status);
    return status;
}

void *BleSendTask(void *arg)
{
#define WAIT_TIME 10
    SendQueueNode *sendNode = NULL;
    while (true) {
        int32_t status = ConnBleDequeueBlock((void **)(&sendNode));
        if (status != SOFTBUS_OK) {
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        ConnBleConnection *connection = ConnBleGetConnectionById(sendNode->connectionId);
        if (connection == NULL) {
            CLOGE("connection is not exist, connId=%u, pid=%d, payload "
                  "(Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
                sendNode->connectionId, sendNode->dataLen, sendNode->pid, sendNode->dataLen, sendNode->flag,
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
                CLOGE("ble connecion %u trans send failed: unexpected protocol: %d", connection->connectionId,
                    connection->protocol);
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
    CONN_CHECK_AND_RETURN_RET_LOG(
        listener != NULL, SOFTBUS_INVALID_PARAM, "init ble trans failed: invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onPostBytesFinished != NULL, SOFTBUS_INVALID_PARAM,
        "init ble trans failed: invalid param, listener onPostByteFinshed is null");

    int32_t status = ConnBleInitSendQueue();
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, status, "init ble trans failed: init send queue failed, err=%d", status);

    status = ConnStartActionAsync(NULL, BleSendTask);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, status, "init ble trans failed: start send task failed, err=%d", status);
    g_transEventListener = *listener;
    return SOFTBUS_OK;
}