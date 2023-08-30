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

#include "softbus_conn_br_trans.h"

#include "securec.h"

#include "softbus_adapter_mem.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_datahead_transform.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

static SppSocketDriver *g_sppDriver = NULL;
static ConnBrTransEventListener g_transEventListener = { 0 };

static uint8_t *BrRecvDataParse(uint32_t connectionId, LimitedBuffer *buffer, int32_t *outLen)
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
        CLOGE("recv unknown data: conn id=%u, magic 0x%x", connectionId, head->magic);
        return NULL;
    }
    if (buffer->capacity - pktHeadLen < head->len) {
        buffer->length = 0;
        CLOGE("recv data too big: conn id=%u, module=%d, seq=%" PRId64", datalen=%d",
            connectionId, head->module, head->seq, head->len);
        return NULL;
    }
    uint32_t packLen = head->len + sizeof(ConnPktHead);
    if (buffer->length < packLen) {
        CLOGI("recv incomplete packet, conn id=%u", connectionId);
        return NULL;
    }
    uint8_t *dataCopy = (uint8_t *)SoftBusCalloc(packLen);
    if (dataCopy == NULL) {
        CLOGE("connection %u parse data failed: calloc failed, retry next time, packLen=%u", connectionId, packLen);
        return NULL;
    }
    if (memcpy_s(dataCopy, packLen, buffer->buffer, packLen) != EOK) {
        CLOGE("connection %u parse data failed: memcpy_s failed, retry next time, packLen=%u, bufferLen=%u",
            connectionId, packLen, buffer->length);
        SoftBusFree(dataCopy);
        return NULL;
    }
    if (buffer->length > packLen &&
        memmove_s(buffer->buffer, buffer->length, buffer->buffer + packLen, buffer->length - packLen) != EOK) {
        CLOGE("connection %u parse data failed: memmove_s failed, retry next time", connectionId);
        SoftBusFree(dataCopy);
        return NULL;
    }
    CLOGI("br receive data, connection id=%u, cached length=%u, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
        connectionId, buffer->length, packLen, head->flag, head->module, head->seq);
    buffer->length -= packLen;
    *outLen = packLen;
    return dataCopy;
}

int32_t ConnBrTransReadOneFrame(uint32_t connectionId, int32_t socketHandle, LimitedBuffer *buffer, uint8_t **outData)
{
    while (true) {
        int32_t dataLen = 0;
        uint8_t *data = BrRecvDataParse(connectionId, buffer, &dataLen);
        if (data != NULL) {
            *outData = data;
            return dataLen;
        }
        int32_t recvLen =
            g_sppDriver->Read(socketHandle, buffer->buffer + buffer->length, buffer->capacity - buffer->length);
        if (recvLen == BR_READ_SOCKET_CLOSED) {
            CLOGW("br connection read return, connection id=%u, socket handle=%d, connection closed", connectionId,
                socketHandle);
            return SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED;
        }
        if (recvLen < 0) {
            CLOGE("br connection read return, connection id=%u, socket handle=%d, error=%d", connectionId, socketHandle,
                recvLen);
            return SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL;
        }
        buffer->length += (uint32_t)recvLen;
    }
}

int32_t BrTransSend(
    uint32_t connectionId, int32_t socketHandle, uint32_t mtu, const uint8_t *data, uint32_t dataLen)
{
    uint32_t waitWriteLen = dataLen;
    while (waitWriteLen > 0) {
        uint32_t len = waitWriteLen > mtu ? mtu : waitWriteLen;
        int32_t writeLen = g_sppDriver->Write(socketHandle, data, len);
        if (writeLen < 0) {
            CLOGE("br connection %u send data failed: underlayer bluetooth write failed, socketHandle=%d, mtu=%d, "
                  "total len=%d, wait write len=%d, already write len=%d, error=%d",
                connectionId, socketHandle, mtu, dataLen, waitWriteLen, dataLen - waitWriteLen, writeLen);
            return SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL;
        }
        data += writeLen;
        waitWriteLen -= (uint32_t)writeLen;
    }
    return SOFTBUS_OK;
}

static int32_t SerializeByJson(BrCtlMessageSerializationContext ctx, char **outData, uint32_t *outDataLen)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (ctx.method == BR_METHOD_NOTIFY_REQUEST) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, BR_METHOD_NOTIFY_REQUEST) ||
            !AddNumberToJsonObject(json, KEY_DELTA, ctx.referenceRequest.delta) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, ctx.referenceRequest.referenceNumber)) {
            cJSON_Delete(json);
            return SOFTBUS_CREATE_JSON_ERR;
        }
    } else if (ctx.method == BR_METHOD_NOTIFY_RESPONSE) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, BR_METHOD_NOTIFY_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, ctx.referenceResponse.referenceNumber)) {
            cJSON_Delete(json);
            return SOFTBUS_CREATE_JSON_ERR;
        }
    } else if (ctx.method == BR_METHOD_NOTIFY_ACK) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, BR_METHOD_NOTIFY_ACK) ||
            !AddNumberToJsonObject(json, KEY_WINDOWS, ctx.ackRequestResponse.window) ||
            !AddNumber64ToJsonObject(json, KEY_ACK_SEQ_NUM, ctx.ackRequestResponse.seq)) {
            cJSON_Delete(json);
            return SOFTBUS_CREATE_JSON_ERR;
        }
    } else if (ctx.method == BR_METHOD_ACK_RESPONSE) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, BR_METHOD_ACK_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_WINDOWS, ctx.ackRequestResponse.window) ||
            !AddNumber64ToJsonObject(json, KEY_ACK_SEQ_NUM, ctx.ackRequestResponse.seq)) {
            cJSON_Delete(json);
            return SOFTBUS_CREATE_JSON_ERR;
        }
    } else {
        cJSON_Delete(json);
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
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

int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outDataLen)
{
    static int64_t ctlMsgSeqGenerator = 0;
    int64_t seq = ctlMsgSeqGenerator++;

    char *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = SerializeByJson(ctx, &data, &dataLen);
    if (ret != SOFTBUS_OK) {
        CLOGE("br connecion %u pack ctl message failed: serialize json bytes failed, method: %d", ctx.connectionId,
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
    ConnPktHead head = { 0 };
    head.magic = MAGIC_NUMBER;
    head.module = MODULE_CONNECTION;
    head.seq = seq;
    head.flag = ctx.flag;
    head.len = dataLen;
    PackConnPktHead(&head);
    if (memcpy_s(buf, bufLen, &head, headSize) != EOK) {
        CLOGE("br connecion %u pack ctl message failed: memcpy connection header failed, method: %d", ctx.connectionId,
            ctx.method);
        cJSON_free(data);
        SoftBusFree(buf);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(buf + headSize, bufLen - headSize, data, dataLen) != EOK) {
        CLOGE("br connecion %u pack ctl message failed: memcpy ctl message bytes failed, method: %d", ctx.connectionId,
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

static void FreeSendNode(SendBrQueueNode *node)
{
    if (node->data != NULL) {
        SoftBusFree(node->data);
    }
    SoftBusFree(node);
}

int32_t ConnBrPostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    CONN_CHECK_AND_RETURN_RET_LOG(data != NULL, SOFTBUS_INVALID_PARAM,
        "br post bytes failed: invalid param, data is null, connectionId=%u, pid=%d, "
        "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
        connectionId, pid, len, flag, module, seq);

    if (len == 0 || len > MAX_DATA_LEN) {
        CLOGE("br post bytes failed, invalid param, data len is 0, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connectionId, pid, len, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_INVALID_PARAM;
    }

    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("br post bytes failed: connection is not exist, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connectionId, pid, len, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR;
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("br post bytes failed: try to lock failed, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), error=%d",
            connectionId, pid, len, flag, module, seq, status);
        ConnBrReturnConnection(&connection);
        SoftBusFree(data);
        return SOFTBUS_LOCK_ERR;
    }
    enum ConnBrConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBrReturnConnection(&connection);
    if (state != BR_CONNECTION_STATE_CONNECTED && module != MODULE_CONNECTION) {
        CLOGE("br post bytes failed: connection is not ready, state=%d, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            state, connectionId, pid, len, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_CONN_BR_CONNECTION_NOT_READY_ERR;
    }

    SendBrQueueNode *node = (SendBrQueueNode *)SoftBusCalloc(sizeof(SendBrQueueNode));
    if (node == NULL) {
        CLOGE("br post bytes failed: calloc queue node failed, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connectionId, pid, len, flag, module, seq);
        SoftBusFree(data);
        return SOFTBUS_MEM_ERR;
    }
    node->connectionId = connectionId;
    node->data = data;
    node->len = len;
    node->pid = pid;
    node->flag = flag;
    node->module = module;
    node->seq = seq;
    node->isInner = (pid == 0);
    status = ConnBrEnqueueNonBlock((const void *)node);
    if (status != SOFTBUS_OK) {
        CLOGE("br post bytes failed: enqueue failed, error=%d, connection id=%u, pid=%d, "
              "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            status, connectionId, pid, len, flag, module, seq);
        FreeSendNode(node);
        return status;
    }
    CLOGE("br post bytes: receive post byte request, connection id=%u, pid=%d, "
          "payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
        connectionId, pid, len, flag, module, seq);
    return SOFTBUS_OK;
}

// call this method MUST wrapper connection lock
static int32_t SendAckUnsafe(const ConnBrConnection *connection)
{
    int32_t flag = CONN_HIGH;
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connection->connectionId,
        .flag = flag,
        .method = BR_METHOD_NOTIFY_ACK,
        .ackRequestResponse = {
            .window = connection->window,
            .seq = connection->sequence,
        },
    };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t ctrlMsgSeq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    if (ctrlMsgSeq < 0) {
        CLOGW("br send ack failed: pack message failed, connection id=%u, window=%d, seq=%" PRId64 ", error=%d",
            connection->connectionId, connection->window, connection->sequence, (int32_t)ctrlMsgSeq);
        return (int32_t)ctrlMsgSeq;
    }
    int32_t status = ConnBrCreateBrPendingPacket(connection->connectionId, connection->sequence);
    if (status != SOFTBUS_OK) {
        CLOGW("br send ack failed: create pending failed, connection id=%u, window=%d, seq=%" PRId64 ", error=%d",
            connection->connectionId, connection->window, connection->sequence, status);
        SoftBusFree(data);
        return status;
    }
    status = BrTransSend(connection->connectionId, connection->socketHandle, connection->mtu, data, dataLen);
    if (status != SOFTBUS_OK) {
        ConnBrDelBrPendingPacket(connection->connectionId, connection->sequence);
    }
    CLOGI("br send ack, connection id=%u, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), error=%d",
        connection->connectionId, dataLen, flag, MODULE_CONNECTION, ctrlMsgSeq, status);
    SoftBusFree(data);
    return status;
}

static void WaitAck(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK,
        "wait ack failed: try to lock failed, connection id=%u", connection->connectionId);
    int64_t waitSequence = connection->waitSequence;
    SoftBusMutexUnlock(&connection->lock);

    void *ignore = NULL;
    int32_t ret = ConnBrGetBrPendingPacket(connection->connectionId, waitSequence, WAIT_ACK_TIMEOUT_MILLS, &ignore);
    SoftBusFree(ignore);

    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK,
        "wait ack failed: try to lock failed after pending, connection id=%u", connection->connectionId);
    switch (ret) {
        case SOFTBUS_ALREADY_TRIGGERED:
            connection->ackTimeoutCount = 0;
            connection->window = connection->window < MAX_WINDOW ? connection->window + 1 : MAX_WINDOW;
            break;
        case SOFTBUS_OK:
            connection->ackTimeoutCount = 0;
            break;
        case SOFTBUS_TIMOUT:
            connection->ackTimeoutCount += 1;
            if (connection->window > MIN_WINDOW && connection->ackTimeoutCount % TIMEOUT_TIMES == 0) {
                connection->window = connection->window - 1;
            }
            if (connection->window < DEFAULT_WINDOW && connection->ackTimeoutCount > ACK_FAILED_TIMES) {
                connection->window = DEFAULT_WINDOW;
            }
            break;
        default:
            connection->ackTimeoutCount = 0;
            break;
    }
    connection->waitSequence = 0;
    SoftBusMutexUnlock(&connection->lock);
}

void *SendHandlerLoop(void *arg)
{
    (void)arg;
    CLOGI("br send data: send loop start");
    SendBrQueueNode *sendNode = NULL;
    while (true) {
        int32_t status = ConnBrDequeueBlock((void **)(&sendNode));
        if (status != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! br send data failed: br dequeue send node failed, error=%d", status);
            continue;
        }
        ConnBrConnection *connection = ConnBrGetConnectionById(sendNode->connectionId);
        if (connection == NULL) {
            CLOGE("br send data failed: connection is not exist, connection id=%u", sendNode->connectionId);
            g_transEventListener.onPostByteFinshed(sendNode->connectionId, sendNode->len, sendNode->pid, sendNode->flag,
                sendNode->module, sendNode->seq, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR);
            FreeSendNode(sendNode);
            continue;
        }

        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CLOGE("br send data failed: try to lock failed, connection id=%u", sendNode->connectionId);
            g_transEventListener.onPostByteFinshed(sendNode->connectionId, sendNode->len, sendNode->pid, sendNode->flag,
                sendNode->module, sendNode->seq, SOFTBUS_LOCK_ERR);
            ConnBrReturnConnection(&connection);
            FreeSendNode(sendNode);
            continue;
        }

        int32_t sockerHandle = connection->socketHandle;
        if (sockerHandle == INVALID_SOCKET_HANDLE) {
            CLOGE("br send data failed: invalid socket, connection id=%u", sendNode->connectionId);
            (void)SoftBusMutexUnlock(&connection->lock);
            ConnBrReturnConnection(&connection);
            g_transEventListener.onPostByteFinshed(sendNode->connectionId, sendNode->len, sendNode->pid, sendNode->flag,
                sendNode->module, sendNode->seq, SOFTBUS_CONN_BR_CONNECTION_INVALID_SOCKET);
            FreeSendNode(sendNode);
            continue;
        }

        connection->sequence += 1;
        if (connection->sequence % connection->window == 0) {
            if (SendAckUnsafe(connection) == SOFTBUS_OK) {
                connection->waitSequence = connection->sequence;
            }
        }
        int32_t window = connection->window;
        int64_t sequence = connection->sequence;
        int64_t waitSequence = connection->waitSequence;
        (void)SoftBusMutexUnlock(&connection->lock);

        if (window > 1 && sequence % window == window - 1 && waitSequence != 0) {
            WaitAck(connection);
        }
        status = BrTransSend(connection->connectionId, sockerHandle, connection->mtu, sendNode->data, sendNode->len);
        ConnBrReturnConnection(&connection);
        CLOGE("br send data, connection id=%u, status=%d", sendNode->connectionId, status);
        g_transEventListener.onPostByteFinshed(sendNode->connectionId, sendNode->len, sendNode->pid, sendNode->flag,
            sendNode->module, sendNode->seq, status);
        FreeSendNode(sendNode);
        sendNode = NULL;
    }
    return NULL;
}

int32_t ConnBrTransMuduleInit(SppSocketDriver *sppDriver, ConnBrTransEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        sppDriver != NULL, SOFTBUS_INVALID_PARAM, "init br trans module failed: invaliad param, sppDriver is null");
    CONN_CHECK_AND_RETURN_RET_LOG(sppDriver->Read != NULL, SOFTBUS_INVALID_PARAM,
        "init br trans module failed: invaliad param, sppDriver->Read is null");
    CONN_CHECK_AND_RETURN_RET_LOG(sppDriver->Write != NULL, SOFTBUS_INVALID_PARAM,
        "init br trans module failed: invaliad param, sppDriver->Write is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        listener != NULL, SOFTBUS_INVALID_PARAM, "init br trans module failed: invaliad param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onPostByteFinshed != NULL, SOFTBUS_INVALID_PARAM,
        "init br trans module failed: invaliad param, listener->onPostByteFinshed is null");

    int32_t status = ConnBrInnerQueueInit();
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, status, "init br trans module failed: init br send queue failed, error=%d", status);

    status = ConnStartActionAsync(NULL, SendHandlerLoop);
    if (status != SOFTBUS_OK) {
        return status;
    }

    g_sppDriver = sppDriver;
    g_transEventListener = *listener;
    return SOFTBUS_OK;
}
