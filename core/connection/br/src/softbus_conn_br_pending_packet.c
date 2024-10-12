/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <stdbool.h>

#include "softbus_conn_br_pending_packet.h"

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_trans.h"
#include "softbus_def.h"

typedef struct {
    ListNode node;
    uint32_t id;
    int64_t seq;
    void *data;
    bool finded;
    SoftBusCond cond;
    SoftBusMutex lock;
} PendingPacket;

static SoftBusMutex g_pendingLock;
static LIST_HEAD(g_pendingList);

int32_t ConnBrInitBrPendingPacket(void)
{
    if (SoftBusMutexInit(&g_pendingLock, NULL) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    PendingPacket *pending = NULL;
    LIST_FOR_EACH_ENTRY(pending, &g_pendingList, PendingPacket, node) {
        if (pending->id == id && pending->seq == seq) {
            CONN_LOGW(CONN_BR, "PendingPacket exist, id=%{public}u, seq=%{public}" PRId64, id, seq);
            (void)SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }
    pending = (PendingPacket *)SoftBusCalloc(sizeof(PendingPacket));
    if (pending == NULL) {
        CONN_LOGE(CONN_BR, "calloc failed, id=%{public}u, seq=%{public}" PRId64, id, seq);
        (void)SoftBusMutexUnlock(&g_pendingLock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&pending->node);
    pending->id = id;
    pending->seq = seq;
    pending->data = NULL;
    pending->finded = false;
    if (SoftBusMutexInit(&pending->lock, NULL) != SOFTBUS_OK) {
        SoftBusFree(pending);
        (void)SoftBusMutexUnlock(&g_pendingLock);
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&pending->cond) != SOFTBUS_OK) {
        SoftBusMutexDestroy(&pending->lock);
        SoftBusFree(pending);
        (void)SoftBusMutexUnlock(&g_pendingLock);
        return SOFTBUS_NO_INIT;
    }
    ListTailInsert(&g_pendingList, &(pending->node));
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_OK;
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        return;
    }
    PendingPacket *pending = NULL;
    LIST_FOR_EACH_ENTRY(pending, &g_pendingList, PendingPacket, node) {
        if (pending->id == id && pending->seq == seq) {
            ListDelete(&pending->node);
            SoftBusCondSignal(&pending->cond);
            SoftBusMutexDestroy(&pending->lock);
            SoftBusCondDestroy(&pending->cond);
            SoftBusFree(pending);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_pendingLock);
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
#define USECTONSEC 1000LL
    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BR, "invalid param");
    CONN_CHECK_AND_RETURN_RET_LOGW(SoftBusMutexLock(&g_pendingLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BR, "lock failed");
    PendingPacket *pending = NULL;
    PendingPacket *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_pendingList, PendingPacket, node) {
        if (item->id == id && item->seq == seq) {
            pending = item;
        }
    }
    if (pending == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingLock);
        return SOFTBUS_NOT_FIND;
    }
    (void)SoftBusMutexUnlock(&g_pendingLock);

    int32_t ret = SOFTBUS_OK;
    if (SoftBusMutexLock(&pending->lock) != SOFTBUS_OK) {
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT;
    }
    if (pending->finded) {
        *data = pending->data;
        ret = SOFTBUS_ALREADY_TRIGGERED;
    } else {
        SoftBusSysTime outtime;
        SoftBusSysTime now;
        (void)SoftBusGetTime(&now);
        int64_t time = (now.sec * USECTONSEC * USECTONSEC + now.usec + (int64_t)(waitMillis * USECTONSEC));
        outtime.sec = time / USECTONSEC / USECTONSEC;
        outtime.usec = time % (USECTONSEC * USECTONSEC);
        (void)SoftBusCondWait(&pending->cond, &pending->lock, &outtime);
        if (pending->finded) {
            *data = pending->data;
        } else {
            ret = SOFTBUS_TIMOUT;
        }
    }
    (void)SoftBusMutexUnlock(&pending->lock);
EXIT:
    (void)SoftBusMutexLock(&g_pendingLock);
    ListDelete(&pending->node);
    SoftBusMutexDestroy(&pending->lock);
    SoftBusCondDestroy(&pending->cond);
    SoftBusFree(pending);
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return ret;
}

int32_t ConnBrSetBrPendingPacket(uint32_t id, int64_t seq, void *data)
{
    PendingPacket *item = NULL;
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_pendingList, PendingPacket, node) {
        if (item->seq == seq && item->id == id) {
            if (SoftBusMutexLock(&item->lock) != SOFTBUS_OK) {
                SoftBusMutexUnlock(&g_pendingLock);
                return SOFTBUS_LOCK_ERR;
            }
            item->finded = true;
            item->data = data;
            SoftBusCondSignal(&item->cond);
            SoftBusMutexUnlock(&item->lock);
            SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_CONN_BR_SET_PENDING_PACKET_ERR;
}

int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BR, "invalid param");
    int32_t peerWindows = 0;
    int64_t peerSeq = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_WINDOWS, &peerWindows) ||
        !GetJsonObjectNumber64Item(json, KEY_ACK_SEQ_NUM, &peerSeq)) {
        CONN_LOGE(CONN_BR, "parse window or seq failed, connId=%{public}u", connection->connectionId);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connId=%{public}u, error=%{public}d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }

    int32_t localWindows = connection->window;
    (void)SoftBusMutexUnlock(&connection->lock);

    CONN_LOGD(CONN_BR,
        "ack request message: connId=%{public}u, localWindow=%{public}d, peerWindow=%{public}d, "
        "peerSeq=%{public}" PRId64,
        connection->connectionId, localWindows, peerWindows, peerSeq);

    int32_t flag = CONN_HIGH;
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connection->connectionId,
        .flag = flag,
        .method = BR_METHOD_ACK_RESPONSE,
        .ackRequestResponse = {
            .window = localWindows,
            .seq = peerSeq,
        },
    };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    if (seq < 0) {
        CONN_LOGE(CONN_BR,
            "pack msg failed: connId=%{public}u, localWindow=%{public}d, peeWindow=%{public}d, "
            "peerSeq=%{public}" PRId64 ", error=%{public}d",
            connection->connectionId, localWindows, peerWindows, peerSeq, (int32_t)seq);
        return (int32_t)seq;
    }
    return ConnBrPostBytes(connection->connectionId, data, dataLen, 0, flag, MODULE_CONNECTION, seq);
}

int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json)
{
    int32_t peerWindows = 0;
    uint64_t seq = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_WINDOWS, &peerWindows) ||
        !GetJsonObjectNumber64Item(json, KEY_ACK_SEQ_NUM, (int64_t *)&seq)) {
        CONN_LOGE(CONN_BR, "parse window or seq fields failed, connId=%{public}u", connection->connectionId);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    CONN_LOGD(CONN_BR, "connId=%{public}u, peerWindow=%{public}d, seq=%{public}" PRId64, connection->connectionId,
        peerWindows, seq);
    int32_t status = ConnBrSetBrPendingPacket(connection->connectionId, (int64_t)seq, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR,
            "set br pending packet failed, connId=%{public}u, error=%{public}d", connection->connectionId, status);
    }
    return status;
}
