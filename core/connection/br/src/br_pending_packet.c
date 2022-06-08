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
#include <stdint.h>
#include <string.h>

#include "br_pending_packet.h"

#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

typedef struct {
    ListNode node;
    uint32_t id;
    uint64_t seq;
    void *data;
    bool finded;
    SoftBusCond cond;
    SoftBusMutex lock;
} PendingPacket;

static SoftBusMutex g_pendingLock;
static LIST_HEAD(g_pendingList);

int32_t InitBrPendingPacket(void)
{
    if (SoftBusMutexInit(&g_pendingLock, NULL) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void DestroyBrPendingPacket(void)
{
    (void)SoftBusMutexDestroy(&g_pendingLock);
}

int32_t CreateBrPendingPacket(uint32_t id, uint64_t seq)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    PendingPacket *pending = NULL;
    LIST_FOR_EACH_ENTRY(pending, &g_pendingList, PendingPacket, node) {
        if (pending->id == id && pending->seq == seq) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PendingPacket existed. id: %u, seq: %" PRIu64, id, seq);
            (void)SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }
    pending = (PendingPacket *)SoftBusCalloc(sizeof(PendingPacket));
    if (pending == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateBrPendingPacket SoftBusCalloc failed");
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
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&pending->cond) != SOFTBUS_OK) {
        SoftBusMutexDestroy(&pending->lock);
        SoftBusFree(pending);
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_pendingList, &(pending->node));
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_OK;
}

void DelBrPendingPacket(uint32_t id, uint64_t seq)
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

int32_t GetBrPendingPacket(uint32_t id, uint64_t seq, uint32_t waitMillis, void **data)
{
#define USECTONSEC 1000LL
    if (data == NULL || SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
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
        int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + waitMillis * USECTONSEC;
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

int32_t SetBrPendingPacket(uint32_t id, uint64_t seq, void *data)
{
    PendingPacket *item = NULL;
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetBrPendingPacket SoftBusMutexLock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_pendingList, PendingPacket, node) {
        if (item->seq == seq && item->id == id) {
            SoftBusMutexLock(&item->lock);
            item->finded = true;
            item->data = data;
            SoftBusCondSignal(&item->cond);
            SoftBusMutexUnlock(&item->lock);
            SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_ERR;
}
