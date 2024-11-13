/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <inttypes.h>
#include <stdbool.h>

#include "client_trans_pending.h"

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_log.h"

typedef struct {
    ListNode node;
    uint32_t id;
    uint64_t seq;
    bool finded;
    SoftBusCond cond;
    SoftBusMutex lock;
    TransPendData data;
} PendingPacket;

static SoftBusMutex g_pendingLock;
static LIST_HEAD(g_pendingList);

#define USECTONSEC 1000LL

int32_t InitPendingPacket(void)
{
    if (SoftBusMutexInit(&g_pendingLock, NULL) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void DestroyPendingPacket(void)
{
    (void)SoftBusMutexDestroy(&g_pendingLock);
}

static int32_t CheckPendingPacketExisted(uint32_t id, uint64_t seq)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Check pending packet is exist, lock error.");
        return SOFTBUS_LOCK_ERR;
    }
    PendingPacket *pending = NULL;
    LIST_FOR_EACH_ENTRY(pending, &g_pendingList, PendingPacket, node) {
        if (pending->id == id && pending->seq == seq) {
            TRANS_LOGE(TRANS_SDK, "PendingPacket existed. pendingId=%{public}u, pendingSeq=%{public}" PRIu64, id, seq);
            (void)SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_OK;
}

int32_t CreatePendingPacket(uint32_t id, uint64_t seq)
{
    int32_t ret = CheckPendingPacketExisted(id, seq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "Check pending packet is exist, ret=%{public}d.", ret);
        return ret;
    }

    PendingPacket *pending = (PendingPacket *)SoftBusCalloc(sizeof(PendingPacket));
    if (pending == NULL) {
        TRANS_LOGE(TRANS_SDK, "SoftBusCalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&pending->node);
    pending->id = id;
    pending->seq = seq;
    pending->data.data = NULL;
    pending->data.len = 0;
    pending->finded = false;
    if (SoftBusMutexInit(&pending->lock, NULL) != SOFTBUS_OK) {
        SoftBusFree(pending);
        TRANS_LOGE(TRANS_SDK, "init lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&pending->cond) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "condInit fail");
        goto EXIT;
    }
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock fail");
        goto EXIT;
    }
    ListTailInsert(&g_pendingList, &(pending->node));
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_OK;
EXIT:
    SoftBusMutexDestroy(&pending->lock);
    SoftBusFree(pending);
    return SOFTBUS_NO_INIT;
}

void DeletePendingPacket(uint32_t id, uint64_t seq)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "mutex lock fail");
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

static void ComputeWaitPendTime(uint32_t waitMillis, SoftBusSysTime *outtime)
{
    SoftBusSysTime now;
    (void)SoftBusGetTime(&now);
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + (int64_t)waitMillis * USECTONSEC;
    outtime->sec = time / USECTONSEC / USECTONSEC;
    outtime->usec = time % (USECTONSEC * USECTONSEC);
}

static int32_t TransPendWaitTime(const PendingPacket *pending, TransPendData *data, uint32_t waitMillis)
{
    if (pending->finded) {
        data->data = pending->data.data;
        data->len = pending->data.len;
        return SOFTBUS_ALREADY_TRIGGERED;
    }
    SoftBusSysTime outtime;
    ComputeWaitPendTime(waitMillis, &outtime);
    while (1) {
        (void)SoftBusCondWait((SoftBusCond *)(&pending->cond), (SoftBusMutex *)(&pending->lock), &outtime);
        if (pending->finded) {
            data->data = pending->data.data;
            data->len = pending->data.len;
            return SOFTBUS_OK;
        }
        SoftBusSysTime now;
        ComputeWaitPendTime(0, &now);
        if (now.sec > outtime.sec || (now.sec == outtime.sec && now.usec >= outtime.usec)) {
            break;
        }
    }
    return SOFTBUS_TIMOUT;
}

int32_t GetPendingPacketData(uint32_t id, uint64_t seq, uint32_t waitMillis, bool isDelete, TransPendData *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "mutex lock fail");
        return SOFTBUS_LOCK_ERR;
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

    int32_t ret;
    if (SoftBusMutexLock(&pending->lock) != SOFTBUS_OK) {
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT;
    }
    ret = TransPendWaitTime(pending, data, waitMillis);
    (void)SoftBusMutexUnlock(&pending->lock);
EXIT:
    (void)SoftBusMutexLock(&g_pendingLock);
    if (isDelete || ret != SOFTBUS_TIMOUT) {
        ListDelete(&pending->node);
        SoftBusMutexDestroy(&pending->lock);
        SoftBusCondDestroy(&pending->cond);
        SoftBusFree(pending);
    }
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return ret;
}

int32_t SetPendingPacketData(uint32_t id, uint64_t seq, const TransPendData *data)
{
    if (SoftBusMutexLock(&g_pendingLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "mutex lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    PendingPacket *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_pendingList, PendingPacket, node) {
        if (item->seq == seq && item->id == id) {
            if (SoftBusMutexLock(&item->lock) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "mutex lock fail");
                (void)SoftBusMutexUnlock(&g_pendingLock);
                return SOFTBUS_LOCK_ERR;
            }
            item->finded = true;
            if (data != NULL) {
                item->data.data = data->data;
                item->data.len = data->len;
            }
            SoftBusCondSignal(&item->cond);
            (void)SoftBusMutexUnlock(&item->lock);
            (void)SoftBusMutexUnlock(&g_pendingLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_pendingLock);
    return SOFTBUS_NOT_FIND;
}