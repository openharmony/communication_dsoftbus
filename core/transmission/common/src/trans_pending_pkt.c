/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "trans_pending_pkt.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define TIME_OUT 20

typedef struct {
    ListNode node;
    SoftBusCond cond;
    SoftBusMutex lock;
    int32_t channelId;
    int32_t seq;
    uint8_t status;
} PendingPktInfo;

enum PackageStatus {
    PACKAGE_STATUS_PENDING = 0,
    PACKAGE_STATUS_FINISHED,
    PACKAGE_STATUS_CANCELED
};

static SoftBusList *g_pendingList[PENDING_TYPE_BUTT] = {NULL, NULL};

static int32_t IsPendingListTypeLegal(int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t PendingInit(int type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d ", type);
        return SOFTBUS_ERR;
    }

    g_pendingList[type] = CreateSoftBusList();
    if (g_pendingList[type] == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void PendingDeinit(int type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return;
    }

    if (g_pendingList[type] != NULL) {
        DestroySoftBusList(g_pendingList[type]);
        g_pendingList[type] = NULL;
    }
    TRANS_LOGI(TRANS_INIT, "PendigPackManagerDeinit init ok");
}

static inline bool TimeBefore(const SoftBusSysTime *inputTime)
{
    SoftBusSysTime now;
    SoftBusGetTime(&now);
    return (now.sec < inputTime->sec || (now.sec == inputTime->sec && now.usec < inputTime->usec));
}

static PendingPktInfo *CreatePendingItem(int32_t channelId, int32_t seqNum)
{
    PendingPktInfo *item = (PendingPktInfo *)SoftBusCalloc(sizeof(PendingPktInfo));
    if (item == NULL) {
        return NULL;
    }

    SoftBusMutexInit(&item->lock, NULL);
    SoftBusCondInit(&item->cond);
    item->channelId = channelId;
    item->seq = seqNum;
    item->status = PACKAGE_STATUS_PENDING;
    return item;
}

static void ReleasePendingItem(PendingPktInfo *item)
{
    if (item == NULL) {
        return;
    }
    (void)SoftBusMutexDestroy(&item->lock);
    (void)SoftBusCondDestroy(&item->cond);
    SoftBusFree(item);
}

int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int type)
{
    int32_t result = IsPendingListTypeLegal(type);
    if (result != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return SOFTBUS_ERR;
    }

    PendingPktInfo *item = NULL;
    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not inited. type=%{public}d", type);
        return SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND;
    }

    SoftBusMutexLock(&pendingList->lock);
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node)
    {
        if (item->seq == seqNum && item->channelId == channelId) {
            TRANS_LOGW(TRANS_SVC, "PendingPacket already Created");
            SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_PENDING;
        }
    }

    item = CreatePendingItem(channelId, seqNum);
    if (item == NULL) {
        SoftBusMutexUnlock(&pendingList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListAdd(&pendingList->list, &item->node);
    TRANS_LOGI(TRANS_SVC, "add channelId = %{public}d", item->channelId);
    pendingList->cnt++;
    SoftBusMutexUnlock(&pendingList->lock);

    SoftBusSysTime outtime;
    SoftBusSysTime now;
    SoftBusGetTime(&now);
    outtime.sec = now.sec + TIME_OUT;
    outtime.usec = now.usec;
    SoftBusMutexLock(&item->lock);
    while (item->status == PACKAGE_STATUS_PENDING && TimeBefore(&outtime)) {
        SoftBusCondWait(&item->cond, &item->lock, &outtime);
    }

    int32_t ret = SOFTBUS_OK;
    if (item->status != PACKAGE_STATUS_FINISHED) {
        ret = SOFTBUS_TIMOUT;
    }
    SoftBusMutexUnlock(&item->lock);

    SoftBusMutexLock(&pendingList->lock);
    ListDelete(&item->node);
    TRANS_LOGI(TRANS_SVC, "delete channelId = %{public}d", item->channelId);
    pendingList->cnt--;
    SoftBusMutexUnlock(&pendingList->lock);
    ReleasePendingItem(item);
    return ret;
}

int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return SOFTBUS_ERR;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not inited. type=%{public}d", type);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "set pendind lock failed.");
        return SOFTBUS_ERR;
    }
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            item->status = PACKAGE_STATUS_FINISHED;
            SoftBusCondSignal(&item->cond);
            SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&pendingList->lock);
    return SOFTBUS_ERR;
}

int32_t DelPendingPacket(int32_t channelId, int type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return SOFTBUS_ERR;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not inited. type=%{public}d", type);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "del pendind lock failed.");
        return SOFTBUS_ERR;
    }
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->channelId == channelId) {
            item->status = PACKAGE_STATUS_CANCELED;
            SoftBusCondSignal(&item->cond);
            SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&pendingList->lock);
    return SOFTBUS_OK;
}

