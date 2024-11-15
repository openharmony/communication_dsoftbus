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

#include "trans_pending_pkt.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define MSG_TIMEOUT_S 20
#define UDP_TIMEOUT_US (150 * 1000)
#define MAX_US (1 * 1000 * 1000)

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
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t PendingInit(int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d ", type);
        return ret;
    }

    g_pendingList[type] = CreateSoftBusList();
    if (g_pendingList[type] == NULL) {
        TRANS_LOGE(TRANS_SVC, "pending init fail");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void PendingDeinit(int32_t type)
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

static void FormalizeTimeFormat(SoftBusSysTime *outTime, int32_t type)
{
    SoftBusSysTime now;
    SoftBusGetTime(&now);
    outTime->sec = (type == PENDING_TYPE_UDP) ? now.sec : now.sec + MSG_TIMEOUT_S;
    outTime->usec = (type == PENDING_TYPE_UDP) ? now.usec + UDP_TIMEOUT_US : now.usec;

    while (outTime->usec >= MAX_US) {
        outTime->usec -= MAX_US;
        outTime->sec += 1;
        TRANS_LOGI(TRANS_SVC,
            "us over limit, after formalize, us=%{public}" PRId64 "sec=%{public}" PRId64, outTime->usec, outTime->sec);
    }
}

int32_t AddPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SVC, "type=%{public}d illegal", type);

    SoftBusList *pendingList = g_pendingList[type];
    TRANS_CHECK_AND_RETURN_RET_LOGE(pendingList != NULL, SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND, TRANS_SVC,
        "type=%{public}d pending list not init", type);

    ret = SoftBusMutexLock(&pendingList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SVC, "pending list lock failed");
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            TRANS_LOGW(TRANS_SVC, "PendingPacket already Created");
            (void)SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_PENDING;
        }
    }

    item = CreatePendingItem(channelId, seqNum);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&pendingList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    ListAdd(&pendingList->list, &item->node);
    TRANS_LOGI(TRANS_SVC, "add channelId=%{public}d", item->channelId);
    pendingList->cnt++;
    (void)SoftBusMutexUnlock(&pendingList->lock);
    return SOFTBUS_OK;
}

static PendingPktInfo *GetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return NULL;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not init. type=%{public}d", type);
        return NULL;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "set pending lock failed.");
        return NULL;
    }
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            (void)SoftBusMutexUnlock(&pendingList->lock);
            return item;
        }
    }
    TRANS_LOGI(TRANS_SVC, "not found channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&pendingList->lock);
    return NULL;
}

void DelPendingPacketbyChannelId(int32_t channelId, int32_t seqNum, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not init. type=%{public}d", type);
        return;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "set pending lock failed.");
        return;
    }
    PendingPktInfo *item = NULL;
    PendingPktInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_SVC, "delete channelId=%{public}d", item->channelId);
            pendingList->cnt--;
            (void)SoftBusMutexUnlock(&pendingList->lock);
            ReleasePendingItem(item);
            return;
        }
    }
    TRANS_LOGI(TRANS_SVC, "not found channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&pendingList->lock);
}

int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SVC, "type=%{public}d illegal", type);

    SoftBusList *pendingList = g_pendingList[type];
    TRANS_CHECK_AND_RETURN_RET_LOGE(pendingList != NULL, SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND, TRANS_SVC,
        "type=%{public}d pending list not init", type);

    SoftBusSysTime outTime;
    FormalizeTimeFormat(&outTime, type);

    PendingPktInfo *item = GetPendingPacket(channelId, seqNum, type);
    TRANS_CHECK_AND_RETURN_RET_LOGE(item != NULL, SOFTBUS_NOT_FIND, TRANS_SVC, "pending item not found");
    ret = SoftBusMutexLock(&item->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SVC, "pending item lock failed");
    while (item->status == PACKAGE_STATUS_PENDING && TimeBefore(&outTime)) {
        SoftBusCondWait(&item->cond, &item->lock, &outTime);
    }
    int32_t errCode = (item->status == PACKAGE_STATUS_FINISHED) ? SOFTBUS_OK : SOFTBUS_TIMOUT;
    (void)SoftBusMutexUnlock(&item->lock);

    ret = SoftBusMutexLock(&pendingList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SVC, "pending list lock failed");
    ListDelete(&item->node);
    TRANS_LOGI(TRANS_SVC, "delete channelId=%{public}d", item->channelId);
    pendingList->cnt--;
    (void)SoftBusMutexUnlock(&pendingList->lock);
    ReleasePendingItem(item);
    return errCode;
}

int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return ret;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not init. type=%{public}d", type);
        return SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "set pending lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            item->status = PACKAGE_STATUS_FINISHED;
            SoftBusCondSignal(&item->cond);
            (void)SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&pendingList->lock);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t DelPendingPacket(int32_t channelId, int32_t type)
{
    int32_t ret = IsPendingListTypeLegal(type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "type illegal. type=%{public}d", type);
        return ret;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "pending type list not init. type=%{public}d", type);
        return SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND;
    }
    if (SoftBusMutexLock(&pendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "del pending lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    PendingPktInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->channelId == channelId) {
            item->status = PACKAGE_STATUS_CANCELED;
            SoftBusCondSignal(&item->cond);
            (void)SoftBusMutexUnlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&pendingList->lock);
    return SOFTBUS_OK;
}

