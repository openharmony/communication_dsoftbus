/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_conn_flow_control.h"

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"

typedef uint64_t timestamp_t;
struct HistoryNode {
    ListNode node;

    timestamp_t timestamp;
    int32_t amount;
};

static int32_t Apply(struct ConnSlideWindowController *self, int32_t expect)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(self, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid parameter, controller is null");

    int32_t status = SoftBusMutexLock(&self->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock failed");
    if (!self->active) {
        (void)SoftBusMutexUnlock(&self->lock);
        return expect;
    }
    struct HistoryNode *it = NULL;
    struct HistoryNode *next = NULL;
    int32_t appliedTotal = 0;
    timestamp_t now = SoftBusGetSysTimeMs();
    timestamp_t expiredTimestamp = now - self->windowInMillis;
    timestamp_t currentWindowStartTimestamp = 0;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &self->histories, struct HistoryNode, node) {
        if (it->timestamp > expiredTimestamp) {
            appliedTotal += it->amount;
            currentWindowStartTimestamp = it->timestamp;
        } else {
            ListDelete(&it->node);
            SoftBusFree(it);
        }
    }

    if (self->quotaInBytes <= appliedTotal) {
        unsigned int sleepMs = self->windowInMillis - (now - currentWindowStartTimestamp);
        (void)SoftBusMutexUnlock(&self->lock);
        SoftBusSleepMs(sleepMs);
        return Apply(self, expect);
    }
    int32_t remain = self->quotaInBytes - appliedTotal;
    int32_t amount = remain > expect ? expect : remain;
    struct HistoryNode *history = SoftBusCalloc(sizeof(*history));
    if (history == NULL) {
        (void)SoftBusMutexUnlock(&self->lock);
        return expect;
    }
    ListInit(&history->node);
    history->amount = amount;
    history->timestamp = now;
    ListAdd(&self->histories, &history->node);

    (void)SoftBusMutexUnlock(&self->lock);
    return amount;
}

static void CleanupHistoriesUnsafe(struct ConnSlideWindowController *self)
{
    struct HistoryNode *it = NULL;
    struct HistoryNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &self->histories, struct HistoryNode, node) {
        ListDelete(&it->node);
        SoftBusFree(it);
    }
}

static int32_t ChangeConfiguration(
    struct ConnSlideWindowController *self, bool active, int32_t windowInMillis, int32_t quotaInBytes)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(self, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid parameter, controller is null");
    if (active) {
        CONN_CHECK_AND_RETURN_RET_LOGE(windowInMillis >= MIN_WINDOW_IN_MILLIS && windowInMillis <= MAX_WINDOW_IN_MILLIS,
            SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid parameter, window=%u", windowInMillis);
        CONN_CHECK_AND_RETURN_RET_LOGE(quotaInBytes >= MIN_QUOTA_IN_BYTES && quotaInBytes <= MAX_QUOTA_IN_BYTES,
            SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid parameter, quota=%u", quotaInBytes);
    }

    int32_t status = SoftBusMutexLock(&self->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock failed");

    self->windowInMillis = windowInMillis;
    self->quotaInBytes = quotaInBytes;
    self->active = active;
    // cleanup histories as configuration change
    CleanupHistoriesUnsafe(self);
    (void)SoftBusMutexUnlock(&self->lock);
    return SOFTBUS_OK;
}

static int32_t Enable(struct ConnSlideWindowController *self, int32_t windowInMillis, int32_t quotaInBytes)
{
    return ChangeConfiguration(self, true, windowInMillis, quotaInBytes);
}

static int32_t Disable(struct ConnSlideWindowController *self)
{
    return ChangeConfiguration(self, false, -1, -1);
}

int32_t ConnSlideWindowControllerConstructor(struct ConnSlideWindowController *self)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(self, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid parameter, controller is null");
    int32_t ret = SoftBusMutexInit(&self->lock, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "init lock failed");

    self->active = false;
    self->windowInMillis = -1;
    self->quotaInBytes = -1;
    ListInit(&self->histories);

    self->apply = Apply;
    self->enable = Enable;
    self->disable = Disable;
    return SOFTBUS_OK;
}

void ConnSlideWindowControllerDestructor(struct ConnSlideWindowController *self)
{
    CONN_CHECK_AND_RETURN_LOGE(self, CONN_COMMON, "invalid parameter, controller is null");
    int32_t status = SoftBusMutexLock(&self->lock);
    CONN_CHECK_AND_RETURN_LOGE(status == SOFTBUS_OK, CONN_COMMON, "lock failed");
    CleanupHistoriesUnsafe(self);
    SoftBusMutexDestroy(&self->lock);
}

struct ConnSlideWindowController *ConnSlideWindowControllerNew(void)
{
    struct ConnSlideWindowController *controller = SoftBusCalloc(sizeof(*controller));
    CONN_CHECK_AND_RETURN_RET_LOGE(controller, NULL, CONN_COMMON, "alloc failed");

    int32_t ret = ConnSlideWindowControllerConstructor(controller);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(controller);
        return NULL;
    }
    return controller;
}

void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self)
{
    ConnSlideWindowControllerDestructor(self);
    SoftBusFree(self);
}
