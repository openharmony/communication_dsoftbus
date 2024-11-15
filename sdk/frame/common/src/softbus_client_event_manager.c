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

#include "softbus_client_event_manager.h"

#include "comm_log.h"
#include "softbus.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define MAX_OBSERVER_CNT 128

typedef struct {
    ListNode node;
    enum SoftBusEvent event;
    EventCallback callback;
    char *userData;
} Observer;

static SoftBusList *g_observerList = NULL;
static bool g_isInit = false;

int EventClientInit(void)
{
    if (g_isInit) {
        return SOFTBUS_OK;
    }

    if (g_observerList != NULL) {
        DestroySoftBusList(g_observerList);
    }
    g_observerList = CreateSoftBusList();
    if (g_observerList == NULL) {
        COMM_LOGE(COMM_SDK, "create observer list failed");
        return SOFTBUS_MALLOC_ERR;
    }

    g_isInit = true;
    return SOFTBUS_OK;
}

void EventClientDeinit(void)
{
    if (!g_isInit) {
        COMM_LOGE(COMM_SDK, "event client not init");
        return;
    }
    if (g_observerList != NULL) {
        DestroySoftBusList(g_observerList);
        g_observerList = NULL;
    }

    g_isInit = false;
}

static bool IsEventValid(enum SoftBusEvent event)
{
    if (event < EVENT_SERVER_DEATH || event >= EVENT_BUTT) {
        return false;
    }
    return true;
}

int RegisterEventCallback(enum SoftBusEvent event, EventCallback cb, void *userData)
{
    if (!IsEventValid(event) || cb == NULL) {
        COMM_LOGE(COMM_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_isInit != true) {
        COMM_LOGE(COMM_SDK, "event manager not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_observerList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (g_observerList->cnt >= MAX_OBSERVER_CNT) {
        COMM_LOGE(COMM_SDK, "observer count over limit");
        (void)SoftBusMutexUnlock(&g_observerList->lock);
        return SOFTBUS_TRANS_OBSERVER_EXCEED_LIMIT;
    }

    Observer *observer = (Observer *)SoftBusCalloc(sizeof(Observer));
    if (observer == NULL) {
        COMM_LOGE(COMM_SDK, "malloc observer failed");
        (void)SoftBusMutexUnlock(&g_observerList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    observer->event = event;
    observer->callback = cb;
    observer->userData = (char *)userData;

    ListInit(&observer->node);
    ListAdd(&g_observerList->list, &observer->node);
    g_observerList->cnt++;
    (void)SoftBusMutexUnlock(&g_observerList->lock);
    return SOFTBUS_OK;
}

void CLIENT_NotifyObserver(enum SoftBusEvent event, void *arg, unsigned int argLen)
{
    if (!IsEventValid(event)) {
        COMM_LOGE(COMM_SDK, "invalid event. event=%{public}d", event);
        return;
    }

    if (g_isInit != true) {
        COMM_LOGE(COMM_SDK, "event manager not init");
        return;
    }

    Observer *observer = NULL;
    if (SoftBusMutexLock(&g_observerList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock failed");
        return;
    }

    LIST_FOR_EACH_ENTRY(observer, &g_observerList->list, Observer, node) {
        if ((observer->event == event) && (observer->callback != NULL) &&
            (observer->callback(arg, argLen, observer->userData) != SOFTBUS_OK)) {
            COMM_LOGE(COMM_SDK, "execute callback failed. event=%{public}d", event);
        }
    }

    (void)SoftBusMutexUnlock(&g_observerList->lock);
}
