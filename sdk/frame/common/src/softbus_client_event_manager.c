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

#include "softbus_client_event_manager.h"

#include "softbus.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define MAX_OBSERVER_CNT 128

typedef struct {
    ListNode node;
    enum SoftBusEvent event;
    EventCallback callback;
    char *userData;
} Observer;

static SoftBusList *g_observerList = NULL;
static bool g_isInited = false;

int EventClientInit(void)
{
    if (g_isInited) {
        return SOFTBUS_OK;
    }

    g_observerList = CreateSoftBusList();
    if (g_observerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create observer list failed");
        return SOFTBUS_ERR;
    }

    g_isInited = true;
    return SOFTBUS_OK;
}

void EventClientDeinit(void)
{
    if (!g_isInited) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "event client not init");
        return;
    }

    if (g_observerList) {
        DestroySoftBusList(g_observerList);
        g_observerList = NULL;
    }

    g_isInited = false;
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    if (g_isInited != true) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "event manager not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_observerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }

    if (g_observerList->cnt >= MAX_OBSERVER_CNT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "observer count over limit");
        (void)pthread_mutex_unlock(&g_observerList->lock);
        return SOFTBUS_ERR;
    }

    Observer *observer = SoftBusCalloc(sizeof(Observer));
    if (observer == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc observer failed");
        (void)pthread_mutex_unlock(&g_observerList->lock);
        return SOFTBUS_ERR;
    }

    observer->event = event;
    observer->callback = cb;
    observer->userData = userData;

    ListInit(&observer->node);
    ListAdd(&g_observerList->list, &observer->node);
    g_observerList->cnt++;
    (void)pthread_mutex_unlock(&g_observerList->lock);
    return SOFTBUS_OK;
}

void CLIENT_NotifyObserver(enum SoftBusEvent event, void *arg, unsigned int argLen)
{
    if (!IsEventValid(event)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid event [%d]", event);
        return;
    }

    if (g_isInited != true) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "event manager not init");
        return;
    }

    Observer *observer = NULL;
    if (pthread_mutex_lock(&g_observerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }

    LIST_FOR_EACH_ENTRY(observer, &g_observerList->list, Observer, node) {
        if ((observer->event == event) &&
            (observer->callback != NULL) &&
            (observer->callback(arg, argLen, observer->userData) != SOFTBUS_OK)) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "execute callback failed [%d]", event);
        }
    }

    (void)pthread_mutex_unlock(&g_observerList->lock);
}
