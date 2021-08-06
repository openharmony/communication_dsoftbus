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

#include "lnn_event_monitor.h"

#include <pthread.h>

#include "common_list.h"
#include "lnn_event_monitor_impl.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

typedef enum {
    MONITOR_IMPL_NETLINK_TYPE = 0,
    MONITOR_IMPL_PRODUCT_TYPE,
    MONITOR_IMPL_MAX_TYPE,
} MonitorImplType;

typedef struct {
    LnnInitEventMonitorImpl implInit;
} EventMonitorImpl;

typedef struct {
    ListNode node;
    LnnMonitorEventHandler handler;
} EventHandler;

typedef struct {
    EventMonitorImpl monitorImpl[MONITOR_IMPL_MAX_TYPE];
    ListNode eventList[LNN_MONITOR_EVENT_TYPE_MAX];
    pthread_mutex_t lock;
} EventMonitorCtrl;

static EventMonitorCtrl g_eventMonitorCtrl = {
    .monitorImpl = {
        [MONITOR_IMPL_NETLINK_TYPE] = {
            .implInit = LnnInitNetlinkMonitorImpl,
        },
        [MONITOR_IMPL_PRODUCT_TYPE] = {
            .implInit = LnnInitProductMonitorImpl,
        },
    },
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static void EventMonitorHandler(LnnMonitorEventType event, const void *para)
{
    EventHandler *item = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX) {
        LOG_ERR("invalid event");
        return;
    }
    if (pthread_mutex_lock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("hold lock failed in event handler");
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventMonitorCtrl.eventList[event], EventHandler, node) {
        item->handler(event, para);
    }
    if (pthread_mutex_unlock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("release lock failed in event handler");
    }
}

static bool IsRepeatEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler)
{
    EventHandler *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_eventMonitorCtrl.eventList[event], EventHandler, node) {
        if (item->handler == handler) {
            return true;
        }
    }
    return false;
}

static EventHandler *CreateEventHandler(LnnMonitorEventHandler handler)
{
    EventHandler *eventHandler = SoftBusMalloc(sizeof(EventHandler));

    if (eventHandler == NULL) {
        return NULL;
    }
    ListInit(&eventHandler->node);
    eventHandler->handler = handler;
    return eventHandler;
}

int32_t LnnInitEventMonitor(void)
{
    uint32_t i;

    for (i = 0; i < LNN_MONITOR_EVENT_TYPE_MAX; ++i) {
        ListInit(&g_eventMonitorCtrl.eventList[i]);
    }
    for (i = 0; i < MONITOR_IMPL_MAX_TYPE; ++i) {
        if (g_eventMonitorCtrl.monitorImpl[i].implInit == NULL) {
            continue;
        }
        if (g_eventMonitorCtrl.monitorImpl[i].implInit(EventMonitorHandler) != SOFTBUS_OK) {
            LOG_ERR("init event monitor impl(%u) failed", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void LnnDeinitEventMonitor(void)
{
    pthread_mutex_destroy(&g_eventMonitorCtrl.lock);
}

int32_t LnnRegisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler)
{
    EventHandler *eventHandler = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX || handler == NULL) {
        LOG_ERR("invalid event handler params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("hold lock failed in register event handler");
    }
    if (IsRepeatEventHandler(event, handler)) {
        LOG_ERR("event(%u) handler is already exist", event);
        return SOFTBUS_INVALID_PARAM;
    }
    eventHandler = CreateEventHandler(handler);
    if (eventHandler == NULL) {
        LOG_ERR("create event handler failed");
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_eventMonitorCtrl.eventList[event], &eventHandler->node);
    if (pthread_mutex_unlock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("release lock failed in register event handler");
    }
    return SOFTBUS_OK;
}

void LnnUnregisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler)
{
    EventHandler *item = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX || handler == NULL) {
        LOG_ERR("invalid event handler params");
        return;
    }
    if (pthread_mutex_lock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("hold lock failed in unregister event handler");
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventMonitorCtrl.eventList[event], EventHandler, node) {
        if (item->handler == handler) {
            ListDelete(&item->node);
            break;
        }
    }
    if (pthread_mutex_unlock(&g_eventMonitorCtrl.lock) != 0) {
        LOG_ERR("release lock failed in unregister event handler");
    }
}