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
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_thread.h"

typedef enum {
    MONITOR_IMPL_NETLINK_TYPE = 0,
    MONITOR_IMPL_PRODUCT_TYPE,
    MONITOR_IMPL_LWIP_TYPE,
    MONITOR_IMPL_WIFISERVICE_TYPE,
    MONITOR_IMPL_DRIVER_TYPE,
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
    SoftBusMutex lock;
} EventMonitorCtrl;

static EventMonitorCtrl g_eventMonitorCtrl = {
    .monitorImpl = {
        [MONITOR_IMPL_NETLINK_TYPE] = {
            .implInit = LnnInitNetlinkMonitorImpl,
        },
        [MONITOR_IMPL_PRODUCT_TYPE] = {
            .implInit = LnnInitProductMonitorImpl,
        },
        [MONITOR_IMPL_LWIP_TYPE] = {
            .implInit = LnnInitLwipMonitorImpl,
        },
        [MONITOR_IMPL_WIFISERVICE_TYPE] = {
            .implInit = LnnInitWifiServiceMonitorImpl,
        },
        [MONITOR_IMPL_DRIVER_TYPE] = {
            .implInit = LnnInitDriverMonitorImpl,
        },
    },
};

static void EventMonitorHandler(LnnMonitorEventType event, const LnnMoniterData *para)
{
    EventHandler *item = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event");
        return;
    }
    if (SoftBusMutexLock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "hold lock failed in event handler");
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventMonitorCtrl.eventList[event], EventHandler, node) {
        item->handler(event, para);
    }
    if (SoftBusMutexUnlock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "release lock failed in event handler");
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

    SoftBusMutexInit(&g_eventMonitorCtrl.lock, NULL);
    for (i = 0; i < LNN_MONITOR_EVENT_TYPE_MAX; ++i) {
        ListInit(&g_eventMonitorCtrl.eventList[i]);
    }
    for (i = 0; i < MONITOR_IMPL_MAX_TYPE; ++i) {
        if (g_eventMonitorCtrl.monitorImpl[i].implInit == NULL) {
            continue;
        }
        if (g_eventMonitorCtrl.monitorImpl[i].implInit(EventMonitorHandler) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init event monitor impl(%u) failed", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void LnnDeinitEventMonitor(void)
{
    SoftBusMutexDestroy(&g_eventMonitorCtrl.lock);
}

int32_t LnnRegisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler)
{
    EventHandler *eventHandler = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event handler params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "hold lock failed in register event handler");
    }
    if (IsRepeatEventHandler(event, handler)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "event(%u) handler is already exist", event);
        return SOFTBUS_INVALID_PARAM;
    }
    eventHandler = CreateEventHandler(handler);
    if (eventHandler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create event handler failed");
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_eventMonitorCtrl.eventList[event], &eventHandler->node);
    if (SoftBusMutexUnlock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "release lock failed in register event handler");
    }
    return SOFTBUS_OK;
}

void LnnUnregisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler)
{
    EventHandler *item = NULL;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX || handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event handler params");
        return;
    }
    if (SoftBusMutexLock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "hold lock failed in unregister event handler");
    }
    LIST_FOR_EACH_ENTRY(item, &g_eventMonitorCtrl.eventList[event], EventHandler, node) {
        if (item->handler == handler) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    if (SoftBusMutexUnlock(&g_eventMonitorCtrl.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "release lock failed in unregister event handler");
    }
}