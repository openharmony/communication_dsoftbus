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

#include "bus_center_event.h"
#include "lnn_event_monitor_impl.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

typedef enum {
    MONITOR_IMPL_NETLINK_TYPE = 0,
    MONITOR_IMPL_PRODUCT_TYPE,
    MONITOR_IMPL_LWIP_TYPE,
    MONITOR_IMPL_WIFISERVICE_TYPE,
    MONITOR_IMPL_DRIVER_TYPE,
    MONITOR_IMPL_MAX_TYPE,
} MonitorImplType;

static LnnInitEventMonitorImpl g_monitorImplInit[MONITOR_IMPL_MAX_TYPE] = {
    LnnInitNetlinkMonitorImpl,
    LnnInitProductMonitorImpl,
    LnnInitLwipMonitorImpl,
    LnnInitWifiServiceMonitorImpl,
    LnnInitDriverMonitorImpl,
};

static void EventMonitorHandler(LnnMonitorEventType event, const LnnMoniterData *para)
{
    LnnMonitorEventInfo info;

    if (event == LNN_MONITOR_EVENT_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid event");
        return;
    }
    info.basic.event = (LnnEventType)event;
    info.data = para;
    LnnNotifyMonitorEvent(&info);
}

int32_t LnnInitEventMonitor(void)
{
    uint32_t i;

    for (i = 0; i < MONITOR_IMPL_MAX_TYPE; ++i) {
        if (g_monitorImplInit[i] == NULL) {
            continue;
        }
        if (g_monitorImplInit[i](EventMonitorHandler) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init event monitor impl(%u) failed", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}