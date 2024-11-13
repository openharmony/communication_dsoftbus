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

#include "bus_center_event.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_devicename_info.h"
#include "lnn_log.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

typedef enum {
    MONITOR_IMPL_NETLINK_TYPE = 0,
    MONITOR_IMPL_PRODUCT_TYPE,
    MONITOR_IMPL_LWIP_TYPE,
    MONITOR_IMPL_WIFISERVICE_TYPE,
    MONITOR_IMPL_BT_STATE_TYPE,
    MONITOR_IMPL_DRIVER_TYPE,
    MONITOR_IMPL_BOOT_EVENT_TYPE,
    MONITOR_IMPL_NETMANAGER_TYPE,
    MONITOR_IMPL_MAX_TYPE,
} MonitorImplType;

static LnnInitEventMonitorImpl g_monitorImplInit[MONITOR_IMPL_MAX_TYPE] = {
    LnnInitNetlinkMonitorImpl,
    LnnInitProductMonitorImpl,
    LnnInitLwipMonitorImpl,
    LnnInitWifiServiceMonitorImpl,
    LnnInitBtStateMonitorImpl,
    LnnInitDriverMonitorImpl,
    LnnInitBootEventMonitorImpl,
    LnnInitNetManagerMonitorImpl,
};

static LnnDeinitEventMonitorImpl g_monitorImplDeinit[MONITOR_IMPL_MAX_TYPE] = {
    LnnDeinitBtStateMonitorImpl,
    LnnDeinitProductMonitorImpl,
    LnnDeinitDriverMonitorImpl,
    LnnDeInitNetlinkMonitorImpl,
    LnnDeinitNetManagerMonitorImpl,
};

int32_t LnnInitEventMonitor(void)
{
    for (uint32_t i = 0; i < MONITOR_IMPL_MAX_TYPE; ++i) {
        if (g_monitorImplInit[i] == NULL) {
            continue;
        }
        if (g_monitorImplInit[i]() != SOFTBUS_OK) {
            LNN_LOGE(LNN_INIT, "init event monitor impl failed. i=%{public}u", i);
            return SOFTBUS_EVENT_MONITER_INIT_FAILED;
        }
    }
    return SOFTBUS_OK;
}

void LnnDeinitEventMonitor(void)
{
    uint32_t i;

    for (i = 0; i < MONITOR_IMPL_MAX_TYPE; ++i) {
        if (g_monitorImplDeinit[i] == NULL) {
            continue;
        }
        g_monitorImplDeinit[i]();
    }
}