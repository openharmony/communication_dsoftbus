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

#ifndef LNN_EVENT_MONITOR_IMPL_H
#define LNN_EVENT_MONITOR_IMPL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_MONITOR_EVENT_IP_ADDR_CHANGED,
    LNN_MONITOR_EVENT_WIFI_STATE_CHANGED,
    LNN_MONITOR_EVENT_TYPE_MAX,
} LnnMonitorEventType;

typedef struct {
    uint32_t len;
    uint8_t value[0];
} LnnMoniterData;

typedef enum {
    SOFTBUS_WIFI_CONNECTED,
    SOFTBUS_WIFI_DISCONNECTED,
    SOFTBUS_WIFI_DISABLED,
    SOFTBUS_UNKNOWN,
} SoftBusWifiState;

typedef void (*LnnMonitorEventHandler)(LnnMonitorEventType event, const LnnMoniterData *para);

typedef int32_t (*LnnInitEventMonitorImpl)(LnnMonitorEventHandler handler);

int32_t LnnInitNetlinkMonitorImpl(LnnMonitorEventHandler handler);

int32_t LnnInitProductMonitorImpl(LnnMonitorEventHandler handler);

int32_t LnnInitLwipMonitorImpl(LnnMonitorEventHandler handler);

int32_t LnnInitWifiServiceMonitorImpl(LnnMonitorEventHandler handler);

#ifdef __cplusplus
}
#endif
#endif /* LNN_EVENT_MONITOR_IMPL_H */