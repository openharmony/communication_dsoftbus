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

#ifndef LNN_EVENT_MONITOR_H
#define LNN_EVENT_MONITOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LNN_MONITOR_EVENT_IP_ADDR_CHANGED,
    LNN_MONITOR_EVENT_TYPE_MAX,
} LnnMonitorEventType;

typedef void (*LnnMonitorEventHandler)(LnnMonitorEventType event, const void *para);

int32_t LnnInitEventMonitor(void);
void LnnDeinitEventMonitor(void);

int32_t LnnRegisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler);
void LnnUnregisterEventHandler(LnnMonitorEventType event, LnnMonitorEventHandler handler);

#ifdef __cplusplus
}
#endif
#endif /* LNN_EVENT_MONITOR_H */