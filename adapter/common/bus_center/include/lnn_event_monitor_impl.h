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
#include "bus_center_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOOTEVENT_ACCOUNT_READY "bootevent.account.ready"

typedef int32_t (*LnnInitEventMonitorImpl)(void);
typedef void (*LnnDeinitEventMonitorImpl)(void);
typedef void (*AccountEventHandle)(const char *key, const char *value, void *context);

int32_t LnnInitNetlinkMonitorImpl(void);

int32_t LnnInitProductMonitorImpl(void);

int32_t LnnInitLwipMonitorImpl(void);

int32_t LnnInitWifiServiceMonitorImpl(void);

int32_t LnnInitDriverMonitorImpl(void);

int32_t LnnInitCommonEventMonitorImpl(void);

int32_t LnnInitBootEventMonitorImpl(void);

int32_t LnnInitBtStateMonitorImpl(void);

void LnnDeinitBtStateMonitorImpl(void);

int32_t LnnInitNetManagerMonitorImpl(void);

void LnnDeinitProductMonitorImpl(void);

void LnnDeinitDriverMonitorImpl(void);

void LnnDeInitNetlinkMonitorImpl(void);

void LnnDeinitNetManagerMonitorImpl(void);

int32_t LnnSubscribeAccountBootEvent(AccountEventHandle handle);

bool LnnQueryLocalScreenStatusOnce(bool notify);
#ifdef __cplusplus
}
#endif
#endif /* LNN_EVENT_MONITOR_IMPL_H */
