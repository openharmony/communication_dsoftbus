/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_EVENT_H
#define SOFTBUS_EVENT_H

#include <stdlib.h>

#include "form/softbus_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONN_EVENT_NAME  "CONNECTION_BEHAVIOR"
#define DISC_EVENT_NAME  "DISCOVER_BEHAVIOR"
#define LNN_EVENT_NAME   "BUSCENTER_BEHAVIOR"
#define TRANS_EVENT_NAME "TRANSPORT_BEHAVIOR"
#define MANAGE_ALARM_EVENT_NAME "SOFTBUS_MANAGE_ALERT"
#define CONTROL_ALARM_EVENT_NAME "SOFTBUS_CONTROL_ALERT"
#define STATS_EVENT_NAME "SOFTBUS_STATISTIC"

typedef enum {
    EVENT_MODULE_CONN,
    EVENT_MODULE_DISC,
    EVENT_MODULE_LNN,
    EVENT_MODULE_TRANS,
    EVENT_MODULE_TRANS_ALARM,
    EVENT_MODULE_CONN_ALARM,
    EVENT_MODULE_LNN_ALARM,
    EVENT_MODULE_DISC_ALARM,
    EVENT_MODULE_STATS,
} SoftbusEventModule;

typedef enum {
    NETWORK_INTERRUPTION_ALARM,
    HEARTBEAT_BROADCAST_ALARM,
    CONNECTION_FAIL_ALARM,
    BANDWIDTH_INSUFFICIANT_ALARM,
    DELAY_JITTER_ALARM,
    NO_PERMISSION_ALARM,
    SPEED_LIMIT_ALARM,
    PREEMPTION_ALARM,
    FORBID_BACKGROUND_SYNC_ALARM,
    BUSINESS_CONFLICT_ALARM,
    DELAY_FREQUENT_RETRY_ALARM,
    OPEN_SESSION_FAIL_ALARM,
} SoftbusAlarmEvent;

void SoftbusEventInner(SoftbusEventModule module, SoftbusEventForm *form);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_EVENT_H
