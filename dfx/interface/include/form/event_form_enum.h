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

#ifndef EVENT_FORM_ENUM_H
#define EVENT_FORM_ENUM_H

#ifdef __cplusplus
extern "C" {
#endif

#define SOFTBUS_DEFAULT_STAGE 1

typedef enum {
    EVENT_STAGE_RESULT_OK = 1,
    EVENT_STAGE_RESULT_FAILED = 2,
    EVENT_STAGE_RESULT_CANCELED = 3,
} SoftbusEventStageResult;

typedef enum {
    MANAGE_ALARM_TYPE = 1,
    CONTROL_ALARM_TYPE = 2,
} SoftbusAlarmEventType;

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

typedef enum {
    AUDIT_EVENT_MSG_ERROR = 1,
    AUDIT_EVENT_REPLAY,
    AUDIT_EVENT_PACKETS_ERROR,
    AUDIT_EVENT_CONN_ERROR,
    AUDIT_EVENT_IO_ERROR,
    AUDIT_EVENT_DOS_ATTACK,
    AUDIT_EVENT_DATA_LIMIT,
    AUDIT_EVENT_HB_FREQ_ERROR,
    AUDIT_EVENT_HB_MSG_ERROR,
} SoftbusAuditType;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // EVENT_FORM_ENUM_H
