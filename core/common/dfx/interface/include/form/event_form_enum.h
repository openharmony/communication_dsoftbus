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

typedef enum {
    EVENT_STAGE_RESULT_OK = 1,
    EVENT_STAGE_RESULT_FAILED = 2,
    EVENT_STAGE_RESULT_CANCELED = 3,
} SoftbusEventStageResult;

typedef enum {
    AUDIT_EVENT_MSG_ERROR = 1,
    AUDIT_EVENT_REPLAY = 2,
    AUDIT_EVENT_PACKETS_ERROR = 3,
    AUDIT_EVENT_CONN_ERROR = 4,
    AUDIT_EVENT_IO_ERROR = 5,
    AUDIT_EVENT_DOS_ATTACK = 6,
    AUDIT_EVENT_DATA_LIMIT = 7,
} SoftbusAuditType;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // EVENT_FORM_ENUM_H
