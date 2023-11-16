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

#ifndef SOFTBUS_EVENT_FORM_H
#define SOFTBUS_EVENT_FORM_H

#include "form/conn_event_form.h"
#include "form/disc_event_form.h"
#include "form/lnn_event_form.h"
#include "form/trans_event_form.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STAGE_RESULT_IDLE = 0,
    STAGE_RESULT_OK = 1,
    STAGE_RESULT_FAILED = 2,
    STAGE_RESULT_CANCELED = 3,
    STAGE_RESULT_UNKNOWN = 4,
} TransEventStageResult;

typedef struct {
    const char *domain;    // DOMAIN
    const char *eventName; // EVENT_NAME
    int32_t eventType;     // EVENT_TYPE
    const char *orgPkg;    // ORG_PKG
    const char *func;      // FUNC
    int32_t scene;         // BIZ_SCENE
    int32_t stage;         // BIZ_STAGE
    int32_t result;        // STAGE_RES
    int32_t errcode;       // ERROR_CODE
    union {
        ConnEventExtra connExtra;
        DiscEventExtra discExtra;
        LnnEventExtra lnnExtra;
        TransEventExtra transExtra;
    };
} SoftbusEventForm;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_EVENT_FORM_H
