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

#include "softbus_event.h"

#include "comm_log.h"
#include "convert/conn_event_converter.h"
#include "convert/disc_event_converter.h"
#include "convert/lnn_event_converter.h"
#include "convert/trans_event_converter.h"
#include "hisysevent_c.h"

#define HISYSEVENT_WRITE_SUCCESS 0

static size_t GetValidParamSize(
    const HiSysEventParam *params, size_t size, const HiSysEventParam *extraParams, size_t extraSize)
{
    size_t validSize = 0;
    for (size_t i = 0; i < size; ++i) {
        if (params[i].t != HISYSEVENT_INVALID) {
            validSize++;
        }
    }
    for (size_t j = 0; j < extraSize; ++j) {
        if (extraParams[j].t != HISYSEVENT_INVALID) {
            validSize++;
        }
    }
    return validSize;
}

static void ConstructHiSysEventParams(HiSysEventParam *eventParams, const HiSysEventParam *params, size_t size,
    const HiSysEventParam *extraParams, size_t extraSize)
{
    size_t index = 0;
    for (size_t i = 0; i < size; ++i) {
        if (params[i].t != HISYSEVENT_INVALID) {
            eventParams[index++] = params[i];
        }
    }
    for (size_t j = 0; j < extraSize; ++j) {
        if (extraParams[j].t != HISYSEVENT_INVALID) {
            eventParams[index++] = extraParams[j];
        }
    }
}

static void WriteHiSysEvent(
    HiSysEventParam params[], size_t size, HiSysEventParam extraParams[], size_t extraSize, SoftbusEventForm form)
{
    size_t validParamSize = GetValidParamSize(params, size, extraParams, extraSize);
    HiSysEventParam eventParams[validParamSize];
    ConstructHiSysEventParams(eventParams, params, size, extraParams, extraSize);
    int32_t ret = HiSysEvent_Write(
        form.func, form.line, form.domain, form.eventName, form.eventType, eventParams, validParamSize);
    if (ret != HISYSEVENT_WRITE_SUCCESS) {
        COMM_LOGE(COMM_DFX, "write to hisysevent failed, ret=%d", ret);
    }
}

static void SoftbusEventParamsFree(HiSysEventParam params[], size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (params[i].t == HISYSEVENT_STRING) {
            free(params[i].v.s);
        }
    }
}

static void WriteSoftbusEvent(SoftbusEventModule module, SoftbusEventForm form)
{
    HiSysEventParam params[SOFTBUS_ASSIGNER_SIZE] = { 0 };
    ConvertSoftbusForm2Param(params, SOFTBUS_ASSIGNER_SIZE, form);
    switch (module) {
        case EVENT_MODULE_CONN: {
            HiSysEventParam connParams[CONN_ASSIGNER_SIZE] = { 0 };
            ConvertConnForm2Param(connParams, CONN_ASSIGNER_SIZE, form);
            WriteHiSysEvent(params, SOFTBUS_ASSIGNER_SIZE, connParams, CONN_ASSIGNER_SIZE, form);
            SoftbusEventParamsFree(connParams, CONN_ASSIGNER_SIZE);
            break;
        }
        case EVENT_MODULE_DISC: {
            HiSysEventParam discParams[DISC_ASSIGNER_SIZE] = { 0 };
            ConvertDiscForm2Param(discParams, DISC_ASSIGNER_SIZE, form);
            WriteHiSysEvent(params, SOFTBUS_ASSIGNER_SIZE, discParams, DISC_ASSIGNER_SIZE, form);
            SoftbusEventParamsFree(discParams, DISC_ASSIGNER_SIZE);
            break;
        }
        case EVENT_MODULE_LNN: {
            HiSysEventParam lnnParams[LNN_ASSIGNER_SIZE] = { 0 };
            ConvertLnnForm2Param(lnnParams, LNN_ASSIGNER_SIZE, form);
            WriteHiSysEvent(params, SOFTBUS_ASSIGNER_SIZE, lnnParams, LNN_ASSIGNER_SIZE, form);
            SoftbusEventParamsFree(lnnParams, LNN_ASSIGNER_SIZE);
            break;
        }
        case EVENT_MODULE_TRANS: {
            HiSysEventParam transParams[TRANS_ASSIGNER_SIZE] = { 0 };
            ConvertTransForm2Param(transParams, TRANS_ASSIGNER_SIZE, form);
            WriteHiSysEvent(params, SOFTBUS_ASSIGNER_SIZE, transParams, TRANS_ASSIGNER_SIZE, form);
            SoftbusEventParamsFree(transParams, TRANS_ASSIGNER_SIZE);
            break;
        }
        default: {
            COMM_LOGW(COMM_DFX, "invalid module %d", (int32_t)module);
            break;
        }
    }
    SoftbusEventParamsFree(params, SOFTBUS_ASSIGNER_SIZE);
}

void SoftbusEventInner(SoftbusEventModule module, SoftbusEventForm form)
{
    form.domain = SOFTBUS_EVENT_DOMAIN;
    form.eventType = SOFTBUS_EVENT_TYPE_BEHAVIOR;
    form.orgPkg = SOFTBUS_EVENT_PKG_NAME;
    WriteSoftbusEvent(module, form);
}