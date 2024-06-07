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
#include "convert/conn_audit_converter.h"
#include "convert/conn_event_converter.h"
#include "convert/disc_audit_converter.h"
#include "convert/disc_event_converter.h"
#include "convert/lnn_audit_converter.h"
#include "convert/lnn_event_converter.h"
#include "convert/trans_audit_converter.h"
#include "convert/trans_event_converter.h"
#include "convert/stats_event_converter.h"
#include "hisysevent_c.h"

#define HISYSEVENT_WRITE_SUCCESS 0

typedef void (*WriteEventAndFree)(HiSysEventParam *params, size_t size, SoftbusEventForm *form);

static void ConstructHiSysEventParams(HiSysEventParam *eventParams, const HiSysEventParam *params, size_t size,
    const HiSysEventParam *extraParams, size_t extraSize)
{
    size_t index = 0;
    for (size_t i = 0; i < size; ++i) {
        eventParams[index++] = params[i];
    }
    for (size_t j = 0; j < extraSize; ++j) {
        eventParams[index++] = extraParams[j];
    }
}

static void WriteHiSysEvent(
    HiSysEventParam params[], size_t size, HiSysEventParam extraParams[], size_t extraSize, SoftbusEventForm *form)
{
    size_t validParamSize = size + extraSize;
    HiSysEventParam eventParams[validParamSize];
    ConstructHiSysEventParams(eventParams, params, size, extraParams, extraSize);
    int32_t ret = HiSysEvent_Write(
        form->func, form->line, form->domain, form->eventName, form->eventType, eventParams, validParamSize);
    if (ret != HISYSEVENT_WRITE_SUCCESS) {
        COMM_LOGD(COMM_DFX, "write to hisysevent failed, ret=%{public}d", ret);
    }
}

static void HiSysEventParamsFree(HiSysEventParam params[], size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (params[i].t == HISYSEVENT_STRING) {
            free(params[i].v.s);
        }
    }
}

static void WriteConnEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam connParams[CONN_ASSIGNER_SIZE] = { 0 };
    size_t connSize = ConvertConnForm2Param(connParams, CONN_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, connParams, connSize, form);
    HiSysEventParamsFree(connParams, connSize);
}

static void WriteDiscEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam discParams[DISC_ASSIGNER_SIZE] = { 0 };
    size_t discSize = ConvertDiscForm2Param(discParams, DISC_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, discParams, discSize, form);
    HiSysEventParamsFree(discParams, discSize);
}

static void WriteLnnEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam lnnParams[LNN_ASSIGNER_SIZE] = { 0 };
    size_t lnnSize = ConvertLnnForm2Param(lnnParams, LNN_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, lnnParams, lnnSize, form);
    HiSysEventParamsFree(lnnParams, lnnSize);
}

static void WriteTransEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam transParams[TRANS_ASSIGNER_SIZE] = { 0 };
    size_t transSize = ConvertTransForm2Param(transParams, TRANS_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, transParams, transSize, form);
    HiSysEventParamsFree(transParams, transSize);
}

static void WriteTransAlarmEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam alarmParams[TRANS_ALARM_ASSIGNER_SIZE] = { 0 };
    size_t alarmSize = ConvertTransAlarmForm2Param(alarmParams, TRANS_ALARM_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, alarmParams, alarmSize, form);
    HiSysEventParamsFree(alarmParams, alarmSize);
}

static void WriteConnAlarmEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam alarmParams[CONN_ALARM_ASSIGNER_SIZE] = { 0 };
    size_t alarmSize = ConvertConnAlarmForm2Param(alarmParams, CONN_ALARM_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, alarmParams, alarmSize, form);
    HiSysEventParamsFree(alarmParams, alarmSize);
}

static void WriteLnnAlarmEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam alarmParams[LNN_ALARM_ASSIGNER_SIZE] = { 0 };
    size_t alarmSize = ConvertLnnAlarmForm2Param(alarmParams, LNN_ALARM_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, alarmParams, alarmSize, form);
    HiSysEventParamsFree(alarmParams, alarmSize);
}

static void WriteDiscAlarmEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam alarmParams[DISC_ALARM_ASSIGNER_SIZE] = { 0 };
    size_t alarmSize = ConvertDiscAlarmForm2Param(alarmParams, DISC_ALARM_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, alarmParams, alarmSize, form);
    HiSysEventParamsFree(alarmParams, alarmSize);
}

static void WriteStateEventAndFree(HiSysEventParam *params, size_t size, SoftbusEventForm *form)
{
    HiSysEventParam statsParams[STATS_ASSIGNER_SIZE] = { 0 };
    size_t statsSize = ConvertStatsForm2Param(statsParams, STATS_ASSIGNER_SIZE, form);
    WriteHiSysEvent(params, size, statsParams, statsSize, form);
    HiSysEventParamsFree(statsParams, statsSize);
}

static WriteEventAndFree g_eventFunc[] = {
    [EVENT_MODULE_CONN] = WriteConnEventAndFree,
    [EVENT_MODULE_DISC] = WriteDiscEventAndFree,
    [EVENT_MODULE_LNN] = WriteLnnEventAndFree,
    [EVENT_MODULE_TRANS] = WriteTransEventAndFree,
    [EVENT_MODULE_TRANS_ALARM] = WriteTransAlarmEventAndFree,
    [EVENT_MODULE_CONN_ALARM] = WriteConnAlarmEventAndFree,
    [EVENT_MODULE_LNN_ALARM] = WriteLnnAlarmEventAndFree,
    [EVENT_MODULE_DISC_ALARM] = WriteDiscAlarmEventAndFree,
    [EVENT_MODULE_STATS] = WriteStateEventAndFree
};

static void WriteSoftbusEvent(SoftbusEventModule module, SoftbusEventForm *form)
{
    HiSysEventParam params[SOFTBUS_ASSIGNER_SIZE] = { 0 };
    size_t size = ConvertSoftbusForm2Param(params, SOFTBUS_ASSIGNER_SIZE, form);
    if (module >= 0 && module < EVENT_MODULE_MAX) {
        g_eventFunc[module](params, size, form);
    } else {
        COMM_LOGW(COMM_DFX, "invalid module. module=%{public}d", (int32_t)module);
    }
    HiSysEventParamsFree(params, size);
}

void SoftbusEventInner(SoftbusEventModule module, SoftbusEventForm *form)
{
    if (form == NULL) {
        return;
    }
    form->domain = SOFTBUS_EVENT_DOMAIN;
    form->eventType = SOFTBUS_EVENT_TYPE_BEHAVIOR;
    form->orgPkg = SOFTBUS_EVENT_PKG_NAME;
    WriteSoftbusEvent(module, form);
}

static void WriteSoftbusAudit(SoftbusEventModule module, SoftbusEventForm *form)
{
    HiSysEventParam params[SOFTBUS_ASSIGNER_SIZE] = { 0 };
    size_t size = ConvertSoftbusForm2Param(params, SOFTBUS_ASSIGNER_SIZE, form);
    switch (module) {
        case EVENT_MODULE_CONN: {
            HiSysEventParam connParams[CONN_AUDIT_ASSIGNER_SIZE] = { 0 };
            size_t connSize = ConvertConnAuditForm2Param(connParams, form);
            WriteHiSysEvent(params, size, connParams, connSize, form);
            HiSysEventParamsFree(connParams, connSize);
            break;
        }
        case EVENT_MODULE_DISC: {
            HiSysEventParam discParams[DISC_AUDIT_ASSIGNER_SIZE] = { 0 };
            size_t discSize = ConvertDiscAuditForm2Param(discParams, form);
            WriteHiSysEvent(params, size, discParams, discSize, form);
            HiSysEventParamsFree(discParams, discSize);
            break;
        }
        case EVENT_MODULE_LNN: {
            HiSysEventParam lnnParams[LNN_AUDIT_ASSIGNER_SIZE] = { 0 };
            size_t lnnSize = ConvertLnnAuditForm2Param(lnnParams, form);
            WriteHiSysEvent(params, size, lnnParams, lnnSize, form);
            HiSysEventParamsFree(lnnParams, lnnSize);
            break;
        }
        case EVENT_MODULE_TRANS: {
            HiSysEventParam transParams[TRANS_AUDIT_ASSIGNER_SIZE] = { 0 };
            size_t transSize = ConvertTransAuditForm2Param(transParams, form);
            WriteHiSysEvent(params, size, transParams, transSize, form);
            HiSysEventParamsFree(transParams, transSize);
            break;
        }
        default: {
            COMM_LOGW(COMM_DFX, "invalid module. module=%{public}d", (int32_t)module);
            break;
        }
    }
    HiSysEventParamsFree(params, size);
}

void SoftbusAuditInner(SoftbusEventModule module, SoftbusEventForm *form)
{
    if (form == NULL) {
        return;
    }
    form->domain = SOFTBUS_EVENT_DOMAIN;
    form->eventType = SOFTBUS_EVENT_TYPE_SECURITY;
    form->orgPkg = SOFTBUS_EVENT_PKG_NAME;
    WriteSoftbusAudit(module, form);
}
