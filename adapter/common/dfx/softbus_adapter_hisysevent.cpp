/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <string>
#include <sstream>
#include <securec.h>
#include "softbus_error_code.h"

#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "message_handler.h"
#include "softbus_adapter_hisysevent.h"

static const char* g_paramTypeTable[SOFTBUS_EVT_PARAMTYPE_BUTT] = {
    "BOOL",
    "UINT8",
    "UINT16",
    "INT32",
    "UINT32",
    "UINT64",
    "FLOAT",
    "DOUBLE",
    "STRING"
};

static const char* g_evtTypeTable[SOFTBUS_EVT_TYPE_BUTT] = {
    "FAULT",
    "FAULT",
    "STATISTIC",
    "SECURITY",
    "BEHAVIOR"
};

static void ReportParamValue(SoftBusEvtParam& evtParam)
{
    switch (evtParam.paramType) {
        case SOFTBUS_EVT_PARAMTYPE_BOOL:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}u",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (unsigned int)evtParam.paramValue.b);
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT8:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}u",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (unsigned int)evtParam.paramValue.u8v);
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT16:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}u",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (unsigned int)evtParam.paramValue.u16v);
            break;
        case SOFTBUS_EVT_PARAMTYPE_INT32:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}d",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (int)evtParam.paramValue.i32v);
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT32:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}u",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (unsigned int)evtParam.paramValue.u32v);
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT64:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}llu",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], (unsigned long long)evtParam.paramValue.u64v);
            break;
        case SOFTBUS_EVT_PARAMTYPE_FLOAT:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}f",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], evtParam.paramValue.f);
            break;
        case SOFTBUS_EVT_PARAMTYPE_DOUBLE:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}lf",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], evtParam.paramValue.d);
            break;
        case SOFTBUS_EVT_PARAMTYPE_STRING:
            HILOG_INFO(SOFTBUS_HILOG_ID, "ParamName: %{public}s;  ParamNum: %{public}s;  ParamValue: %{public}s",
                evtParam.paramName, g_paramTypeTable[evtParam.paramType], evtParam.paramValue.str);
            break;
        default:
            break;
    }
}

static void ConvertReportMsgToStr(SoftBusEvtReportMsg* reportMsg)
{
    HILOG_INFO(SOFTBUS_HILOG_ID, "EvtName: %{public}s;  EvtType: %{public}s;  ParamNum: %{public}d",
        reportMsg->evtName, g_evtTypeTable[reportMsg->evtType], reportMsg->paramNum);

    for (uint32_t i = 0; i < reportMsg->paramNum; i++) {
        ReportParamValue(reportMsg->paramArray[i]);
    }
}

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SoftbusWriteHisEvt(SoftBusEvtReportMsg* reportMsg)
{
    if (reportMsg == nullptr) {
        return SOFTBUS_ERR;
    }
    
    ConvertReportMsgToStr(reportMsg);

    return SOFTBUS_OK;
}

void SoftbusFreeEvtReporMsg(SoftBusEvtReportMsg* msg)
{
    if (msg == nullptr) {
        return;
    }

    if (msg->paramArray != nullptr) {
        SoftBusFree(msg->paramArray);
    }
    
    SoftBusFree(msg);
}

SoftBusEvtReportMsg* SoftbusCreateEvtReportMsg(int32_t paramNum)
{
    SoftBusEvtReportMsg *msg = (SoftBusEvtReportMsg*)SoftBusMalloc(sizeof(SoftBusEvtReportMsg));
    if (msg == nullptr) {
        return nullptr;
    }

    msg->paramArray = (SoftBusEvtParam*)SoftBusMalloc(sizeof(SoftBusEvtParam) * paramNum);
    if (msg->paramArray == nullptr) {
        SoftbusFreeEvtReporMsg(msg);
    }
    
    return msg;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
