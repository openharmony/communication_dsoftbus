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
    "STATISTIC",
    "SECURITY",
    "BEHAVIOR"
};

static void AppendParamValue(std::stringstream& strStream, SoftBusEvtParam& evtParam)
{
    switch (evtParam.paramType) {
        case SOFTBUS_EVT_PARAMTYPE_BOOL:
            strStream << (unsigned int)evtParam.paramValue.b;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT8:
            strStream << (unsigned int)evtParam.paramValue.u8v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT16:
            strStream << (unsigned int)evtParam.paramValue.u16v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_INT32:
            strStream << (int)evtParam.paramValue.i32v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT32:
            strStream << (unsigned long)evtParam.paramValue.u32v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT64:
            strStream << (unsigned long long)evtParam.paramValue.u64v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_FLOAT:
            strStream << evtParam.paramValue.f;
            break;
        case SOFTBUS_EVT_PARAMTYPE_DOUBLE:
            strStream << evtParam.paramValue.d;
            break;
        case SOFTBUS_EVT_PARAMTYPE_STRING:
            strStream << (const char*)evtParam.paramValue.str;
            break;
        default:
            break;
    }
}

static char* ConvertReportMsgToStr(SoftBusEvtReportMsg* reportMsg)
{
    std::string outStr;
    std::stringstream strStream(outStr);

    strStream << "EvtName: " << (const char*)reportMsg->evtName <<" And EvtType: ";
    strStream << (const char*)g_evtTypeTable[reportMsg->evtType];
    strStream << "  ParamNum: " << (unsigned long)reportMsg->paramNum << "  ";

    for (uint32_t i = 0; i < reportMsg->paramNum; i++) {
        strStream << "ParamName: " << (const char*)reportMsg->paramArray[i].paramName;
        strStream << "  ParamType: " << (const char*)g_paramTypeTable[reportMsg->paramArray[i].paramType];
        AppendParamValue(strStream, reportMsg->paramArray[i]);
    }

    unsigned int strlen = outStr.length();
    char* msgStr = (char*)SoftBusMalloc(strlen + 1);
    if (msgStr != nullptr) {
        strcpy_s(msgStr, strlen + 1, outStr.c_str());
    }
    
    return msgStr;
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
    
    char* reportMsgStr = ConvertReportMsgToStr(reportMsg);
    if (reportMsgStr == nullptr) {
        return SOFTBUS_ERR;
    }
    
    HILOG_INFO(SOFTBUS_HILOG_ID, "[COMM]%{public}s", reportMsgStr);
    SoftBusFree((void*)reportMsgStr);

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
    SoftBusEvtReportMsg *msg = SoftBusMalloc(sizeof(SoftBusEvtReportMsg));
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
