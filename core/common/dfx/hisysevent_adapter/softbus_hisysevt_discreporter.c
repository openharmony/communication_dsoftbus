/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_hisysevt_discreporter.h"

uint8_t SoftBusCreateFirstDiscDurationEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t maxDiscDuration,
    uint32_t minDiscDuration, int avgDiscDuration)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_FIRST_DISC_DURATION) != EOK) {
        return SOFTBUS_ERR;
    }

    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;

    msg->paramArray = (SoftBusEvtParam *)SoftBusMalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_MAX_DISC_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = maxDiscDuration;

    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_MIN_DISC_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = minDiscDuration;

    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_AVG_DISC_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = avgDiscDuration;
    return SOFTBUS_OK;
}

uint8_t SoftBusCreateScanTimesEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t scanCount)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_SCAN_TIMES) != EOK) {
        return SOFTBUS_ERR;
    }

    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_TWO;

    msg->paramArray = (SoftBusEvtParam *)SoftBusMalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_SCAN_COUNTER) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = scanCount;

    return SOFTBUS_OK;
}

uint8_t SoftBusCreateDiscFaultEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint8_t errorType,
    uint8_t errorCode, uint32_t errorCount)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DISC_FAULT) != EOK) {
        return SOFTBUS_ERR;
    }

    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;

    msg->paramArray = (SoftBusEvtParam *)SoftBusMalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }

    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_ERROR_TYPE) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u8v = errorType;

    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_ERROR_CODE) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u8v = errorCode;

    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_ERROR_COUNTER) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = errorCount;
    return SOFTBUS_OK;
}

uint8_t SoftBusCreateDiscStartupEvt(SoftBusEvtReportMsg *msg, char *PackageName)
{
    if (msg == NULL || PackageName == NULL) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, BEHAVIOR_EVT_DISC_START) != EOK) {
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_BEHAVIOR;
    msg->paramNum = SOFTBUS_EVT_PARAM_ONE;

    msg->paramArray = (SoftBusEvtParam *)SoftBusMalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }

    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        DISC_PARAM_DISC_PACKAGE_NAME) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.str, 
        SOFTBUS_HISYSEVT_PARAM_LEN, PackageName) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    
    return SOFTBUS_OK;
}