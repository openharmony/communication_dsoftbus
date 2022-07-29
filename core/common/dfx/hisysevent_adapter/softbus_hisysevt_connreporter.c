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
#include "softbus_hisysevt_connreporter.h"

uint8_t SoftBusCreateConnDurationEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t maxConnDuration,
    uint32_t minConnDuration, int avgConnDuration)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CONN_DURATION) != EOK) {
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
        CONN_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_MAX_CONN_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = maxConnDuration;

    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_MIN_CONN_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = minConnDuration;

    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_AVG_CONN_DURATION) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = avgConnDuration;
    return SOFTBUS_OK;
}

uint8_t SoftBusCreateConnSuccRateEvt(SoftBusEvtReportMsg *msg, uint8_t medium, float succRate)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CONN_SUCC_RATE) != EOK) {
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
        CONN_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_FLOAT;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_CONN_SUCC_RATE) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u32v = succRate;

    return SOFTBUS_OK;
}

uint8_t SoftBusCreateConnExceptionEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint8_t errorCode, char *devId,
    uint8_t nightmode)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, FAULT_EVT_CONN_EXCEPTION) != EOK) {
        return SOFTBUS_ERR;
    }

    msg->evtType = SOFTBUS_EVT_TYPE_FAULT;
    msg->paramNum = SOFTBUS_EVT_PARAM_SEVEN;

    msg->paramArray = (SoftBusEvtParam *)SoftBusMalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_MEDIUM) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ZERO].paramValue.u8v = medium;

    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_ERROR_CODE) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_ONE].paramValue.u8v = errorCode;

    msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_DEV_ID) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_TWO].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, devId) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }

    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
        CONN_PARAM_NIGHT_MODE) != EOK) {
        SoftBusFree(msg->paramArray);
        return SOFTBUS_ERR;
    }
    msg->paramArray[SOFTBUS_EVT_PARAM_THREE].paramValue.u8v = nightmode;
    return SOFTBUS_OK;
}