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
#include "softbus_hisysevt_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "securec.h"
#include "softbus_adapter_hisysevent.h"
#include "softbus_hisysevt_common.h"


#define FAULT_EVT_BUS_CENTER "BUS_CENTER_FAULT_EVT"
#define FAULT_EVT_BUS_PARAM_ERROR "ERROR_CODE"
#define FAULT_EVT_BUS_PARAM_ERROR_STR "ERROR_STR"
#define BUS_CENTER_PARAM_CONN_TYPE "CONN_TYPE"

#define STATISTIC_EVT_BUS_CENTER_SUCCESS "BUS_CENTER_SUCCESS_RATE"
#define BUS_CENTER_PARAM_TOTAL_COUNT "TOTAL_COUNT"
#define BUS_CENTER_PARAM_SUCCESS_COUNT "SUCCESS_COUNT"
#define BUS_CENTER_PARAM_SUCCESS_RATE "SUCCESS_RATE"

#define STATISTIC_EVT_BUS_CENTER_DURATION "BUS_CENTER_DURATION"
#define BUS_CENTER_PARAM_AVG_DURATION "AVG_DURATION"
#define BUS_CENTER_PARAM_MAX_DURATION "MAX_DURATION"
#define BUS_CENTER_PARAM_MIN_DURATION "MIN_DURATION"

#define LNN_TCP_CONNECTION_ERROR "conn_tcp_error"
#define LNN_BR_CONNECTION_ERROR "conn_bt_error"
#define LNN_BLE_CONNECTION_ERROR "conn_ble_error"
#define LNN_AUTH_START_ERROR "hichain_start_error"
#define LNN_AUTH_ERROR "hichain_error"
#define LNN_AUTH_TIMEOUT "auth_timeout"
#define LNN_AUTH_PROCESS_ERROR "hichain_pro_error"
#define LNN_UNPACK_DEV_INFO_ERROR "unpack_info_error"
#define LNN_PACK_DEV_INFO_ERROR "pack_info_error"

#define LNN_DIVIDE_AVERAGE_VALUE 2
#define DEFAULT_INT_VALUE 0
#define DEFAULT_FLOAT_VAULE 0.0

typedef struct {
    int32_t errorCode;
    char *errorCodeStr;
} BusCenterFaultError;

typedef enum {
    EVT_INDEX_ZERO = 0,
    EVT_INDEX_ONE = 1,
    EVT_INDEX_TWO = 2,
    EVT_INDEX_THREE = 3,
    EVT_INDEX_MAX = 4,
} SoftBusEvtParamIndex;

static BusCenterFaultError g_errorMap[] = {
    {SOFTBUS_NETWORK_AUTH_TCP_ERR, LNN_TCP_CONNECTION_ERROR},
    {SOFTBUS_NETWORK_AUTH_BLE_ERR, LNN_BLE_CONNECTION_ERROR},
    {SOFTBUS_NETWORK_AUTH_BR_ERR, LNN_BR_CONNECTION_ERROR},
    {SOFTBUS_AUTH_HICHAIN_AUTH_FAIL, LNN_AUTH_START_ERROR},
    {SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL, LNN_AUTH_PROCESS_ERROR},
    {SOFTBUS_AUTH_HICHAIN_AUTH_ERROR, LNN_AUTH_ERROR},
    {SOFTBUS_AUTH_TIMEOUT, LNN_AUTH_TIMEOUT},
    {SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL, LNN_UNPACK_DEV_INFO_ERROR},
};

SoftBusEvtReportMsg g_coapSuccessRate;
SoftBusEvtReportMsg g_bleSuccessRate;
SoftBusEvtReportMsg g_coapDuration;
SoftBusEvtReportMsg g_bleDuration;
static bool g_isBusCenterInit = false;

static int32_t InitDurationMsgDefault(SoftBusEvtReportMsg *msg)
{
    if (msg->paramArray == NULL) {
        msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;
        msg->paramArray = (SoftBusEvtParam *)SoftBusCalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
        if (msg->paramArray == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        do {
            msg->paramArray[EVT_INDEX_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_AVG_DURATION) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_AVG_DURATION);
                break;
            }
            msg->paramArray[EVT_INDEX_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_MAX_DURATION) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_MAX_DURATION);
                break;
            }
            msg->paramArray[EVT_INDEX_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_MIN_DURATION) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_MIN_DURATION);
                break;
            }
            msg->paramArray[EVT_INDEX_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_CONN_TYPE) != EOK) {
                break;
            }
            return SOFTBUS_OK;
        } while (false);
        SoftBusFree(msg->paramArray);
        msg->paramNum = SOFTBUS_EVT_PARAM_ZERO;
        msg->paramArray = NULL;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_ERR;
}

static void RecoveryStatisticDuration(SoftBusEvtReportMsg *msg)
{
    msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v = DEFAULT_INT_VALUE;
    msg->paramArray[EVT_INDEX_ONE].paramValue.i32v = DEFAULT_INT_VALUE;
    msg->paramArray[EVT_INDEX_TWO].paramValue.i32v = DEFAULT_INT_VALUE;
    if (msg == &g_coapDuration) {
        msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = CONNECTION_ADDR_WLAN;
    }
    if (msg == &g_bleDuration) {
        msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = CONNECTION_ADDR_BLE;
    }
}

static int32_t InitRateOfSuccessMsgDefault(SoftBusEvtReportMsg *msg)
{
    if (msg->paramArray == NULL) {
        msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;
        msg->paramArray = (SoftBusEvtParam *)SoftBusCalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
        if (msg->paramArray == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        do {
            msg->paramArray[EVT_INDEX_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_TOTAL_COUNT) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_TOTAL_COUNT);
                break;
            }
            msg->paramArray[EVT_INDEX_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_SUCCESS_COUNT) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_SUCCESS_COUNT);
                break;
            }
            msg->paramArray[EVT_INDEX_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_FLOAT;
            if (strcpy_s(msg->paramArray[EVT_INDEX_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_SUCCESS_RATE) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_SUCCESS_RATE);
                break;
            }
            msg->paramArray[EVT_INDEX_THREE].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
            if (strcpy_s(msg->paramArray[EVT_INDEX_THREE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
                BUS_CENTER_PARAM_CONN_TYPE) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_CONN_TYPE);
                break;
            }
            return SOFTBUS_OK;
        } while (false);
        SoftBusFree(msg->paramArray);
        msg->paramNum = SOFTBUS_EVT_PARAM_ZERO;
        msg->paramArray = NULL;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_ERR;
}

static void RecoveryStatisticRateOfSuccessMsg(SoftBusEvtReportMsg *msg)
{
    msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v = DEFAULT_INT_VALUE;
    msg->paramArray[EVT_INDEX_ONE].paramValue.i32v = DEFAULT_INT_VALUE;
    msg->paramArray[EVT_INDEX_TWO].paramValue.f = DEFAULT_FLOAT_VAULE;
    if (msg == &g_coapSuccessRate) {
        msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = CONNECTION_ADDR_WLAN;
    }
    if (msg == &g_bleSuccessRate) {
        msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = CONNECTION_ADDR_BLE;
    }
    return;
}

static int32_t InitSuccessRateStatisticMsg(SoftBusEvtReportMsg *msg)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_BUS_CENTER_SUCCESS) != EOK) {
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_ZERO;
    msg->paramArray = NULL;
    if (InitRateOfSuccessMsgDefault(msg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "InitSuccessRateStatisticMsg failed!");
        return SOFTBUS_ERR;
    }
    RecoveryStatisticRateOfSuccessMsg(msg);
    return SOFTBUS_OK;
}

static int32_t InitDurationStatisticMsg(SoftBusEvtReportMsg *msg)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_BUS_CENTER_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s evtname %s fail", STATISTIC_EVT_BUS_CENTER_DURATION);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_ZERO;
    msg->paramArray = NULL;
    if (InitDurationMsgDefault(msg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "InitDurationMsgDefault failed!");
        return SOFTBUS_ERR;
    }
    RecoveryStatisticDuration(msg);
    return SOFTBUS_OK;
}

static int32_t InitStatisticMsg(void)
{
    if (InitSuccessRateStatisticMsg(&g_coapSuccessRate) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (InitSuccessRateStatisticMsg(&g_bleSuccessRate) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (InitDurationStatisticMsg(&g_coapDuration) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (InitDurationStatisticMsg(&g_bleDuration) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static SoftBusEvtReportMsg *GetStatisticDurationEvtMsg(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN) {
        return &g_coapDuration;
    } else if (type == CONNECTION_ADDR_BLE) {
        return &g_bleDuration;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dfx don't support connection type=%d", type);
    return NULL;
}

static SoftBusEvtReportMsg *GetStatisticSuccessRateEvtMsg(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN) {
        return &g_coapSuccessRate;
    } else if (type == CONNECTION_ADDR_BLE) {
        return &g_bleSuccessRate;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dfx don't support connection type=%d", type);
    return NULL;
}

char *ConvertErrorToErrorStr(int32_t codeError)
{
    uint32_t count = sizeof(g_errorMap) / sizeof(BusCenterFaultError);
    for (uint32_t i = 0; i < count; i++) {
        if (g_errorMap[i].errorCode == codeError) {
            return g_errorMap[i].errorCodeStr;
        }
    }
    return NULL;
}

static SoftBusEvtReportMsg *GetRateOfSuccessMsg(LnnStatisticData *data)
{
    return GetStatisticSuccessRateEvtMsg(data->type);
}

int32_t AddStatisticRateOfSuccess(LnnStatisticData *data)
{
    if (data == NULL) {
        return SOFTBUS_ERR;
    }
    SoftBusEvtReportMsg *msg = GetRateOfSuccessMsg(data);
    if (msg == NULL || msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v++;
    if (data->retCode == SOFTBUS_OK) {
        msg->paramArray[EVT_INDEX_ONE].paramValue.i32v++;
    }
    if (msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v > 0) {
        msg->paramArray[EVT_INDEX_TWO].paramValue.f = (float)msg->paramArray[EVT_INDEX_ONE].paramValue.i32v /
            (float)msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v;
    }
    msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = data->type;
    return SOFTBUS_OK;
}

static SoftBusEvtReportMsg *GetDurationMsg(LnnStatisticData *data)
{
    return GetStatisticDurationEvtMsg(data->type);
}

int32_t AddStatisticDuration(LnnStatisticData *data)
{
    if (data == NULL || data->retCode != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    int32_t duration = 0;
    if (data->beginTime !=0 && data->endTime != 0) {
        duration = (data->endTime > data->beginTime) ? (data->endTime - data->beginTime) : 0;
    }
    if (duration == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add duration fail due to duration = 0");
        return SOFTBUS_ERR;
    }
    SoftBusEvtReportMsg *msg = GetDurationMsg(data);
    if (msg == NULL || msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v = (msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v + duration) /
        LNN_DIVIDE_AVERAGE_VALUE;
    msg->paramArray[EVT_INDEX_ONE].paramValue.i32v = (msg->paramArray[EVT_INDEX_ONE].paramValue.i32v > duration) ?
        msg->paramArray[EVT_INDEX_ONE].paramValue.i32v : duration;
    if (msg->paramArray[EVT_INDEX_TWO].paramValue.i32v != 0) {
        msg->paramArray[EVT_INDEX_TWO].paramValue.i32v = (msg->paramArray[EVT_INDEX_TWO].paramValue.i32v < duration) ?
            msg->paramArray[EVT_INDEX_TWO].paramValue.i32v : duration;
    } else {
        msg->paramArray[EVT_INDEX_TWO].paramValue.i32v = duration;
    }
    msg->paramArray[EVT_INDEX_THREE].paramValue.i32v = data->type;
    return SOFTBUS_OK;
}

static int32_t ReportStatisticBleDurationEvt(void)
{
    int32_t ret = SoftbusWriteHisEvt(&g_bleDuration);
    if (g_bleDuration.paramArray != NULL) {
        RecoveryStatisticDuration(&g_bleDuration);
    }
    return ret;
}

static int32_t ReportStatisticWlanDurationEvt(void)
{
    int32_t ret = SoftbusWriteHisEvt(&g_coapDuration);
    if (g_coapDuration.paramArray != NULL) {
        RecoveryStatisticDuration(&g_coapDuration);
    }
    return ret;
}

static int32_t ReportStatisticWlanSuccessRataEvt(void)
{
    int32_t ret = SoftbusWriteHisEvt(&g_coapSuccessRate);
    if (g_coapSuccessRate.paramArray != NULL) {
        RecoveryStatisticRateOfSuccessMsg(&g_coapSuccessRate);
    }
    return ret;
}

static int32_t ReportStatisticBleSuccessRataEvt(void)
{
    int32_t ret = SoftbusWriteHisEvt(&g_bleSuccessRate);
    if (g_bleSuccessRate.paramArray != NULL) {
        RecoveryStatisticRateOfSuccessMsg(&g_bleSuccessRate);
    }
    return ret;
}

static int32_t MakeFaultEvt(SoftBusEvtReportMsg *msg)
{
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, FAULT_EVT_BUS_CENTER) != EOK) {
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_FAULT;
    msg->paramNum = SOFTBUS_EVT_PARAM_THREE;
    msg->paramArray = (SoftBusEvtParam *)SoftBusCalloc(sizeof(SoftBusEvtParam) * msg->paramNum);
    if (msg->paramArray == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " make fault evt malloc fail");
        return SOFTBUS_ERR;
    }
    do {
        msg->paramArray[EVT_INDEX_ZERO].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
        if (strcpy_s(msg->paramArray[EVT_INDEX_ZERO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
            FAULT_EVT_BUS_PARAM_ERROR) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    FAULT_EVT_BUS_PARAM_ERROR);
            break;
        }
        msg->paramArray[EVT_INDEX_ONE].paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
        if (strcpy_s(msg->paramArray[EVT_INDEX_ONE].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
            FAULT_EVT_BUS_PARAM_ERROR_STR) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    FAULT_EVT_BUS_PARAM_ERROR_STR);
            break;
        }
        msg->paramArray[EVT_INDEX_TWO].paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
        if (strcpy_s(msg->paramArray[EVT_INDEX_TWO].paramName, SOFTBUS_HISYSEVT_PARAM_LEN,
            BUS_CENTER_PARAM_CONN_TYPE) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, " strcpy_s param name %s fail",
                    BUS_CENTER_PARAM_CONN_TYPE);
            break;
        }
        return SOFTBUS_OK;
    } while (false);
    SoftBusFree(msg->paramArray);
    msg->paramArray = NULL;
    return SOFTBUS_ERR;
}

int32_t CreateBusCenterFaultEvt(SoftBusEvtReportMsg *msg, int32_t errorCode, ConnectionAddr *addr)
{
    if (msg == NULL || addr == NULL) {
        return SOFTBUS_ERR;
    }
    char *errorStr = ConvertErrorToErrorStr(errorCode);
    if (errorStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dfx error not need report");
        return SOFTBUS_OK;
    }
    if (MakeFaultEvt(msg) != SOFTBUS_OK || msg->paramArray == NULL) {
        return SOFTBUS_ERR;
    }
    msg->paramArray[EVT_INDEX_ZERO].paramValue.i32v = errorCode;
    if (strcpy_s(msg->paramArray[EVT_INDEX_ONE].paramValue.str, sizeof(msg->paramArray[EVT_INDEX_ONE].paramValue.str),
        errorStr) != EOK) {
        SoftBusFree(msg->paramArray);
        msg->paramArray = NULL;
        return SOFTBUS_ERR;
    }
    msg->paramArray[EVT_INDEX_TWO].paramValue.i32v = addr->type;
    return SOFTBUS_OK;
}

int32_t ReportBusCenterFaultEvt(SoftBusEvtReportMsg *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "msg is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(msg->evtName, FAULT_EVT_BUS_CENTER) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not match msg name!!!");
        return SOFTBUS_ERR;
    }
    int32_t ret = SoftbusWriteHisEvt(msg);
    if (msg->paramArray != NULL) {
        SoftBusFree(msg->paramArray);
        msg->paramArray = NULL;
    }
    return ret;
}

int32_t InitBusCenterDfx(void)
{
    if (g_isBusCenterInit) {
        return SOFTBUS_OK;
    }
    if (InitStatisticMsg() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_WLAN_DURATION, ReportStatisticWlanDurationEvt)
        != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_BLE_DURATION, ReportStatisticBleDurationEvt)
        != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_WLAN_RATE_SUCCESS, ReportStatisticWlanSuccessRataEvt)
        != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_BLE_RATE_SUCCESS, ReportStatisticBleSuccessRataEvt)
        != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    g_isBusCenterInit = true;
    return SOFTBUS_OK;
}