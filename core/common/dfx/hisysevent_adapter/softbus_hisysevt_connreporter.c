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

#include "softbus_hisysevt_connreporter.h"

#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_hisysevt_common.h"

#define STATISTIC_EVT_CONN_DURATION "CONN_DURATION"
#define STATISTIC_EVT_CONN_SUCC_RATE "CONN_SUCC_RATE"
#define FAULT_EVT_CONN_FAULT "CONN_FAULT"

#define CONN_PARAM_MEDIUM "MEDIUM"
#define CONN_PARAM_MAX_CONN_DURATION "MAX_CONN_DURATION"
#define CONN_PARAM_MIN_CONN_DURATION "MIN_CONN_DURATION"
#define CONN_PARAM_AVG_CONN_DURATION "AVG_CONN_DURATION"
#define CONN_PARAM_CONN_SUCC_RATE "SUCC_RATE"
#define CONN_PARAM_CONN_SUCC_TIMES "SUCC_TIMES"
#define CONN_PARAM_CONN_FAIL_TIMES "FAIL_TIMES"
#define CONN_PARAM_ERROR_CODE "ERROR_CODE"
#define CONN_PARAM_ERROR_COUNTER "ERROR_COUNTER"

typedef struct {
    SoftBusMutex lock;
    uint32_t maxConnDur;
    uint32_t minConnDur;
    uint32_t avgConnDur;
    uint64_t totalConnTime;
} ConnTimeDur;

typedef struct {
    SoftBusMutex lock;
    uint32_t succTime;
    uint32_t failTime;
    uint32_t totalCnt;
    float succRate;
} ConnSuccRate;

static ConnTimeDur g_connTimeDur[SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT];
static ConnSuccRate g_connSuccRate[SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT];

static inline int32_t InitConnItemMutexLock(uint32_t index, SoftBusMutexAttr *mutexAttr)
{
    if (SoftBusMutexInit(&g_connTimeDur[index].lock, mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_connTimeDur lock mutex failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_connSuccRate[index].lock, mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_connSuccRate lock mutex failed");
        (void)SoftBusMutexDestroy(&g_connTimeDur[index].lock);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitConnEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    int32_t nRet = SOFTBUS_OK;
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP; i < SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT; i++) {
        nRet = InitConnItemMutexLock(i, &mutexAttr);
    }
    return nRet;
}

static inline void ClearConnTimeDur(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP; i < SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT; i++) {
        memset_s(&g_connTimeDur[i].maxConnDur, sizeof(ConnTimeDur) - sizeof(SoftBusMutex),
            0, sizeof(ConnTimeDur) - sizeof(SoftBusMutex));
    }
}

static int32_t SoftBusCreateConnDurMsg(SoftBusEvtReportMsg *msg, uint8_t medium)
{
    if (SoftBusMutexLock(&g_connTimeDur[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_connTimeDur lock fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CONN_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy evtname %s fail", STATISTIC_EVT_CONN_DURATION);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;

    SoftBusEvtParam *param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_MAX_CONN_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_MAX_CONN_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_connTimeDur[medium].maxConnDur;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_MIN_CONN_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_MIN_CONN_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_connTimeDur[medium].minConnDur;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_AVG_CONN_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_AVG_CONN_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_connTimeDur[medium].avgConnDur;

    (void)SoftBusMutexUnlock(&g_connTimeDur[medium].lock);
    return SOFTBUS_OK;
}

static int32_t SoftBusReportConnTimeDurEvt(void)
{
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_FOUR);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP; i < SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT; i++) {
        if (SoftBusCreateConnDurMsg(msg, i) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearConnTimeDur();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create conn time reportMsg fail");
            return SOFTBUS_ERR;
        }
        if (SoftbusWriteHisEvt(msg) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearConnTimeDur();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create conn time reportMsg fail");
            return SOFTBUS_ERR;
        }
    }
    SoftbusFreeEvtReporMsg(msg);
    ClearConnTimeDur();
    return SOFTBUS_OK;
}

static inline void ClearConnSuccRate(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP; i < SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT; i++) {
        memset_s(&g_connSuccRate[i].succTime, sizeof(ConnSuccRate) - sizeof(SoftBusMutex),
            0, sizeof(ConnSuccRate) - sizeof(SoftBusMutex));
    }
}

static int32_t SoftBusCreateConnSuccRateMsg(SoftBusEvtReportMsg *msg, uint8_t medium)
{
    if (SoftBusMutexLock(&g_connSuccRate[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_connSuccRate lock fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CONN_SUCC_RATE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy evtname %s fail", STATISTIC_EVT_CONN_SUCC_RATE);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;

    SoftBusEvtParam *param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_CONN_SUCC_TIMES) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_CONN_SUCC_TIMES);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_connSuccRate[medium].succTime;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_CONN_FAIL_TIMES) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_CONN_FAIL_TIMES);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_connSuccRate[medium].failTime;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_FLOAT;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_CONN_SUCC_RATE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", CONN_PARAM_CONN_SUCC_RATE);
        return SOFTBUS_ERR;
    }
    param->paramValue.f = g_connSuccRate[medium].succRate;
    (void)SoftBusMutexUnlock(&g_connSuccRate[medium].lock);
    return SOFTBUS_OK;
}

static int32_t SoftBusReportConnSuccRateEvt(void)
{
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_FOUR);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP; i < SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT; i++) {
        if (SoftBusCreateConnSuccRateMsg(msg, i) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearConnSuccRate();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create conn succ reportMsg fail");
            return SOFTBUS_ERR;
        }
        if (SoftbusWriteHisEvt(msg) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearConnSuccRate();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "write conn succ reportMsg fail");
            return SOFTBUS_ERR;
        }
    }
    SoftbusFreeEvtReporMsg(msg);
    ClearConnSuccRate();
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateConnFaultMsg(SoftBusEvtReportMsg *msg, uint8_t medium, int32_t errCode)
{
    if (msg == NULL) {
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, FAULT_EVT_CONN_FAULT) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s evtname %s fail", FAULT_EVT_CONN_FAULT);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_FAULT;
    msg->paramNum = SOFTBUS_EVT_PARAM_TWO;

    SoftBusEvtParam *param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", CONN_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, CONN_PARAM_ERROR_CODE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", CONN_PARAM_ERROR_CODE);
        return SOFTBUS_ERR;
    }
    param->paramValue.i32v = errCode;

    return SOFTBUS_OK;
}

int32_t SoftBusReportConnFaultEvt(uint8_t medium, int32_t errCode)
{
    if (medium >= SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT || errCode < SOFTBUS_HISYSEVT_CONN_MANAGER_OP_NOT_SUPPORT ||
        errCode >= SOFTBUS_HISYSEVT_CONN_ERRCODE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_THREE);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Alloc EvtReport Msg Fail!");
        return SOFTBUS_ERR;
    }

    SoftBusCreateConnFaultMsg(msg, medium, errCode);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReporMsg(msg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Sys Evt Witre conn fault msg fail!");
    }
    return ret;
}

int32_t SoftbusRecordConnInfo(uint8_t medium, SoftBusConnStatus isSucc, uint32_t time)
{
    if (medium >= SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_connSuccRate[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record conn info fail");
        return SOFTBUS_ERR;
    }
    
    g_connSuccRate[medium].failTime += (isSucc != SOFTBUS_EVT_CONN_SUCC);
    g_connSuccRate[medium].succTime += (isSucc == SOFTBUS_EVT_CONN_SUCC);
    g_connSuccRate[medium].totalCnt += 1;
    g_connSuccRate[medium].succRate = (float)(g_connSuccRate[medium].succTime) /
        (float)(g_connSuccRate[medium].totalCnt);

    (void)SoftBusMutexUnlock(&g_connSuccRate[medium].lock);

    if (isSucc != SOFTBUS_EVT_CONN_SUCC) {
        return SOFTBUS_OK;
    }

    if (SoftBusMutexLock(&g_connTimeDur[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_connTimeDur lock fail");
        return SOFTBUS_ERR;
    }
    
    if (time > g_connTimeDur[medium].maxConnDur) {
        g_connTimeDur[medium].maxConnDur = time;
    } else if (time < g_connTimeDur[medium].minConnDur) {
        g_connTimeDur[medium].minConnDur = time;
    }

    g_connTimeDur[medium].totalConnTime += time;
    g_connTimeDur[medium].avgConnDur = (uint32_t)(g_connTimeDur[medium].totalConnTime /
        g_connSuccRate[medium].succTime);

    (void)SoftBusMutexUnlock(&g_connTimeDur[medium].lock);
    return SOFTBUS_OK;
}

int32_t InitConnStatisticSysEvt(void)
{
    if (InitConnEvtMutexLock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Conn Statistic Evt Lock Init Fail!");
        return SOFTBUS_ERR;
    }
    ClearConnTimeDur();
    ClearConnSuccRate();
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_CONN_DURATION, SoftBusReportConnTimeDurEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_CONN_SUCC_RATE, SoftBusReportConnSuccRateEvt);
    return SOFTBUS_OK;
}
