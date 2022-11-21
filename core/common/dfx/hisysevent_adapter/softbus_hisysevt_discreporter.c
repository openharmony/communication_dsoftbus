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

#include "softbus_hisysevt_discreporter.h"
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_hisysevt_common.h"

#define BEHAVIOR_EVT_DISC_START "DISC_STARTUP"
#define STATISTIC_EVT_FIRST_DISC_DURATION "FIRST_DISC_DURATION"
#define STATISTIC_EVT_SCAN_TIMES "SCAN_TIMES"
#define STATISTIC_EVT_DISC_FAULT "DISC_FAULT"

#define DISC_PARAM_DISC_PACKAGE_NAME "PACKAGE_NAME"
#define DISC_PARAM_MEDIUM "MEDIUM"
#define DISC_PARAM_MAX_DISC_DURATION "MAX_DISC_DURATION"
#define DISC_PARAM_MIN_DISC_DURATION "MIN_DISC_DURATION"
#define DISC_PARAM_AVG_DISC_DURATION "AVG_DISC_DURATION"
#define DISC_PARAM_SCAN_COUNTER "SCAN_COUNTER"
#define DISC_PARAM_ERROR_COUNTER "ERROR_COUNTER"
#define DISC_PARAM_ERROR_CODE "ERROR_CODE"

typedef struct {
    SoftBusMutex lock;
    uint32_t maxDiscDur;
    uint32_t minDiscDur;
    uint64_t totalDiscTime;
    uint32_t discCnt;
    uint32_t avgDiscDur;
} FirstDiscTime;

typedef struct {
    SoftBusMutex lock;
    uint32_t scanTimes;
} DiscScanTimes;

typedef struct {
    SoftBusMutex lock;
    uint32_t errCnt[SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT];
} DiscFault;

typedef struct {
    int32_t originErrCode;
    int32_t dstErrCode;
} ErrorCodeMap;

static FirstDiscTime g_firstDiscTime[SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT];
static DiscScanTimes g_scanTimes[SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT];
static DiscFault g_discFault[SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT];

static int32_t InitDiscItemMutexLock(uint32_t index, SoftBusMutexAttr *mutexAttr)
{
    if (SoftBusMutexInit(&g_firstDiscTime[index].lock, mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init g_firstDiscTime lock fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_scanTimes[index].lock, mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init g_scanTimes lock fail");
        (void)SoftBusMutexDestroy(&g_firstDiscTime[index].lock);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_discFault[index].lock, mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init g_discFault lock fail");
        (void)SoftBusMutexDestroy(&g_firstDiscTime[index].lock);
        (void)SoftBusMutexDestroy(&g_scanTimes[index].lock);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitDiscEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    int32_t nRet = SOFTBUS_OK;
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        nRet = InitDiscItemMutexLock(i, &mutexAttr);
    }

    return nRet;
}

static inline void ClearFirstDiscTime(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        memset_s(&g_firstDiscTime[i].maxDiscDur, sizeof(FirstDiscTime) - sizeof(SoftBusMutex),
            0, sizeof(FirstDiscTime) - sizeof(SoftBusMutex));
    }
}

static int32_t SoftBusCreateFirstDiscDurMsg(SoftBusEvtReportMsg *msg, uint8_t medium)
{
    if (SoftBusMutexLock(&g_firstDiscTime[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_firstDiscTime lock fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_FIRST_DISC_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy evtname %s fail", STATISTIC_EVT_FIRST_DISC_DURATION);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FOUR;

    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", DISC_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_MAX_DISC_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", DISC_PARAM_MAX_DISC_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_firstDiscTime[medium].maxDiscDur;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_MIN_DISC_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", DISC_PARAM_MIN_DISC_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_firstDiscTime[medium].minDiscDur;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_AVG_DISC_DURATION) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy paramName %s fail", DISC_PARAM_AVG_DISC_DURATION);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_firstDiscTime[medium].avgDiscDur;

    (void)SoftBusMutexUnlock(&g_firstDiscTime[medium].lock);
    return SOFTBUS_OK;
}

static int32_t SoftBusReportFirstDiscDurationEvt(void)
{
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_FOUR);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        if (SoftBusCreateFirstDiscDurMsg(msg, i) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearFirstDiscTime();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create first disc duration reportMsg fail");
            return SOFTBUS_ERR;
        }
        if (SoftbusWriteHisEvt(msg) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearFirstDiscTime();
            return SOFTBUS_ERR;
        }
    }
    SoftbusFreeEvtReporMsg(msg);
    ClearFirstDiscTime();
    return SOFTBUS_OK;
}

static inline void ClearScanTimes(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        g_scanTimes[i].scanTimes = 0;
    }
}

static int32_t SoftBusCreateScanTimesMsg(SoftBusEvtReportMsg *msg, uint8_t medium)
{
    if (SoftBusMutexLock(&g_scanTimes[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_scanTimes lock fail medium %d", medium);
        return SOFTBUS_ERR;
    }

    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_SCAN_TIMES) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s evtname %s fail", STATISTIC_EVT_SCAN_TIMES);
        return SOFTBUS_ERR;
    }

    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_TWO;

    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_SCAN_COUNTER) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_SCAN_COUNTER);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_scanTimes[medium].scanTimes;
    (void)SoftBusMutexUnlock(&g_scanTimes[medium].lock);
    return SOFTBUS_OK;
}

static int32_t SoftBusReportScanTimesEvt(void)
{
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_TWO);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        if (SoftBusCreateScanTimesMsg(msg, i) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearScanTimes();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create scan timers reportMsg fail");
            return SOFTBUS_ERR;
        }
        if (SoftbusWriteHisEvt(msg) != SOFTBUS_OK) {
            SoftbusFreeEvtReporMsg(msg);
            ClearScanTimes();
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "write scan times reportMsg fail");
            return SOFTBUS_ERR;
        }
    }
    SoftbusFreeEvtReporMsg(msg);
    ClearScanTimes();
    return SOFTBUS_OK;
}

static inline void ClearDiscFault(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        memset_s(&g_discFault[i].errCnt, sizeof(DiscFault) - sizeof(SoftBusMutex),
            0, sizeof(DiscFault) - sizeof(SoftBusMutex));
    }
}

static int32_t SoftBusCreateDiscFaultMsg(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t errorCode)
{
    if (SoftBusMutexLock(&g_discFault[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "add g_discFault lock fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DISC_FAULT) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s evt name %s fail", STATISTIC_EVT_DISC_FAULT);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_THREE;

    SoftBusEvtParam *param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_MEDIUM) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_MEDIUM);
        return SOFTBUS_ERR;
    }
    param->paramValue.u8v = medium;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_ERROR_CODE) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_ERROR_CODE);
        return SOFTBUS_ERR;
    }
    param->paramValue.i32v = (int)errorCode;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_ERROR_COUNTER) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_ERROR_COUNTER);
        return SOFTBUS_ERR;
    }
    param->paramValue.u32v = g_discFault[medium].errCnt[errorCode];
    (void)SoftBusMutexUnlock(&g_discFault[medium].lock);
    return SOFTBUS_OK;
}

static int32_t SoftBusReportDiscFaultEvt(void)
{
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_THREE);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        for (int32_t k = 0; k < SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT; k++) {
            int32_t ret = SoftBusCreateDiscFaultMsg(msg, i, k);
            if (ret == SOFTBUS_ERR) {
                SoftbusFreeEvtReporMsg(msg);
                ClearDiscFault();
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create disc fault msg fail");
                return SOFTBUS_ERR;
            }
            if (SoftbusWriteHisEvt(msg) != SOFTBUS_OK) {
                SoftbusFreeEvtReporMsg(msg);
                ClearDiscFault();
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "write disc fault msg fail");
                return SOFTBUS_ERR;
            }
        }
    }

    SoftbusFreeEvtReporMsg(msg);
    ClearDiscFault();
    return SOFTBUS_OK;
}

static int32_t SoftbusCreateDiscStartupMsg(SoftBusEvtReportMsg *msg, const char *pkgName)
{
    // event
    if (strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, BEHAVIOR_EVT_DISC_START) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s evtname %s fail", BEHAVIOR_EVT_DISC_START);
        return SOFTBUS_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_BEHAVIOR;
    msg->paramNum = SOFTBUS_EVT_PARAM_ONE;

    // param 0
    SoftBusEvtParam *param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_PARAM_DISC_PACKAGE_NAME) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", DISC_PARAM_DISC_PACKAGE_NAME);
        return SOFTBUS_ERR;
    }
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    int32_t offset = strlen(pkgName) - SOFTBUS_HISYSEVT_PARAM_LEN + 1;
    offset = offset > 0 ? offset : 0;
    if (strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, pkgName + offset) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy_s param name %s fail", pkgName);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusReportDiscStartupEvt(const char *packageName)
{
    if (packageName == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create reportMsg fail");
        return SOFTBUS_ERR;
    }
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_ONE);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Alloc disc startup Msg Fail!");
        return SOFTBUS_ERR;
    }

    SoftbusCreateDiscStartupMsg(msg, packageName);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReporMsg(msg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Sys Evt Witre Startup msg fail!");
    }
    return ret;
}

int32_t SoftbusRecordFirstDiscTime(uint8_t medium, uint32_t time)
{
    if (medium >= SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_firstDiscTime[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record first disc time lock fail");
        return SOFTBUS_ERR;
    }
    
    g_firstDiscTime[medium].totalDiscTime += time;
    g_firstDiscTime[medium].discCnt++;
    if (time > g_firstDiscTime[medium].maxDiscDur) {
        g_firstDiscTime[medium].maxDiscDur = time;
    } else if (time < g_firstDiscTime[medium].minDiscDur) {
        g_firstDiscTime[medium].minDiscDur = time;
    }
    g_firstDiscTime[medium].avgDiscDur = (uint32_t)(g_firstDiscTime[medium].totalDiscTime /
        g_firstDiscTime[medium].discCnt);
    if (SoftBusMutexUnlock(&g_firstDiscTime[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record first disc time unlock fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusRecordDiscScanTimes(uint8_t medium)
{
    if (medium >= SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scanTimes[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record disc scan lock fail");
        return SOFTBUS_ERR;
    }
    g_scanTimes[medium].scanTimes++;
    if (SoftBusMutexUnlock(&g_scanTimes[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record disc scan unlock fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static ErrorCodeMap g_error_map [SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT] = {
    {SOFTBUS_TIMOUT, SOFTBUS_HISYSEVT_DISC_ERRCODE_TIMEOUT},
    {SOFTBUS_DISCOVER_NOT_INIT, SOFTBUS_HISYSEVT_DISCOVER_NOT_INIT},
    {SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL, SOFTBUS_HISYSEVT_DISCOVER_MANAGER_INNERFUNCTION_FAIL},
    {SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL},
    {SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL},
    {SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL},
    {SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL},
    {SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL},
    {SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL, SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL},
    {SOFTBUS_ERR, SOFTBUS_HISYSEVT_ERR},
};

static int32_t ErrCodeConvert(int32_t errCode)
{
    for (int32_t i = 0; i < SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT - 1; i++) {
        if (errCode == g_error_map[i].originErrCode) {
            return g_error_map[i].dstErrCode;
        }
    }
    return SOFTBUS_HISYSEVT_ERR;
}

int32_t SoftbusRecordDiscFault(uint8_t medium, int32_t errCode)
{
    if (medium >= SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_discFault[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record disc fault lock fail");
        return SOFTBUS_ERR;
    }
    g_discFault[medium].errCnt[ErrCodeConvert(errCode)]++;
    if (SoftBusMutexUnlock(&g_discFault[medium].lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "record disc fault unlock fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t InitDiscStatisticSysEvt(void)
{
    if (InitDiscEvtMutexLock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "disc Statistic Evt Lock Init Fail!");
        return SOFTBUS_ERR;
    }
    ClearFirstDiscTime();
    ClearScanTimes();
    ClearDiscFault();

    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_FIRST_DISC_DURATION, SoftBusReportFirstDiscDurationEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_SCAN_TIMES, SoftBusReportScanTimesEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_FAULT, SoftBusReportDiscFaultEvt);
    return SOFTBUS_OK;
}