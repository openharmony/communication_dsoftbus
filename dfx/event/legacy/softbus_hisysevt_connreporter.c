/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "legacy/softbus_hisysevt_connreporter.h"

#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_common.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "softbus_utils.h"

#define DEFAULT_PACKAGE_NAME "dsoftbus"
#define TOTAL_TIME_KEY "TOTAL_TIME"
#define TOTAL_COUNT_KEY "TOTAL_COUNT"
#define COUNT1_KEY "COUNT1"
#define COUNT2_KEY "COUNT2"
#define COUNT3_KEY "COUNT3"
#define COUNT4_KEY "COUNT4"
#define COUNT5_KEY "COUNT5"
#define REQID_MAX 1000000

// CONN_DURATION
#define CONN_RESULT_DURATION_PARAM_NUM 13
#define SOFT_BUS_VERSION_KEY "SOFT_BUS_VERSION"
#define PACKAGE_VERSION_KEY "PACKAGE_VERSION"
#define CALLER_PACKAGE_NAME_KEY "CALLER_PACKAGE_NAME"
#define LINK_TYPE_KEY "LINK_TYPE"
#define FAIL_TIME_KEY "FAIL_TOTAL_TIME"
#define FAIL_COUNT_KEY "FAIL_TOTAL_COUNT"

// PROCESS_STEP_DURATION
#define PROCESS_STEP_DURATION_PARAM_NUM 11
#define SOFT_BUS_VERSION_KEY "SOFT_BUS_VERSION"
#define PACKAGE_VERSION_KEY "PACKAGE_VERSION"
#define PROCESS_STEP_KEY "PROCESS_STEP"
#define LINK_TYPE_KEY "LINK_TYPE"

typedef struct {
    SoftBusEvtParamType paramType;
    char paramName[SOFTBUS_HISYSEVT_NAME_LEN];
} SoftBusEvtParamSize;

typedef enum {
    STANDARD_S = 1500,
    STANDARD_A = 2000,
    STANDARD_B = 2500,
    STANDARD_C = 3000,
    STANDARD_D = 4000,
} ConnThreshold;

typedef struct {
    uint64_t mConnTotalTime;
    uint32_t mConnTotalCount;
    uint64_t mConnFailTime;
    uint32_t mConnFailCount;
    uint32_t mConnCount1;
    uint32_t mConnCount2;
    uint32_t mConnCount3;
    uint32_t mConnCount4;
    uint32_t mConnCount5;
} ConnResultRecord;

typedef struct {
    ListNode node;
    uint32_t pId;
    char pkgName[PKG_NAME_SIZE_MAX];
} PIdOfPkgNameNode;

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    ConnResultRecord connResultRecord[SOFTBUS_HISYSEVT_CONN_TYPE_BUTT];
} ConnResultApiRecordNode;

static SoftBusEvtParamSize g_connResultParam[CONN_RESULT_DURATION_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_STRING, SOFT_BUS_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_STRING, PACKAGE_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_STRING, CALLER_PACKAGE_NAME_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, LINK_TYPE_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, FAIL_TIME_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, FAIL_COUNT_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, TOTAL_TIME_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, TOTAL_COUNT_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT1_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT2_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT3_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT4_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT5_KEY},
};

typedef struct {
    uint64_t mStepTotalTime;
    uint32_t mStepTotalCount;
    uint32_t mStepCount1;
    uint32_t mStepCount2;
    uint32_t mStepCount3;
    uint32_t mStepCount4;
    uint32_t mStepCount5;
} ProcessStepRecord;

static SoftBusEvtParamSize g_processStepParam[PROCESS_STEP_DURATION_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_STRING, SOFT_BUS_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_STRING, PACKAGE_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, PROCESS_STEP_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, LINK_TYPE_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, TOTAL_TIME_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, TOTAL_COUNT_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT1_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT2_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT3_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT4_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT5_KEY},
};

static ListNode g_pIdOfPkgName = {0};
static SoftBusMutex g_pIdOfNameLock = {0};

static ListNode g_connResultApiRecord = {0};
static SoftBusMutex g_connResApiLock = {0};

static ProcessStepRecord g_processStep[SOFTBUS_HISYSEVT_CONN_TYPE_BUTT][STEP_BUTT] = {0};
static SoftBusMutex g_procStepLock = {0};

static char *g_softbusVersion = "default softbus version";
static char *g_packageVersion = "default package version";

uint32_t SoftbusGetConnectTraceId()
{
    static uint32_t connectTraceId = 0;
    connectTraceId = connectTraceId % REQID_MAX;
    return connectTraceId++;
}

static void ClearConnResultRecord(void)
{
    PIdOfPkgNameNode *pIdItem = NULL;
    PIdOfPkgNameNode *pIdNext = NULL;
    if (g_pIdOfPkgName.prev == NULL && g_pIdOfPkgName.next == NULL) {
        COMM_LOGE(COMM_EVENT, "g_pIdOfPkgName is NULL");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pIdItem, pIdNext, &(g_pIdOfPkgName), PIdOfPkgNameNode, node) {
        ListDelete(&pIdItem->node);
        SoftBusFree(pIdItem);
    }

    ConnResultApiRecordNode *conItem = NULL;
    ConnResultApiRecordNode *conNext = NULL;
    if (g_connResultApiRecord.prev == NULL && g_connResultApiRecord.next == NULL) {
        COMM_LOGE(COMM_EVENT, "g_connResultApiRecord is NULL");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(conItem, conNext, &(g_connResultApiRecord), ConnResultApiRecordNode, node) {
        ListDelete(&conItem->node);
        SoftBusFree(conItem);
    }
}

static void ClearProcessStep(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_CONN_TYPE_P2P; i < SOFTBUS_HISYSEVT_CONN_TYPE_BUTT; i++) {
        for (int32_t j = NEGOTIATION_STEP; j < STEP_BUTT; j++) {
            ProcessStepRecord *stepRecord = &g_processStep[i][j];
            if (stepRecord == NULL) {
                COMM_LOGE(COMM_EVENT, "stepRecord is NULL");
                continue;
            }
            stepRecord->mStepTotalTime = 0;
            stepRecord->mStepTotalCount = 0;
            stepRecord->mStepCount1 = 0;
            stepRecord->mStepCount2 = 0;
            stepRecord->mStepCount3 = 0;
            stepRecord->mStepCount4 = 0;
            stepRecord->mStepCount5 = 0;
        }
    }
}

static PIdOfPkgNameNode *GetPkgNameByPId(uint32_t pId)
{
    PIdOfPkgNameNode *item = NULL;
    PIdOfPkgNameNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_pIdOfPkgName), PIdOfPkgNameNode, node) {
        if (pId == item->pId) {
            return item;
        }
    }
    return NULL;
}

static int32_t AddPIdOfPkgNameNode(PIdOfPkgNameNode **pIdOfNameNode, uint32_t pId, const char *pkgName)
{
    PIdOfPkgNameNode *newNode = (PIdOfPkgNameNode *)SoftBusCalloc(sizeof(PIdOfPkgNameNode));
    COMM_CHECK_AND_RETURN_RET_LOGE(newNode != NULL, SOFTBUS_MALLOC_ERR, COMM_EVENT, "malloc fail");
    if (strcpy_s(newNode->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy pkgName fail. pkgName=%{public}s", pkgName);
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    newNode->pId = pId;
    ListAdd(&g_pIdOfPkgName, &newNode->node);
    *pIdOfNameNode = newNode;
    return SOFTBUS_OK;
}

static ConnResultApiRecordNode *GetRecordNodeByPkgName(const char *pkgName)
{
    ConnResultApiRecordNode *item = NULL;
    ConnResultApiRecordNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connResultApiRecord), ConnResultApiRecordNode, node) {
        if (strcmp(item->pkgName, pkgName) == 0) {
            return item;
        }
    }
    return NULL;
}

static int32_t InitConnResultRecord(ConnResultRecord *connResultRecord)
{
    for (SoftBusConnType connType = SOFTBUS_HISYSEVT_CONN_TYPE_BR; connType < SOFTBUS_HISYSEVT_CONN_TYPE_BUTT;
         connType++) {
        ConnResultRecord *connRecord = &connResultRecord[connType];
        connRecord->mConnTotalTime = 0;
        connRecord->mConnTotalCount = 0;
        connRecord->mConnFailTime = 0;
        connRecord->mConnFailCount = 0;
        connRecord->mConnCount1 = 0;
        connRecord->mConnCount2 = 0;
        connRecord->mConnCount3 = 0;
        connRecord->mConnCount4 = 0;
        connRecord->mConnCount5 = 0;
    }
    return SOFTBUS_OK;
}

static int32_t AddConnResultApiRecordNode(ConnResultApiRecordNode **connResultNode, char *pkgName)
{
    ConnResultApiRecordNode *newNode = (ConnResultApiRecordNode *)SoftBusCalloc(sizeof(ConnResultApiRecordNode));
    COMM_CHECK_AND_RETURN_RET_LOGE(newNode != NULL, SOFTBUS_MALLOC_ERR, COMM_EVENT, "malloc fail");
    if (strcpy_s(newNode->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy pkgName fail. pkgName=%{public}s", pkgName);
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    InitConnResultRecord(newNode->connResultRecord);
    ListAdd(&g_connResultApiRecord, &newNode->node);
    *connResultNode = newNode;
    return SOFTBUS_OK;
}

static int32_t SetMsgParamNameAndType(SoftBusEvtReportMsg *msg, SoftBusEvtParamSize *paramSize)
{
    SoftBusEvtParam *param = NULL;
    for (uint32_t i = SOFTBUS_EVT_PARAM_ZERO; i < msg->paramNum; i++) {
        param = &msg->paramArray[i];
        param->paramType = paramSize[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, paramSize[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "copy param name fail. paramName=%{public}s", paramSize[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetDevConnResultMsgParamValue(SoftBusEvtReportMsg *msg, ConnResultRecord *record, char *pkgName,
                                             SoftBusConnType connType)
{
    SoftBusEvtParam *param = msg->paramArray;
    errno_t errnoRet = strcpy_s(param[SOFTBUS_EVT_PARAM_ZERO].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN,
                                g_softbusVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy softbus version fail");

    errnoRet = strcpy_s(param[SOFTBUS_EVT_PARAM_ONE].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_packageVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy package version fail");

    errnoRet = strcpy_s(param[SOFTBUS_EVT_PARAM_TWO].paramValue.str, PKG_NAME_SIZE_MAX, pkgName);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy package name fail");

    param[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = connType;
    param[SOFTBUS_EVT_PARAM_FOUR].paramValue.u64v = record->mConnFailTime;
    param[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = record->mConnFailCount;
    param[SOFTBUS_EVT_PARAM_SIX].paramValue.u64v = record->mConnTotalTime;
    param[SOFTBUS_EVT_PARAM_SEVEN].paramValue.u32v = record->mConnTotalCount;
    param[SOFTBUS_EVT_PARAM_EIGHT].paramValue.u32v = record->mConnCount1;
    param[SOFTBUS_EVT_PARAM_NINE].paramValue.u32v = record->mConnCount2;
    param[SOFTBUS_EVT_PARAM_TEN].paramValue.u32v = record->mConnCount3;
    param[SOFTBUS_EVT_PARAM_ELEVEN].paramValue.u32v = record->mConnCount4;
    param[SOFTBUS_EVT_PARAM_TWELVE].paramValue.u32v = record->mConnCount5;

    return SOFTBUS_OK;
}

static int32_t SetDevProcStepMsgParamValue(SoftBusEvtReportMsg *msg, ProcessStepRecord *record,
                                           SoftBusConnType connType, ProcessStep step)
{
    SoftBusEvtParam *param = msg->paramArray;
    errno_t errnoRet = strcpy_s(param[SOFTBUS_EVT_PARAM_ZERO].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN,
                                g_softbusVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy softbus version fail");

    errnoRet = strcpy_s(param[SOFTBUS_EVT_PARAM_ONE].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_packageVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy package version fail");

    param[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = step;
    param[SOFTBUS_EVT_PARAM_THREE].paramValue.u32v = connType;
    param[SOFTBUS_EVT_PARAM_FOUR].paramValue.u64v = record->mStepTotalTime;
    param[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = record->mStepTotalCount;
    param[SOFTBUS_EVT_PARAM_SIX].paramValue.u32v = record->mStepCount1;
    param[SOFTBUS_EVT_PARAM_SEVEN].paramValue.u32v = record->mStepCount2;
    param[SOFTBUS_EVT_PARAM_EIGHT].paramValue.u32v = record->mStepCount3;
    param[SOFTBUS_EVT_PARAM_NINE].paramValue.u32v = record->mStepCount4;
    param[SOFTBUS_EVT_PARAM_TEN].paramValue.u32v = record->mStepCount5;
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateConnDurMsg(SoftBusEvtReportMsg *msg, ConnResultRecord *record, char *pkgName,
                                       SoftBusConnType connType)
{
    errno_t errnoRet = strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CONN_DURATION);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy evtname fail. STATISTIC_EVT_CONN_DURATION=%{public}s", STATISTIC_EVT_CONN_DURATION);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = CONN_RESULT_DURATION_PARAM_NUM;

    int32_t ret = SetMsgParamNameAndType(msg, g_connResultParam);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set name and type fail");
        return ret;
    }
    ret = SetDevConnResultMsgParamValue(msg, record, pkgName, connType);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param value fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateProcStepMsg(SoftBusEvtReportMsg *msg, SoftBusConnType connType, ProcessStep step)
{
    ProcessStepRecord *record = &g_processStep[connType][step];
    errno_t errnoRet = strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_PROCESS_STEP_DURATION);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy evtname fail. STATISTIC_EVT_PROCESS_STEP_DURATION=%{public}s", STATISTIC_EVT_PROCESS_STEP_DURATION);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = PROCESS_STEP_DURATION_PARAM_NUM;

    int32_t ret = SetMsgParamNameAndType(msg, g_processStepParam);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param name and type fail");
        return ret;
    }
    ret = SetDevProcStepMsgParamValue(msg, record, connType, step);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param value fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static inline void ClearConnResultMsg(SoftBusEvtReportMsg *msg)
{
    SoftbusFreeEvtReportMsg(msg);
    ClearConnResultRecord();
    SoftBusMutexUnlock(&g_connResApiLock);
}

static int32_t SoftBusReportConnResultRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report conn duration event");
    int32_t ret = SoftBusMutexLock(&g_connResApiLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "g_connResApiLock fail");

    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(CONN_RESULT_DURATION_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create duration event msg fail");
        ClearConnResultRecord();
        SoftBusMutexUnlock(&g_connResApiLock);
        return SOFTBUS_MALLOC_ERR;
    }
    ConnResultApiRecordNode *item = NULL;
    ConnResultApiRecordNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_connResultApiRecord), ConnResultApiRecordNode, node) {
        for (SoftBusConnType connType = SOFTBUS_HISYSEVT_CONN_TYPE_BR; connType < SOFTBUS_HISYSEVT_CONN_TYPE_BUTT;
             connType++)  {
            COMM_LOGD(COMM_EVENT, "create conn duration event msg connType=%{public}d", connType);
            char *pkgName = item->pkgName;
            ConnResultRecord *record = &item->connResultRecord[connType];
            if (record->mConnTotalCount == 0) {
                continue;
            }
            ret = SoftBusCreateConnDurMsg(msg, record, pkgName, connType);
            if (ret != SOFTBUS_OK) {
                ClearConnResultMsg(msg);
                COMM_LOGE(COMM_EVENT, "create conn duration event msg fail");
                return ret;
            }
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                ClearConnResultMsg(msg);
                COMM_LOGE(COMM_EVENT, "create conn duration event msg fail");
                return ret;
            }
        }
    }
    ClearConnResultMsg(msg);
    return SOFTBUS_OK;
}

static inline void ClearProcStepMsg(SoftBusEvtReportMsg *msg)
{
    SoftbusFreeEvtReportMsg(msg);
    ClearProcessStep();
    SoftBusMutexUnlock(&g_procStepLock);
}

static int32_t SoftBusReportProcessStepRecordEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report process step duration event");
    int32_t ret = SoftBusMutexLock(&g_procStepLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "process step duration lock fail");
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(PROCESS_STEP_DURATION_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create process step reportMsg fail");
        ClearProcessStep();
        SoftBusMutexUnlock(&g_procStepLock);
        return SOFTBUS_MALLOC_ERR;
    }
    for (SoftBusConnType connType = SOFTBUS_HISYSEVT_CONN_TYPE_P2P; connType < SOFTBUS_HISYSEVT_CONN_TYPE_BUTT;
         connType++)  {
        for (ProcessStep step = NEGOTIATION_STEP; step < STEP_BUTT; step++) {
            if (g_processStep[connType][step].mStepTotalCount == 0) {
                continue;
            }
            ret = SoftBusCreateProcStepMsg(msg, connType, step);
            if (ret != SOFTBUS_OK) {
                ClearProcStepMsg(msg);
                COMM_LOGE(COMM_EVENT, "create process step duration reportMsg fail");
                return ret;
            }
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                ClearProcStepMsg(msg);
                COMM_LOGE(COMM_EVENT, "write process step duration reportMsg fail");
                return ret;
            }
        }
    }
    ClearProcStepMsg(msg);
    return SOFTBUS_OK;
}

int32_t SoftBusRecordPIdAndPkgName(uint32_t pId, const char *pkgName)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(IsValidString(pkgName, PKG_NAME_SIZE_MAX), SOFTBUS_INVALID_PKGNAME, COMM_EVENT,
        "invalid param!");
    COMM_LOGD(COMM_EVENT, "record pid and pkg name, pid=%{public}d, pkgName=%{public}s", pId, pkgName);
    int32_t ret = SoftBusMutexLock(&g_pIdOfNameLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "pId of name lock fail");
    PIdOfPkgNameNode *pIdOfPkgNameNode = GetPkgNameByPId(pId);
    if (pIdOfPkgNameNode == NULL) {
        ret = AddPIdOfPkgNameNode(&pIdOfPkgNameNode, pId, pkgName);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "add pId of pkg name node fail");
            SoftBusMutexUnlock(&g_pIdOfNameLock);
            return ret;
        }
    }
    (void)SoftBusMutexUnlock(&g_pIdOfNameLock);
    return SOFTBUS_OK;
}

static void ConnResultRecordCount(ConnResultRecord *record, uint64_t costTime)
{
    record->mConnTotalTime += costTime;
    record->mConnTotalCount++;
    if (costTime > STANDARD_S) {
        record->mConnCount1++;
    }
    if (costTime > STANDARD_A) {
        record->mConnCount2++;
    }
    if (costTime > STANDARD_B) {
        record->mConnCount3++;
    }
    if (costTime > STANDARD_C) {
        record->mConnCount4++;
    }
    if (costTime > STANDARD_D) {
        record->mConnCount5++;
    }
}

static int32_t SoftbusReportConnFault(SoftBusConnType connType, int32_t errCode, char *pkgName)
{
    COMM_LOGD(COMM_EVENT, "report conn fault event");
    SoftBusFaultEvtInfo connFaultInfo;
    (void)memset_s(&connFaultInfo, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    connFaultInfo.moduleType = MODULE_TYPE_CONNECT;
    connFaultInfo.linkType = connType;
    connFaultInfo.errorCode = errCode;
    if (strcpy_s(connFaultInfo.callerPackName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy pkgName fail. pkgName=%{public}s", pkgName);
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = SoftBusReportBusCenterFaultEvt(&connFaultInfo);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "report conn fault evt fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusRecordConnResult(uint32_t pId, SoftBusConnType connType, SoftBusConnStatus status,
                                uint64_t costTime, int32_t errCode)
{
    COMM_LOGD(COMM_EVENT,
        "record conn duration. connType=%{public}d, status=%{public}d, costTime=%{public}" PRIu64,
        connType, status, costTime);
    if (connType < SOFTBUS_HISYSEVT_CONN_TYPE_BR || connType >= SOFTBUS_HISYSEVT_CONN_TYPE_BUTT ||
        status > SOFTBUS_EVT_CONN_FAIL) {
        COMM_LOGE(COMM_EVENT, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_pIdOfNameLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT,
        "pId lock fail!");
    PIdOfPkgNameNode *pIdNode = GetPkgNameByPId(pId);
    char pkgName[PKG_NAME_SIZE_MAX] = DEFAULT_PACKAGE_NAME;
    if (pIdNode != NULL) {
        COMM_LOGI(COMM_EVENT, "get pkg name by pId is NULL");
        errno_t errnoRet = strcpy_s(pkgName, PKG_NAME_SIZE_MAX, pIdNode->pkgName);
        if (errnoRet != EOK) {
            COMM_LOGE(COMM_EVENT, "strcpy pkgName fail");
            SoftBusMutexUnlock(&g_pIdOfNameLock);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    SoftBusMutexUnlock(&g_pIdOfNameLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_connResApiLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT,
        "conn res fail!");
    ConnResultApiRecordNode *connResultNode = GetRecordNodeByPkgName(pkgName);
    if (connResultNode == NULL) {
        int32_t ret = AddConnResultApiRecordNode(&connResultNode, pkgName);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "add conn result api record node fail");
            SoftBusMutexUnlock(&g_connResApiLock);
            return ret;
        }
    }
    ConnResultRecord *record = &connResultNode->connResultRecord[connType];
    ConnResultRecordCount(record, costTime);
    if (status == SOFTBUS_EVT_CONN_SUCC) {
        SoftBusMutexUnlock(&g_connResApiLock);
        return SOFTBUS_OK;
    }
    record->mConnFailTime += costTime;
    record->mConnFailCount++;
    SoftBusMutexUnlock(&g_connResApiLock);
    errCode = GetErrorCodeEx(errCode);
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftbusReportConnFault(connType, errCode, pkgName) == SOFTBUS_OK, SOFTBUS_STRCPY_ERR,
                                   COMM_EVENT, "report conn fault event fail!");
    return SOFTBUS_OK;
}

int32_t SoftbusRecordProccessDuration(uint32_t pId, SoftBusConnType connType, SoftBusConnStatus status,
                                      ProcessStepTime *stepTime, int32_t errCode)
{
    COMM_LOGD(COMM_EVENT, "record process step duration");
    if (stepTime == NULL || connType >= SOFTBUS_HISYSEVT_CONN_TYPE_BUTT || connType < SOFTBUS_HISYSEVT_CONN_TYPE_P2P) {
        COMM_LOGE(COMM_EVENT, "param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusRecordConnResult(pId, connType, status, stepTime->totalTime, errCode);
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_procStepLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT,
                                   "record g_procStepLock fail");
    for (ProcessStep i = NEGOTIATION_STEP; i < STEP_BUTT; i++) {
        uint64_t costTime = stepTime->connGroupTime;
        switch (i) {
            case NEGOTIATION_STEP:
                costTime = stepTime->negotiationTime;
                break;
            case GROUP_CREATE_STEP:
                costTime = stepTime->groupCreateTime;
                break;
            case CONN_GROUP_STEP:
                costTime = stepTime->connGroupTime;
                break;
            case STEP_BUTT:
                break;
        }
        ProcessStepRecord *record = &g_processStep[connType][i];
        record->mStepTotalTime += costTime;
        record->mStepTotalCount++;
        if (costTime > STANDARD_S) {
            record->mStepCount1++;
        }
        if (costTime > STANDARD_A) {
            record->mStepCount2++;
        }
        if (costTime > STANDARD_B) {
            record->mStepCount3++;
        }
        if (costTime > STANDARD_C) {
            record->mStepCount4++;
        }
        if (costTime > STANDARD_D) {
            record->mStepCount5++;
        }
    }
    if (SoftBusMutexUnlock(&g_procStepLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "record process step unlock fail");
    }
    return SOFTBUS_OK;
}

static int32_t InitConnEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexInit(&g_pIdOfNameLock, &mutexAttr) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
                                   COMM_EVENT, "init pId of name lock fail");
    int32_t nRet = SoftBusMutexInit(&g_connResApiLock, &mutexAttr);
    if (nRet != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init conn res api lock fail");
        (void)SoftBusMutexDestroy(&g_pIdOfNameLock);
    }
    nRet = SoftBusMutexInit(&g_procStepLock, &mutexAttr);
    if (nRet != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init process step lock fail");
        (void)SoftBusMutexDestroy(&g_pIdOfNameLock);
        (void)SoftBusMutexDestroy(&g_connResApiLock);
    }
    return nRet;
}

int32_t InitConnStatisticSysEvt(void)
{
    ListInit(&g_pIdOfPkgName);
    ListInit(&g_connResultApiRecord);
    int32_t ret = InitConnEvtMutexLock();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "Conn Statistic Evt Lock Init Fail!");
        return ret;
    }
    ClearConnResultRecord();
    ClearProcessStep();
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_CONN_DURATION, SoftBusReportConnResultRecordEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_PROCESS_STEP_DURATION, SoftBusReportProcessStepRecordEvt);
    return SOFTBUS_OK;
}

void DeinitConnStatisticSysEvt(void)
{
    ClearConnResultRecord();
    ClearProcessStep();
    SoftBusMutexDestroy(&g_pIdOfNameLock);
    SoftBusMutexDestroy(&g_connResApiLock);
    SoftBusMutexDestroy(&g_procStepLock);
}