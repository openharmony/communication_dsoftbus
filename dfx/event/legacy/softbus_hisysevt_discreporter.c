/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "legacy/softbus_hisysevt_discreporter.h"

#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "legacy/softbus_hisysevt_common.h"
#include "softbus_utils.h"

#define MODULE_NAME_MAX_LEN 65

#define FIRST_DISC_DURATION_PARAM_NUM 10
#define SOFT_BUS_VERSION_KEY "SOFT_BUS_VERSION"
#define PACKAGE_VERSION_KEY "PACKAGE_VERSION"
#define LINK_TYPE_KEY "LINK_TYPE"
#define TOTAL_TIME_KEY "TOTAL_TIME"
#define TOTAL_COUNT_KEY "TOTAL_COUNT"
#define COUNT1_KEY "COUNT1"
#define COUNT2_KEY "COUNT2"
#define COUNT3_KEY "COUNT3"
#define COUNT4_KEY "COUNT4"
#define COUNT5_KEY "COUNT5"

#define DISCOVERY_DETAILS_PARAM_NUM 6
#define MODULE_KEY "MODULE"
#define DISC_TYPE_KEY "DISCTYPE"
#define DURATION_KEY "DURATION"
#define REPORT_TIMES_KEY "REPTIMES"
#define DEVICE_NUM_KEY "DEVNUM"
#define DISC_TIMES_KEY "DISCTIMES"

#define DISCOVERY_BLE_RSSI_PARAM_NUM 2
#define RANGE_ID_KEY "RANGEID"
#define RANGE_DATA_KEY "RANGEDATA"

#define BLE_RSSI_RANGE_SIZE 52
#define MAX_RANGE_ID 130
#define MIN_RANGE_ID (-130)
#define INTERVAL_OF_RSSI 5

typedef enum {
    STANDARD_S = 500,
    STANDARD_A = 1000,
    STANDARD_B = 1500,
    STANDARD_C = 2000,
    STANDARD_D = 2500,
} DiscoveryThreshold;

typedef struct {
    SoftBusMutex lock;
    uint64_t mDiscTotalTime;
    uint32_t mDiscTotalCount;
    uint32_t mDiscCount1;
    uint32_t mDiscCount2;
    uint32_t mDiscCount3;
    uint32_t mDiscCount4;
    uint32_t mDiscCount5;
} FirstDiscTime;

typedef struct {
    SoftBusEvtParamType paramType;
    char paramName[SOFTBUS_HISYSEVT_NAME_LEN];
    size_t paramSize;
} SoftBusEvtParamSize;

static SoftBusEvtParamSize g_firstDsicTimeParam[FIRST_DISC_DURATION_PARAM_NUM] = {
    {SOFTBUS_EVT_PARAMTYPE_STRING, SOFT_BUS_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_STRING, PACKAGE_VERSION_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, LINK_TYPE_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT64, TOTAL_TIME_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, TOTAL_COUNT_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT1_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT2_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT3_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT4_KEY},
    {SOFTBUS_EVT_PARAMTYPE_UINT32, COUNT5_KEY},
};

typedef struct {
    ListNode node;
    char moduleName[MODULE_NAME_MAX_LEN];
    uint32_t discType;
    uint64_t duration;
    uint32_t repTimes;
    uint32_t devNum;
    uint32_t discTimes;
} DiscDetailNode;

static char g_softbusVersion[SOFTBUS_HISYSEVT_PARAM_LEN] = "default softbus version";
static char g_packageVersion[SOFTBUS_HISYSEVT_PARAM_LEN] = "default package version";
static FirstDiscTime g_firstDiscTime[SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT];

static SoftBusMutex g_discDetailLock = {0};
static ListNode g_discDetailList = {0};

static uint32_t g_bleRssiRangeId[BLE_RSSI_RANGE_SIZE] = {0};
static uint32_t g_bleRssiRangeData[BLE_RSSI_RANGE_SIZE] = {0};
static SoftBusMutex g_bleRssiRangeLock = {0};

static inline void ClearFirstDiscTime(void)
{
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        FirstDiscTime *record = &g_firstDiscTime[i];
        record->mDiscTotalTime = 0;
        record->mDiscTotalCount = 0;
        record->mDiscCount1 = 0;
        record->mDiscCount2 = 0;
        record->mDiscCount3 = 0;
        record->mDiscCount4 = 0;
        record->mDiscCount5 = 0;
    }
}

static inline void ClearBleRssi(void)
{
    for (size_t rangeId = 0; rangeId < BLE_RSSI_RANGE_SIZE; rangeId++) {
        g_bleRssiRangeId[rangeId] = 0;
        g_bleRssiRangeData[rangeId] = 0;
    }
}

static int32_t SetMsgParamNameAndType(SoftBusEvtReportMsg *msg, SoftBusEvtParamSize *paramSize)
{
    SoftBusEvtParam *param = NULL;
    for (uint32_t i = SOFTBUS_EVT_PARAM_ZERO; i < msg->paramNum; i++) {
        param = &msg->paramArray[i];
        param->paramType = paramSize[i].paramType;
        if (strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, paramSize[i].paramName) != EOK) {
            COMM_LOGE(COMM_EVENT, "set msg strcpy_s param name fail. paramName=%{public}s", paramSize[i].paramName);
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetDevFirstDiscMsgParamValve(SoftBusEvtReportMsg *msg, uint32_t medium)
{
    SoftBusEvtParam *param = msg->paramArray;
    errno_t ret = strcpy_s(param[SOFTBUS_EVT_PARAM_ZERO].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_softbusVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy softbus version fail");

    ret = strcpy_s(param[SOFTBUS_EVT_PARAM_ONE].paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_packageVersion);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT, "strcpy package version fail");

    param[SOFTBUS_EVT_PARAM_TWO].paramValue.u32v = medium;
    FirstDiscTime *firstDisc = &g_firstDiscTime[medium];
    param[SOFTBUS_EVT_PARAM_THREE].paramValue.u64v = firstDisc->mDiscTotalTime;
    param[SOFTBUS_EVT_PARAM_FOUR].paramValue.u32v = firstDisc->mDiscTotalCount;
    param[SOFTBUS_EVT_PARAM_FIVE].paramValue.u32v = firstDisc->mDiscCount1;
    param[SOFTBUS_EVT_PARAM_SIX].paramValue.u32v = firstDisc->mDiscCount2;
    param[SOFTBUS_EVT_PARAM_SEVEN].paramValue.u32v = firstDisc->mDiscCount3;
    param[SOFTBUS_EVT_PARAM_EIGHT].paramValue.u32v = firstDisc->mDiscCount4;
    param[SOFTBUS_EVT_PARAM_NINE].paramValue.u32v = firstDisc->mDiscCount5;
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateFirstDiscDurMsg(SoftBusEvtReportMsg *msg, uint32_t medium)
{
    errno_t errnoRet = strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_FIRST_DISC_DURATION);
    if (errnoRet != EOK) {
        COMM_LOGE(COMM_EVENT,
            "strcpy evtname fail. STATISTIC_EVT_FIRST_DISC_DURATION=%{public}s", STATISTIC_EVT_FIRST_DISC_DURATION);
        return SOFTBUS_STRCPY_ERR;
    }
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = FIRST_DISC_DURATION_PARAM_NUM;

    if (SetMsgParamNameAndType(msg, g_firstDsicTimeParam) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param name and type fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (SetDevFirstDiscMsgParamValve(msg, medium) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "set param valve fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static inline void ClearDiscDetails(void)
{
    DiscDetailNode *item = NULL;
    DiscDetailNode *next = NULL;
    if (g_discDetailList.prev == NULL && g_discDetailList.next == NULL) {
        COMM_LOGE(COMM_EVENT, "g_discDetailList is NULL");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_discDetailList), DiscDetailNode, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static DiscDetailNode *GetDiscDetailByModuleName(char *moduleName)
{
    DiscDetailNode *item = NULL;
    DiscDetailNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_discDetailList), DiscDetailNode, node) {
        if (strcmp(item->moduleName, moduleName) == 0) {
            return item;
        }
    }
    return NULL;
}

static int32_t AddDiscDetailNode(DiscDetailNode **discDetailNode, char *moduleName)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(discDetailNode != NULL, SOFTBUS_INVALID_PARAM, COMM_EVENT, "invalid discDetailNode");
    DiscDetailNode *newNode = (DiscDetailNode *)SoftBusCalloc(sizeof(DiscDetailNode));
    COMM_CHECK_AND_RETURN_RET_LOGE(newNode != NULL, SOFTBUS_MALLOC_ERR, COMM_EVENT, "malloc fail");
    if (strcpy_s(newNode->moduleName, MODULE_NAME_MAX_LEN, moduleName) != EOK) {
        COMM_LOGE(COMM_EVENT, "strcpy module name fail. moduleName=%{public}s", moduleName);
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    newNode->discType = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE;
    newNode->devNum = 0;
    newNode->discTimes = 0;
    newNode->duration = 0;
    newNode->repTimes = 0;
    ListAdd(&g_discDetailList, &newNode->node);
    *discDetailNode = newNode;
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateDiscDetailsMsg(SoftBusEvtReportMsg *msg, DiscDetailNode *discDetailItem)
{
    errno_t errnoRet = strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DISCOVERY_DETAILS);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy evtName fail. STATISTIC_EVT_DISCOVERY_DETAILS=%{public}s", STATISTIC_EVT_DISCOVERY_DETAILS);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = DISCOVERY_DETAILS_PARAM_NUM;

    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, MODULE_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. MODULE_KEY=%{public}s", MODULE_KEY);
    errnoRet = strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, discDetailItem->moduleName);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy moduleName fail. g_softbusVersion=%{public}s", g_softbusVersion);

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_TYPE_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. DISC_TYPE_KEY=%{public}s", DISC_TYPE_KEY);
    param->paramValue.u32v = discDetailItem->discType;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT64;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DURATION_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. DURATION_KEY=%{public}s", DURATION_KEY);
    param->paramValue.u64v = discDetailItem->duration;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, REPORT_TIMES_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. REPORT_TIMES_KEY=%{public}s", REPORT_TIMES_KEY);
    param->paramValue.u32v = discDetailItem->repTimes;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FOUR];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DEVICE_NUM_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. DEVICE_NUM_KEY=%{public}s", DEVICE_NUM_KEY);
    param->paramValue.u32v = discDetailItem->devNum;

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FIVE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, DISC_TIMES_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. DISC_TIMES_KEY=%{public}s", DISC_TIMES_KEY);
    param->paramValue.u32v = discDetailItem->discTimes;
    return SOFTBUS_OK;
}

static int32_t SoftBusCreateDiscBleRssiMsg(SoftBusEvtReportMsg *msg)
{
    errno_t errnoRet = strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_DISCOVERY_BLE_RSSI);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy evtname fail. STATISTIC_EVT_DISCOVERY_BLE_RSSI=%{public}s", STATISTIC_EVT_DISCOVERY_BLE_RSSI);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = DISCOVERY_BLE_RSSI_PARAM_NUM;

    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32_ARRAY;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, RANGE_ID_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. RANGE_ID_KEY=%{public}s", RANGE_ID_KEY);
    for (int i = 0; i < SOFTBUS_HISYSEVT_PARAM_UINT32_ARRAY_SIZE; i++) {
        param->paramValue.u32a[i] = g_bleRssiRangeId[i];
    }

    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32_ARRAY;
    errnoRet = strcpy_s(param->paramName, SOFTBUS_HISYSEVT_PARAM_LEN, RANGE_DATA_KEY);
    COMM_CHECK_AND_RETURN_RET_LOGE(errnoRet == EOK, SOFTBUS_STRCPY_ERR, COMM_EVENT,
        "strcpy paramName fail. RANGE_DATA_KEY=%{public}s", RANGE_DATA_KEY);
    for (int i = 0; i < SOFTBUS_HISYSEVT_PARAM_UINT32_ARRAY_SIZE; i++) {
        param->paramValue.u32a[i] = g_bleRssiRangeData[i];
    }
    return SOFTBUS_OK;
}

static int32_t SoftBusReportFirstDiscDurationEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report first disc duration event");
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(FIRST_DISC_DURATION_PARAM_NUM);
    COMM_CHECK_AND_RETURN_RET_LOGE(msg != NULL, SOFTBUS_MALLOC_ERR, COMM_EVENT, "create reportMsg fail");
    int32_t ret = SOFTBUS_OK;
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        if (SoftBusMutexLock(&g_firstDiscTime[i].lock) != SOFTBUS_OK) {
            SoftbusFreeEvtReportMsg(msg);
            ClearFirstDiscTime();
            COMM_LOGE(COMM_EVENT, "lock first disc time fail");
            return SOFTBUS_LOCK_ERR;
        }
        if (g_firstDiscTime[i].mDiscTotalCount == 0) {
            SoftBusMutexUnlock(&g_firstDiscTime[i].lock);
            continue;
        }
        ret = SoftBusCreateFirstDiscDurMsg(msg, i);
        if (ret != SOFTBUS_OK) {
            ClearFirstDiscTime();
            SoftBusMutexUnlock(&g_firstDiscTime[i].lock);
            SoftbusFreeEvtReportMsg(msg);
            COMM_LOGE(COMM_EVENT, "create first disc duration reportMsg fail");
            return ret;
        }
        ret = SoftbusWriteHisEvt(msg);
        if (ret != SOFTBUS_OK) {
            ClearFirstDiscTime();
            SoftBusMutexUnlock(&g_firstDiscTime[i].lock);
            SoftbusFreeEvtReportMsg(msg);
            COMM_LOGE(COMM_EVENT, "write first disc duration reportMsg fail");
            return ret;
        }
        SoftBusMutexUnlock(&g_firstDiscTime[i].lock);
    }
    SoftbusFreeEvtReportMsg(msg);
    ClearFirstDiscTime();
    return SOFTBUS_OK;
}

static inline void FreeDiscDetailsMsg(SoftBusEvtReportMsg *msg)
{
    SoftbusFreeEvtReportMsg(msg);
    ClearDiscDetails();
    (void)SoftBusMutexUnlock(&g_discDetailLock);
}

static int32_t SoftBusReportDiscDetailsEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report disc detail event");
    int32_t ret = SoftBusMutexLock(&g_discDetailLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "disc detail lock fail");

    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(DISCOVERY_DETAILS_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create disc details reportMsg fail");
        ClearDiscDetails();
        (void)SoftBusMutexUnlock(&g_discDetailLock);
        return SOFTBUS_MEM_ERR;
    }
    DiscDetailNode *item = NULL;
    DiscDetailNode *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_discDetailList), DiscDetailNode, node) {
        if (SoftBusCreateDiscDetailsMsg(msg, item) != SOFTBUS_OK) {
            FreeDiscDetailsMsg(msg);
            COMM_LOGE(COMM_EVENT, "create first disc detials reportMsg fail");
            return SOFTBUS_STRCPY_ERR;
        }
        ret = SoftbusWriteHisEvt(msg);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "write disc detail evt fail");
            FreeDiscDetailsMsg(msg);
            return ret;
        }
    }
    FreeDiscDetailsMsg(msg);
    return SOFTBUS_OK;
}

static inline void FreeDiscBleRssiMsg(SoftBusEvtReportMsg *msg)
{
    SoftbusFreeEvtReportMsg(msg);
    ClearBleRssi();
    (void)SoftBusMutexUnlock(&g_bleRssiRangeLock);
}

static int32_t SoftBusReportDiscBleRssiEvt(void)
{
    COMM_LOGD(COMM_EVENT, "report disc ble rssi event");
    int32_t ret = SoftBusMutexLock(&g_bleRssiRangeLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "ble rssi range lock fail");

    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(DISCOVERY_BLE_RSSI_PARAM_NUM);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "create disc ble rssi reportMsg fail");
        ClearBleRssi();
        SoftBusMutexUnlock(&g_bleRssiRangeLock);
        return SOFTBUS_MEM_ERR;
    }
    ret = SoftBusCreateDiscBleRssiMsg(msg);
    if (ret != SOFTBUS_OK) {
        FreeDiscBleRssiMsg(msg);
        COMM_LOGE(COMM_EVENT, "create disc ble rssi reportMsg fail");
        return ret;
    }
    ret = SoftbusWriteHisEvt(msg);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "write disc ble rssi evt fail");
        FreeDiscBleRssiMsg(msg);
        return ret;
    }
    FreeDiscBleRssiMsg(msg);
    return SOFTBUS_OK;
}

int32_t SoftbusRecordFirstDiscTime(SoftBusDiscMedium medium, uint64_t costTime)
{
    COMM_LOGD(COMM_EVENT, "record first disc time start");
    if (medium >= SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT || medium < SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE) {
        COMM_LOGE(COMM_EVENT, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_firstDiscTime[medium].lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "first disc time lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    FirstDiscTime *record = &g_firstDiscTime[medium];
    uint64_t diffTime = UINT64_MAX - record->mDiscTotalTime;
    if (diffTime > costTime) {
        record->mDiscTotalTime += costTime;
    } else {
        COMM_LOGE(COMM_EVENT, "time is too long");
        record->mDiscTotalTime = costTime - diffTime;
    }
    record->mDiscTotalCount++;
    if (costTime > STANDARD_S) {
        record->mDiscCount1++;
    }
    if (costTime > STANDARD_A) {
        record->mDiscCount2++;
    }
    if (costTime > STANDARD_B) {
        record->mDiscCount3++;
    }
    if (costTime > STANDARD_C) {
        record->mDiscCount4++;
    }
    if (costTime > STANDARD_D) {
        record->mDiscCount5++;
    }
    if (SoftBusMutexUnlock(&record->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "record first disc time unlock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static inline uint32_t AddAndCheckOverflowUint32(uint32_t a, uint32_t b)
{
    return (a > UINT32_MAX - b) ? UINT32_MAX : (a + b);
}

static inline uint64_t AddAndCheckOverflowUint64(uint64_t a, uint64_t b)
{
    return (a > UINT64_MAX - b) ? UINT64_MAX : (a + b);
}

int32_t SoftbusRecordBleDiscDetails(char *moduleName, uint64_t duration, uint32_t repTimes, uint32_t devNum,
                                    uint32_t discTimes)
{
    COMM_LOGD(COMM_EVENT, "record ble disc detail");
    COMM_CHECK_AND_RETURN_RET_LOGE(IsValidString(moduleName, MODULE_NAME_MAX_LEN), SOFTBUS_INVALID_PKGNAME, COMM_EVENT,
        "invalid param!");
    int32_t ret = SoftBusMutexLock(&g_discDetailLock);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT, "disc detail lock fail");
    DiscDetailNode *discDetailNode = GetDiscDetailByModuleName(moduleName);
    if (discDetailNode == NULL) {
        ret = AddDiscDetailNode(&discDetailNode, moduleName);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_EVENT, "add disc detail node fail");
            SoftBusMutexUnlock(&g_discDetailLock);
            return ret;
        }
    }

    discDetailNode->devNum = AddAndCheckOverflowUint32(discDetailNode->devNum, devNum);
    discDetailNode->discTimes = AddAndCheckOverflowUint32(discDetailNode->discTimes, discTimes);
    discDetailNode->duration = AddAndCheckOverflowUint64(discDetailNode->duration, duration);
    discDetailNode->repTimes = AddAndCheckOverflowUint32(discDetailNode->repTimes, repTimes);
    (void)SoftBusMutexUnlock(&g_discDetailLock);
    return SOFTBUS_OK;
}

int32_t SoftbusRecordDiscBleRssi(int32_t rssi)
{
    COMM_LOGD(COMM_EVENT, "record disc ble rssi");
    if (rssi > MAX_RANGE_ID || rssi <= MIN_RANGE_ID) {
        COMM_LOGE(COMM_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleRssiRangeLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_EVENT,
                                   "ble rssi range lock fail");

    uint32_t rangeId = (uint32_t)((MAX_RANGE_ID - rssi) / INTERVAL_OF_RSSI);
    if (rangeId >= BLE_RSSI_RANGE_SIZE) {
        COMM_LOGE(COMM_EVENT, "range id fail");
        (void)SoftBusMutexUnlock(&g_bleRssiRangeLock);
        return SOFTBUS_INVALID_NUM;
    }
    g_bleRssiRangeId[rangeId] = rangeId;
    g_bleRssiRangeData[rangeId] += 1;
    (void)SoftBusMutexUnlock(&g_bleRssiRangeLock);
    return SOFTBUS_OK;
}

static int32_t InitDiscItemMutexLock(uint32_t index, SoftBusMutexAttr *mutexAttr)
{
    if (SoftBusMutexInit(&g_firstDiscTime[index].lock, mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init first disc time lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitDiscEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexInit(&g_discDetailLock, &mutexAttr) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
                                   COMM_EVENT, "init disc detail lock fail");
    int32_t nRet = SoftBusMutexInit(&g_bleRssiRangeLock, &mutexAttr);
    if (nRet != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init ble rssi range lock fail");
        (void)SoftBusMutexDestroy(&g_discDetailLock);
    }
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        nRet = InitDiscItemMutexLock(i, &mutexAttr);
    }
    if (nRet != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "init disc first time lock fail");
        (void)SoftBusMutexDestroy(&g_discDetailLock);
        (void)SoftBusMutexDestroy(&g_bleRssiRangeLock);
    }
    return nRet;
}

int32_t SoftbusReportDiscFault(SoftBusDiscMedium medium, int32_t errCode)
{
    COMM_LOGI(COMM_EVENT, "report disc fault event");
    if (medium >= SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT || medium < SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE) {
        COMM_LOGE(COMM_EVENT, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusFaultEvtInfo discFaultInfo;
    (void)memset_s(&discFaultInfo, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    discFaultInfo.moduleType = MODULE_TYPE_DISCOVERY;
    discFaultInfo.linkType = medium;
    discFaultInfo.errorCode = errCode;
    int32_t ret = SoftBusReportBusCenterFaultEvt(&discFaultInfo);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "report disc fault evt fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t InitDiscStatisticSysEvt(void)
{
    ListInit(&g_discDetailList);
    int32_t ret = InitDiscEvtMutexLock();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "disc Statistic Evt Lock Init Fail!");
        return ret;
    }
    ClearDiscDetails();
    ClearBleRssi();
    ClearFirstDiscTime();

    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_BLE_RSSI, SoftBusReportDiscBleRssiEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_DETAILS, SoftBusReportDiscDetailsEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_FIRST_DISC_DURATION, SoftBusReportFirstDiscDurationEvt);
    return SOFTBUS_OK;
}
static void DestroyMutex(void)
{
    SoftBusMutexDestroy(&g_discDetailLock);
    SoftBusMutexDestroy(&g_bleRssiRangeLock);
    for (int32_t i = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE; i < SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT; i++) {
        SoftBusMutexDestroy(&g_firstDiscTime[i].lock);
    }
}

void DeinitDiscStatisticSysEvt(void)
{
    ClearDiscDetails();
    DestroyMutex();
}
