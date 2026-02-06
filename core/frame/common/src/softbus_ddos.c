/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "softbus_ddos.h"

#include <securec.h>
#include <time.h>

#include "anonymizer.h"
#include "lnn_event.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "legacy/softbus_hidumper_buscenter.h"

#define TABLE_COLUMNS 3
#define SAME_USER_SAME_ID_TIMES 100
#define USE_SAME_GET_DEVICE_INFO_ID_TIMES 300
#define ALL_USER_SAME_ID_TIMES 800
#define SAME_USER_ALL_ID_TIMES 1000
#define ALL_USER_ALL_ID_TIMES 2000
#define DDOS_HIDUMP_ENABLE "DdosHiDumperEnable"
#define DDOS_HIDUMP_DISABLE "DdosHiDumperDisable"

static SoftBusList* g_callRecord = NULL;
static bool g_isEnable = true;

static int32_t SetDdosStateEnable(int fd)
{
    g_isEnable = true;
    SOFTBUS_DPRINTF(fd, "%s\n", "ddos already set true");
    return SOFTBUS_OK;
}

static int32_t SetDdosStateDisable(int fd)
{
    g_isEnable = false;
    SOFTBUS_DPRINTF(fd, "%s\n", "ddos already set false");
    return SOFTBUS_OK;
}

static bool IsEnableDdos()
{
    return g_isEnable;
}

static int32_t DdosHiDumperRegister()
{
    int32_t ret = SoftBusRegBusCenterVarDump(DDOS_HIDUMP_ENABLE, &SetDdosStateEnable);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_EVENT, "regist ddos enable failed ret=%{public}d", ret);
    ret = SoftBusRegBusCenterVarDump(DDOS_HIDUMP_DISABLE, &SetDdosStateDisable);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_EVENT, "regist ddos disable failed ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t callTable[SOFTBUS_FUNC_ID_BUIT][TABLE_COLUMNS] = {
    [SERVER_JOIN_LNN] =                   {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_LEAVE_LNN] =                  {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_GET_ALL_ONLINE_NODE_INFO] =   {USE_SAME_GET_DEVICE_INFO_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_GET_LOCAL_DEVICE_INFO] =      {USE_SAME_GET_DEVICE_INFO_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_SET_NODE_DATA_CHANGE_FLAG] =  {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_GET_NODE_KEY_INFO] =          {USE_SAME_GET_DEVICE_INFO_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_START_TIME_SYNC] =            {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_STOP_TIME_SYNC] =             {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_PUBLISH_LNN] =                {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_STOP_PUBLISH_LNN] =           {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_REFRESH_LNN] =                {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_STOP_REFRESH_LNN] =           {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_ACTIVE_META_NODE] =           {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_DEACTIVE_META_NODE] =         {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_GET_ALL_META_NODE_INFO] =     {USE_SAME_GET_DEVICE_INFO_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_SHIFT_LNN_GEAR] =             {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_SYNC_TRUSTED_RELATION] =      {SAME_USER_SAME_ID_TIMES, ALL_USER_SAME_ID_TIMES},
    [SERVER_SET_NODE_KEY_INFO] =          {USE_SAME_GET_DEVICE_INFO_ID_TIMES, ALL_USER_SAME_ID_TIMES},
};

static int32_t CallRecordLock(void)
{
    return SoftBusMutexLock(&g_callRecord->lock);
}

static void CallRecordUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_callRecord->lock);
}

static CallRecord* CreateAndAddCallRecord(const char* pkgName, int interfaceId)
{
    CallRecord* newRecord = (CallRecord*)SoftBusCalloc(sizeof(CallRecord));
    if (newRecord == NULL) {
        LNN_LOGE(LNN_EVENT, "newRecord malloc fail");
        return NULL;
    }
    if (strcpy_s(newRecord->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        LNN_LOGE(LNN_EVENT, "strcpy pkgName fail");
        SoftBusFree(newRecord);
        return NULL;
    }
    newRecord->interfaceId = interfaceId;
    newRecord->timestamp = time(NULL);
    ListAdd(&g_callRecord->list, &newRecord->node);
    g_callRecord->cnt++;
    return newRecord;
}

static int32_t QueryCallRecord(const char* pkgName, enum SoftBusFuncId interfaceId, DdosInfo *ddosInfo)
{
    CallRecord *next = NULL;
    CallRecord *item = NULL;
    ddosInfo->funcId = interfaceId;
    ddosInfo->userCount = 1;
    ddosInfo->idCount = 1;
    ddosInfo->recordCount = 1;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_callRecord->list, CallRecord, node) {
        if (strncmp(item->pkgName, pkgName, PKG_NAME_SIZE_MAX) == 0) {
            ddosInfo->userCount++;
        }
        if (item->interfaceId == interfaceId) {
            ddosInfo->idCount++;
            if (strncmp(item->pkgName, pkgName, PKG_NAME_SIZE_MAX)  == 0) {
                ddosInfo->recordCount++;
            }
        }
    }
    if (strcpy_s(ddosInfo->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        LNN_LOGE(LNN_EVENT, "strcpy pkgName fail");
        return SOFTBUS_STRCPY_ERR;
    }
    ddosInfo->totalCount = (int32_t)g_callRecord->cnt;
    int32_t column = 0;
    int32_t ret = SOFTBUS_OK;
    LNN_LOGI(LNN_EVENT, "ddos info, recordCount=%{public}d, idCount=%{public}d, "
        "userCount=%{public}d, totalCount=%{public}d, interfaceid=%{public}d",
        ddosInfo->recordCount, ddosInfo->idCount, ddosInfo->userCount, ddosInfo->totalCount, interfaceId);
    if (ddosInfo->recordCount > callTable[interfaceId][column++]) {
        ret = SOFTBUS_DDOS_ID_AND_USER_SAME_COUNT_LIMIT;
    } else if (ddosInfo->idCount > callTable[interfaceId][column]) {
        ret =  SOFTBUS_DDOS_ID_SAME_COUNT_LIMIT;
    } else if (ddosInfo->userCount > SAME_USER_ALL_ID_TIMES) {
        ret =  SOFTBUS_DDOS_USER_SAME_ID_COUNT_LIMIT;
    } else if (ddosInfo->totalCount > ALL_USER_ALL_ID_TIMES) {
        ret =  SOFTBUS_DDOS_USER_ID_ALL_COUNT_LIMIT;
    }
    return ret;
}

static void ClearExpiredRecords(void)
{
    if (CallRecordLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "CallRecord lock fail");
        return;
    }
    time_t currentTime = time(NULL);
    CallRecord *next = NULL;
    CallRecord *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_callRecord->list, CallRecord, node) {
        if (currentTime - item->timestamp > TIME_THRESHOLD_SIZE) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_callRecord->cnt--;
        }
    }
    CallRecordUnlock();
}

static int32_t IsInterfaceFuncIdValid(enum SoftBusFuncId interfaceId)
{
    if ((interfaceId < 0) || (interfaceId >= SOFTBUS_FUNC_ID_BUIT)) {
        return false;
    }
    return true;
}

static void DfxReportDdosInfoResult(int32_t ret, const DdosInfo* info)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.errcode = info->errorCode;
    extra.callerPkg = info->pkgName;
    extra.recordCnt = info->recordCount;
    extra.funcId = info->funcId;
    extra.idCount = info->idCount;
    extra.userCount = info->userCount;
    extra.totalCount = info->totalCount;
    LNN_EVENT(EVENT_SCENE_DDOS, EVENT_STAGE_DDOS_THRESHOLD, extra);
}

int32_t IsOverThreshold(const char* pkgName, enum SoftBusFuncId interfaceId)
{
    if (!IsEnableDdos()) {
        LNN_LOGE(LNN_EVENT, "ddos not enable");
        return SOFTBUS_DDOS_DISABLE;
    }
    if (pkgName == NULL || !IsInterfaceFuncIdValid(interfaceId)) {
        LNN_LOGE(LNN_EVENT, "pkgName or id  is invalid, interfaceId=%{public}d", interfaceId);
        return SOFTBUS_INVALID_PARAM;
    }
    ClearExpiredRecords();
    if (CallRecordLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "CallRecord lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    DdosInfo info;
    int32_t ret = QueryCallRecord(pkgName, interfaceId, &info);
    if (ret != SOFTBUS_OK) {
        info.errorCode = ret;
        DfxReportDdosInfoResult(ret, &info);
        char *tmpName = NULL;
        Anonymize(pkgName, &tmpName);
        LNN_LOGE(LNN_EVENT, "use over limit ret=%{public}d, pkgName=%{public}s, interfaceId=%{public}d",
            ret, AnonymizeWrapper(tmpName), interfaceId);
        AnonymizeFree(tmpName);
        CallRecordUnlock();
        return ret;
    }
    CallRecord* record = CreateAndAddCallRecord(pkgName, interfaceId);
    if (record == NULL) {
        LNN_LOGE(LNN_EVENT, "create callrecord failed");
        CallRecordUnlock();
        return SOFTBUS_INVALID_PARAM;
    }
    CallRecordUnlock();
    return ret;
}

static void RegisterClearRecordsTimer(void)
{
    int32_t ret = RegisterTimeoutCallback(SOFTBUS_DDOS_TIMER_FUN, ClearExpiredRecords);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "regist callback failed ret=%{public}d", ret);
    }
}

int32_t InitDdos(void)
{
    if (g_callRecord != NULL) {
        return SOFTBUS_OK;
    }
    g_callRecord = CreateSoftBusList();
    if (g_callRecord == NULL) {
        LNN_LOGE(LNN_EVENT, "create callRecord list fail");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    int32_t ret = DdosHiDumperRegister();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "register ddos hidumer failed");
        return ret;
    }
    RegisterClearRecordsTimer();
    g_callRecord->cnt = 0;
    return SOFTBUS_OK;
}

void DeinitDdos(void)
{
    if (CallRecordLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "CallRecord lock fail");
        return;
    }
    CallRecord *next = NULL;
    CallRecord *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_callRecord->list, CallRecord, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    CallRecordUnlock();
    DestroySoftBusList(g_callRecord);
    g_callRecord = NULL;
}