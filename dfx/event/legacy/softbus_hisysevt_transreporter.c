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
#include "comm_log.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "legacy/softbus_hisysevt_common.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_server_ipc_interface_code.h"

#define STATISTIC_EVT_TRANSPORT_KPI "TRANSPORT_KPI"
#define STATISTIC_EVT_CALLED_API_INFO "CALLED_API_INFO"
#define STATISTIC_EVT_CALLED_API_CNT "CALLED_API_CNT"
#define STATISTIC_EVT_TRANS_OPEN_SESSION_CNT "TRANS_OPEN_SESSION_CNT"
#define STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_COST "TRANS_OPEN_SESSION_TIME_COST"

#define FAULT_EVT_TRANS_FAULT "TRANS_FAULT"
#define BEHAVIOR_EVT_TRANS_INFO "TRANS_INFO"

#define TRANS_PARAM_LINK_TYPE "LINK_TYPE"

#define TRANS_PARAM_APP_NAME "APP_NAME"
#define TRANS_PARAM_API_NAME "API_NAME"

#define TRANS_PARAM_TOTAL_CNT "TOTAL_COUNT"
#define TRANS_PARAM_FAIL_TOTAL_CNT "FAIL_TOTAL_COUNT"
#define TRANS_PARAM_SUCCESS_CNT "SUCCESS_CNT"
#define TRANS_PARAM_FAIL_CNT "FAIL_CNT"
#define TRANS_PARAM_SUCCESS_RATE "SUCCESS_RATE"

#define TRANS_PARAM_TOTAL_TIME "TOTAL_TIME"
#define TRANS_PARAM_FAIL_TOTAL_TIME "FAIL_TOTAL_TIME"
#define TRANS_PARAM_MAX_TIME_COST "MAX_TIME_COST"
#define TRANS_PARAM_MIN_TIME_COST "MIN_TIME_COST"
#define TRANS_PARAM_AVE_TIME_COST "AVE_TIME_COST"
#define TRANS_PARAM_TIMES_UNDER_500MS "TIMES_UNDER_500MS"
#define TRANS_PARAM_TIMES_BETWEEN_500MS_1S "TIMES_BETWEEN_500MS_1S"
#define TRANS_PARAM_TIMES_BETWEEN_1S_2S "TIMES_BETWEEN_1S_2S"
#define TRANS_PARAM_TIMES_ABOVE_2S "TIMES_ABOVE_2S"
#define TRANS_OPEN_TIMES_ABOVE_1S "COUNT1"
#define TRANS_OPEN_TIMES_ABOVE_2S "COUNT2"
#define TRANS_OPEN_TIMES_ABOVE_4S "COUNT3"
#define TRANS_OPEN_TIMES_ABOVE_7S "COUNT4"
#define TRANS_OPEN_TIMES_ABOVE_11S "COUNT5"

#define TRANS_PARAM_PACKAGE_VERSION "PACKAGE_VERSION"
#define TRANS_PARAM_SOFTBUS_VERSION "SOFT_BUS_VERSION"
#define TRANS_PARAM_CALLER_PACKAGE "CALLER_PACKAGE_NAME"

#define TRANS_PARAM_ERRCODE "ERROR_CODE"
#define TRANS_PARAM_INFOMSG "INFO_MSG"

#define TIME_COST_500MS (500)
#define TIME_COST_1S (1000)
#define TIME_COST_2S (2000)
#define TIME_COST_4S (4000)
#define TIME_COST_7S (7000)
#define TIME_COST_11S (11000)
#define API_TYPE_DEFAULT (1)
#define API_CALLED_DEFAULT (1)

static char g_softbusVersion[SOFTBUS_HISYSEVT_PARAM_LEN] = "softbusVersion1";
static char g_pkgVersion[SOFTBUS_HISYSEVT_PARAM_LEN] = "packageVersion1";
typedef struct {
    uint32_t code;
    char *apiName;
}ApiNameIdMap;
static ApiNameIdMap g_apiNameIdMapTbl[] = {
    {MANAGE_REGISTER_SERVICE, "SoftbusRegisterService"},
    {SERVER_CREATE_SESSION_SERVER, "CreateSessionServer"},
    {SERVER_REMOVE_SESSION_SERVER, "RemoveSessionServer"},
    {SERVER_OPEN_SESSION, "OpenSession"},
    {SERVER_OPEN_AUTH_SESSION, "OpenAuthSession"},
    {SERVER_NOTIFY_AUTH_SUCCESS, "NotifyAuthSuccess"},
    {SERVER_CLOSE_CHANNEL, "CloseChannel"},
    {SERVER_SESSION_SENDMSG, "SendMessage"},
    {SERVER_JOIN_LNN, "JoinLNN"},
    {SERVER_JOIN_METANODE, "JoinMetaNode"},
    {SERVER_LEAVE_LNN, "LeaveLNN"},
    {SERVER_LEAVE_METANODE, "LeaveMetaNode"},
    {SERVER_GET_ALL_ONLINE_NODE_INFO, "GetAllOnlineNodeInfo"},
    {SERVER_GET_LOCAL_DEVICE_INFO, "GetLocalDeviceInfo"},
    {SERVER_GET_NODE_KEY_INFO, "GetNodeKeyInfo"},
    {SERVER_SET_NODE_DATA_CHANGE_FLAG, "SetNodeDataChangeFlag"},
    {SERVER_REG_DATA_LEVEL_CHANGE_CB, "RegDataChangeLevelCb"},
    {SERVER_UNREG_DATA_LEVEL_CHANGE_CB, "UnregDataChangeLevelCb"},
    {SERVER_SET_DATA_LEVEL, "SetDataLevel"},
    {SERVER_START_TIME_SYNC, "StartTimeSync"},
    {SERVER_STOP_TIME_SYNC, "StopTimeSync"},
    {SERVER_QOS_REPORT, "QosReport"},
    {SERVER_STREAM_STATS, "StreamStats"},
    {SERVER_GRANT_PERMISSION, "GrantPermission"},
    {SERVER_REMOVE_PERMISSION, "RemovePermission"},
    {SERVER_PUBLISH_LNN, "PublishLNN"},
    {SERVER_STOP_PUBLISH_LNN, "StopPublishLNN"},
    {SERVER_REFRESH_LNN, "RefreshLNN"},
    {SERVER_STOP_REFRESH_LNN, "StopRefreshLNN"},
    {SERVER_ACTIVE_META_NODE, "ActiveMetaNode"},
    {SERVER_DEACTIVE_META_NODE, "DeactiveMetaNode"},
    {SERVER_GET_ALL_META_NODE_INFO, "GetAllMetaNodeInfo"},
    {SERVER_SHIFT_LNN_GEAR, "ShiftLNNGear"},
    {SERVER_SYNC_TRUSTED_RELATION, "SyncTrustedRelationShip"},
    {SERVER_RIPPLE_STATS, "RippleStats"},
    {SERVER_CTRL_LNN_BLE_HB, "CtrlLNNBleHb"},
    {SERVER_SET_DISPLAY_NAME, "SetDisplayName"},
};

typedef struct {
    SoftBusMutex lock;
    uint32_t failCnt;
    uint32_t successCnt;
    float successRate;
} OpenSessionCntStruct;

typedef struct {
    SoftBusMutex lock;
    uint32_t maxTimeCost;
    uint32_t minTimeCost;
    uint32_t aveTimeCost;
    uint32_t timesIn500ms;
    uint32_t timesIn500and1s;
    uint32_t timesIn1and2s;
    uint32_t timesOn2s;
} OpenSessionTimeStruct;

typedef struct {
    SoftBusMutex lock;
    int32_t linkType;
    int64_t totalTime;
    int32_t totalCnt;
    int32_t successTotalCnt;
    int64_t failTotalTime;
    int32_t failTotalCnt;
    char packageVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    char softbusVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    int32_t count1;
    int32_t count2;
    int32_t count3;
    int32_t count4;
    int32_t count5;
    char callerPackageName[SOFTBUS_HISYSEVT_PARAM_LEN];
} OpenSessionKpiStruct;

typedef struct {
    ListNode node;
    char appName[SOFTBUS_HISYSEVT_PARAM_LEN];
    char softbusVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    char packageVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    int32_t cnt; //Api count
    ListNode apiCntList;
} CalledApiInfoStruct;

typedef struct {
    ListNode node;
    char apiName[SOFTBUS_HISYSEVT_PARAM_LEN];
    int32_t calledtotalCnt;
} CalledApiCntStruct;

static OpenSessionCntStruct g_openSessionCnt;
static OpenSessionTimeStruct g_openSessionTime;
static OpenSessionKpiStruct g_openSessionKpi;
static SoftBusList *g_calledApiInfoList = NULL;
static SoftBusList *g_calledApiCntlist = NULL;

#define TIME_THOUSANDS_FACTOR (1000)

int64_t GetSoftbusRecordTimeMillis(void)
{
    SoftBusSysTime t;
    t.sec = 0;
    t.usec = 0;
    SoftBusGetTime(&t);
    int64_t when = t.sec * TIME_THOUSANDS_FACTOR + (t.usec / TIME_THOUSANDS_FACTOR);
    return when;
}

static void ReleaseCalledApiInfoList(void)
{
    if (g_calledApiInfoList == NULL) {
        COMM_LOGE(COMM_EVENT, "list NULL");
        return;
    }
    if (SoftBusMutexLock(&g_calledApiInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "ReleaseCalledApiInfoList lock failed");
        return;
    }
    CalledApiInfoStruct *item = NULL;
    CalledApiInfoStruct *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_calledApiInfoList->list, CalledApiInfoStruct, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
        g_calledApiInfoList->cnt--;
    }
    ListInit(&g_calledApiInfoList->list);
    (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
}

static void ReleaseCalledApiCntList(void)
{
    if (g_calledApiCntlist == NULL) {
        COMM_LOGE(COMM_EVENT, "list NULL");
        return;
    }
    if (SoftBusMutexLock(&g_calledApiCntlist->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "ReleaseCalledApiCntList lock failed");
        return;
    }
    CalledApiCntStruct *item = NULL;
    CalledApiCntStruct *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_calledApiCntlist->list, CalledApiCntStruct, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
        g_calledApiCntlist->cnt--;
    }
    ListInit(&g_calledApiCntlist->list);
    (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
}

static CalledApiCntStruct *GetNewApiCnt(char *apiName)
{
    CalledApiCntStruct *apiCnt = (CalledApiCntStruct *)SoftBusMalloc(sizeof(CalledApiCntStruct));
    if (apiCnt == NULL) {
        COMM_LOGE(COMM_EVENT, "GetNewApiCnt malloc failed");
        return NULL;
    }
    if (strcpy_s(apiCnt->apiName, SOFTBUS_HISYSEVT_PARAM_LEN, apiName) != EOK) {
        COMM_LOGE(COMM_EVENT, "GetNewApiCnt strcpy failed");
        SoftBusFree(apiCnt);
        return NULL;
    }
    ListInit(&apiCnt->node);
    apiCnt->calledtotalCnt = API_CALLED_DEFAULT;
    return apiCnt;
}

static CalledApiInfoStruct *GetNewApiInfo(const char *appName, char *apiName)
{
    CalledApiInfoStruct *apiInfo = (CalledApiInfoStruct *)SoftBusMalloc(sizeof(CalledApiInfoStruct));
    if (apiInfo == NULL) {
        COMM_LOGE(COMM_EVENT, "GetNewApiInfo malloc failed");
        return NULL;
    }
    if (strcpy_s(apiInfo->appName, SOFTBUS_HISYSEVT_PARAM_LEN, appName) != EOK ||
        strcpy_s(apiInfo->softbusVersion, SOFTBUS_HISYSEVT_PARAM_LEN, g_softbusVersion) != EOK ||
        strcpy_s(apiInfo->packageVersion, SOFTBUS_HISYSEVT_PARAM_LEN, g_pkgVersion) != EOK) {
        COMM_LOGE(COMM_EVENT, "GetNewApiInfo strcpy failed");
        SoftBusFree(apiInfo);
        return NULL;
    }
    ListInit(&apiInfo->node);
    ListInit(&apiInfo->apiCntList);
    CalledApiCntStruct *apiCnt = GetNewApiCnt(apiName);
    if (apiCnt == NULL) {
        COMM_LOGE(COMM_EVENT, "GetNewApiCnt return NULL");
        SoftBusFree(apiInfo);
        return NULL;
    }
    ListAdd(&apiInfo->apiCntList, &apiCnt->node);
    apiInfo->cnt = API_TYPE_DEFAULT;
    return apiInfo;
}

static char *GetApiNameByCode(uint32_t code)
{
    for (uint32_t i = 0; i < sizeof(g_apiNameIdMapTbl) / sizeof(ApiNameIdMap); i++) {
        if (g_apiNameIdMapTbl[i].code == code) {
            return g_apiNameIdMapTbl[i].apiName;
        }
    }
    return NULL;
}

static void AddInfoNodeToList(bool isAppDiff, const char *appName, char *apiName)
{
#define MAX_PKG_NAME_CNT 200
    CalledApiInfoStruct *apiInfoNode = NULL;
    if (isAppDiff) {
        if (g_calledApiInfoList->cnt > MAX_PKG_NAME_CNT) {
            COMM_LOGE(COMM_EVENT, "the number %{public}u of callers exceeds the limit", g_calledApiInfoList->cnt);
            return;
        }
        apiInfoNode = GetNewApiInfo(appName, apiName);
        if (apiInfoNode == NULL) {
            COMM_LOGE(COMM_EVENT, "GetNewApiInfo fail");
            return;
        }
        ListAdd(&g_calledApiInfoList->list, &apiInfoNode->node);
        g_calledApiInfoList->cnt++;
        COMM_LOGD(COMM_EVENT, "GetNewApiInfo success");
    }
}

void SoftbusRecordCalledApiInfo(const char *appName, uint32_t code)
{
    COMM_CHECK_AND_RETURN_LOGE(appName != NULL, COMM_EVENT, "app name is null");
    COMM_CHECK_AND_RETURN_LOGE(g_calledApiInfoList != NULL, COMM_EVENT, "g_calledApiInfoList is null");
    COMM_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_calledApiInfoList->lock) == SOFTBUS_OK,
        COMM_EVENT, "SoftbusRecordCalledApiInfo lock fail");
    char *apiName = GetApiNameByCode(code);
    if (apiName == NULL) {
        (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
        COMM_LOGE(COMM_EVENT, "GetApiNameByCode fail");
        return;
    }

    CalledApiInfoStruct *apiInfoNode = NULL;
    CalledApiCntStruct *apiCntNode = NULL;
    bool isAppDiff = true;
    bool isApiDiff = true;
    LIST_FOR_EACH_ENTRY(apiInfoNode, &g_calledApiInfoList->list, CalledApiInfoStruct, node) {
        if (strcmp(apiInfoNode->appName, appName) == 0) {
            isAppDiff = false;
            LIST_FOR_EACH_ENTRY(apiCntNode, &apiInfoNode->apiCntList, CalledApiCntStruct, node) {
                if (strcmp(apiCntNode->apiName, apiName) == 0) {
                    isApiDiff = false;
                    apiCntNode->calledtotalCnt++;
                    COMM_LOGD(COMM_EVENT, "cmpare apiName success");
                    break;
                }
            }
        }
    }
    AddInfoNodeToList(isAppDiff, appName, apiName);
    if ((isAppDiff == false) && (isApiDiff == true)) {
        apiInfoNode = NULL;
        LIST_FOR_EACH_ENTRY(apiInfoNode, &g_calledApiInfoList->list, CalledApiInfoStruct, node) {
            if (strcmp(apiInfoNode->appName, appName) == 0) {
                apiCntNode = GetNewApiCnt(apiName);
                if (apiCntNode == NULL) {
                    COMM_LOGE(COMM_EVENT, "GetNewApiCnt fail");
                    (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
                    return;
                }
                ListAdd(&apiInfoNode->apiCntList, &apiCntNode->node);
                apiInfoNode->cnt++;
                COMM_LOGD(COMM_EVENT, "GetNewApiCnt success");
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
}

void SoftbusRecordCalledApiCnt(uint32_t code)
{
    if (g_calledApiCntlist == NULL) {
        COMM_LOGE(COMM_EVENT, "g_calledApiCntlist is null");
        return;
    }
    if (SoftBusMutexLock(&g_calledApiCntlist->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "SoftbusRecordCalledApiCnt lock fail");
        return;
    }
    char *apiName = GetApiNameByCode(code);
    if (apiName == NULL) {
        (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
        return;
    }

    CalledApiCntStruct *apiCntNode = NULL;
    bool isDiff = true;
    LIST_FOR_EACH_ENTRY(apiCntNode, &g_calledApiCntlist->list, CalledApiCntStruct, node) {
        if (strcmp(apiCntNode->apiName, apiName) == 0) {
            isDiff = false;
            apiCntNode->calledtotalCnt++;
            break;
        }
    }
    if (isDiff == true) {
        apiCntNode = GetNewApiCnt(apiName);
        if (apiCntNode == NULL) {
            COMM_LOGE(COMM_EVENT, "GetNewApiCnt fail");
            (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
            return;
        }
        ListAdd(&g_calledApiCntlist->list, &apiCntNode->node);
        g_calledApiCntlist->cnt++;
    }
    (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
}

void SoftbusRecordOpenSessionKpi(const char *pkgName, int32_t linkType, SoftBusOpenSessionStatus isSucc, int64_t time)
{
    COMM_CHECK_AND_RETURN_LOGE(pkgName != NULL, COMM_EVENT, "pkg name is null");
    COMM_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_openSessionKpi.lock) == SOFTBUS_OK, COMM_EVENT, "lock fail");
    g_openSessionKpi.linkType = linkType;

    g_openSessionKpi.failTotalCnt += (isSucc != SOFTBUS_EVT_OPEN_SESSION_SUCC);
    g_openSessionKpi.successTotalCnt += (isSucc == SOFTBUS_EVT_OPEN_SESSION_SUCC);
    g_openSessionKpi.totalCnt = g_openSessionKpi.failTotalCnt + g_openSessionKpi.successTotalCnt;

    (void)strcpy_s(g_openSessionKpi.softbusVersion, SOFTBUS_HISYSEVT_PARAM_LEN, g_softbusVersion);
    (void)strcpy_s(g_openSessionKpi.packageVersion, SOFTBUS_HISYSEVT_PARAM_LEN, g_pkgVersion);
    (void)strcpy_s(g_openSessionKpi.callerPackageName, SOFTBUS_HISYSEVT_PARAM_LEN, pkgName);
    g_openSessionKpi.totalTime = time;
    if (isSucc != SOFTBUS_EVT_OPEN_SESSION_SUCC) {
        g_openSessionKpi.failTotalTime = time;
    }

    if (time > TIME_COST_1S && time <= TIME_COST_2S) {
        g_openSessionKpi.count1++;
    } else if (time > TIME_COST_2S && time <= TIME_COST_4S) {
        g_openSessionKpi.count2++;
    } else if (time > TIME_COST_4S && time <= TIME_COST_7S) {
        g_openSessionKpi.count3++;
    } else if (time > TIME_COST_7S && time <= TIME_COST_11S) {
        g_openSessionKpi.count4++;
    } else if (time > TIME_COST_11S) {
        g_openSessionKpi.count5++;
    }
    (void)SoftBusMutexUnlock(&g_openSessionKpi.lock);
}

void SoftbusRecordOpenSession(SoftBusOpenSessionStatus isSucc, uint32_t time)
{
    if (SoftBusMutexLock(&g_openSessionCnt.lock) != SOFTBUS_OK) {
        return;
    }

    g_openSessionCnt.failCnt += (isSucc != SOFTBUS_EVT_OPEN_SESSION_SUCC);
    g_openSessionCnt.successCnt += (isSucc == SOFTBUS_EVT_OPEN_SESSION_SUCC);
    uint32_t totalCnt = g_openSessionCnt.failCnt + g_openSessionCnt.successCnt;
    if (totalCnt != 0) {
        g_openSessionCnt.successRate = (float)(g_openSessionCnt.successCnt) / (float)(totalCnt);
    }

    (void)SoftBusMutexUnlock(&g_openSessionCnt.lock);

    if (isSucc != SOFTBUS_EVT_OPEN_SESSION_SUCC) {
        return;
    }

    if (SoftBusMutexLock(&g_openSessionTime.lock) != SOFTBUS_OK) {
        return;
    }

    if (time > g_openSessionTime.maxTimeCost) {
        g_openSessionTime.maxTimeCost = time;
    } else if (time < g_openSessionTime.minTimeCost) {
        g_openSessionTime.minTimeCost = time;
    }

    if (g_openSessionCnt.successCnt != 0) {
        uint64_t totalTimeCost = (g_openSessionTime.aveTimeCost) * (g_openSessionCnt.successCnt - 1) + time;
        g_openSessionTime.aveTimeCost = (uint32_t)(totalTimeCost / g_openSessionCnt.successCnt);
    }

    if (time < TIME_COST_500MS) {
        g_openSessionTime.timesIn500ms++;
    } else if (time < TIME_COST_1S) {
        g_openSessionTime.timesIn500and1s++;
    } else if (time < TIME_COST_2S) {
        g_openSessionTime.timesIn1and2s++;
    } else {
        g_openSessionTime.timesOn2s++;
    }

    (void)SoftBusMutexUnlock(&g_openSessionTime.lock);
}

static inline void ClearOpenSessionKpi(void)
{
    memset_s(&g_openSessionKpi.linkType, sizeof(OpenSessionKpiStruct) - sizeof(SoftBusMutex),
        0, sizeof(OpenSessionKpiStruct) - sizeof(SoftBusMutex));
}

static inline void ClearOpenSessionCnt(void)
{
    memset_s(&g_openSessionCnt.failCnt, sizeof(OpenSessionCntStruct) - sizeof(SoftBusMutex),
        0, sizeof(OpenSessionCntStruct) - sizeof(SoftBusMutex));
}

static inline void ClearOpenSessionTime(void)
{
    memset_s(&g_openSessionTime.maxTimeCost, sizeof(OpenSessionTimeStruct) - sizeof(SoftBusMutex),
        0, sizeof(OpenSessionTimeStruct) - sizeof(SoftBusMutex));
}

static inline int32_t InitOpenSessionEvtMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    if (SoftBusMutexInit(&g_openSessionCnt.lock, &mutexAttr) != SOFTBUS_OK ||
        SoftBusMutexInit(&g_openSessionTime.lock, &mutexAttr) != SOFTBUS_OK ||
        SoftBusMutexInit(&g_openSessionKpi.lock, &mutexAttr) != SOFTBUS_OK) {
        return SOFTBUS_DFX_INIT_FAILED;
    }
    return SOFTBUS_OK;
}

static void CreateCalledApiInfoMsg(SoftBusEvtReportMsg* msg, CalledApiCntStruct *apiCntItem,
    char *appName, char *softbusVersion, char *packageVersion)
{
    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CALLED_API_INFO);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_FIVE;
    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_APP_NAME);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, appName);
    // param 1
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_SOFTBUS_VERSION);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, softbusVersion);
    // param 2
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_PACKAGE_VERSION);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, packageVersion);
    // param 3
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_API_NAME);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, apiCntItem->apiName);
    // param 4
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FOUR];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TOTAL_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = apiCntItem->calledtotalCnt;
}

static void CreateCalledApiCntMsg(SoftBusEvtReportMsg* msg, CalledApiCntStruct *apiCntItem)
{
    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_CALLED_API_CNT);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_TWO;
    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_API_NAME);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, apiCntItem->apiName);
    // param 1
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TOTAL_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = apiCntItem->calledtotalCnt;
}

static void CreateOpenSessionKpiMsg(SoftBusEvtReportMsg* msg)
{
    if (SoftBusMutexLock(&g_openSessionKpi.lock) != SOFTBUS_OK) {
        return;
    }
    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_TRANSPORT_KPI);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_THIRTEEN;
    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_LINK_TYPE);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.linkType;
    // param 1
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TOTAL_TIME);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT64;
    param->paramValue.i64v = g_openSessionKpi.totalTime;
    // param 2
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TOTAL_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.totalCnt;
    // param 3
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_FAIL_TOTAL_TIME);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT64;
    param->paramValue.i64v = g_openSessionKpi.failTotalTime;
    // param 4
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FOUR];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_FAIL_TOTAL_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.failTotalCnt;
    // param 5
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FIVE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_PACKAGE_VERSION);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_openSessionKpi.packageVersion);
    // param 6
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_SIX];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_SOFTBUS_VERSION);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_openSessionKpi.softbusVersion);
    // param 7
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_SEVEN];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_OPEN_TIMES_ABOVE_1S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.count1;
    // param 8
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_EIGHT];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_OPEN_TIMES_ABOVE_2S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.count2;
    // param 9
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_NINE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_OPEN_TIMES_ABOVE_4S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.count3;
    // param 10
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TEN];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_OPEN_TIMES_ABOVE_7S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.count4;
    // param 11
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ELEVEN];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_OPEN_TIMES_ABOVE_11S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = g_openSessionKpi.count5;
    // param 12
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWELVE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_CALLER_PACKAGE);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, SOFTBUS_HISYSEVT_PARAM_LEN, g_openSessionKpi.callerPackageName);
    ClearOpenSessionKpi();
    (void)SoftBusMutexUnlock(&g_openSessionKpi.lock);
}

static void CreateOpenSessionCntMsg(SoftBusEvtReportMsg* msg)
{
    if (SoftBusMutexLock(&g_openSessionCnt.lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "CreateOpenSessionCntMsg lock fail");
        return;
    }

    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_TRANS_OPEN_SESSION_CNT);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_THREE;

    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_SUCCESS_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionCnt.successCnt;

    // param 1
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_FAIL_CNT);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = (g_openSessionCnt.failCnt);

    // param 2
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_SUCCESS_RATE);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_FLOAT;
    param->paramValue.f = g_openSessionCnt.successRate;

    ClearOpenSessionCnt();

    (void)SoftBusMutexUnlock(&g_openSessionCnt.lock);
}

static int32_t SoftbusReportCalledAPIEvt(void)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_FIVE);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    if (g_calledApiInfoList == NULL) {
        COMM_LOGE(COMM_EVENT, "g_calledApiInfoList is null");
        SoftbusFreeEvtReportMsg(msg);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_calledApiInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "SoftbusReportCalledAPIEvt lock fail");
        SoftbusFreeEvtReportMsg(msg);
        return SOFTBUS_LOCK_ERR;
    }
    char appName[SOFTBUS_HISYSEVT_PARAM_LEN];
    char softbusVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    char packageVersion[SOFTBUS_HISYSEVT_PARAM_LEN];
    CalledApiInfoStruct *apiInfoItem = NULL;
    CalledApiCntStruct *apiCntItem = NULL;
    int32_t ret = SOFTBUS_OK;
    LIST_FOR_EACH_ENTRY(apiInfoItem, &g_calledApiInfoList->list, CalledApiInfoStruct, node) {
        (void)strcpy_s(appName, SOFTBUS_HISYSEVT_NAME_LEN, apiInfoItem->appName);
        (void)strcpy_s(softbusVersion, SOFTBUS_HISYSEVT_NAME_LEN, apiInfoItem->softbusVersion);
        (void)strcpy_s(packageVersion, SOFTBUS_HISYSEVT_NAME_LEN, apiInfoItem->packageVersion);
        LIST_FOR_EACH_ENTRY(apiCntItem, &apiInfoItem->apiCntList, CalledApiCntStruct, node) {
            CreateCalledApiInfoMsg(msg, apiCntItem, appName, softbusVersion, packageVersion);
            ret = SoftbusWriteHisEvt(msg);
            if (ret != SOFTBUS_OK) {
                SoftbusFreeEvtReportMsg(msg);
                (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
                ReleaseCalledApiInfoList();
                return ret;
            }
        }
    }
    SoftbusFreeEvtReportMsg(msg);
    (void)SoftBusMutexUnlock(&g_calledApiInfoList->lock);
    ReleaseCalledApiInfoList();
    return SOFTBUS_OK;
}

static int32_t SoftbusReportCalledAPICntEvt(void)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_TWO);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    if (g_calledApiCntlist == NULL) {
        COMM_LOGE(COMM_EVENT, "g_calledApiCntlist is null");
        SoftbusFreeEvtReportMsg(msg);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_calledApiCntlist->lock) != SOFTBUS_OK) {
        SoftbusFreeEvtReportMsg(msg);
        return SOFTBUS_LOCK_ERR;
    }
    CalledApiCntStruct *apiCntItem = NULL;
    int32_t ret = SOFTBUS_OK;
    LIST_FOR_EACH_ENTRY(apiCntItem, &g_calledApiCntlist->list, CalledApiCntStruct, node) {
        CreateCalledApiCntMsg(msg, apiCntItem);
        ret = SoftbusWriteHisEvt(msg);
        if (ret != SOFTBUS_OK) {
            SoftbusFreeEvtReportMsg(msg);
            (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
            ReleaseCalledApiCntList();
            return ret;
        }
    }
    SoftbusFreeEvtReportMsg(msg);
    (void)SoftBusMutexUnlock(&g_calledApiCntlist->lock);
    ReleaseCalledApiCntList();
    return SOFTBUS_OK;
}

static int32_t SoftbusReportOpenSessionKpiEvt(void)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_THIRTEEN);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    CreateOpenSessionKpiMsg(msg);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);
    return ret;
}

static int32_t SoftbusReportOpenSessionCntEvt(void)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_THREE);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    CreateOpenSessionCntMsg(msg);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);

    return ret;
}

static void CreateOpenSessionTimeMsg(SoftBusEvtReportMsg* msg)
{
    if (SoftBusMutexLock(&g_openSessionTime.lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "CreateOpenSessionTimeMsg lock fail");
        return;
    }

    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_COST);
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_SEVEN;

    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_MAX_TIME_COST);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.maxTimeCost;

    // param 1
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_ONE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_MIN_TIME_COST);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.minTimeCost;

    // param 2
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_TWO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_AVE_TIME_COST);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.aveTimeCost;

    // param 3
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_THREE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TIMES_UNDER_500MS);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.timesIn500ms;

    // param 4
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FOUR];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TIMES_BETWEEN_500MS_1S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.timesIn500and1s;

    // param 5
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_FIVE];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TIMES_BETWEEN_1S_2S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.timesIn1and2s;

    // param 6
    param = &msg->paramArray[SOFTBUS_EVT_PARAM_SIX];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_TIMES_ABOVE_2S);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = g_openSessionTime.timesOn2s;

    ClearOpenSessionTime();

    (void)SoftBusMutexUnlock(&g_openSessionTime.lock);
}

static int32_t SoftbusReportOpenSessionTimeEvt(void)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_SEVEN);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "SoftbusCreateEvtReportMsg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    CreateOpenSessionTimeMsg(msg);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);

    return ret;
}

static inline void CreateTransErrMsg(SoftBusEvtReportMsg* msg, int32_t errcode)
{
    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, FAULT_EVT_TRANS_FAULT);
    msg->evtType = SOFTBUS_EVT_TYPE_FAULT;
    msg->paramNum = SOFTBUS_EVT_PARAM_ONE;

    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_ERRCODE);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    param->paramValue.i32v = errcode;
}

static inline void CreateTransInfoMsg(SoftBusEvtReportMsg* msg, const char *infoMsg)
{
    // event
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, BEHAVIOR_EVT_TRANS_INFO);
    msg->evtType = SOFTBUS_EVT_TYPE_BEHAVIOR;
    msg->paramNum = SOFTBUS_EVT_PARAM_ONE;

    // param 0
    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, TRANS_PARAM_INFOMSG);
    param->paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    (void)strcpy_s(param->paramValue.str, sizeof(param->paramValue.str), infoMsg);
}

void SoftbusReportTransErrorEvt(int32_t errcode)
{
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_ONE);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return;
    }
    errcode = GetErrorCodeEx(errcode);
    CreateTransErrMsg(msg, errcode);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);

    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "Sys Evt Witre FAIL! errCode=%{public}d", errcode);
    }
}

void SoftbusReportTransInfoEvt(const char *infoMsg)
{
    if (infoMsg == NULL) {
        COMM_LOGE(COMM_EVENT, "infoMsg is null");
        return;
    }
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(SOFTBUS_EVT_PARAM_ONE);
    if (msg == NULL) {
        COMM_LOGE(COMM_EVENT, "Alloc EvtReport Msg Fail!");
        return;
    }
    CreateTransInfoMsg(msg, infoMsg);
    int ret = SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);

    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "Sys Evt Witre FAIL! errMsg=%{public}s", infoMsg);
    }
}

static void DeinitOpenSessionEvtMutexLock(void)
{
    SoftBusMutexDestroy(&g_openSessionCnt.lock);
    SoftBusMutexDestroy(&g_openSessionTime.lock);
    SoftBusMutexDestroy(&g_openSessionKpi.lock);
}

int32_t InitTransStatisticSysEvt(void)
{
    if (InitOpenSessionEvtMutexLock() != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "Trans Statistic Evt Lock Init Fail!");
        DeinitOpenSessionEvtMutexLock();
        return SOFTBUS_DFX_INIT_FAILED;
    }

    g_calledApiInfoList = CreateSoftBusList();
    g_calledApiCntlist = CreateSoftBusList();
    ClearOpenSessionCnt();
    ClearOpenSessionKpi();
    ClearOpenSessionTime();

    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_CNT, SoftbusReportOpenSessionCntEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_KPI, SoftbusReportOpenSessionKpiEvt);
    SetStatisticEvtReportFunc(TRANSPORT_API_CALLED_INFO_STATISTIC_EVENT, SoftbusReportCalledAPIEvt);
    SetStatisticEvtReportFunc(TRANSPORT_API_CALLED_CNT_STATISTIC_EVENT, SoftbusReportCalledAPICntEvt);
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_COST, SoftbusReportOpenSessionTimeEvt);
    return SOFTBUS_OK;
}

void DeinitTransStatisticSysEvt(void)
{
    if (g_calledApiInfoList == NULL || g_calledApiCntlist == NULL) {
        COMM_LOGE(COMM_EVENT, "g_calledApiInfoList or g_calledApiCntlist is NULL");
        return;
    }
    DestroySoftBusList(g_calledApiInfoList);
    DestroySoftBusList(g_calledApiCntlist);
    g_calledApiInfoList = NULL;
    g_calledApiCntlist = NULL;
}
