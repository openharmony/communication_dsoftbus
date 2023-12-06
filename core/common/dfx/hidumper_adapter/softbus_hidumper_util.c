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
#include "softbus_hidumper_util.h"

#include <stdio.h>
#include <string.h>
#include <securec.h>
#include <time.h>

#include "lnn_map.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_event.h"
#include "softbus_log_old.h"
#include "stats_event.h"
#include "hisysevent_manager_c.h"

#define BIZ_SCENE_NAME "BIZ_SCENE"
#define BIZ_STAGE_NAME "BIZ_STAGE"
#define STAGE_RES_NAME "STAGE_RES"
#define ONLINE_NUM_NAME "ONLINE_NUM"
#define TIME_CONSUMING_NAME "COST_TIME"
#define BT_FLOW_NAME "BT_FLOW"
#define CALLER_PID_NAME "CALLER_PID"
#define LINK_TYPE_NAME "LINK_TYPE"
#define MIN_BW_NAME "MIN_BW"
#define METHOD_ID_NAME "METHOD_ID"
#define PERMISSION_NAME "PERMISSION_NAME"
#define SESSION_NAME "SESSION_NAME"

#define QUERY_EVENT_FULL_QUERY_PARAM (-1)
#define MAX_NUM_OF_EVENT_RESULT 100
#define DAY_MINUTE (24 * 60)
#define SEVEN_DAY_MINUTE (7 * DAY_MINUTE)
#define DAY_TIME (24 * 60 * 60 * 1000)
#define MINUTE_TIME (60 * 1000)
#define TIME_THOUSANDS_FACTOR (1000L)
#define WAIT_QUERY_TIME (1000L)
#define RATE_HUNDRED 100
#define MSG_STATISTIC_QUERY_REPORT 0

#define QUERY_RULES_MAX_NUM 10
#define MAX_LENGTH_OF_EVENT_DOMAIN 17
#define MAX_LENGTH_OF_EVENT_NAME 33

typedef void (*HandleMessageFunc)(SoftBusMessage* msg);

typedef enum {
    SOFTBUS_CONNECTION_STATS_TYPE,
    SOFTBUS_BUSCENTER_STATS_TYPE,
    SOFTBUS_TRANSPORT_STATS_TYPE,
    STATS_UNUSE_BUTT,
} SoftBusStatsType;

typedef struct {
    HiSysEventQueryRule queryRules[QUERY_RULES_MAX_NUM];
    HiSysEventQueryCallback callback;
    int32_t eventSize;
    int32_t dataSize;
} HiSysEventQueryParam;

typedef struct {
    int32_t connFailTotal;
    int32_t connSuccessTotal;
} ConnStatsInfo;

typedef struct {
    int32_t authFailTotal;
    int32_t authSuccessTotal;
    int32_t onlineDevMaxNum;
    int32_t joinLnnNum;
    int32_t leaveLnnNum;
} LnnStatsInfo;

typedef struct {
    int32_t openSessionFailTotal;
    int32_t openSessionSuccessTotal;
    int32_t delayTimeTotal;
    int32_t delayNum;
    int32_t btFlowTotal;
    int32_t currentParaSessionNum;
    int32_t maxParaSessionNum;
    int32_t laneScoreOverTimes;
    int32_t activityFailTotal;
    int32_t activitySuccessTotal;
    int32_t detectionTimes;
} TransStatsInfo;

static bool g_isDumperInit = false;

static bool g_isConnQueryEnd = false;
static bool g_isLnnQueryEnd = false;
static bool g_isTransQueryEnd = false;
static bool g_isAlarmQueryEnd = false;

static SoftBusMutex g_statsQueryLock = {0};
static SoftBusMutex g_alarmQueryLock = {0};
static SoftBusMutex g_connOnQueryLock = {0};
static SoftBusMutex g_lnnOnQueryLock = {0};
static SoftBusMutex g_transOnQueryLock = {0};
static SoftBusMutex g_alarmOnQueryLock = {0};

static ConnStatsInfo g_connStatsInfo = {0};
static LnnStatsInfo g_lnnStatsInfo = {0};
static TransStatsInfo g_transStatsInfo = {0};
static SoftBusAlarmEvtResult g_alarmEvtResult = {0};

static HiSysEventQueryParam g_queryStatsParam[STATS_UNUSE_BUTT];
static HiSysEventQueryParam g_queryAlarmParam[ALARM_UNUSE_BUTT];

static int32_t GetInt32ValueByRecord(HiSysEventRecordC* record, char* name)
{
    int64_t value;
    int32_t res = OH_HiSysEvent_GetParamInt64Value(record, name, &value);
    if (res != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return (int32_t)value;
}

static char* GetStringValueByRecord(HiSysEventRecordC* record, char* name)
{
    char* value;
    int32_t res = OH_HiSysEvent_GetParamStringValue(record, name, &value);
    if (res != SOFTBUS_OK) {
        return NULL;
    }
    return value;
}

static void GetLocalTime(char* time, uint64_t timestamp)
{
    time_t t = (time_t)timestamp;
    struct tm* tmInfo = NULL;
    tmInfo = localtime(&t);
    if (tmInfo == NULL) {
        return;
    }
    (void)strftime(time, SOFTBUS_ALARM_TIME_LEN, "%Y-%m-%d %H:%M:%S", tmInfo);
}

static void OnQueryConn(HiSysEventRecordC srcRecord[], size_t size)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnQueryConn start");
    if (SoftBusMutexLock(&g_connOnQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "conn query lock fail");
        return;
    }

    for (size_t i = 0; i < size; i++) {
        int32_t scene = GetInt32ValueByRecord(&srcRecord[i], BIZ_SCENE_NAME);
        int32_t stage = GetInt32ValueByRecord(&srcRecord[i], BIZ_STAGE_NAME);
        int32_t stageRes = GetInt32ValueByRecord(&srcRecord[i], STAGE_RES_NAME);
        if (scene == SOFTBUS_ERR || stage == SOFTBUS_ERR || stageRes == SOFTBUS_ERR) {
            continue;
        }
        if (scene == EVENT_SCENE_CONNECT && stage == EVENT_STAGE_CONNECT_END &&
            stageRes == EVENT_STAGE_RESULT_OK) {
            g_connStatsInfo.connSuccessTotal++;
        }
        if (scene == EVENT_SCENE_CONNECT && stage == EVENT_STAGE_CONNECT_END &&
            stageRes == EVENT_STAGE_RESULT_FAILED) {
            g_connStatsInfo.connFailTotal++;
        }
    }
    (void)SoftBusMutexUnlock(&g_connOnQueryLock);
}

static void OnCompleteConn(int32_t reason, int32_t total)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnCompleteConn start, reason is %d, total is %d", reason, total);
    g_isConnQueryEnd = true;
}

static void LnnStats(int32_t scene, int32_t stage, int32_t stageRes)
{
    if (scene == EVENT_SCENE_JOIN_LNN && stage == EVENT_STAGE_AUTH_DEVICE && stageRes == EVENT_STAGE_RESULT_OK) {
        g_lnnStatsInfo.authSuccessTotal++;
        return;
    }
        
    if (scene == EVENT_SCENE_JOIN_LNN && stage == EVENT_STAGE_AUTH_DEVICE && stageRes == EVENT_STAGE_RESULT_FAILED) {
        g_lnnStatsInfo.authFailTotal++;
        return;
    }
        
    if (scene == EVENT_SCENE_JOIN_LNN && stage == EVENT_STAGE_JOIN_LNN_END && stageRes == EVENT_STAGE_RESULT_OK) {
        g_lnnStatsInfo.joinLnnNum++;
        return;
    }

    if (scene == EVENT_SCENE_LEAVE_LNN && stage == EVENT_STAGE_LEAVE_LNN_END && stageRes == EVENT_STAGE_RESULT_OK) {
        g_lnnStatsInfo.leaveLnnNum++;
        return;
    }
}

static void OnQueryLnn(HiSysEventRecordC srcRecord[], size_t size)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnQueryLnn start");
    if (SoftBusMutexLock(&g_lnnOnQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lnn query lock fail");
        return;
    }

    for (size_t i = 0; i < size; i++) {
        int32_t scene = GetInt32ValueByRecord(&srcRecord[i], BIZ_SCENE_NAME);
        int32_t stage = GetInt32ValueByRecord(&srcRecord[i], BIZ_STAGE_NAME);
        int32_t stageRes = GetInt32ValueByRecord(&srcRecord[i], STAGE_RES_NAME);
        if (scene == SOFTBUS_ERR || stage == SOFTBUS_ERR || stageRes == SOFTBUS_ERR) {
            continue;
        }

        LnnStats(scene, stage, stageRes);
        int32_t onlineMaxNum = g_lnnStatsInfo.onlineDevMaxNum;
        int32_t onlineNum = GetInt32ValueByRecord(&srcRecord[i], ONLINE_NUM_NAME);
        if (onlineNum != SOFTBUS_ERR) {
            g_lnnStatsInfo.onlineDevMaxNum = (onlineMaxNum > onlineNum) ? onlineMaxNum : onlineNum;
        }
    }
    (void)SoftBusMutexUnlock(&g_lnnOnQueryLock);
}

static void OnCompleteLnn(int32_t reason, int32_t total)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnCompleteLnn start, reason is %d, total is %d", reason, total);
    g_isLnnQueryEnd = true;
}

static void TransStats(int32_t scene, int32_t stage, int32_t stageRes)
{
    if (scene == EVENT_SCENE_OPEN_CHANNEL && stage == EVENT_STAGE_START_CONNECT && stageRes == EVENT_STAGE_RESULT_OK) {
        g_transStatsInfo.openSessionSuccessTotal++;
        return;
    }

    if (scene == EVENT_SCENE_OPEN_CHANNEL && stage == EVENT_STAGE_START_CONNECT &&
        stageRes == EVENT_STAGE_RESULT_FAILED) {
        g_transStatsInfo.openSessionFailTotal++;
        return;
    }

    if (scene == EVENT_SCENE_ACTIVATION && stage == SOFTBUS_DEFAULT_STAGE && stageRes == EVENT_STAGE_RESULT_OK) {
        g_transStatsInfo.activitySuccessTotal++;
        return;
    }

    if (scene == EVENT_SCENE_ACTIVATION && stage == SOFTBUS_DEFAULT_STAGE && stageRes == EVENT_STAGE_RESULT_FAILED) {
        g_transStatsInfo.activityFailTotal++;
        return;
    }

    if (scene == EVENT_SCENE_LANE_SCORE && stage == SOFTBUS_DEFAULT_STAGE && stageRes == EVENT_STAGE_RESULT_OK) {
        g_transStatsInfo.laneScoreOverTimes++;
        return;
    }

    if (scene == EVENT_SCENE_DETECTION && stage == SOFTBUS_DEFAULT_STAGE && stageRes == EVENT_STAGE_RESULT_OK) {
        g_transStatsInfo.detectionTimes++;
        return;
    }
}

static void OnQueryTrans(HiSysEventRecordC srcRecord[], size_t size)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnQueryTrans start");
    if (SoftBusMutexLock(&g_transOnQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "trans query lock fail");
        return;
    }

    for (size_t i = 0; i < size; i++) {
        int32_t scene = GetInt32ValueByRecord(&srcRecord[i], BIZ_SCENE_NAME);
        int32_t stage = GetInt32ValueByRecord(&srcRecord[i], BIZ_STAGE_NAME);
        int32_t stageRes = GetInt32ValueByRecord(&srcRecord[i], STAGE_RES_NAME);
        if (scene == SOFTBUS_ERR || stage == SOFTBUS_ERR || stageRes == SOFTBUS_ERR) {
            continue;
        }

        TransStats(scene, stage, stageRes);
        if (scene == EVENT_SCENE_OPEN_CHANNEL && stage == EVENT_STAGE_OPEN_CHANNEL_END &&
            stageRes == EVENT_STAGE_RESULT_OK) {
            g_transStatsInfo.currentParaSessionNum++;
        }
        if (scene == EVENT_SCENE_CLOSE_CHANNEL_ACTIVE && stage == EVENT_STAGE_CLOSE_CHANNEL &&
            stageRes == EVENT_STAGE_RESULT_OK && g_transStatsInfo.currentParaSessionNum > 0) {
            g_transStatsInfo.currentParaSessionNum--;
        }
        int32_t maxParaSessionNum = g_transStatsInfo.maxParaSessionNum;
        g_transStatsInfo.maxParaSessionNum = (maxParaSessionNum > g_transStatsInfo.currentParaSessionNum) ?
            maxParaSessionNum : g_transStatsInfo.currentParaSessionNum;

        int32_t timeConsuming = GetInt32ValueByRecord(&srcRecord[i], TIME_CONSUMING_NAME);
        if (timeConsuming != SOFTBUS_ERR) {
            g_transStatsInfo.delayTimeTotal += timeConsuming;
            g_transStatsInfo.delayNum++;
        }
        int32_t btFlow = GetInt32ValueByRecord(&srcRecord[i], BT_FLOW_NAME);
        if (btFlow != SOFTBUS_ERR) {
            g_transStatsInfo.btFlowTotal += btFlow;
        }
    }
    (void)SoftBusMutexUnlock(&g_transOnQueryLock);
}

static void OnCompleteTrans(int32_t reason, int32_t total)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnCompleteTrans start, reason is %d, total is %d", reason, total);
    g_isTransQueryEnd = true;
}

static void OnQueryAlarm(HiSysEventRecordC srcRecord[], size_t size)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnQueryAlarm start");
    if (SoftBusMutexLock(&g_alarmOnQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "alarm query lock fail");
        return;
    }
    g_alarmEvtResult.recordSize = size;

    for (size_t i = 0; i < size; i++) {
        AlarmRecord* record = &g_alarmEvtResult.records[i];
        int32_t scene = GetInt32ValueByRecord(&srcRecord[i], BIZ_SCENE_NAME);
        if (scene != SOFTBUS_ERR) {
            record->type = scene;
        }

        int32_t callerPid = GetInt32ValueByRecord(&srcRecord[i], CALLER_PID_NAME);
        if (callerPid != SOFTBUS_ERR) {
            record->callerPid = callerPid;
        }

        int32_t linkType = GetInt32ValueByRecord(&srcRecord[i], LINK_TYPE_NAME);
        if (linkType != SOFTBUS_ERR) {
            record->linkType = linkType;
        }

        int32_t minBw = GetInt32ValueByRecord(&srcRecord[i], MIN_BW_NAME);
        if (minBw != SOFTBUS_ERR) {
            record->minBw = minBw;
        }

        int32_t methodId = GetInt32ValueByRecord(&srcRecord[i], METHOD_ID_NAME);
        if (methodId != SOFTBUS_ERR) {
            record->methodId = methodId;
        }

        char* permissionName = GetStringValueByRecord(&srcRecord[i], PERMISSION_NAME);
        if (permissionName != NULL) {
            record->permissionName = permissionName;
        }

        char* sessionName = GetStringValueByRecord(&srcRecord[i], SESSION_NAME);
        if (sessionName != NULL) {
            record->sessionName = sessionName;
        }

        GetLocalTime(record->time, srcRecord[i].time / TIME_THOUSANDS_FACTOR);
    }
    (void)SoftBusMutexUnlock(&g_alarmOnQueryLock);
}

static void OnCompleteAlarm(int32_t reason, int32_t total)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnCompleteAlarm start, reason is %d, total is %d", reason, total);
    g_isAlarmQueryEnd = true;
}

static void SoftBusEventQueryInfo(int time, HiSysEventQueryParam* queryParam)
{
    HiSysEventQueryArg queryArg;
    queryArg.endTime = SoftBusGetSysTimeMs();
    queryArg.beginTime = queryArg.endTime - time * MINUTE_TIME;
    queryArg.maxEvents = queryParam->dataSize;
    
    int32_t ret = OH_HiSysEvent_Query(&queryArg, queryParam->queryRules, queryParam->eventSize, &queryParam->callback);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusHisEvtQuery result, reason is %d", ret);
}

static void SoftBusProcessStatsQueryData(SoftBusStatsResult* result)
{
    result->btFlow = g_transStatsInfo.btFlowTotal;
    int32_t total = g_transStatsInfo.openSessionSuccessTotal + g_transStatsInfo.openSessionFailTotal;
    if (total == 0) {
        result->successRate = 0;
    } else {
        result->successRate = (1.0 * g_transStatsInfo.openSessionSuccessTotal) / total;
    }

    result->sessionSuccessDuration = 0;
    if (g_transStatsInfo.delayNum != 0) {
        result->sessionSuccessDuration = g_transStatsInfo.delayTimeTotal / g_transStatsInfo.delayNum;
    }

    int32_t activityTotal = g_transStatsInfo.activityFailTotal + g_transStatsInfo.activitySuccessTotal;
    if (activityTotal == 0) {
        result->activityRate = 0;
    } else {
        result->activityRate = (1.0 * g_transStatsInfo.activitySuccessTotal) / activityTotal;
    }

    result->deviceOnlineNum = g_lnnStatsInfo.onlineDevMaxNum;
    result->deviceOnlineTimes = g_lnnStatsInfo.joinLnnNum;
    result->deviceOfflineTimes = g_lnnStatsInfo.leaveLnnNum;
    result->maxParaSessionNum = g_transStatsInfo.maxParaSessionNum;
    result->laneScoreOverTimes = g_transStatsInfo.laneScoreOverTimes;
    result->detectionTimes = g_transStatsInfo.detectionTimes;

    if (memset_s(&g_connStatsInfo, sizeof(g_connStatsInfo), 0, sizeof(g_connStatsInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "memset g_connStatsInfo fail!");
        return;
    }
    if (memset_s(&g_lnnStatsInfo, sizeof(g_lnnStatsInfo), 0, sizeof(g_lnnStatsInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "memset g_lnnStatsInfo fail!");
        return;
    }
    if (memset_s(&g_transStatsInfo, sizeof(g_transStatsInfo), 0, sizeof(g_transStatsInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "memset g_transStatsInfo fail!");
        return;
    }

    g_isConnQueryEnd = false;
    g_isLnnQueryEnd = false;
    g_isTransQueryEnd = false;
}

static void SoftBusProcessAlarmQueryData(SoftBusAlarmEvtResult* result)
{
    result->recordSize = g_alarmEvtResult.recordSize;
    result->records = g_alarmEvtResult.records;
    g_isAlarmQueryEnd = false;
    return;
}

int32_t SoftBusQueryStatsInfo(int time, SoftBusStatsResult* result)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusQueryStatsInfo start");
    if (time <= SOFTBUS_ZERO || time > SEVEN_DAY_MINUTE) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftBusQueryStatsInfo fail, time is %d", time);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_statsQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock g_statsQueryLock fail");
        return SOFTBUS_ERR;
    }
    for (int i = 0; i < STATS_UNUSE_BUTT; i++) {
        SoftBusEventQueryInfo(time, &g_queryStatsParam[i]);
    }
    while (!g_isConnQueryEnd || !g_isLnnQueryEnd || !g_isTransQueryEnd) {
        SoftBusSleepMs(WAIT_QUERY_TIME);
    }

    SoftBusProcessStatsQueryData(result);
    (void)SoftBusMutexUnlock(&g_statsQueryLock);
    return SOFTBUS_OK;
}

int32_t SoftBusQueryAlarmInfo(int time, int type, SoftBusAlarmEvtResult* result)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusQueryAlarmInfo start");
    if (time <= SOFTBUS_ZERO || time > SEVEN_DAY_MINUTE) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QueryAlarmInfo fail, time is %d", time);
        return SOFTBUS_ERR;
    }
    if (type < SOFTBUS_MANAGEMENT_ALARM_TYPE || type >= ALARM_UNUSE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QueryAlarmInfo fail, type is %d", type);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_alarmQueryLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "QueryAlarmInfo fail,lock fail");
        return SOFTBUS_ERR;
    }
    SoftBusEventQueryInfo(time, &g_queryAlarmParam[type]);
    while (!g_isAlarmQueryEnd) {
        SoftBusSleepMs(WAIT_QUERY_TIME);
    }

    SoftBusProcessAlarmQueryData(result);
    (void)SoftBusMutexUnlock(&g_alarmQueryLock);
    return SOFTBUS_OK;
}

static int32_t InitDumperUtilMutexLock(void)
{
    SoftBusMutexAttr mutexAttr = {SOFTBUS_MUTEX_RECURSIVE};
    if (SoftBusMutexInit(&g_statsQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init statistic lock fail");
        (void)SoftBusMutexDestroy(&g_statsQueryLock);
        return SOFTBUS_ERR;
    }
    
    if (SoftBusMutexInit(&g_alarmQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init alarm lock fail");
        (void)SoftBusMutexDestroy(&g_alarmQueryLock);
        return SOFTBUS_ERR;
    }
    
    if (SoftBusMutexInit(&g_connOnQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init conn onQuery lock fail");
        (void)SoftBusMutexDestroy(&g_connOnQueryLock);
        return SOFTBUS_ERR;
    }
    
    if (SoftBusMutexInit(&g_lnnOnQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init lnn onQuery lock fail");
        (void)SoftBusMutexDestroy(&g_lnnOnQueryLock);
        return SOFTBUS_ERR;
    }
    
    if (SoftBusMutexInit(&g_transOnQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init trans onQuery lock fail");
        (void)SoftBusMutexDestroy(&g_transOnQueryLock);
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexInit(&g_alarmOnQueryLock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init alarm onQuery lock fail");
        (void)SoftBusMutexDestroy(&g_alarmOnQueryLock);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UpdateSysEventQueryParam(HiSysEventQueryParam* param, char* eventName)
{
    HiSysEventQueryRule* queryRule = &param->queryRules[SOFTBUS_ZERO];
    if (strcpy_s(queryRule->domain, MAX_LENGTH_OF_EVENT_DOMAIN, SOFTBUS_EVENT_DOMAIN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "UpdateSysEventQueryParam  copy domain fail");
    }
    if (strcpy_s(queryRule->eventList[SOFTBUS_ZERO], MAX_LENGTH_OF_EVENT_NAME, eventName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "UpdateSysEventQueryParam  copy domain fail");
    }
    queryRule->eventListSize = SOFTBUS_ONE;
    queryRule->condition = NULL;
    param->eventSize = SOFTBUS_ONE;
}

static void InitSoftBusQueryEventParam()
{
    HiSysEventQueryParam* connParam = &g_queryStatsParam[SOFTBUS_CONNECTION_STATS_TYPE];
    UpdateSysEventQueryParam(connParam, CONN_EVENT_NAME);
    connParam->callback.OnQuery = OnQueryConn;
    connParam->callback.OnComplete = OnCompleteConn;
    connParam->dataSize = QUERY_EVENT_FULL_QUERY_PARAM;

    HiSysEventQueryParam* lnnParam = &g_queryStatsParam[SOFTBUS_BUSCENTER_STATS_TYPE];
    UpdateSysEventQueryParam(lnnParam, LNN_EVENT_NAME);
    lnnParam->callback.OnQuery = OnQueryLnn;
    lnnParam->callback.OnComplete = OnCompleteLnn;
    lnnParam->dataSize = QUERY_EVENT_FULL_QUERY_PARAM;

    HiSysEventQueryParam* transParam = &g_queryStatsParam[SOFTBUS_TRANSPORT_STATS_TYPE];
    UpdateSysEventQueryParam(transParam, TRANS_EVENT_NAME);
    transParam->callback.OnQuery = OnQueryTrans;
    transParam->callback.OnComplete = OnCompleteTrans;
    transParam->dataSize = QUERY_EVENT_FULL_QUERY_PARAM;

    HiSysEventQueryParam* manageParam = &g_queryAlarmParam[SOFTBUS_MANAGEMENT_ALARM_TYPE];
    UpdateSysEventQueryParam(manageParam, MANAGE_ALARM_EVENT_NAME);
    manageParam->callback.OnQuery = OnQueryAlarm;
    manageParam->callback.OnComplete = OnCompleteAlarm;
    manageParam->dataSize = MAX_NUM_OF_EVENT_RESULT;

    HiSysEventQueryParam* controlParam = &g_queryAlarmParam[SOFTBUS_CONTROL_ALARM_TYPE];
    UpdateSysEventQueryParam(controlParam, CONTROL_ALARM_EVENT_NAME);
    controlParam->callback.OnQuery = OnQueryAlarm;
    controlParam->callback.OnComplete = OnCompleteAlarm;
    controlParam->dataSize = MAX_NUM_OF_EVENT_RESULT;
}

static void QueryStatisticInfo(SoftBusMessage* param)
{
    (void)param;
    SoftBusStatsResult* result = SoftBusMalloc(sizeof(SoftBusStatsResult));
    if (result == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "create SoftBusStatsResult failed");
        return;
    }
    
    if (SoftBusQueryStatsInfo(DAY_MINUTE, result) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "QueryStatisticInfo query fail!\n");
        SoftBusFree(result);
        return;
    }

    StatsEventExtra extra = {
        .btFlow = result->btFlow,
        .successRate = (int32_t)(result->successRate * RATE_HUNDRED),
        .maxParaSessionNum = result->maxParaSessionNum,
        .sessionSuccessDuration = result->sessionSuccessDuration,
        .deviceOnlineNum = result->deviceOnlineNum,
        .deviceOnlineTimes = result->deviceOnlineTimes,
        .deviceOfflineTimes = result->deviceOfflineTimes,
        .laneScoreOverTimes = result->laneScoreOverTimes,
        .activationRate = (int32_t)(result->activityRate * RATE_HUNDRED),
        .detectionTimes = result->detectionTimes,
        .result = EVENT_STAGE_RESULT_OK
    };
    DSOFTBUS_STATS(EVENT_SCENE_STATS, extra);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "QueryStatisticInfo query success!\n");
    SoftBusFree(result);
}

static inline SoftBusHandler* CreateHandler(SoftBusLooper* looper, HandleMessageFunc callback)
{
    SoftBusHandler* handler = SoftBusMalloc(sizeof(SoftBusHandler));
    if (handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "create handler failed");
        return NULL;
    }
    handler->looper = looper;
    handler->name = "softbusHidumperHandler";
    handler->HandleMessage = callback;

    return handler;
}

static void FreeMessageFunc(SoftBusMessage* msg)
{
    if (msg == NULL) {
        return;
    }

    if (msg->handler != NULL) {
        SoftBusFree(msg->handler);
    }
    SoftBusFree(msg);
}

static SoftBusMessage* CreateMessage(SoftBusLooper* looper, HandleMessageFunc callback)
{
    SoftBusMessage* msg = SoftBusMalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "malloc softbus message failed");
        return NULL;
    }

    SoftBusHandler* handler = CreateHandler(looper, callback);
    msg->what = MSG_STATISTIC_QUERY_REPORT;
    msg->obj = NULL;
    msg->handler = handler;
    msg->FreeMessage = FreeMessageFunc;
    return msg;
}

static int32_t CreateAndQueryMsgDelay(SoftBusLooper* looper, HandleMessageFunc callback, uint64_t delayMillis)
{
    if ((looper == NULL) || (callback == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }

    SoftBusMessage* message = CreateMessage(looper, callback);
    if (message == NULL) {
        return SOFTBUS_MEM_ERR;
    }

    looper->PostMessageDelay(looper, message, delayMillis);
    return SOFTBUS_OK;
}

static void QueryStatisticInfoPeriod(SoftBusMessage* msg)
{
    QueryStatisticInfo(msg);
    CreateAndQueryMsgDelay(GetLooper(LOOP_TYPE_DEFAULT), QueryStatisticInfoPeriod, DAY_TIME);
}

int32_t SoftBusHidumperUtilInit(void)
{
    if (g_isDumperInit) {
        return SOFTBUS_OK;
    }
    if (InitDumperUtilMutexLock() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init dump util lock fail");
        return SOFTBUS_ERR;
    }

    g_alarmEvtResult.records = SoftBusMalloc(sizeof(AlarmRecord) * MAX_NUM_OF_EVENT_RESULT);
    if (g_alarmEvtResult.records == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init alarm record fail");
        return SOFTBUS_ERR;
    }
    InitSoftBusQueryEventParam();
    g_isDumperInit = true;
    if (CreateAndQueryMsgDelay(GetLooper(LOOP_TYPE_DEFAULT), QueryStatisticInfoPeriod, DAY_TIME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "CreateAndQueryMsgDelay fail");
    }
    return SOFTBUS_OK;
}

void SoftBusHidumperUtilDeInit(void)
{
    if (!g_isDumperInit) {
        return;
    }

    SoftBusFree(g_alarmEvtResult.records);
    SoftBusMutexDestroy(&g_statsQueryLock);
    SoftBusMutexDestroy(&g_alarmQueryLock);
    SoftBusMutexDestroy(&g_connOnQueryLock);
    SoftBusMutexDestroy(&g_lnnOnQueryLock);
    SoftBusMutexDestroy(&g_transOnQueryLock);
    SoftBusMutexDestroy(&g_alarmOnQueryLock);
    g_isDumperInit = false;
}
