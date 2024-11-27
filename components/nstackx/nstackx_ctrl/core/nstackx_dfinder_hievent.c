/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "nstackx_dfinder_hievent.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_statistics.h"
#include "nstackx_error.h"
#include "nstackx_common.h"
#include "nstackx_event.h"
#include "nstackx_util.h"
#include "securec.h"

#define TAG "nStackXDFinder"
#define STAT_EVT_PARA_NUM 4
#define STAT_EVT_NAME "DFINDER_STATS"

static void *g_softObj;
static DFinderEventFunc g_eventFunc;
static pthread_mutex_t g_eventFuncLock = PTHREAD_MUTEX_INITIALIZER;

static int g_statisticsIdx[STAT_EVT_PARA_NUM] = {
    STATS_INVALID_OPT_AND_PAYLOAD,
    STATS_BUILD_PKT_FAILED,
    STATS_INVALID_RESPONSE_MSG,
    STATS_OVER_DEVICE_LIMIT
};

static DFinderEventParam g_statisticsPara[STAT_EVT_PARA_NUM] = {
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "INVALID_OPTION_CNT"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "BUILD_PKT_FAIL_CNT"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "INVALID_RSP_CNT"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "OVER_DEVICE_LIMIT_CNT"
    }
};

static DFinderEventParam *CreateStatisticsEventParams(void)
{
    int i;
    const uint64_t *stat = GetStatistics();
    DFinderEventParam *para = (DFinderEventParam *)calloc(STAT_EVT_PARA_NUM, sizeof(DFinderEventParam));
    if (para == NULL) {
        return NULL;
    }

    for (i = 0; i < STAT_EVT_PARA_NUM; i++) {
        para[i] = g_statisticsPara[i];
        para[i].value.u64v = stat[g_statisticsIdx[i]];
    }
    return para;
}

void NotifyStatisticsEvent(void)
{
    int ret;
    DFinderEvent evt;

    if (g_eventFunc == NULL) {
        return;
    }

    (void)memset_s(&evt, sizeof(evt), 0, sizeof(evt));
    evt.type = DFINDER_EVENT_TYPE_STATISTIC;
    evt.level = DFINDER_EVENT_LEVEL_MINOR;
    evt.paramNum = STAT_EVT_PARA_NUM;
    ret = memcpy_s(evt.eventName, DFINDER_EVENT_NAME_LEN, STAT_EVT_NAME, strlen(STAT_EVT_NAME));
    if (ret != EOK) {
        DFINDER_LOGE(TAG, "memcpy_s eventName failed");
        return;
    }

    evt.params = CreateStatisticsEventParams();
    if (evt.params == NULL) {
        DFINDER_LOGE(TAG, "create statistics params failed");
        return;
    }
    g_eventFunc(g_softObj, &evt);
    free(evt.params);
    DFINDER_LOGD(TAG, "report statistics event");
}

typedef struct {
    void *softobj;
    DFinderEventFunc func;
} DFinderEventMsg;

static void SetEventFuncInner(void *arg)
{
    DFinderEventMsg *msg = (DFinderEventMsg *)arg;
    g_softObj = msg->softobj;
    g_eventFunc = msg->func;
    free(msg);
}

int SetEventFunc(void *softobj, DFinderEventFunc func)
{
    DFinderEventMsg *msg = (DFinderEventMsg *)malloc(sizeof(DFinderEventMsg));
    if (msg == NULL) {
        return NSTACKX_EFAILED;
    }

    msg->softobj = softobj;
    msg->func = func;
    if (PostEvent(GetEventNodeChain(), GetEpollFD(), SetEventFuncInner, msg) != NSTACKX_EOK) {
        free(msg);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int SetEventFuncDirectly(void *softobj, DFinderEventFunc func)
{
    if (PthreadMutexLock(&g_eventFuncLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    g_softObj = softobj;
    g_eventFunc = func;
    if (PthreadMutexUnlock(&g_eventFuncLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void ResetEventFunc(void)
{
    if (PthreadMutexLock(&g_eventFuncLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return;
    }
    g_softObj = NULL;
    g_eventFunc = NULL;
    if (PthreadMutexUnlock(&g_eventFuncLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
    }
}
