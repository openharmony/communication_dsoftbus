/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implementation of dfinder hievent.
 * Author: NA
 * Create: 2022-07-21
 */

#include "nstackx_dfinder_hievent.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_statistics.h"
#include "nstackx_error.h"
#include "nstackx_common.h"
#include "nstackx_event.h"
#include "securec.h"

#define TAG "nStackXDFinder"
#define STAT_EVT_PARA_NUM 4
#define STAT_EVT_NAME "dfinderStatistics"

static void *g_softObj;
static DFinderEventFunc g_eventFunc;

static int g_statisticsIdx[STAT_EVT_PARA_NUM] = {
    STATS_INVALID_OPT_AND_PAYLOAD,
    STATS_BUILD_PKT_FAILED,
    STATS_INVALID_RESPONSE_MSG,
    STATS_OVER_DEVICE_LIMIT
};

static DFinderEventParam g_statisticsPara[STAT_EVT_PARA_NUM] = {
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "invalidOptionCnt"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "buildPktFailCnt"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "invalidRspCnt"
    },
    {
        .type = DFINDER_PARAM_TYPE_UINT64,
        .name = "overDeviceLimitCnt"
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
        DFINDER_LOGE(TAG, "memcpy_s eventName failed.");
        return;
    }

    evt.params = CreateStatisticsEventParams();
    if (evt.params == NULL) {
        DFINDER_LOGE(TAG, "SetStatisticsPara failed.");
        return;
    }
    g_eventFunc(g_softObj, &evt);
    free(evt.params);
    DFINDER_LOGD(TAG, "report the dfinder statistics event.");
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