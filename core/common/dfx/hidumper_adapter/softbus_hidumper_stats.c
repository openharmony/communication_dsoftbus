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
#include "softbus_hidumper_stats.h"

#include <stdio.h>
#include <string.h>

#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_util.h"
#include "softbus_log_old.h"

#define SOFTBUS_FIFTEEN_MINUTES_STATS_ORDER "15min"
#define SOFTBUS_TWENTY_FOUR_HOURS_STATS_ORDER "24h"

#define SOFTBUS_STATS_MODULE_NAME "stats"
#define SOFTBUS_STATS_MODULE_HELP "List all the dump item of stats"

#define FIFTEEN_MINUTES 15
#define TWENTY_FOUR_HOURS (24 * 60)

static int32_t SoftBusStatsDumpHander(int fd, int32_t argc, const char **argv)
{
    if (fd < 0 || argc != 1 || argv == NULL) {
        return SOFTBUS_ERR;
    }

    SoftBusStatsResult *result = (SoftBusStatsResult *)SoftBusMalloc(sizeof(SoftBusStatsResult));
    if (result == NULL) {
        SOFTBUS_DPRINTF(fd, "SoftBusStatsDumpHander result malloc fail!\n");
        return SOFTBUS_ERR;
    }
    if (strcmp(argv[0], SOFTBUS_FIFTEEN_MINUTES_STATS_ORDER) == SOFTBUS_OK) {
        if (SoftBusQueryStatsInfo(FIFTEEN_MINUTES, result) != SOFTBUS_OK) {
            SOFTBUS_DPRINTF(fd, "SoftBusStatsDumpHander query fail!\n");
            SoftBusFree(result);
            return SOFTBUS_ERR;
        }
        SOFTBUS_DPRINTF(fd, "SoftBus 15min Statistics:\n");
        SOFTBUS_DPRINTF(fd, "BT traffic = %dkb\n", result->btFlow);
        SOFTBUS_DPRINTF(fd, "Connection success rate = %f\n", result->successRate);
        SOFTBUS_DPRINTF(fd, "Maximun concurrent number = %d\n", result->maxParaSessionNum);
        SOFTBUS_DPRINTF(fd, "Service delay threshold = %dms\n", result->sessionSuccessDuration);
        SOFTBUS_DPRINTF(fd, "Maximun online number = %d\n", result->deviceOnlineNum);
        SOFTBUS_DPRINTF(fd, "Online/Offine times = %d/%d\n", result->deviceOnlineTimes, result->deviceOfflineTimes);
        SOFTBUS_DPRINTF(fd, "Channel score exceeded times = %d\n", result->laneScoreOverTimes);
    } else if (strcmp(argv[0], SOFTBUS_TWENTY_FOUR_HOURS_STATS_ORDER) == SOFTBUS_OK) {
        if (SoftBusQueryStatsInfo(TWENTY_FOUR_HOURS, result) != SOFTBUS_OK) {
            SoftBusFree(result);
            SOFTBUS_DPRINTF(fd, "SoftBusStatsDumpHander query fail!\n");
            return SOFTBUS_ERR;
        }
        SOFTBUS_DPRINTF(fd, "SoftBus 24h Statistics:\n");
        SOFTBUS_DPRINTF(fd, "BT traffic = %dkb\n", result->btFlow);
        SOFTBUS_DPRINTF(fd, "Connection success rate = %f\n", result->successRate);
        SOFTBUS_DPRINTF(fd, "Act rate =  %f\n", result->activityRate);
        SOFTBUS_DPRINTF(fd, "Maximun online number = %d\n", result->deviceOnlineNum);
        SOFTBUS_DPRINTF(fd, "Online times = %d\n", result->deviceOnlineTimes);
        SOFTBUS_DPRINTF(fd, "Offine times = %d\n", result->deviceOfflineTimes);
        SOFTBUS_DPRINTF(fd, "Keepalive detection times = %d\n", result->detectionTimes);
    } else {
        SOFTBUS_DPRINTF(fd, "SoftBusStatsDumpHander invalid param!\n");
        SoftBusFree(result);
        return SOFTBUS_ERR;
    }
    
    SoftBusFree(result);
    return SOFTBUS_OK;
}

int32_t SoftBusStatsHiDumperInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler(SOFTBUS_STATS_MODULE_NAME, SOFTBUS_STATS_MODULE_HELP,
        &SoftBusStatsDumpHander);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftBusRegStatsDumpCb registe fail");
    }
    return ret;
}