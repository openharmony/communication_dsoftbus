/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_HIDUMPER_UTIL_H
#define SOFTBUS_HIDUMPER_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_ZERO 0
#define SOFTBUS_ONE 1
#define SOFTBUS_ALARM_TIME_LEN 26

typedef enum {
    SOFTBUS_MANAGEMENT_ALARM_TYPE,
    SOFTBUS_CONTROL_ALARM_TYPE,
    ALARM_UNUSE_BUTT,
} SoftBusAlarmType;

typedef struct {
    char time[SOFTBUS_ALARM_TIME_LEN];
    int32_t type;
    int32_t callerPid;
    int32_t errorCode;
    int32_t linkType;
    int32_t minBw;
    int32_t methodId;
    char *permissionName;
    char *sessionName;
} AlarmRecord;

typedef struct {
    AlarmRecord *records;
    size_t recordSize;
} SoftBusAlarmEvtResult;

typedef struct {
    int32_t btFlow;
    float successRate;
    int32_t maxParaSessionNum;
    int32_t sessionSuccessDuration;
    int32_t deviceOnlineNum;
    int32_t deviceOnlineTimes;
    int32_t deviceOfflineTimes;
    int32_t laneScoreOverTimes;
    float activityRate;
    int32_t detectionTimes;
    char *successRateDetail;
} SoftBusStatsResult;

SoftBusStatsResult* MallocSoftBusStatsResult(unsigned int size);

void FreeSoftBusStatsResult(SoftBusStatsResult* result);

int32_t SoftBusQueryStatsInfo(int time, SoftBusStatsResult* result);

int32_t SoftBusQueryAlarmInfo(int time, int type, SoftBusAlarmEvtResult* result);

int32_t SoftBusHidumperUtilInit(void);

void SoftBusHidumperUtilDeInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_HIDUMPER_ALARM_H */