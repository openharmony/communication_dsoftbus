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

#ifndef STATS_EVENT_FORM_H
#define STATS_EVENT_FORM_H

#include <stdint.h>

#include "event_form_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_STATS = 1,
} StatsEventScene;


typedef struct {
    int32_t result;
    int32_t btFlow;
    int32_t successRate;
    int32_t maxParaSessionNum;
    int32_t sessionSuccessDuration;
    int32_t deviceOnlineNum;
    int32_t deviceOnlineTimes;
    int32_t deviceOfflineTimes;
    int32_t laneScoreOverTimes;
    int32_t activationRate;
    int32_t detectionTimes;
    const char *successRateDetail;
} StatsEventExtra;


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // CONN_EVENT_FORM_H
