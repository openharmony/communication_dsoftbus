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

#ifndef STATS_EVENT_CONVERTER_H
#define STATS_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATS_ASSIGNER(type, fieldName, field)                                                                \
    static inline bool StatsAssigner##fieldName(                                                              \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->statsExtra->field, &param) &&                                                \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

STATS_ASSIGNER(Errcode, Result, result)
STATS_ASSIGNER(Int32, BtFlow, btFlow)
STATS_ASSIGNER(Int32, SuccessRate, successRate)
STATS_ASSIGNER(Int32, MaxParaSessionNum, maxParaSessionNum)
STATS_ASSIGNER(Int32, SessionSuccessDuration, sessionSuccessDuration)
STATS_ASSIGNER(Int32, DeviceOnlineNum, deviceOnlineNum)
STATS_ASSIGNER(Int32, DeviceOnlineTimes, deviceOnlineTimes)
STATS_ASSIGNER(Int32, DeviceOfflineTimes, deviceOfflineTimes)
STATS_ASSIGNER(Int32, LaneScoreOverTimes, laneScoreOverTimes)
STATS_ASSIGNER(Int32, ActivationRate, activationRate)
STATS_ASSIGNER(Int32, DetectionTimes, detectionTimes)
STATS_ASSIGNER(LongString, SuccessRateDetail, successRateDetail)

#define STATS_ASSIGNER_SIZE 12 // Size of g_statsAssigners
static HiSysEventParamAssigner g_statsAssigners[] = {
    { "STAGE_RES",                  HISYSEVENT_INT32,  StatsAssignerResult                 },
    { "BT_FLOW",                    HISYSEVENT_INT32,  StatsAssignerBtFlow                 },
    { "SUCCESS_RATE",               HISYSEVENT_INT32,  StatsAssignerSuccessRate            },
    { "MAX_PARA_SESSION_NUM",       HISYSEVENT_INT32,  StatsAssignerMaxParaSessionNum      },
    { "SESSION_SUCCESS_DURATION",   HISYSEVENT_INT32,  StatsAssignerSessionSuccessDuration },
    { "DEVICE_ONLINE_NUM",          HISYSEVENT_INT32,  StatsAssignerDeviceOnlineNum        },
    { "DEVICE_ONLINE_TIMES",        HISYSEVENT_INT32,  StatsAssignerDeviceOnlineTimes      },
    { "DEVICE_OFFLINE_TIMES",       HISYSEVENT_INT32,  StatsAssignerDeviceOfflineTimes     },
    { "LANE_SCORE_OVER_TIMES",      HISYSEVENT_INT32,  StatsAssignerLaneScoreOverTimes     },
    { "ACTIVATION_RATE",            HISYSEVENT_INT32,  StatsAssignerActivationRate         },
    { "DETECTION_TIMES",            HISYSEVENT_INT32,  StatsAssignerDetectionTimes         },
    { "SUCCESS_RATE_DETAIL",        HISYSEVENT_STRING, StatsAssignerSuccessRateDetail      },

    // Modification Note: remember updating STATS_ASSIGNER_SIZE
};

static inline size_t ConvertStatsForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->statsExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_statsAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // STATS_EVENT_CONVERTER_H
