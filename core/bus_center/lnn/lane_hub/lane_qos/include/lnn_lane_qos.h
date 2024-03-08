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

#ifndef LNN_LANE_QOS_H
#define LNN_LANE_QOS_H

#include <stdint.h>
#include "lnn_lane_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRAFFIC_DATA_LEN 32

typedef enum {
    FRAME_COST_TIME_SMALL = 0, /* less than 10ms */
    FRAME_COST_TIME_MEDIUM, /* [10ms, 100ms) */
    FRAME_COST_TIME_LARGE, /* greater than or equal to 100ms */
    FRAME_COST_TIME_MAX,
} FrameCostTimeStats;

typedef enum {
    FRAME_BIT_RATE_SMALL = 0, /* less than 3Mbps */
    FRAME_BIT_RATE_MEDIUM, /* [3Mbps, 30Mbps) */
    FRAME_BIT_RATE_LARGE, /* greater than or equal to 30Mbps */
    FRAME_BIT_RATE_MAX,
} FrameBitRateStats;

typedef struct {
    uint32_t costTimeStatsCnt[FRAME_COST_TIME_MAX];
    uint32_t sendBitRateStatsCnt[FRAME_BIT_RATE_MAX];
} FrameSendStats;

typedef struct {
    uint32_t rtt;
    uint32_t peakBw;
} MsgStats;

typedef struct {
    uint32_t peakBw;
} ByteStats;

typedef struct {
    uint32_t retransRate;
    uint32_t recvPktLoss;
    uint32_t sendPktLoss;
} FileStats;

typedef struct {
    FrameSendStats frameStats;
} StreamInfo;

typedef struct {
    uint64_t laneId;
    LaneTransType statsType;
    union {
        MsgStats msg;
        ByteStats bytes;
        FileStats file;
        StreamInfo stream;
    } statsInfo;
} LaneIdStatsInfo;

typedef enum {
    OPT_RESULT_SUCCESS = 0,
    OPT_RESULT_REQUEST_FREQUENTLY,
    OPT_RESULT_CANNOT_OPTIMIZE,
} QosOptResult;

typedef struct {
    unsigned char stats[TRAFFIC_DATA_LEN];
} LnnRippleData;

typedef void (*OnStatsPeriodAdjustment)(uint32_t ms);

int32_t LnnInitQos(void);
void LnnDeinitQos(void);
int32_t LnnRegPeriodAdjustmentCallback(OnStatsPeriodAdjustment callback);
void LnnReportLaneIdStatsInfo(const LaneIdStatsInfo *statsList, uint32_t listSize);
void LnnReportRippleData(uint64_t laneId, const LnnRippleData *data);
int32_t LnnRequestQosOptimization(const uint64_t *laneIdList,
    uint32_t listSize, int32_t *result, uint32_t resultSize);
void LnnCancelQosOptimization(const uint64_t *laneIdList, uint32_t listSize);

#ifdef __cplusplus
}
#endif
#endif
