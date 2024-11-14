/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_qos.h"
#include "softbus_error_code.h"

int32_t LnnInitQos(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitQos(void)
{
    return;
}

int32_t LnnRegPeriodAdjustmentCallback(OnStatsPeriodAdjustment callback)
{
    (void)callback;
    return SOFTBUS_OK;
}

void LnnReportLaneIdStatsInfo(const LaneIdStatsInfo *statsList, uint32_t listSize)
{
    (void)statsList;
    (void)listSize;
    return;
}

void LnnReportRippleData(uint64_t laneId, const LnnRippleData *data)
{
    (void)laneId;
    (void)data;
    return;
}

int32_t LnnRequestQosOptimization(const uint64_t *laneIdList, uint32_t listSize, int32_t *result, uint32_t resultSize)
{
    (void)laneIdList;
    (void)listSize;
    (void)result;
    (void)resultSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnCancelQosOptimization(const uint64_t *laneIdList, uint32_t listSize)
{
    (void)laneIdList;
    (void)listSize;
}