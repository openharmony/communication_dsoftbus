/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_listener.h"
#include "lnn_trans_lane.h"

#include "softbus_error_code.h"

int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request, const ILaneListener *listener)
{
    (void)laneReqId;
    (void)request;
    (void)listener;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid)
{
    (void)oldLaneId;
    (void)newLaneId;
    (void)peerUdid;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LaneDeleteP2pAddress(const char *networkId, bool isDestroy)
{
    (void)networkId;
    (void)isDestroy;
}

void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId)
{
    (void)ipAddr;
    (void)networkId;
}

int32_t UpdateLaneBusinessInfoItem(uint64_t oldLaneId, uint64_t newLaneId)
{
    (void)oldLaneId;
    (void)newLaneId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t UpdateReqListLaneId(uint64_t oldLaneId, uint64_t newLaneId)
{
    (void)oldLaneId;
    (void)newLaneId;
    return SOFTBUS_NOT_IMPLEMENT;
}
