/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_lane_manager.h"

#include <securec.h>

#include "lnn_smart_communication.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

struct LnnLanesObject {
    LnnLaneProperty prop;
    uint32_t laneNum;
    int32_t laneId[0];
};

LnnLanesObject *LnnRequestLanesObject(const char *netWorkId, LnnLaneProperty prop, uint32_t laneNum)
{
    if (prop < LNN_MESSAGE_LANE || prop >= LNN_LANE_PROPERTY_BUTT || netWorkId == NULL ||
        laneNum == 0 || laneNum > LNN_REQUEST_MAX_LANE_NUM) {
        LOG_ERR("param error, prop = %d, laneNum = %u", prop, laneNum);
        return NULL;
    }
    uint32_t memLen = sizeof(LnnLanesObject) + sizeof(int32_t) * laneNum;
    LnnLanesObject *lanesObject = (LnnLanesObject *)SoftBusMalloc(memLen);
    if (lanesObject == NULL) {
        LOG_ERR("SoftBusMalloc error.");
        return NULL;
    }
    (void)memset_s(lanesObject, memLen, 0, memLen);
    lanesObject->prop = prop;
    lanesObject->laneNum = laneNum;

    for (uint32_t i = 0; i < laneNum; i++) {
        int32_t laneId = LnnGetRightLane(netWorkId, prop);
        if (laneId < 0) {
            LOG_ERR("LnnGetRightLane error. laneId = %d", laneId);
            SoftBusFree(lanesObject);
            return NULL;
        }
        lanesObject->laneId[i] = laneId;
    }
    return lanesObject;
}

void LnnReleaseLanesObject(LnnLanesObject *lanesObject)
{
    if (lanesObject == NULL) {
        return;
    }
    for (uint32_t i = 0; i < lanesObject->laneNum; i++) {
        LnnReleaseLane(lanesObject->laneId[i]);
    }
    SoftBusFree(lanesObject);
}

int32_t LnnGetLaneId(LnnLanesObject *lanesObject, uint32_t num)
{
    if (lanesObject == NULL || num >= lanesObject->laneNum) {
        LOG_ERR("param error. num = %u", num);
        return SOFTBUS_ERR;
    }
    return lanesObject->laneId[num];
}

uint32_t LnnGetLaneNum(LnnLanesObject *lanesObject)
{
    if (lanesObject == NULL) {
        LOG_ERR("param error");
        return SOFTBUS_ERR;
    }
    return lanesObject->laneNum;
}