/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_lane_hub.h"

#include "bus_center_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnInitLaneHub(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init virtual lane hub");
    return SOFTBUS_OK;
}

int32_t LnnInitLaneHubDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init virtual lane hub delay");
    return SOFTBUS_OK;
}

void LnnDeinitLaneHub(void)
{
}

LnnLanesObject *LnnRequestLanesObject(const char *netWorkId, int32_t pid, LnnLaneProperty prop,
    const LnnPreferredLinkList *list, uint32_t laneNum)
{
    (void)netWorkId;
    (void)pid;
    (void)prop;
    (void)list;
    (void)laneNum;
    return NULL;
}

void LnnReleaseLanesObject(LnnLanesObject *lanesObject)
{
}

int32_t LnnGetLaneId(LnnLanesObject *lanesObject, uint32_t num)
{
    (void)lanesObject;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}

const LnnLaneInfo *LnnGetLaneInfo(int32_t laneId)
{
    (void)laneId;
    return NULL;
}