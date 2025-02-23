/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_prelink.h"
#include "softbus_error_code.h"

int32_t GetConcurrencyPeerUdidByActionId(uint32_t actionId, char *peerUdid)
{
    (void)actionId;
    (void)peerUdid;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool HaveConcurrencyBleGuideChannel(uint32_t actionId)
{
    (void)actionId;
    return false;
}

int32_t InitActionBleConcurrency(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void DeinitActionBleConcurrency(void)
{
    return;
}

int32_t LnnTriggerPreLink(const void *msg)
{
    (void)msg;
    return SOFTBUS_NOT_IMPLEMENT;
}