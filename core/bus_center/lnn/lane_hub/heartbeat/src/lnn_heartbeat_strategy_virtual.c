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

#include "lnn_heartbeat_strategy.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t ShiftLNNGear(const char *pkgName, int32_t callingUid, const char *targetNetworkId,
    GearMode mode, const HeartbeatImplPolicy *implPolicy)
{
    (void)pkgName;
    (void)callingUid;
    (void)targetNetworkId;
    (void)mode;
    (void)implPolicy;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub ShiftLNNGear");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetHeartbeatGearMode(GearMode *mode)
{
    (void)mode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetHeartbeatImplPolicy(LnnHeartbeatImplType type, HeartbeatImplPolicy *implPolicy)
{
    (void)type;
    (void)implPolicy;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyMasterNodeChanged(const char *masterUdid, int32_t weight)
{
    (void)masterUdid;
    (void)weight;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartHeartbeatDelay(void)
{
    return SOFTBUS_OK;
}

void LnnStopHeartbeat(void)
{
}

int32_t LnnInitHeartbeat(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub LnnInitHeartbeat");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
}
