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

#include "lnn_heartbeat_ctrl.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnStartHeartbeatFrameDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) stub process start.");
    return SOFTBUS_OK;
}

int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param)
{
    (void)param;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub set medium param");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    (void)pkgName;
    (void)callerId;
    (void)targetNetworkId;
    (void)mode;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub ShiftLNNGear");
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    (void)type;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub update send info");
}

void LnnHbOnAuthGroupCreated(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub process auth group created");
}

void LnnHbOnAuthGroupDeleted(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat stub process auth group deleted");
}

int32_t LnnInitHeartbeat(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) stub init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
}
