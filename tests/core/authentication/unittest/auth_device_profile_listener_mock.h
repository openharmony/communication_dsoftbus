/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef DSOFTBUS_APP_BIND_MOCK_H
#define DSOFTBUS_APP_BIND_MOCK_H

#include "bus_center_event.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_ohos_account.h"
#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class AuthDeviceProfileListenerInterface {
public:
    AuthDeviceProfileListenerInterface() {};
    virtual ~AuthDeviceProfileListenerInterface() {};
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay) = 0;
    virtual bool LnnIsLocalSupportBurstFeature(void) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId) = 0;
    virtual int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId) = 0;
    virtual SoftBusScreenState GetScreenState(void) = 0;
    virtual bool IsHeartbeatEnable(void) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual void LnnHbOnTrustedRelationIncreased(int32_t groupType) = 0;
    virtual void LnnHbOnTrustedRelationReduced(void) = 0;
};

class AuthDeviceProfileListenerInterfaceMock : public AuthDeviceProfileListenerInterface {
public:
    AuthDeviceProfileListenerInterfaceMock();
    ~AuthDeviceProfileListenerInterfaceMock() override;
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD0(LnnIsLocalSupportBurstFeature, bool (void));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t (void));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD3(DpHasAccessControlProfile, bool (const char *, bool, int32_t));
    MOCK_METHOD2(LnnDeleteSpecificTrustedDevInfo, int32_t(const char *, int32_t));
    MOCK_METHOD0(GetScreenState, SoftBusScreenState (void));
    MOCK_METHOD0(IsHeartbeatEnable, bool (void));
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t (const char *));
    MOCK_METHOD1(LnnHbOnTrustedRelationIncreased, void (int32_t));
    MOCK_METHOD0(LnnHbOnTrustedRelationReduced, void (void));
};

extern "C" {
void DelNotTrustDevice(const char *udid);
void RestartCoapDiscovery(void);
void LnnUpdateOhosAccount(UpdateAccountReason reason);
void NotifyRemoteDevOffLineByUserId(int32_t userId, const char *udid);
void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type);
}
} // namespace OHOS
#endif // AUTH_LANE_H
