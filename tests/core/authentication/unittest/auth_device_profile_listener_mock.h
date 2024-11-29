/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_utils.h"
#include "lnn_distributed_net_ledger.h"
#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class AuthDeviceProfileListenerInterface {
public:
    AuthDeviceProfileListenerInterface() {};
    virtual ~AuthDeviceProfileListenerInterface() {};
    virtual void DelNotTrustDevice(const char *udid) = 0;
    virtual void RestartCoapDiscovery(void) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay) = 0;
    virtual void LnnUpdateOhosAccount(bool isNeedUpdateHeartbeat) = 0;
    virtual void NotifyRemoteDevOffLineByUserId(int32_t userId, const char *udid) = 0;
    virtual bool LnnIsLocalSupportBurstFeature(void) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
};
class AuthDeviceProfileListenerInterfaceMock : public AuthDeviceProfileListenerInterface {
public:
    AuthDeviceProfileListenerInterfaceMock();
    ~AuthDeviceProfileListenerInterfaceMock() override;
    MOCK_METHOD1(DelNotTrustDevice, void(const char *udid));
    MOCK_METHOD0(RestartCoapDiscovery, void(void));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(bool));
    MOCK_METHOD2(NotifyRemoteDevOffLineByUserId, void(int32_t, const char *));
    MOCK_METHOD0(LnnIsLocalSupportBurstFeature, bool (void));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t (void));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
};
} // namespace OHOS
#endif // AUTH_LANE_H
