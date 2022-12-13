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

#ifndef HEARTBEAT_STRATEGY_H
#define HEARTBEAT_STRATEGY_H

#include "lnn_heartbeat_strategy.h"
#include "lnn_net_builder.h"
#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class HeartBeatStategyInterface {
public:
    HeartBeatStategyInterface() {};
    virtual ~HeartBeatStategyInterface() {};

    virtual int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr) = 0;
    virtual int32_t LnnSetHbAsMasterNodeState(bool isMasterNode) = 0;
    virtual int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay) = 0;
};
class HeartBeatStategyInterfaceMock : public HeartBeatStategyInterface {
public:
    HeartBeatStategyInterfaceMock();
    ~HeartBeatStategyInterfaceMock() override;

    MOCK_METHOD2(LnnStartOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStopOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *));
    MOCK_METHOD3(LnnNotifyMasterElect, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD1(LnnSetHbAsMasterNodeState, int32_t(bool));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H