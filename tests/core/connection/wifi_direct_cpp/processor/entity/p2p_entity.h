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
#ifndef P2P_ENTITY_H
#define P2P_ENTITY_H

#include <atomic>
#include <string>

#include <gmock/gmock.h>

#include "adapter/p2p_adapter.h"
#include "entity/p2p_operation_result.h"
#include "entity/wifi_direct_entity.h"

namespace OHOS::SoftBus {
using P2pCreateGroupParam = P2pAdapter::CreateGroupParam;
using P2pConnectParam = P2pAdapter::ConnectParam;
using P2pDestroyGroupParam = P2pAdapter::DestroyGroupParam;

struct ClientJoinEvent {
    int32_t result_;
    std::string remoteDeviceId_;
    std::string remoteMac_;
};

class P2pEntityInterface {
public:
    P2pEntityInterface() = default;
    virtual ~P2pEntityInterface() = default;

    virtual void CancelNewClientJoining(const std::string &remoteMac) = 0;
    virtual void NotifyNewClientJoining(const std::string &remoteMac) = 0;
    virtual P2pOperationResult CreateGroup(const P2pCreateGroupParam &param) = 0;
    virtual P2pOperationResult Connect(const P2pConnectParam &param) = 0;
    virtual P2pOperationResult DestroyGroup(const P2pDestroyGroupParam &param) = 0;
    virtual int32_t ReuseLink() = 0;
    virtual P2pOperationResult Disconnect(const P2pDestroyGroupParam &param) = 0;
};

class P2pEntity : public P2pEntityInterface, public WifiDirectEntity {
public:
    static P2pEntity &GetInstance()
    {
        auto &instance = *(mock.load());
        return instance;
    }

    P2pEntity()
    {
        mock.store(this);
    }

    MOCK_METHOD(void, CancelNewClientJoining, (const std::string &remoteMac), (override));
    MOCK_METHOD(void, NotifyNewClientJoining, (const std::string &remoteMac), (override));
    MOCK_METHOD(P2pOperationResult, CreateGroup, (const P2pCreateGroupParam &param), (override));
    MOCK_METHOD(P2pOperationResult, Connect, (const P2pConnectParam &param), (override));
    MOCK_METHOD(P2pOperationResult, DestroyGroup, (const P2pDestroyGroupParam &param), (override));
    MOCK_METHOD(int32_t, ReuseLink, (), (override));
    MOCK_METHOD(P2pOperationResult, Disconnect, (const P2pDestroyGroupParam &param), (override));
    MOCK_METHOD(void, DisconnectLink, (const std::string &remoteMac), (override));
    MOCK_METHOD(void, DestroyGroupIfNeeded, (), (override));
private:
    static inline std::atomic<P2pEntity *> mock = nullptr;
};
} // namespace OHOS::SoftBus
#endif // P2P_ENTITY_H
