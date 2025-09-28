/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_MOCK_H
#define WIFI_DIRECT_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include "entity/p2p_entity.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
using P2pCreateGroupParam = P2pAdapter::CreateGroupParam;
using P2pConnectParam = P2pAdapter::ConnectParam;
using P2pDestroyGroupParam = P2pAdapter::DestroyGroupParam;
class P2pEntityMock {
public:
    static P2pEntityMock *GetMock()
    {
        return mock.load();
    }

    P2pEntityMock();
    ~P2pEntityMock();

    MOCK_METHOD(void, Init, ());
    MOCK_METHOD(void, DisconnectLink, (const std::string &));
    MOCK_METHOD(void, DestroyGroupIfNeeded, ());
    MOCK_METHOD(P2pOperationResult, CreateGroup, (const P2pCreateGroupParam &));
    MOCK_METHOD(P2pOperationResult, Connect, (const P2pConnectParam &));
    MOCK_METHOD(P2pOperationResult, DestroyGroup, (const P2pDestroyGroupParam &));
    MOCK_METHOD(P2pOperationResult, Disconnect, (const P2pDestroyGroupParam &));
    MOCK_METHOD(int32_t, ReuseLink, ());
    MOCK_METHOD(void, NotifyNewClientJoining, (const std::string &, int));
    MOCK_METHOD(void, CancelNewClientJoining, (const std::string &));
    MOCK_METHOD(void, RemoveNewClientJoining, (const std::string &));
    MOCK_METHOD(void, ClearJoiningClient, ());
    MOCK_METHOD(size_t, GetJoiningClientCount, ());
    MOCK_METHOD(void, ChangeState, (P2pEntityState *, const std::shared_ptr<P2pOperation> &));
    MOCK_METHOD(void, OnP2pStateChangeEvent, (P2pState));
    MOCK_METHOD(void, OnP2pConnectionChangeEvent,
        (const WifiP2pLinkedInfo &, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo>));
    MOCK_METHOD(void, PushOperation, (const std::shared_ptr<P2pOperation> &));
    MOCK_METHOD(void, ExecuteNextOperation, ());
    MOCK_METHOD(bool, HasPendingOperation, ());
    MOCK_METHOD(void, ClearPendingOperation, ());
    MOCK_METHOD(void, UpdateInterfaceManager,
        (const WifiP2pLinkedInfo &, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo>));
    MOCK_METHOD(void, UpdateLinkManager,
        (const WifiP2pLinkedInfo &, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo>));
    MOCK_METHOD(void, UpdateInterfaceManagerWhenStateChanged, (P2pState));
    MOCK_METHOD(void, Listener, (BroadcastReceiverAction, const struct BroadcastParam &));
    MOCK_METHOD(void, Dump, (P2pEntitySnapshot &));

private:
    static inline std::atomic<P2pEntityMock *> mock = nullptr;
};

} // namespace OHOS::SoftBus
#endif // WIFI_DIRECT_MOCK_H
