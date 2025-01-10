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

#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "conn_log.h"
#include "kits/c/wifi_p2p.h"

#include "adapter/p2p_adapter.h"
#include "channel/auth_negotiate_channel.h"
#include "dfx/p2p_entity_snapshot.h"
#include "p2p_available_state.h"
#include "p2p_broadcast_receiver.h"
#include "p2p_create_group_state.h"
#include "p2p_destroy_group_state.h"
#include "p2p_entity_state.h"
#include "p2p_operation.h"
#include "wifi_direct_entity.h"
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {
using P2pCreateGroupParam = P2pAdapter::CreateGroupParam;
using P2pConnectParam = P2pAdapter::ConnectParam;
using P2pDestroyGroupParam = P2pAdapter::DestroyGroupParam;

struct ClientJoinEvent {
    int32_t result_;
    std::string remoteDeviceId_;
    std::string remoteMac_;
};

class P2pEntitySnapshot;
class P2pEntity : public WifiDirectEntity {
public:
    static constexpr int TIMEOUT_WAIT_CLIENT_JOIN_MS = 10000;

    static P2pEntity &GetInstance()
    {
        static P2pEntity instance;
        return instance;
    }

    static void Init();
    void DisconnectLink(const std::string &remoteMac) override;
    void DestroyGroupIfNeeded() override;
    P2pOperationResult CreateGroup(const P2pCreateGroupParam &param);
    P2pOperationResult Connect(const P2pConnectParam &param);
    P2pOperationResult DestroyGroup(const P2pDestroyGroupParam &param);
    P2pOperationResult Disconnect(const P2pDestroyGroupParam &param);
    int32_t ReuseLink();

    void NotifyNewClientJoining(const std::string &remoteMac);
    void CancelNewClientJoining(const std::string &remoteMac);
    void RemoveNewClientJoining(const std::string &remoteMac);
    void ClearJoiningClient();
    size_t GetJoiningClientCount();

    void ChangeState(P2pEntityState *state, const std::shared_ptr<P2pOperation> &operation);

    void OnP2pStateChangeEvent(P2pState state);
    void OnP2pConnectionChangeEvent(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo);

    void PushOperation(const std::shared_ptr<P2pOperation> &operation);
    void ExecuteNextOperation();
    bool HasPendingOperation();
    void ClearPendingOperation();

    void UpdateInterfaceManager(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo);
    void UpdateLinkManager(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo);

    void UpdateInterfaceManagerWhenStateChanged(P2pState state);
    static void Listener(BroadcastReceiverAction action, const struct BroadcastParam &param);
    
    void Dump(P2pEntitySnapshot &snapshot);

    void Lock()
    {
        CONN_LOGD(CONN_WIFI_DIRECT, "lock");
        operationLock_.lock();
    }
    void Unlock()
    {
        CONN_LOGD(CONN_WIFI_DIRECT, "unlock");
        operationLock_.unlock();
    }

private:
    P2pEntity();

    class Initiator {
    public:
        Initiator()
        {
            WifiDirectInitiator::GetInstance().Add(P2pEntity::Init);
        }
    };

    static inline Initiator initiator_;

    friend P2pCreateGroupState;
    friend P2pAvailableState;
    friend P2pDestroyGroupState;
    std::recursive_mutex operationLock_;
    P2pEntityState *state_;
    int currentFrequency_ = 0;
    std::recursive_mutex pendingOperationLock_;
    std::queue<std::shared_ptr<P2pOperation>> pendingOperations_;

    OHOS::Utils::Timer timer_;
    std::recursive_mutex joiningClientsLock_;
    std::map<std::string, uint32_t> joiningClients_;
};
} // namespace OHOS::SoftBus
#endif
