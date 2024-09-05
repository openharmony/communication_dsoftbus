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

#ifndef P2P_DESTROY_GROUP_STATE_H
#define P2P_DESTROY_GROUP_STATE_H

#include "p2p_entity_state.h"
#include "timer.h"

namespace OHOS::SoftBus {
class P2pDestroyGroupState : public P2pEntityState {
public:
    static P2pDestroyGroupState *Instance();
    std::string GetName() override { return "P2pDestroyGroupState"; }
    void Enter(const std::shared_ptr<P2pOperation> &operation) override;
    void Exit() override;

    int CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation) override;
    int Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation) override;
    int DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation) override;
    int RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation) override;

    void OnP2pStateChangeEvent(P2pState state) override;
    void OnP2pConnectionChangeEvent(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo) override;
    void OnTimeout();

private:
    static constexpr int DESTROY_GROUP_TIMEOUT_MS = 2000;

    P2pDestroyGroupState();

    std::shared_ptr<P2pOperation> operation_;
    OHOS::Utils::Timer timer_;
};
} // namespace OHOS::SoftBus
#endif