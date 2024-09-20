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
#ifndef P2P_ENTITY_STATE_H
#define P2P_ENTITY_STATE_H

#include "kits/c/wifi_p2p.h"

#include "adapter/p2p_adapter.h"
#include "p2p_operation.h"

namespace OHOS::SoftBus {
using P2pCreateGroupParam = P2pAdapter::CreateGroupParam;
using P2pConnectParam = P2pAdapter::ConnectParam;
using P2pDestroyGroupParam = P2pAdapter::DestroyGroupParam;

class P2pEntity;
class P2pEntityState {
public:
    P2pEntityState() = default;
    virtual ~P2pEntityState() = default;

    virtual void Enter(const std::shared_ptr<P2pOperation> &operation) = 0;
    virtual void Exit() = 0;
    virtual std::string GetName() = 0;
    virtual int CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation) = 0;
    virtual int Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation) = 0;
    virtual int DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation) = 0;
    virtual int RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation) = 0;

    virtual void OnP2pStateChangeEvent(P2pState state) = 0;
    virtual void PreprocessP2pConnectionChangeEvent(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo) {};
    virtual void OnP2pConnectionChangeEvent(
        const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo) = 0;

protected:
    static constexpr int TIMER_TIMEOUT = 50;

    static void ChangeState(P2pEntityState *state, const std::shared_ptr<P2pOperation> &operation);
};
}
#endif
