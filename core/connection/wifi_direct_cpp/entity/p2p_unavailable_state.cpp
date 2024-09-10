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

#include "p2p_unavailable_state.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "adapter/p2p_adapter.h"
#include "p2p_available_state.h"
#include "p2p_entity.h"

namespace OHOS::SoftBus {
P2pUnavailableState *P2pUnavailableState::Instance()
{
    static P2pUnavailableState instance;
    return &instance;
}

void P2pUnavailableState::Enter(const std::shared_ptr<P2pOperation> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    P2pEntity::GetInstance().ClearPendingOperation();
}

void P2pUnavailableState::Exit()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
}

int P2pUnavailableState::CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation)
{
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pUnavailableState::Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation)
{
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pUnavailableState::DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pUnavailableState::RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

void P2pUnavailableState::OnP2pStateChangeEvent(P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (state == P2P_STATE_STARTED) {
        ChangeState(P2pAvailableState::Instance(), nullptr);
    }
}

void P2pUnavailableState::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "P2pUnavailableState");
}

} // namespace OHOS::SoftBus