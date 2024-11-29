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

#include "p2p_available_state.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "adapter/p2p_adapter.h"
#include "data/interface_manager.h"
#include "p2p_connect_state.h"
#include "p2p_create_group_state.h"
#include "p2p_destroy_group_state.h"
#include "p2p_entity.h"
#include "p2p_unavailable_state.h"

namespace OHOS::SoftBus {
P2pAvailableState *P2pAvailableState::Instance()
{
    static P2pAvailableState instance;
    return &instance;
}

void P2pAvailableState::Enter(const std::shared_ptr<P2pOperation> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (P2pEntity::GetInstance().HasPendingOperation()) {
        std::thread handler([] {
            P2pEntity::GetInstance().ExecuteNextOperation();
        });
        handler.detach();
    }
}

void P2pAvailableState::Exit()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
}

int P2pAvailableState::CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    P2pOperationResult result {};
    if (P2pEntity::GetInstance().currentFrequency_ != 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "group is existed, currentFreq=%{public}d, freq=%{public}d",
            P2pEntity::GetInstance().currentFrequency_, operation->content_.frequency);
        if (operation->content_.frequency == P2pEntity::GetInstance().currentFrequency_) {
            result.errorCode_ = SOFTBUS_OK;
            operation->promise_.set_value(result);
            return SOFTBUS_OK;
        } else {
            result.errorCode_ = SOFTBUS_CONN_CREATE_GROUP_FAILED;
            return SOFTBUS_CONN_CREATE_GROUP_FAILED;
        }
    }
    int ret = P2pAdapter::P2pCreateGroup(operation->content_);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "create group failed");
    ChangeState(P2pCreateGroupState::Instance(), operation);
    return SOFTBUS_OK;
}

int P2pAvailableState::Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation)
{
    int ret = P2pAdapter::P2pConnectGroup(operation->content_);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ChangeState(P2pConnectState::Instance(), operation);
    return SOFTBUS_OK;
}

int P2pAvailableState::DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    int ret = P2pAdapter::DestroyGroup(operation->content_);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ChangeState(P2pDestroyGroupState::Instance(), operation);
    return SOFTBUS_OK;
}

int P2pAvailableState::RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "start remove group");
    auto ret = P2pAdapter::P2pShareLinkRemoveGroup(operation->content_);
    if (ret != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remove group failed, error=%{public}d", ret);
        return ret;
    }
    ChangeState(P2pDestroyGroupState::Instance(), operation);
    return SOFTBUS_OK;
}

void P2pAvailableState::OnP2pStateChangeEvent(P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (state == P2P_STATE_STARTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "state is P2P_STATE_STARTED");
    } else {
        ChangeState(P2pUnavailableState::Instance(), nullptr);
    }
}

void P2pAvailableState::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    if (groupInfo == nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "no groupInfo");
        P2pEntity::GetInstance().ClearJoiningClient();
        return;
    }

    if (!groupInfo->isGroupOwner) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not group owner, ignore");
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "remove joining client, clientDeviceSize=%{public}zu", groupInfo->clientDevices.size());
    for (const auto &client : groupInfo->clientDevices) {
        P2pEntity::GetInstance().RemoveNewClientJoining(client.address);
    }

    int reuseCount = 0;
    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&reuseCount](const InterfaceInfo &interface) {
        reuseCount = interface.GetReuseCount();
        return SOFTBUS_OK;
    });
    auto joiningClientCount = P2pEntity::GetInstance().GetJoiningClientCount();
    CONN_LOGI(
        CONN_WIFI_DIRECT, "joiningClientCount=%{public}zu, reuseCount=%{public}d", joiningClientCount, reuseCount);
    if (groupInfo->clientDevices.empty() && joiningClientCount == 0 && reuseCount > 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "gc disconnected abnormally");
        P2pAdapter::DestroyGroupParam param{IF_NAME_P2P};
        P2pAdapter::P2pShareLinkRemoveGroup(param);
    }
}

} // namespace OHOS::SoftBus
