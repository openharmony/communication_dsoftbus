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

#include "p2p_create_group_state.h"
#include "common_timer_errors.h"
#include "conn_log.h"
#include "p2p_entity.h"
#include "p2p_operation_result.h"
#include "p2p_unavailable_state.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
P2pCreateGroupState *P2pCreateGroupState::Instance()
{
    static P2pCreateGroupState instance;
    return &instance;
}

P2pCreateGroupState::P2pCreateGroupState() : timer_("P2pCreateGroup", TIMER_TIMEOUT) { }

void P2pCreateGroupState::Enter(const std::shared_ptr<P2pOperation> &operation)
{
    timer_.Setup();
    operation_ = operation;
    operation_->timerId_ = timer_.Register(
        [this]() {
            std::thread thread(&P2pCreateGroupState::OnTimeout, this);
            thread.detach();
        },
        CREATE_GROUP_TIMEOUT_MS, true);
}

void P2pCreateGroupState::Exit()
{
    timer_.Shutdown();
}

int P2pCreateGroupState::CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "push to pending queue");
    P2pEntity::GetInstance().PushOperation(operation);
    return SOFTBUS_OK;
}

int P2pCreateGroupState::Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "not support");
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pCreateGroupState::DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "not support");
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pCreateGroupState::RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "not support");
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

void P2pCreateGroupState::OnP2pStateChangeEvent(P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    P2pOperationResult result;
    if (state == P2P_STATE_STARTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "state is P2P_STATE_STARTED");
    } else {
        if (operation_ != nullptr) {
            timer_.Unregister(operation_->timerId_);
            result.errorCode_ = SOFTBUS_CONN_P2P_CONNECT_STATE_WIFI_STATE_NOT_STARTED;
            operation_->promise_.set_value(result);
        }
        ChangeState(P2pUnavailableState::Instance(), nullptr);
    }
}

void P2pCreateGroupState::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    P2pEntity::GetInstance().Lock();
    if (operation_ == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "operation is null");
        P2pEntity::GetInstance().Unlock();
        return;
    }
    timer_.Unregister(operation_->timerId_);
    P2pOperationResult result;
    if (info.connectState == P2P_DISCONNECTED) {
        result.errorCode_ = SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION;
        CONN_LOGE(CONN_WIFI_DIRECT, "create group call event failed, error=%{public}d", result.errorCode_);
    } else {
        P2pEntity::GetInstance().currentFrequency_ = groupInfo->frequency;
        result.errorCode_ = SOFTBUS_OK;
    }
    ChangeState(P2pAvailableState::Instance(), nullptr);
    operation_->promise_.set_value(result);
    operation_ = nullptr;
    P2pEntity::GetInstance().Unlock();
}

void P2pCreateGroupState::OnTimeout()
{
    P2pEntity::GetInstance().Lock();
    CONN_LOGE(CONN_WIFI_DIRECT, "timeout");
    if (operation_ == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "operation is nullptr");
        P2pEntity::GetInstance().Unlock();
        return;
    }
    ChangeState(P2pAvailableState::Instance(), nullptr);
    operation_->promise_.set_value(P2pOperationResult(static_cast<int>(SOFTBUS_CONN_CREATE_GROUP_TIMEOUT)));
    operation_ = nullptr;
    P2pEntity::GetInstance().Unlock();
}
} // namespace OHOS::SoftBus