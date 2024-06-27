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

#include "p2p_connect_state.h"
#include "common_timer_errors.h"
#include "conn_log.h"
#include "p2p_entity.h"
#include "p2p_operation_result.h"
#include "p2p_unavailable_state.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
P2pConnectState *P2pConnectState::Instance()
{
    static P2pConnectState instance;
    return &instance;
}

P2pConnectState::P2pConnectState() : timer_("P2pConnect") { }

void P2pConnectState::Enter(const std::shared_ptr<P2pOperation> &operation)
{
    timer_.Setup();
    operation_ = operation;
    int outTime = CONNECT_TIMEOUT_MS;
    auto connectOp = std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation);
    if (connectOp->content_.isNeedDhcp) {
        outTime = CONNECT_TIMEOUT_DHCP_MS;
    }
    operation_->timerId_ = timer_.Register(
        [this]() {
            CONN_LOGE(CONN_WIFI_DIRECT, "timeout");
            P2pOperationResult result {};
            result.errorCode_ = SOFTBUS_TIMOUT;
            operation_->promise_.set_value(result);
            ChangeState(P2pAvailableState::Instance(), nullptr);
        },
        outTime, true);
}

void P2pConnectState::Exit()
{
    timer_.Shutdown(false);
    operation_ = nullptr;
}

int P2pConnectState::CreateGroup(const std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "push to pending queue");
    P2pEntity::GetInstance().PushOperation(operation);
    return SOFTBUS_OK;
}

int P2pConnectState::Connect(const std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "push to pending queue");
    P2pEntity::GetInstance().PushOperation(operation);
    return SOFTBUS_OK;
}

int P2pConnectState::DestroyGroup(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "not support");
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

int P2pConnectState::RemoveLink(const std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> &operation)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "not support");
    return SOFTBUS_CONN_NOT_SUPPORT_FAILED;
}

void P2pConnectState::OnP2pStateChangeEvent(P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    P2pOperationResult result;
    if (state == P2P_STATE_STARTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "state is P2P_STATE_STARTED");
    } else {
        timer_.Unregister(operation_->timerId_);
        if (operation_ != nullptr) {
            result.errorCode_ = SOFTBUS_CONN_P2P_CONNECT_STATE_WIFI_STATE_NOT_STARTED;
            operation_->promise_.set_value(result);
        }
        ChangeState(P2pUnavailableState::Instance(), nullptr);
    }
}

void P2pConnectState::PreprocessP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    if (info.connectState != P2pConnectionState::P2P_CONNECTED) {
        return;
    }
    auto operation = std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation_);
    if (operation->content_.isNeedDhcp) {
        return;
    }
    if (groupInfo == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "group info is null, skip config ip");
        return;
    }
    auto ret = P2pAdapter::P2pConfigGcIp(groupInfo->interface, operation->content_.gcIp);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "config gc ip failed, error=%d", ret);
}

void P2pConnectState::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    P2pAdapter::WifiDirectP2pGroupInfo ignore {};
    auto ret = P2pAdapter::GetGroupInfo(ignore);

    timer_.Unregister(operation_->timerId_);
    P2pOperationResult result;
    if (ret != SOFTBUS_OK || info.connectState == P2P_DISCONNECTED) {
        result.errorCode_ = SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION;
        CONN_LOGE(CONN_WIFI_DIRECT, "connect call event failed, error=%d", result.errorCode_);
    } else {
        auto connectOp = std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation_);
        result.errorCode_ = SOFTBUS_OK;
    }
    operation_->promise_.set_value(result);
    ChangeState(P2pAvailableState::Instance(), nullptr);
}
} // namespace OHOS::SoftBus