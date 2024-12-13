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
#include "softbus_adapter_crypto.h"
#include "utils/wifi_direct_anonymous.h"
#include "data/interface_manager.h"
#include "data/link_manager.h"

namespace OHOS::SoftBus {
static constexpr int IP_SUFFIX_RANGE = 253;
static constexpr int GC_IP_SUFFIX_START = 2;
static constexpr int MAX_CALCULATE_GC_IP_COUNT = 5;

P2pConnectState *P2pConnectState::Instance()
{
    static P2pConnectState instance;
    return &instance;
}

P2pConnectState::P2pConnectState() : timer_("P2pConnect", TIMER_TIMEOUT) { }

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
            std::thread thread(&P2pConnectState::OnTimeout, this);
            thread.detach();
        },
        outTime, true);
}

void P2pConnectState::Exit()
{
    timer_.Shutdown();
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
        if (operation_ != nullptr) {
            timer_.Unregister(operation_->timerId_);
            result.errorCode_ = SOFTBUS_CONN_P2P_CONNECT_STATE_WIFI_STATE_NOT_STARTED;
            operation_->promise_.set_value(result);
        }
        ChangeState(P2pUnavailableState::Instance(), nullptr);
    }
}

std::string P2pConnectState::CalculateGcIp(const std::string &goIpAddr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(!goIpAddr.empty(), "", CONN_WIFI_DIRECT, "go ip is empty");
    auto lastDotPos = goIpAddr.find_last_of('.');
    CONN_CHECK_AND_RETURN_RET_LOGE(
        lastDotPos != std::string::npos, "", CONN_WIFI_DIRECT, "not find last dot of go ip addr");
    auto goIpSuffix = std::stoi(goIpAddr.substr(lastDotPos + 1));
    int gcIpSuffix = 0;
    int count = 0;
    do {
        gcIpSuffix = static_cast<int>(SoftBusCryptoRand() % IP_SUFFIX_RANGE + GC_IP_SUFFIX_START);
        count++;
    } while (gcIpSuffix == goIpSuffix && count < MAX_CALCULATE_GC_IP_COUNT);
    CONN_CHECK_AND_RETURN_RET_LOGE(gcIpSuffix != goIpSuffix, "", CONN_WIFI_DIRECT, "goIp is equal to gcIp");
    return goIpAddr.substr(0, lastDotPos + 1) + std::to_string(gcIpSuffix);
}

void P2pConnectState::PreprocessP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    if (info.connectState != P2pConnectionState::P2P_CONNECTED) {
        return;
    }
    if (groupInfo == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "group info is null, skip config ip");
        return;
    }
    P2pEntity::GetInstance().Lock();
    auto operation = std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation_);
    if (operation == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "operation is null");
        P2pEntity::GetInstance().Unlock();
        return;
    }
    if (operation->content_.isNeedDhcp) {
        std::string localIpStr;
        if (P2pAdapter::GetIpAddress(localIpStr) == SOFTBUS_OK) {
            P2pEntity::GetInstance().Unlock();
            return;
        }
        localIpStr = CalculateGcIp(operation->content_.goIp);
        if (localIpStr.empty()) {
            CONN_LOGE(CONN_WIFI_DIRECT, "gc ip is empty");
            P2pEntity::GetInstance().Unlock();
            return;
        }
        operation->content_.gcIp = localIpStr;
        CONN_LOGI(CONN_WIFI_DIRECT, "calculated gc ip %{public}s", WifiDirectAnonymizeIp(localIpStr).c_str());
    }
    auto ret = P2pAdapter::P2pConfigGcIp(groupInfo->interface, operation->content_.gcIp);
    P2pEntity::GetInstance().Unlock();
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "config gc ip failed, error=%{public}d", ret);
}

void P2pConnectState::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    P2pEntity::GetInstance().Lock();
    P2pAdapter::WifiDirectP2pGroupInfo ignore {};
    auto ret = P2pAdapter::GetGroupInfo(ignore);
    if (operation_ == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "operation is null");
        P2pEntity::GetInstance().Unlock();
        return;
    }
    timer_.Unregister(operation_->timerId_);
    P2pOperationResult result;
    if (ret != SOFTBUS_OK || info.connectState == P2P_DISCONNECTED) {
        result.errorCode_ = SOFTBUS_CONN_P2P_ABNORMAL_DISCONNECTION;
        CONN_LOGE(CONN_WIFI_DIRECT, "connect call event failed, error=%{public}d", result.errorCode_);
    } else {
        result.errorCode_ = SOFTBUS_OK;
    }
    ChangeState(P2pAvailableState::Instance(), nullptr);
    operation_->promise_.set_value(result);
    operation_ = nullptr;
    P2pEntity::GetInstance().Unlock();
}

bool P2pConnectState::DetectDhcpTimeout()
{
    auto operation = std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation_);
    if (operation == nullptr || !operation->content_.isNeedDhcp) {
        return false;
    }
    P2pAdapter::WifiDirectP2pGroupInfo groupInfo {};
    if (P2pAdapter::GetGroupInfo(groupInfo) != SOFTBUS_OK) {
        return false;
    }
    return true;
}

void P2pConnectState::OnTimeout()
{
    P2pEntity::GetInstance().Lock();
    CONN_LOGE(CONN_WIFI_DIRECT, "timeout");
    if (operation_ == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "operation is nullptr");
        P2pEntity::GetInstance().Unlock();
        return;
    }

    SoftBusErrNo resultCode = SOFTBUS_CONN_CONNECT_GROUP_TIMEOUT;
    if (DetectDhcpTimeout()) {
        resultCode = SOFTBUS_CONN_CONNECT_DHCP_TIMEOUT;
    }
    ChangeState(P2pAvailableState::Instance(), nullptr);
    operation_->promise_.set_value(P2pOperationResult(static_cast<int>(resultCode)));
    operation_ = nullptr;
    P2pEntity::GetInstance().Unlock();
}
} // namespace OHOS::SoftBus