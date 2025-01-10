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
#include "p2p_entity.h"

#include <algorithm>
#include <future>

#include "conn_log.h"
#include "softbus_error_code.h"

#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "p2p_available_state.h"
#include "p2p_broadcast_receiver.h"
#include "utils/wifi_direct_anonymous.h"
#include "wifi_direct_scheduler_factory.h"

namespace OHOS::SoftBus {
using InterfaceType = InterfaceInfo::InterfaceType;

static void P2pStateChangeCallback(P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "state=%{public}d", state);
    BroadcastParam param {};
    param.p2pState = state;
    P2pBroadcast::GetInstance()->DispatchWorkHandler(BroadcastReceiverAction::WIFI_P2P_STATE_CHANGED_ACTION, param);
}

static void P2pConnectionChangeCallback(const WifiP2pLinkedInfo info)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ConnectionState=%{public}d, isGroupOwner=%{public}d", info.connectState,
        info.isP2pGroupOwner);
    BroadcastParam param;
    param.p2pLinkInfo = info;
    param.groupInfo = std::make_shared<P2pAdapter::WifiDirectP2pGroupInfo>();
    auto ret = P2pAdapter::GetGroupInfo(*(param.groupInfo));
    if (ret != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "get group info failed, error=%{public}d", ret);
        param.groupInfo = nullptr;
    }
    P2pBroadcast::GetInstance()->DispatchWorkHandler(
        BroadcastReceiverAction::WIFI_P2P_CONNECTION_CHANGED_ACTION, param);
}

void P2pEntity::Listener(BroadcastReceiverAction action, const struct BroadcastParam &param)
{
    if (action == BroadcastReceiverAction::WIFI_P2P_STATE_CHANGED_ACTION) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_P2P_STATE_CHANGED_ACTION");
        P2pEntity::GetInstance().OnP2pStateChangeEvent(param.p2pState);
    } else if (action == BroadcastReceiverAction::WIFI_P2P_CONNECTION_CHANGED_ACTION) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_P2P_CONNECTION_CHANGED_ACTION");
        P2pEntity::GetInstance().OnP2pConnectionChangeEvent(param.p2pLinkInfo, param.groupInfo);
    }
}

void P2pEntity::Init()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    BroadcastReceiverAction actions[2] = {
        BroadcastReceiverAction::WIFI_P2P_STATE_CHANGED_ACTION,
        BroadcastReceiverAction::WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };
    P2pBroadcast::GetInstance()->RegisterBroadcastListener(
        actions, ARRAY_SIZE(actions), "P2pEntity", ListenerPriority::LISTENER_PRIORITY_HIGH, P2pEntity::Listener);
    RegisterP2pStateChangedCallback(P2pStateChangeCallback);
    RegisterP2pConnectionChangedCallback(P2pConnectionChangeCallback);

    /* The P2P may report the event through callback early, and softbus register the callback later.
     * Therefore, after theregistration is successful, check wethere the P2P is enable. */
    InterfaceManager::GetInstance().InitInterface(InterfaceInfo::InterfaceType::P2P);
}

P2pEntity::P2pEntity() : timer_("P2pEntity")
{
    state_ = P2pAvailableState::Instance();
}

void P2pEntity::DisconnectLink(const std::string &remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    P2pAdapter::WifiDirectP2pGroupInfo groupInfo {};
    auto ret = P2pAdapter::GetGroupInfo(groupInfo);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get group info failed");
    bool isNeedRemove = true;
    if (groupInfo.isGroupOwner) {
        if (groupInfo.clientDevices.size() > 1) {
            isNeedRemove = false;
        }
        if ((groupInfo.clientDevices.size() == 1 && remoteMac == groupInfo.clientDevices[0].address) ||
            groupInfo.clientDevices.size() == 0) {
            isNeedRemove = true;
        }
    }
    if (isNeedRemove) {
        P2pAdapter::DestroyGroupParam params;
        params.interface = IF_NAME_P2P;
        DestroyGroup(params);
    }
}

void P2pEntity::DestroyGroupIfNeeded() { };

P2pOperationResult P2pEntity::CreateGroup(const P2pCreateGroupParam &param)
{
    std::shared_ptr<P2pOperationWrapper<P2pCreateGroupParam>> operation;
    P2pOperationResult result;
    {
        std::lock_guard lock(operationLock_);
        operation = std::make_shared<P2pOperationWrapper<P2pCreateGroupParam>>(param, P2pOperationType::CREATE_GROUP);
        int ret = state_->CreateGroup(operation);
        if (ret != SOFTBUS_OK) {
            result.errorCode_ = ret;
            return result;
        }
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "wait to be done");
    return operation->promise_.get_future().get();
}

P2pOperationResult P2pEntity::Connect(const P2pConnectParam &param)
{
    std::shared_ptr<P2pOperationWrapper<P2pConnectParam>> operation;
    P2pOperationResult result;
    {
        std::lock_guard lock(operationLock_);
        operation = std::make_shared<P2pOperationWrapper<P2pConnectParam>>(param, P2pOperationType::CONNECT);
        int ret = state_->Connect(operation);
        result.errorCode_ = ret;
        if (ret != SOFTBUS_OK) {
            return result;
        }
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "wait to be done");
    return operation->promise_.get_future().get();
}

int32_t P2pEntity::ReuseLink()
{
    int32_t ret = P2pAdapter::P2pShareLinkReuse();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return ret;
}

static void SendClientJoinEvent(const std::string &remoteMac, int32_t result)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    std::string remoteDeviceId;
    auto success = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [&remoteDeviceId](InnerLink &link) {
        remoteDeviceId = link.GetRemoteDeviceId();
    });
    CONN_CHECK_AND_RETURN_LOGW(
        success, CONN_WIFI_DIRECT, "link not found, remote mac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());

    ClientJoinEvent event { result, remoteDeviceId, remoteMac };
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

void P2pEntity::NotifyNewClientJoining(const std::string &remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    CONN_CHECK_AND_RETURN_LOGW(!remoteMac.empty(), CONN_WIFI_DIRECT, "remote mac is empty, skip");
    std::lock_guard lock(joiningClientsLock_);
    if (joiningClients_.empty()) {
        timer_.Setup();
    }

    auto timerId = timer_.Register(
        [this, remoteMac]() {
            CONN_LOGI(CONN_WIFI_DIRECT, "enter");
            std::lock_guard lock(joiningClientsLock_);
            SendClientJoinEvent(remoteMac, SOFTBUS_CONN_PV1_CONNECT_GROUP_TIMEOUT);
            joiningClients_.erase(remoteMac);
            if (joiningClients_.empty()) {
                timer_.Shutdown(false);
            }
        },
        TIMEOUT_WAIT_CLIENT_JOIN_MS, true);
    joiningClients_[remoteMac] = timerId;
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s, joining client count=%{public}zu",
        WifiDirectAnonymizeMac(remoteMac).c_str(), joiningClients_.size());
}

void P2pEntity::CancelNewClientJoining(const std::string &remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    CONN_CHECK_AND_RETURN_LOGW(!remoteMac.empty(), CONN_WIFI_DIRECT, "remote mac is empty, skip");
    std::lock_guard lock(joiningClientsLock_);
    auto it = joiningClients_.find(remoteMac);
    if (it == joiningClients_.end()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s not exist, joining client count=%{public}zu",
            WifiDirectAnonymizeMac(remoteMac).c_str(), joiningClients_.size());
        return;
    }
    timer_.Unregister(it->second);
    joiningClients_.erase(it);
    if (joiningClients_.empty()) {
        timer_.Shutdown(false);
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s, joining client count=%{public}zu",
        WifiDirectAnonymizeMac(remoteMac).c_str(), joiningClients_.size());
}

void P2pEntity::RemoveNewClientJoining(const std::string &remoteMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    CONN_CHECK_AND_RETURN_LOGW(!remoteMac.empty(), CONN_WIFI_DIRECT, "remote mac is empty, skip");
    std::lock_guard lock(joiningClientsLock_);
    auto it = joiningClients_.find(remoteMac);
    if (it == joiningClients_.end()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s not exist, joining client count=%{public}zu",
            WifiDirectAnonymizeMac(remoteMac).c_str(), joiningClients_.size());
        return;
    }
    timer_.Unregister(it->second);
    SendClientJoinEvent(remoteMac, SOFTBUS_OK);
    joiningClients_.erase(it);
    if (joiningClients_.empty()) {
        timer_.Shutdown(false);
    }
}

void P2pEntity::ClearJoiningClient()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(joiningClientsLock_);
    if (joiningClients_.empty()) {
        return;
    }
    for (const auto &kv : joiningClients_) {
        timer_.Unregister(kv.second);
        SendClientJoinEvent(kv.first, SOFTBUS_CONN_P2P_CLEAR_JOIN_CLIENTS_FAILED);
    }
    joiningClients_.clear();
    timer_.Shutdown(false);
}

size_t P2pEntity::GetJoiningClientCount()
{
    std::lock_guard lock(joiningClientsLock_);
    return joiningClients_.size();
}

P2pOperationResult P2pEntity::Disconnect(const P2pDestroyGroupParam &param)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> operation = nullptr;
    P2pOperationResult result;
    int reuseCount = 0;
    {
        std::lock_guard lock(operationLock_);
        auto ret =
            InterfaceManager::GetInstance().ReadInterface(InterfaceType::P2P, [&reuseCount](const InterfaceInfo &info) {
                reuseCount = info.GetReuseCount();
                return SOFTBUS_OK;
            });
        if (ret != SOFTBUS_OK) {
            CONN_LOGI(CONN_WIFI_DIRECT, "get reuse cnt from interface info failed, error=%{public}d", ret);
            result.errorCode_ = ret;
            return result;
        }

        if (reuseCount > 1) {
            CONN_LOGI(CONN_WIFI_DIRECT, "shareLinkRemoveGroupSync");
            result.errorCode_ = P2pAdapter::P2pShareLinkRemoveGroup(param);
            return result;
        }

        operation = std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param, P2pOperationType::DESTROY_GROUP);
        ret = state_->RemoveLink(operation);
        result.errorCode_ = ret;
        if (ret != SOFTBUS_OK) {
            return result;
        }
    }
    return operation->promise_.get_future().get();
}

P2pOperationResult P2pEntity::DestroyGroup(const P2pDestroyGroupParam &param)
{
    std::shared_ptr<P2pOperationWrapper<P2pDestroyGroupParam>> operation;
    P2pOperationResult result;
    {
        std::lock_guard lock(operationLock_);
        operation = std::make_shared<P2pOperationWrapper<P2pDestroyGroupParam>>(param, P2pOperationType::DESTROY_GROUP);
        int ret = state_->DestroyGroup(operation);
        result.errorCode_ = ret;
        if (ret != SOFTBUS_OK) {
            return result;
        }
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "wait to be done");
    return operation->promise_.get_future().get();
}

void P2pEntity::ChangeState(P2pEntityState *state, const std::shared_ptr<P2pOperation> &operation)
{
    std::lock_guard lock(operationLock_);
    state_->Exit();
    CONN_LOGI(CONN_WIFI_DIRECT, "%{public}s ==> %{public}s", state_->GetName().c_str(), state->GetName().c_str());
    state_ = state;
    state_->Enter(operation);
}

void P2pEntity::PushOperation(const std::shared_ptr<P2pOperation> &operation)
{
    std::lock_guard lock(pendingOperationLock_);
    pendingOperations_.push(operation);
}

void P2pEntity::ExecuteNextOperation()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    std::shared_ptr<P2pOperation> operation;
    {
        std::lock_guard lock(pendingOperationLock_);
        if (pendingOperations_.empty()) {
            return;
        }
        operation = pendingOperations_.front();
        pendingOperations_.pop();
    }

    int ret = SOFTBUS_OK;
    P2pOperationResult result {};
    switch (operation->type_) {
        case P2pOperationType::CREATE_GROUP:
            ret = state_->CreateGroup(std::dynamic_pointer_cast<P2pOperationWrapper<P2pCreateGroupParam>>(operation));
            break;
        case P2pOperationType::CONNECT:
            ret = state_->Connect(std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(operation));
            break;
        case P2pOperationType::DESTROY_GROUP:
            ret = state_->DestroyGroup(std::dynamic_pointer_cast<P2pOperationWrapper<P2pDestroyGroupParam>>(operation));
            break;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "operation type invalid");
    }

    if (ret != SOFTBUS_OK) {
        result.errorCode_ = ret;
        operation->promise_.set_value(result);
    }
}

bool P2pEntity::HasPendingOperation()
{
    std::lock_guard lock(pendingOperationLock_);
    return !pendingOperations_.empty();
}

void P2pEntity::ClearPendingOperation()
{
    std::lock_guard lock(pendingOperationLock_);
    P2pOperationResult result;
    result.errorCode_ = SOFTBUS_CONN_ENTITY_UNAVAILABLE;
    while (!pendingOperations_.empty()) {
        pendingOperations_.front()->promise_.set_value(result);
        pendingOperations_.pop();
    }
}

void P2pEntity::OnP2pStateChangeEvent(P2pState state)
{
    std::lock_guard lock(operationLock_);
    UpdateInterfaceManagerWhenStateChanged(state);
    WifiDirectUtils::SyncLnnInfoForP2p(WIFI_DIRECT_ROLE_NONE, P2pAdapter::GetMacAddress(), "");
    state_->OnP2pStateChangeEvent(state);
}

void P2pEntity::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    std::lock_guard lock(operationLock_);

    if (info.connectState == P2pConnectionState::P2P_DISCONNECTED) {
        currentFrequency_ = 0;
    }

    state_->PreprocessP2pConnectionChangeEvent(info, groupInfo);
    UpdateInterfaceManager(info, groupInfo);
    UpdateLinkManager(info, groupInfo);
    state_->OnP2pConnectionChangeEvent(info, groupInfo);
}

static void ResetInterfaceInfo(const std::string &localMac)
{
    int listenModule = -1;
    int listenPort = -1;
    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [&listenPort, &listenModule, localMac](InterfaceInfo &interface) {
            listenPort = interface.GetP2pListenPort();
            listenModule = interface.GetP2pListenModule();

            interface.SetConnectedDeviceCount(0);
            interface.SetRole(LinkInfo::LinkMode::NONE);
            interface.SetReuseCount(0);
            interface.SetP2pListenPort(0);
            interface.SetSsid("");
            interface.SetDynamicMac("");
            interface.SetPsk("");
            interface.SetCenter20M(0);
            interface.SetIpString(Ipv4Info());
            interface.SetP2pListenModule(-1);
            interface.SetBaseMac(localMac);
            return SOFTBUS_OK;
        });
    if (listenPort > 0) {
        AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_P2P, static_cast<ListenerModule>(listenModule));
    }
}

static void UpdateInterfaceInfo(
    const std::string &localMac, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "isGroupOwner=%{public}d, clientDeviceSize=%{public}zu", groupInfo->isGroupOwner,
        groupInfo->clientDevices.size());
    std::string groupConfig;
    if (groupInfo->isGroupOwner) {
        auto ret = P2pAdapter::GetGroupConfig(groupConfig);
        CONN_CHECK_AND_RETURN_LOGE(
            ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get group config failed, error=%{public}d", ret);
    }
    std::string dynamicMac;
    auto ret = P2pAdapter::GetDynamicMacAddress(dynamicMac);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get dynamic mac failed, error=%{public}d", ret);
    std::string ip;
    ret = P2pAdapter::GetIpAddress(ip);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "get ip failed, error=%{public}d", ret);
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "localIp=%{public}s", WifiDirectAnonymizeIp(ip).c_str());
    }

    InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [localMac, dynamicMac, ip, groupInfo, groupConfig](InterfaceInfo &interface) {
            interface.SetBaseMac(localMac);
            interface.SetDynamicMac(dynamicMac);
            if (!ip.empty()) {
                interface.SetIpString(Ipv4Info(ip));
            }
            interface.SetConnectedDeviceCount(groupInfo->clientDevices.size());
            interface.SetRole(groupInfo->isGroupOwner ? LinkInfo::LinkMode::GO : LinkInfo::LinkMode::GC);
            if (groupInfo->isGroupOwner) {
                interface.SetP2pGroupConfig(groupConfig);
            }
            return SOFTBUS_OK;
        });
}

void P2pEntity::UpdateInterfaceManager(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    auto localMac = P2pAdapter::GetMacAddress();
    if (info.connectState == P2pConnectionState::P2P_DISCONNECTED || groupInfo == nullptr) {
        ResetInterfaceInfo(localMac);
        return;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "p2p has group, update p2p interface info");
    UpdateInterfaceInfo(localMac, groupInfo);
}

static void UpdateInnerLink(const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo,
    const std::string &localMac)
{
    auto frequency = groupInfo->frequency;
    if (!groupInfo->isGroupOwner) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not group owner, groupOwnerMac=%{public}s",
            WifiDirectAnonymizeMac(groupInfo->groupOwner.address).c_str());
        LinkManager::GetInstance().ProcessIfPresent(groupInfo->groupOwner.address, [frequency, groupInfo, localMac]
            (InnerLink &link) {
                link.SetState(InnerLink::LinkState::CONNECTED);
                link.SetFrequency(frequency);
                link.SetRemoteDynamicMac(groupInfo->groupOwner.randomMac);
                link.SetLocalDynamicMac(localMac);
            });
        return;
    }
    std::string ip;
    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&ip](const InterfaceInfo &interface) {
        ip = interface.GetIpString().ToIpString();
        return SOFTBUS_OK;
    });
    for (const auto &client : groupInfo->clientDevices) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(client.address).c_str());
        LinkManager::GetInstance().ProcessIfPresent(client.address, [ip, frequency, client, localMac](InnerLink &link) {
            link.SetState(InnerLink::LinkState::CONNECTED);
            link.SetFrequency(frequency);
            link.SetLocalIpv4(ip);
            link.SetRemoteDynamicMac(client.randomMac);
            link.SetLocalDynamicMac(localMac);
        });
    }
    std::vector<std::string> invalidLinks;
    auto clients = groupInfo->clientDevices;
    LinkManager::GetInstance().ForEach([&invalidLinks, clients](const InnerLink &link) {
        if (link.GetLinkType() != InnerLink::LinkType::P2P) {
            return false;
        }
        if (link.GetState() == InnerLink::LinkState::CONNECTING) {
            return false;
        }
        if (std::none_of(clients.begin(), clients.end(), [&link](const P2pAdapter::WifiDirectP2pDeviceInfo &item) {
                return item.address == link.GetRemoteBaseMac();
            })) {
            invalidLinks.push_back(link.GetRemoteDeviceId());
        }
        // return false to range all link
        return false;
    });
    for (const auto &remoteDeviceId : invalidLinks) {
        LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::P2P, remoteDeviceId);
    }
}

void P2pEntity::UpdateLinkManager(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    if (info.connectState == P2pConnectionState::P2P_DISCONNECTED) {
        LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
        return;
    }
    CONN_CHECK_AND_RETURN_LOGE(groupInfo, CONN_WIFI_DIRECT, "groupInfo is null");
    std::string dynamicMac;
    auto ret = P2pAdapter::GetDynamicMacAddress(dynamicMac);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get dynamic mac failed, error=%{public}d", ret);
    UpdateInnerLink(groupInfo, dynamicMac);
}

void P2pEntity::UpdateInterfaceManagerWhenStateChanged(P2pState state)
{
    bool enable;
    std::string localMac;
    if (state != P2pState::P2P_STATE_STARTED) {
        enable = false;
    } else {
        localMac = P2pAdapter::GetMacAddress();
        enable = true;
    }

    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [enable, localMac](InterfaceInfo &interface) {
        interface.SetIsEnable(enable);
        interface.SetBaseMac(localMac);
        if (!enable) {
            interface.SetIpString(Ipv4Info());
        }
        return SOFTBUS_OK;
    });
}

void P2pEntity::Dump(P2pEntitySnapshot &snapshot)
{
    {
        std::lock_guard lock(operationLock_);
        snapshot.state_ = state_->GetName();
        snapshot.frequency_ = currentFrequency_;
    }
    std::map<std::string, uint32_t> joinClients;
    {
        std::lock_guard lock(joiningClientsLock_);
        std::string macString;
        for (const auto &client : joiningClients_) {
            macString += client.first + " ";
        }
        snapshot.joiningClients_ = macString;
    }
}
} // namespace OHOS::SoftBus
