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

#include "p2p_entity_mock.h"

#include <dlfcn.h>
#include <thread>
#include "bus_center_event.h"
#include "conn_log.h"
#include "entity/p2p_entity.h"
#include "softbus_adapter_socket.h"
#include "wifi_direct_init.h"

namespace OHOS::SoftBus {
P2pEntityMock::P2pEntityMock()
{
    mock.store(this);
}

P2pEntityMock::~P2pEntityMock()
{
    mock.store(nullptr);
}

P2pEntity::P2pEntity() : timer_("P2pEntity") { }

P2pEntity& P2pEntity::GetInstance()
{
    static P2pEntity instance;
    return instance;
}

void P2pEntity::Init()
{
    return P2pEntityMock::GetMock()->Init();
}

void P2pEntity::DisconnectLink(const std::string &remoteMac)
{
    return P2pEntityMock::GetMock()->DisconnectLink(remoteMac);
}

void P2pEntity::DestroyGroupIfNeeded()
{
    return P2pEntityMock::GetMock()->DestroyGroupIfNeeded();
}

P2pOperationResult P2pEntity::CreateGroup(const P2pCreateGroupParam &param)
{
    return P2pEntityMock::GetMock()->CreateGroup(param);
}

P2pOperationResult P2pEntity::Connect(const P2pConnectParam &param)
{
    return P2pEntityMock::GetMock()->Connect(param);
}

P2pOperationResult P2pEntity::DestroyGroup(const P2pDestroyGroupParam &param)
{
    return P2pEntityMock::GetMock()->DestroyGroup(param);
}

P2pOperationResult P2pEntity::Disconnect(const P2pDestroyGroupParam &param)
{
    return P2pEntityMock::GetMock()->Disconnect(param);
}

int32_t P2pEntity::ReuseLink()
{
    return P2pEntityMock::GetMock()->ReuseLink();
}

void P2pEntity::NotifyNewClientJoining(const std::string &remoteMac, int waitTime)
{
    return P2pEntityMock::GetMock()->NotifyNewClientJoining(remoteMac, waitTime);
}

void P2pEntity::CancelNewClientJoining(const std::string &remoteMac)
{
    return P2pEntityMock::GetMock()->CancelNewClientJoining(remoteMac);
}

void P2pEntity::RemoveNewClientJoining(const std::string &remoteMac)
{
    return P2pEntityMock::GetMock()->RemoveNewClientJoining(remoteMac);
}

void P2pEntity::ClearJoiningClient()
{
    return P2pEntityMock::GetMock()->ClearJoiningClient();
}

size_t P2pEntity::GetJoiningClientCount()
{
    return P2pEntityMock::GetMock()->GetJoiningClientCount();
}


void P2pEntity::ChangeState(P2pEntityState *state, const std::shared_ptr<P2pOperation> &operation)
{
    return P2pEntityMock::GetMock()->ChangeState(state, operation);
}


void P2pEntity::OnP2pStateChangeEvent(P2pState state)
{
    return P2pEntityMock::GetMock()->OnP2pStateChangeEvent(state);
}

void P2pEntity::OnP2pConnectionChangeEvent(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    return P2pEntityMock::GetMock()->OnP2pConnectionChangeEvent(info, groupInfo);
}


void P2pEntity::PushOperation(const std::shared_ptr<P2pOperation> &operation)
{
    return P2pEntityMock::GetMock()->PushOperation(operation);
}

void P2pEntity::ExecuteNextOperation()
{
    return P2pEntityMock::GetMock()->ExecuteNextOperation();
}

bool P2pEntity::HasPendingOperation()
{
    return P2pEntityMock::GetMock()->HasPendingOperation();
}

void P2pEntity::ClearPendingOperation()
{
    return P2pEntityMock::GetMock()->ClearPendingOperation();
}


void P2pEntity::UpdateInterfaceManager(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    return P2pEntityMock::GetMock()->UpdateInterfaceManager(info, groupInfo);
}

void P2pEntity::UpdateLinkManager(
    const WifiP2pLinkedInfo &info, const std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> &groupInfo)
{
    return P2pEntityMock::GetMock()->UpdateLinkManager(info, groupInfo);
}


void P2pEntity::UpdateInterfaceManagerWhenStateChanged(P2pState state)
{
    return P2pEntityMock::GetMock()->UpdateInterfaceManagerWhenStateChanged(state);
}

void P2pEntity::Listener(BroadcastReceiverAction action, const struct BroadcastParam &param)
{
    return P2pEntityMock::GetMock()->Listener(action, param);
}

void Dump(P2pEntitySnapshot &snapshot)
{
    return P2pEntityMock::GetMock()->Dump(snapshot);
}
} // namespace OHOS::SoftBus
// namespace OHOS::SoftBus
