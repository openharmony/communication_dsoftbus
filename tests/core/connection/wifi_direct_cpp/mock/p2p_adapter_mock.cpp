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

#include "p2p_adapter_mock.h"

#include <dlfcn.h>
#include <thread>
#include "bus_center_event.h"
#include "conn_log.h"
#include "softbus_adapter_socket.h"
#include "wifi_direct_init.h"

namespace OHOS::SoftBus {
P2pAdapterMock::P2pAdapterMock()
{
    mock.store(this);
}

P2pAdapterMock::~P2pAdapterMock()
{
    mock.store(nullptr);
}

int32_t P2pAdapter::GetChannel5GListIntArray(std::vector<int> &channels)
{
    return P2pAdapterMock::GetMock()->GetChannel5GListIntArray(channels);
}

bool P2pAdapter::IsWifiP2pEnabled()
{
    return P2pAdapterMock::GetMock()->IsWifiP2pEnabled();
}

std::string P2pAdapter::GetInterfaceCoexistCap()
{
    return P2pAdapterMock::GetMock()->GetInterfaceCoexistCap();
}

int32_t P2pAdapter::GetStationFrequency()
{
    return P2pAdapterMock::GetMock()->GetStationFrequency();
}

int32_t P2pAdapter::P2pCreateGroup(const CreateGroupParam &param)
{
    return P2pAdapterMock::GetMock()->P2pCreateGroup(param);
}

int32_t P2pAdapter::P2pConnectGroup(const ConnectParam &param)
{
    return P2pAdapterMock::GetMock()->P2pConnectGroup(param);
}

int32_t P2pAdapter::P2pShareLinkReuse()
{
    return P2pAdapterMock::GetMock()->P2pShareLinkReuse();
}

int32_t P2pAdapter::DestroyGroup(const DestroyGroupParam &param)
{
    return P2pAdapterMock::GetMock()->DestroyGroup(param);
}

int32_t P2pAdapter::P2pShareLinkRemoveGroup(const DestroyGroupParam &param)
{
    return P2pAdapterMock::GetMock()->P2pShareLinkRemoveGroup(param);
}
 int32_t P2pAdapter::GetStationFrequencyWithFilter()
{
    return P2pAdapterMock::GetMock()->GetStationFrequencyWithFilter();
}

int32_t P2pAdapter::GetRecommendChannel()
{
    return P2pAdapterMock::GetMock()->GetRecommendChannel();
}

int32_t P2pAdapter::GetSelfWifiConfigInfo(std::string &config)
{
    return P2pAdapterMock::GetMock()->GetSelfWifiConfigInfo(config);
}

int32_t P2pAdapter::SetPeerWifiConfigInfo(const std::string &config)
{
    return P2pAdapterMock::GetMock()->SetPeerWifiConfigInfo(config);
}

int32_t P2pAdapter::GetGroupInfo(WifiDirectP2pGroupInfo &groupInfoOut)
{
    return P2pAdapterMock::GetMock()->GetGroupInfo(groupInfoOut);
}

int32_t P2pAdapter::GetGroupConfig(std::string &groupConfigString)
{
    return P2pAdapterMock::GetMock()->GetGroupConfig(groupConfigString);
}

int32_t P2pAdapter::GetIpAddress(std::string &ipString)
{
    return P2pAdapterMock::GetMock()->GetIpAddress(ipString);
}

std::string P2pAdapter::GetMacAddress()
{
    return P2pAdapterMock::GetMock()->GetMacAddress();
}

int32_t P2pAdapter::GetDynamicMacAddress(std::string &macString)
{
    return P2pAdapterMock::GetMock()->GetDynamicMacAddress(macString);
}

int32_t P2pAdapter::RequestGcIp(const std::string &macString, std::string &ipString)
{
    return P2pAdapterMock::GetMock()->RequestGcIp(macString, ipString);
}

int32_t P2pAdapter::P2pConfigGcIp(const std::string &interface, const std::string &ip)
{
    return P2pAdapterMock::GetMock()->P2pConfigGcIp(interface, ip);
}

int32_t P2pAdapter::SetPeerWifiConfigInfoV2(const uint8_t *cfg, size_t size)
{
    return P2pAdapterMock::GetMock()->SetPeerWifiConfigInfoV2(cfg, size);
}

bool P2pAdapter::IsWideBandSupported()
{
    return P2pAdapterMock::GetMock()->IsWideBandSupported();
}

bool P2pAdapter::IsWifiEnable()
{
    return P2pAdapterMock::GetMock()->IsWifiEnable();
}

bool P2pAdapter::IsWifiConnected()
{
    return P2pAdapterMock::GetMock()->IsWifiConnected();
}

void P2pAdapter::Register(const GetCoexConflictCodeHook &coexConflictor)
{
    return P2pAdapterMock::GetMock()->Register(coexConflictor);
}

int P2pAdapter::GetCoexConflictCode(const char *ifName, int32_t channelId)
{
    return P2pAdapterMock::GetMock()->GetCoexConflictCode(ifName, channelId);
}

int P2pAdapter::GetApChannel()
{
    return P2pAdapterMock::GetMock()->GetApChannel();
}

int32_t P2pAdapter::GetP2pGroupFrequency()
{
    return P2pAdapterMock::GetMock()->GetP2pGroupFrequency();
}

void P2pAdapter::RegisterFastWakeUp(const FastWakeUpHook &fastWakeUp)
{
    return P2pAdapterMock::GetMock()->RegisterFastWakeUp(fastWakeUp);
}

int32_t P2pAdapter::FastWakeUp(const std::string &remoteMac, int32_t level)
{
    return P2pAdapterMock::GetMock()->FastWakeUp(remoteMac, level);
}
} // namespace OHOS::SoftBus
// namespace OHOS::SoftBus
