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

#ifndef P2P_ADAPTER_MOCK_H
#define P2P_ADAPTER_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include "adapter/p2p_adapter.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
class P2pAdapterMock {
public:
    static P2pAdapterMock *GetMock()
    {
        return mock.load();
    }

    P2pAdapterMock();
    ~P2pAdapterMock();

    MOCK_METHOD(int32_t, GetChannel5GListIntArray, (std::vector<int> &));
    MOCK_METHOD(bool, IsWifiP2pEnabled, ());
    MOCK_METHOD(std::string, GetInterfaceCoexistCap, ());
    MOCK_METHOD(int32_t, GetStationFrequency, ());
    MOCK_METHOD(int32_t, P2pCreateGroup, (const P2pAdapter::CreateGroupParam &));
    MOCK_METHOD(int32_t, P2pConnectGroup, (const P2pAdapter::ConnectParam &));
    MOCK_METHOD(int32_t, P2pShareLinkReuse, ());
    MOCK_METHOD(int32_t, DestroyGroup, (const P2pAdapter::DestroyGroupParam &));
    MOCK_METHOD(int32_t, P2pShareLinkRemoveGroup, (const P2pAdapter::DestroyGroupParam &));
    MOCK_METHOD(int32_t, GetStationFrequencyWithFilter, ());
    MOCK_METHOD(int32_t, GetRecommendChannel, ());
    MOCK_METHOD(int32_t, GetSelfWifiConfigInfo, (std::string &));
    MOCK_METHOD(int32_t, SetPeerWifiConfigInfo, (const std::string &));
    MOCK_METHOD(int32_t, GetGroupInfo, (P2pAdapter::WifiDirectP2pGroupInfo &));
    MOCK_METHOD(int32_t, GetGroupConfig, (std::string &));
    MOCK_METHOD(int32_t, GetIpAddress, (std::string &));
    MOCK_METHOD(std::string, GetMacAddress, ());
    MOCK_METHOD(int32_t, GetDynamicMacAddress, (std::string &));
    MOCK_METHOD(int32_t, RequestGcIp, (const std::string &, std::string &));
    MOCK_METHOD(int32_t, P2pConfigGcIp, (const std::string &, const std::string &));
    MOCK_METHOD(int32_t, SetPeerWifiConfigInfoV2, (const uint8_t *, size_t));
    MOCK_METHOD(int32_t, IsWideBandSupported, ());
    MOCK_METHOD(int32_t, IsWifiEnable, ());
    MOCK_METHOD(int32_t, IsWifiConnected, ());
    using GetCoexConflictCodeHook = std::function<int(const char *, int32_t)>;
    MOCK_METHOD(void, Register, (const GetCoexConflictCodeHook &));
    MOCK_METHOD(int, GetCoexConflictCode, (const char *, int32_t));
    using FastWakeUpHook = std::function<int32_t(const std::string &, int32_t)>;
    MOCK_METHOD(void, RegisterFastWakeUp, (const FastWakeUpHook &));
    MOCK_METHOD(int32_t, FastWakeUp, (const std::string &, int32_t));
    MOCK_METHOD(int, GetApChannel, ());
    MOCK_METHOD(int32_t, GetP2pGroupFrequency, ());

private:
    static inline std::atomic<P2pAdapterMock *> mock = nullptr;
};

} // namespace OHOS::SoftBus
#endif // WIFI_DIRECT_MOCK_H
