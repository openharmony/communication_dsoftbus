/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "wifi_direct_p2p_adapter_mock.h"
#include "wifi_direct_p2p_adapter.h"
#include "softbus_error_code.h"

static int32_t SetPeerWifiConfigInfo(const char *config)
{
    return WifiDirectP2pAdapterMock::GetMock()->SetPeerWifiConfigInfo(config);
}

static int32_t P2pShareLinkRemoveGroup(const char *interface)
{
    return WifiDirectP2pAdapterMock::GetMock()->P2pShareLinkRemoveGroup(interface);
}

static int32_t P2pShareLinkReuse(void)
{
    return WifiDirectP2pAdapterMock::GetMock()->P2pShareLinkReuse();
}

bool IsWifiConnected(void)
{
    return WifiDirectP2pAdapterMock::GetMock()->IsWifiConnected();
}

bool IsWifiApEnabled(void)
{
    return WifiDirectP2pAdapterMock::GetMock()->IsWifiApEnabled();
}

static bool IsWideBandSupported(void)
{
    return WifiDirectP2pAdapterMock::GetMock()->IsWideBandSupported();
}

static int32_t GetStationFrequency(void)
{
    return WifiDirectP2pAdapterMock::GetMock()->GetStationFrequency();
}

static int32_t GetSelfWifiConfigInfo(uint8_t *config, size_t *configSize)
{
    return WifiDirectP2pAdapterMock::GetMock()->GetSelfWifiConfigInfo(config, configSize);
}

static int32_t RequestGcIp(const char *macString, char *ipString, size_t ipStringSize)
{
    return WifiDirectP2pAdapterMock::GetMock()->RequestGcIp(macString, ipString, ipStringSize);
}

static bool IsThreeVapConflict()
{
    return WifiDirectP2pAdapterMock::GetMock()->IsThreeVapConflict();
}

static int32_t GetSelfWifiConfigInfoV2(uint8_t *cfg, size_t *size)
{
    return WifiDirectP2pAdapterMock::GetMock()->GetSelfWifiConfigInfoV2(cfg, size);
}

static int32_t GetInterfaceCoexistCap(char **cap)
{
    return WifiDirectP2pAdapterMock::GetMock()->GetInterfaceCoexistCap(cap);
}

static int32_t GetMacAddress(char *macString, size_t macStringSize)
{
    return WifiDirectP2pAdapterMock::GetMock()->GetMacAddress(macString, macStringSize);
}

static int32_t GetChannel5GListIntArray(int32_t *array, size_t *size)
{
    *size = 0;
    return WifiDirectP2pAdapterMock::GetMock()->GetChannel5GListIntArray(array, size);
}

static bool IsWifiP2pEnabled()
{
    return WifiDirectP2pAdapterMock::GetMock()->IsWifiP2pEnabled();
}

static WifiDirectP2pAdapter g_adapter = {
    .requestGcIp = RequestGcIp,
    .isThreeVapConflict = IsThreeVapConflict,
    .getSelfWifiConfigInfoV2 = GetSelfWifiConfigInfoV2,
    .getInterfaceCoexistCap = GetInterfaceCoexistCap,
    .getMacAddress = GetMacAddress,
    .getChannel5GListIntArray = GetChannel5GListIntArray,
    .isWifiP2pEnabled = IsWifiP2pEnabled,
    .getSelfWifiConfigInfo = GetSelfWifiConfigInfo,
    .getStationFrequency = GetStationFrequency,
    .isWideBandSupported = IsWideBandSupported,
    .isWifiConnected = IsWifiConnected,
    .isWifiApEnabled = IsWifiApEnabled,
    .shareLinkReuse = P2pShareLinkReuse,
    .shareLinkRemoveGroupSync = P2pShareLinkRemoveGroup,
    .shareLinkRemoveGroupAsync = P2pShareLinkRemoveGroup,
    .setPeerWifiConfigInfo = SetPeerWifiConfigInfo,
};

struct WifiDirectP2pAdapter* GetWifiDirectP2pAdapter(void)
{
    return &g_adapter;
}

WifiDirectP2pAdapterMock* WifiDirectP2pAdapterMock::mock = nullptr;

WifiDirectP2pAdapterMock::WifiDirectP2pAdapterMock()
{
    mock = this;
}

WifiDirectP2pAdapterMock::~WifiDirectP2pAdapterMock()
{
    mock = nullptr;
}

int32_t WifiDirectP2pAdapterMock::ActionOfRequestGcIp(const char *macString, char *ipString, size_t ipStringSize)
{
    return strcpy_s(ipString, ipStringSize, "192.168.43.2") == EOK ? SOFTBUS_OK : SOFTBUS_ERR;
}

bool WifiDirectP2pAdapterMock::ActionOfIsThreeVapConfict()
{
    return true;
}