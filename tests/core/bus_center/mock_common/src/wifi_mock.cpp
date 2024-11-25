/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "wifi_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_wifiInterface;

WifiInterfaceMock::WifiInterfaceMock()
{
    g_wifiInterface = reinterpret_cast<void *>(this);
}

WifiInterfaceMock::~WifiInterfaceMock()
{
    g_wifiInterface = nullptr;
}

static WifiInterface *GetWifiInterface()
{
    return reinterpret_cast<WifiInterfaceMock *>(g_wifiInterface);
}

extern "C" {
WifiErrorCode GetDeviceConfigs(WifiDeviceConfig *result, unsigned int *size)
{
    return GetWifiInterface()->GetDeviceConfigs(result, size);
}

WifiErrorCode ConnectToDevice(const WifiDeviceConfig *config)
{
    return GetWifiInterface()->ConnectToDevice(config);
}

WifiErrorCode Scan(void)
{
    return GetWifiInterface()->Scan();
}

WifiErrorCode RegisterWifiEvent(WifiEvent *event)
{
    return GetWifiInterface()->RegisterWifiEvent(event);
}

WifiErrorCode GetScanInfoList(WifiScanInfo *result, unsigned int *size)
{
    return GetWifiInterface()->GetScanInfoList(result, size);
}

WifiErrorCode UnRegisterWifiEvent(WifiEvent *event)
{
    return GetWifiInterface()->UnRegisterWifiEvent(event);
}

WifiErrorCode Hid2dGetChannelListFor5G(int32_t *chanList, int32_t len)
{
    return GetWifiInterface()->Hid2dGetChannelListFor5G(chanList, len);
}

WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info)
{
    return GetWifiInterface()->GetLinkedInfo(info);
}

WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo *groupInfo)
{
    return GetWifiInterface()->GetCurrentGroup(groupInfo);
}

int32_t IsWifiActive(void)
{
    return GetWifiInterface()->IsWifiActive();
}

WifiErrorCode GetWifiDetailState(WifiDetailState *state)
{
    return GetWifiInterface()->GetWifiDetailState(state);
}

WifiErrorCode GetP2pEnableStatus(P2pState *state)
{
    return GetWifiInterface()->GetP2pEnableStatus(state);
}
}
} // namespace OHOS