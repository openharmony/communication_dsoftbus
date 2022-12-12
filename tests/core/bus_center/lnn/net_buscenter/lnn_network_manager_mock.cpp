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

#include "lnn_network_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_networkManagerInterface;
LnnNetworkManagerInterfaceMock::LnnNetworkManagerInterfaceMock()
{
    g_networkManagerInterface = reinterpret_cast<void *>(this);
}

LnnNetworkManagerInterfaceMock::~LnnNetworkManagerInterfaceMock()
{
    g_networkManagerInterface = nullptr;
}

static LnnNetworkManagerInterface *GetNetworkManagerInterface()
{
    return reinterpret_cast<LnnNetworkManagerInterface *>(g_networkManagerInterface);
}

extern "C" {
int32_t RegistIPProtocolManager(void)
{
    return GetNetworkManagerInterface()->RegistIPProtocolManager();
}

int32_t LnnInitPhysicalSubnetManager(void)
{
    return GetNetworkManagerInterface()->LnnInitPhysicalSubnetManager();
}

void LnnOnOhosAccountChanged(void)
{
    return GetNetworkManagerInterface()->LnnOnOhosAccountChanged();
}

void LnnHbOnAuthGroupCreated(int32_t groupType)
{
    return GetNetworkManagerInterface()->LnnHbOnAuthGroupCreated(groupType);
}

void LnnStopDiscovery(void)
{
    return GetNetworkManagerInterface()->LnnStopDiscovery();
}

int32_t LnnStartDiscovery(void)
{
    return GetNetworkManagerInterface()->LnnStartDiscovery();
}

void SetCallLnnStatus(bool flag)
{
    return GetNetworkManagerInterface()->SetCallLnnStatus(flag);
}

void LnnHbOnAuthGroupDeleted(void)
{
    return GetNetworkManagerInterface()->LnnHbOnAuthGroupDeleted();
}
}
}