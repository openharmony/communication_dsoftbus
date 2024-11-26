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

#include "lnn_bt_network_impl_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_btNetworkImplInterface;
LnnBtNetworkImplInterfaceMock::LnnBtNetworkImplInterfaceMock()
{
    g_btNetworkImplInterface = reinterpret_cast<void *>(this);
}

LnnBtNetworkImplInterfaceMock::~LnnBtNetworkImplInterfaceMock()
{
    g_btNetworkImplInterface = nullptr;
}

static LnnBtNetworkImplInterface *GetLnnBtNetworkImplInterface()
{
    return reinterpret_cast<LnnBtNetworkImplInterface *>(g_btNetworkImplInterface);
}

int32_t LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBr(const char *ifName, LnnNetIfType *type)
{
    *type = (LnnNetIfType)LNN_NETIF_TYPE_BR;
    return SOFTBUS_OK;
}

int32_t LnnBtNetworkImplInterfaceMock::ActionOfLnnGetNetIfTypeByNameBle(const char *ifName, LnnNetIfType *type)
{
    *type = (LnnNetIfType)LNN_NETIF_TYPE_BLE;
    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return GetLnnBtNetworkImplInterface()->LnnRequestLeaveSpecific(networkId, addrType);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    return GetLnnBtNetworkImplInterface()->LnnRequestLeaveByAddrType(type, typeLen);
}

int32_t SoftBusGetBtState(void)
{
    return GetLnnBtNetworkImplInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetLnnBtNetworkImplInterface()->SoftBusGetBtMacAddr(mac);
}

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return GetLnnBtNetworkImplInterface()->ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLnnBtNetworkImplInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    return GetLnnBtNetworkImplInterface()->LnnGetNetIfTypeByName(ifName, type);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnBtNetworkImplInterface()->LnnVisitNetif(callback, data);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnBtNetworkImplInterface()->LnnRegistPhysicalSubnet(manager);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLnnBtNetworkImplInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}
}
} // namespace OHOS
