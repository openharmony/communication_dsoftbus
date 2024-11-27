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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_ip_network_impl_mock.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_ipNetworkImplInterface;
LnnIpNetworkImplInterfaceMock::LnnIpNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = reinterpret_cast<void *>(this);
}

LnnIpNetworkImplInterfaceMock::~LnnIpNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = nullptr;
}

static LnnIpNetworkImplInterface *GetLnnIpNetworkImplInterface()
{
    return reinterpret_cast<LnnIpNetworkImplInterface *>(g_ipNetworkImplInterface);
}

int32_t LnnIpNetworkImplInterfaceMock::ActionOfGetNetworkIpByIfName(
    const char *ifName, char *ip, char *netmask, uint32_t len)
{
    if (ifName == nullptr || netmask == nullptr || len == 0) {
        LNN_LOGI(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(ip, strlen("127.0.0.2") + 1, "127.0.0.2", strlen("127.0.0.2") + 1) != EOK) {
        LNN_LOGI(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLnnIpNetworkImplInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnIpNetworkImplInterface()->LnnRegistPhysicalSubnet(manager);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium)
{
    return GetLnnIpNetworkImplInterface()->DiscLinkStatusChanged(status, medium);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLnnIpNetworkImplInterface()->LnnVisitPhysicalSubnet(callback, data);
}

void LnnStopPublish(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStopPublish();
}

void LnnStopDiscovery(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStopDiscovery();
}

void LnnIpAddrChangeEventHandler(void)
{
    return GetLnnIpNetworkImplInterface()->LnnIpAddrChangeEventHandler();
}

void AuthStopListening(AuthLinkType type)
{
    return GetLnnIpNetworkImplInterface()->AuthStopListening(type);
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    return GetLnnIpNetworkImplInterface()->TransTdcStopSessionListener(module);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->ConnStopLocalListening(info);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetLnnIpNetworkImplInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnStartPublish(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStartPublish();
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    return GetLnnIpNetworkImplInterface()->LnnIsAutoNetWorkingEnabled();
}

int32_t LnnStartDiscovery(void)
{
    return GetLnnIpNetworkImplInterface()->LnnStartDiscovery();
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetLnnIpNetworkImplInterface()->AuthStartListening(type, ip, port);
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->TransTdcStartSessionListener(module, info);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetLnnIpNetworkImplInterface()->ConnStartLocalListening(info);
}

bool LnnIsLinkReady(const char *iface)
{
    return GetLnnIpNetworkImplInterface()->LnnIsLinkReady(iface);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLnnIpNetworkImplInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnIpNetworkImplInterface()->LnnVisitNetif(callback, data);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    return GetLnnIpNetworkImplInterface()->LnnRequestLeaveByAddrType(type, typeLen);
}

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    return GetLnnIpNetworkImplInterface()->GetNetworkIpByIfName(ifName, ip, netmask, len);
}

int32_t lnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    return GetLnnIpNetworkImplInterface()->LnnRegistProtocol(protocolMgr);
}

int32_t LnnGetWlanIpv4Addr(char *ip, uint32_t size)
{
    return GetLnnIpNetworkImplInterface()->GetWlanIpv4Addr(ip, size);
}

int32_t ConnCoapStartServerListen(void)
{
    return GetLnnIpNetworkImplInterface()->ConnCoapStartServerListen();
}

void ConnCoapStopServerListen(void)
{
    return GetLnnIpNetworkImplInterface()->ConnCoapStopServerListen();
}
}
} // namespace OHOS
