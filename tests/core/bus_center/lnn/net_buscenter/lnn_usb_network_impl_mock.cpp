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

#include <gtest/gtest.h>
#include <netinet/in.h>
#include <securec.h>

#include "lnn_log.h"
#include "lnn_usb_network_impl_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_ipNetworkImplInterface;
LnnUsbNetworkImplInterfaceMock::LnnUsbNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = reinterpret_cast<void *>(this);
}

LnnUsbNetworkImplInterfaceMock::~LnnUsbNetworkImplInterfaceMock()
{
    g_ipNetworkImplInterface = nullptr;
}

static LnnUsbNetworkImplInterface *GetLnnUsbNetworkImplInterface()
{
    return reinterpret_cast<LnnUsbNetworkImplInterface *>(g_ipNetworkImplInterface);
}

int32_t LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName(const char *ifName, char *ip, uint32_t len)
{
    if (ifName == nullptr || ip == nullptr) {
        LNN_LOGE(LNN_TEST, "ifName or ip buffer is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len < INET6_ADDRSTRLEN) {
        LNN_LOGE(LNN_TEST, "len value is not long enough !");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(ip, strlen("::2") + 1, "::2", strlen("::2") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnUsbNetworkImplInterfaceMock::ActionOfGetNetworkIpv6ByIfName2(const char *ifName, char *ip, uint32_t len)
{
    if (ifName == nullptr || ip == nullptr) {
        LNN_LOGE(LNN_TEST, "ifName or ip buffer is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (len < INET6_ADDRSTRLEN) {
        LNN_LOGE(LNN_TEST, "len value is not long enough !");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(ip, strlen("::3") + 1, "::3", strlen("::3") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnUsbNetworkImplInterfaceMock::ActionOfLnnGetLocalStrInfoByIfnameIdx(
    InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    (void)ifIdx;
    if (info == nullptr) {
        LNN_LOGE(LNN_TEST, "para error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (key == STRING_KEY_NET_IF_NAME) {
        if (strcpy_s(info, len, "deviceName") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_IP) {
        if (strcpy_s(info, len, "::2") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    if (key == STRING_KEY_IP6_WITH_IF) {
        if (strcpy_s(info, len, "::2%ncm0") != EOK) {
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

extern "C" {
int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLnnUsbNetworkImplInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnUsbNetworkImplInterface()->LnnRegistPhysicalSubnet(manager);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx)
{
    return GetLnnUsbNetworkImplInterface()->DiscLinkStatusChanged(status, medium, ifnameIdx);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLnnUsbNetworkImplInterface()->LnnVisitPhysicalSubnet(callback, data);
}

void LnnIpAddrChangeEventHandler(void)
{
    return GetLnnUsbNetworkImplInterface()->LnnIpAddrChangeEventHandler();
}

void AuthStopListening(AuthLinkType type)
{
    return GetLnnUsbNetworkImplInterface()->AuthStopListening(type);
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    return GetLnnUsbNetworkImplInterface()->TransTdcStopSessionListener(module);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetLnnUsbNetworkImplInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetLnnUsbNetworkImplInterface()->AuthStartListening(type, ip, port);
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetLnnUsbNetworkImplInterface()->TransTdcStartSessionListener(module, info);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLnnUsbNetworkImplInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnUsbNetworkImplInterface()->LnnVisitNetif(callback, data);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLnnUsbNetworkImplInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}

int32_t GetNetworkIpv6ByIfName(const char *ifName, char *ip, uint32_t len)
{
    return GetLnnUsbNetworkImplInterface()->GetNetworkIpv6ByIfName(ifName, ip, len);
}

int32_t lnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    return GetLnnUsbNetworkImplInterface()->LnnRegistProtocol(protocolMgr);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLnnUsbNetworkImplInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnUsbNetworkImplInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnUsbNetworkImplInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetLnnUsbNetworkImplInterface()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetLnnUsbNetworkImplInterface()->LnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx)
{
    return GetLnnUsbNetworkImplInterface()->LnnGetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnSetLocalStrInfoByIfnameIdx(InfoKey key, const char *info, int32_t ifIdx)
{
    return GetLnnUsbNetworkImplInterface()->LnnSetLocalStrInfoByIfnameIdx(key, info, ifIdx);
}

int32_t LnnSetLocalNumInfoByIfnameIdx(InfoKey key, int32_t info, int32_t ifIdx)
{
    return GetLnnUsbNetworkImplInterface()->LnnSetLocalNumInfoByIfnameIdx(key, info, ifIdx);
}
}
} // namespace OHOS
