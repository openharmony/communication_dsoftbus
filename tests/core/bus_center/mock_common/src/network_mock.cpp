/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "network_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_networkInterface;

NetworkInterfaceMock::NetworkInterfaceMock()
{
    g_networkInterface = reinterpret_cast<void *>(this);
}

NetworkInterfaceMock::~NetworkInterfaceMock()
{
    g_networkInterface = nullptr;
}

static NetworkInterface *GetNetworkInterface()
{
    return reinterpret_cast<NetworkInterfaceMock *>(g_networkInterface);
}

extern "C" {
int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd)
{
    return GetNetworkInterface()->SoftBusSocketCreate(domain, type, protocol, socketFd);
}

int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen)
{
    return GetNetworkInterface()->SoftBusSocketSetOpt(socketFd, level, optName, optVal, optLen);
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    return GetNetworkInterface()->SoftBusSocketClose(socketFd);
}

int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen)
{
    return GetNetworkInterface()->SoftBusSocketBind(socketFd, addr, addrLen);
}

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type)
{
    return GetNetworkInterface()->LnnGetNetIfTypeByName(ifName, type);
}

void LnnNotifyAddressChangedEvent(const char *ifName)
{
    return GetNetworkInterface()->LnnNotifyAddressChangedEvent(ifName);
}

int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags)
{
    return GetNetworkInterface()->SoftBusSocketRecv(socketFd, buf, len, flags);
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetNetworkInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state)
{
    return GetNetworkInterface()->LnnNotifyBtAclStateChangeEvent(btMac, state);
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    return GetNetworkInterface()->SoftBusAddBtStateListener(listener, listenerId);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetNetworkInterface()->SoftbusGetConfig(type, val, len);
}

void LnnNotifyBtStateChangeEvent(void *state)
{
    return GetNetworkInterface()->LnnNotifyBtStateChangeEvent(state);
}

void LnnNotifyNetlinkStateChangeEvent(NetManagerIfNameState state, const char *ifName)
{
    return GetNetworkInterface()->LnnNotifyNetlinkStateChangeEvent(state, ifName);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetNetworkInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    return GetNetworkInterface()->StartBaseClient(module, listener);
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetNetworkInterface()->AddTrigger(module, fd, trigger);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetNetworkInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info)
{
    return GetNetworkInterface()->LnnSetLocalNumU32Info(key, info);
}

SoftBusBand SoftBusGetLinkBand(void)
{
    return GetNetworkInterface()->SoftBusGetLinkBand();
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetworkInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetworkInterface()->LnnClearNetCapability(capability, type);
}
}
}