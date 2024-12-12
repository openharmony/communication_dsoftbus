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

void LnnStopDiscovery(void)
{
    return GetNetworkManagerInterface()->LnnStopDiscovery();
}

int32_t LnnStartDiscovery(void)
{
    return GetNetworkManagerInterface()->LnnStartDiscovery();
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetNetworkManagerInterface()->SoftbusGetConfig(type, val, len);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium)
{
    return GetNetworkManagerInterface()->DiscLinkStatusChanged(status, medium);
}

void LnnStopPublish(void)
{
    return GetNetworkManagerInterface()->LnnStopPublish();
}

int32_t LnnStartPublish(void)
{
    return GetNetworkManagerInterface()->LnnStartPublish();
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetNetworkManagerInterface()->LnnGetOnlineStateById(id, type);
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    return GetNetworkManagerInterface()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    return GetNetworkManagerInterface()->LnnRequestLeaveByAddrType(type, typeLen);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetNetworkManagerInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    return GetNetworkManagerInterface()->LnnUpdateOhosAccount(reason);
}

void LnnOnOhosAccountLogout(void)
{
    return GetNetworkManagerInterface()->LnnOnOhosAccountLogout();
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetNetworkManagerInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state)
{
    return GetNetworkManagerInterface()->LnnNotifyOOBEStateChangeEvent(state);
}

void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    return GetNetworkManagerInterface()->LnnNotifyAccountStateChangeEvent(state);
}

void LnnDeinitPhysicalSubnetManager(void)
{
    return GetNetworkManagerInterface()->LnnDeinitPhysicalSubnetManager();
}
void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetNetworkManagerInterface()->LnnUnregisterEventHandler(event, handler);
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    return GetNetworkManagerInterface()->DfxRecordTriggerTime(reason, stage);
}
}
} // namespace OHOS