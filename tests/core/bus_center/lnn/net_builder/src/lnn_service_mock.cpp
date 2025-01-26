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

#include "lnn_log.h"
#include "lnn_service_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_serviceInterface;
LnnServicetInterfaceMock::LnnServicetInterfaceMock()
{
    g_serviceInterface = reinterpret_cast<void *>(this);
}

LnnServicetInterfaceMock::~LnnServicetInterfaceMock()
{
    g_serviceInterface = nullptr;
}

static LnnServiceInterface *GetServiceInterface()
{
    return reinterpret_cast<LnnServiceInterface *>(g_serviceInterface);
}

extern "C" {
int32_t LnnInitBusCenterEvent(void)
{
    return GetServiceInterface()->LnnInitBusCenterEvent();
}

void LnnDeinitBusCenterEvent(void)
{
    return GetServiceInterface()->LnnDeinitBusCenterEvent();
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetServiceInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetServiceInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info)
{
    return GetServiceInterface()->LnnNotifyOnlineState(isOnline, info);
}

void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type)
{
    return GetServiceInterface()->LnnNotifyBasicInfoChanged(info, type);
}

void LnnNotifyWlanStateChangeEvent(void *state)
{
    return GetServiceInterface()->LnnNotifyWlanStateChangeEvent(state);
}

void LnnNotifyBtStateChangeEvent(void *state)
{
    return GetServiceInterface()->LnnNotifyBtStateChangeEvent(state);
}

void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type, uint8_t relation, bool isJoin)
{
    return GetServiceInterface()->LnnNotifyLnnRelationChanged(udid, type, relation, isJoin);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight)
{
    return GetServiceInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetServiceInterface()->LnnUnregisterEventHandler(event, handler);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    return GetServiceInterface()->LnnOfflineTimingByHeartbeat(networkId, addrType);
}

uint32_t AuthGenRequestId(void)
{
    return GetServiceInterface()->AuthGenRequestId();
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    return GetServiceInterface()->AuthHandleLeaveLNN(authHandle);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetServiceInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num)
{
    return GetServiceInterface()->SoftBusGetWifiDeviceConfig(configList, num);
}

int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig)
{
    return GetServiceInterface()->SoftBusConnectToDevice(wifiConfig);
}

int32_t SoftBusDisconnectDevice(void)
{
    return GetServiceInterface()->SoftBusDisconnectDevice();
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetServiceInterface()->LnnDiscTypeToConnAddrType(type);
}

void UpdateProfile(const NodeInfo *info)
{
    return GetServiceInterface()->UpdateProfile(info);
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetServiceInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategy, bool isRelay)
{
    return GetServiceInterface()->LnnStartHbByTypeAndStrategy(hbType, strategy, isRelay);
}

bool SoftBusIsWifiTripleMode(void)
{
    return GetServiceInterface()->SoftBusIsWifiTripleMode();
}

SoftBusBand SoftBusGetLinkBand(void)
{
    return GetServiceInterface()->SoftBusGetLinkBand();
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return GetServiceInterface()->SoftBusGetWifiState();
}

bool SoftBusHasWifiDirectCapability(void)
{
    return GetServiceInterface()->SoftBusHasWifiDirectCapability();
}

char *SoftBusGetWifiInterfaceCoexistCap(void)
{
    return GetServiceInterface()->SoftBusGetWifiInterfaceCoexistCap();
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetServiceInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetServiceInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetServiceInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName, uint32_t len)
{
    return GetServiceInterface()->LnnGetDeviceDisplayName(nickName, defaultName, deviceName, len);
}

int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len)
{
    return GetServiceInterface()->LnnGetUnifiedDeviceName(unifiedName, len);
}

int32_t LnnGetUnifiedDefaultDeviceName(char *unifiedDefaultName, uint32_t len)
{
    return GetServiceInterface()->LnnGetUnifiedDefaultDeviceName(unifiedDefaultName, len);
}

int32_t GetCurrentAccount(int64_t *account)
{
    return GetServiceInterface()->GetCurrentAccount(account);
}

int32_t LnnSetLocalUnifiedName(const char *unifiedName)
{
    return GetServiceInterface()->LnnSetLocalUnifiedName(unifiedName);
}

void LnnNotifyLocalNetworkIdChanged(void)
{
    return GetServiceInterface()->LnnNotifyLocalNetworkIdChanged();
}

int32_t LnnGetSettingNickName(const char *defaultName, const char *unifiedName, char *nickName, uint32_t len)
{
    return GetServiceInterface()->LnnGetSettingNickName(defaultName, unifiedName, nickName, len);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetServiceInterface()->SoftbusGetConfig(type, val, len);
}

int32_t LnnSubscribeAccountBootEvent(AccountEventHandle handle)
{
    return GetServiceInterface()->LnnSubscribeAccountBootEvent(handle);
}

void LnnNotifyOnlineNetType(const char *networkId, ConnectionAddrType addrType)
{
    return GetServiceInterface()->LnnNotifyOnlineNetType(networkId, addrType);
}

void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state)
{
    return GetServiceInterface()->LnnNotifyDeviceInfoChanged(state);
}

int32_t LnnServicetInterfaceMock::ActionOfLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    if (event == LNN_EVENT_TYPE_MAX || handler == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_lnnEventHandlers.emplace(event, handler);
    return SOFTBUS_OK;
}
} // extern "C"
} // namespace OHOS