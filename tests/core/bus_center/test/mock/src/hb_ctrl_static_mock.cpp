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

#include "hb_ctrl_static_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbCtrlStaticInterface;
HeartBeatCtrlStaticInterfaceMock::HeartBeatCtrlStaticInterfaceMock()
{
    g_hbCtrlStaticInterface = reinterpret_cast<void *>(this);
}

HeartBeatCtrlStaticInterfaceMock::~HeartBeatCtrlStaticInterfaceMock()
{
    g_hbCtrlStaticInterface = nullptr;
}

extern "C" {
static HeartBeatCtrlStaticInterface *HeartBeatCtrlStaticInterface(void)
{
    return reinterpret_cast<HeartBeatCtrlStaticInterfaceMock *>(g_hbCtrlStaticInterface);
}

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state)
{
    HeartBeatCtrlStaticInterface()->LnnNotifyNetworkStateChanged(state);
}

int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable)
{
    return HeartBeatCtrlStaticInterface()->LnnEnableHeartbeatByType(type, isEnable);
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return HeartBeatCtrlStaticInterface()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

int32_t LnnStartHeartbeat(uint64_t delayMillis)
{
    return HeartBeatCtrlStaticInterface()->LnnStartHeartbeat(delayMillis);
}

int32_t LnnStopHeartbeatByType(LnnHeartbeatType type)
{
    return HeartBeatCtrlStaticInterface()->LnnStopHeartbeatByType(type);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return HeartBeatCtrlStaticInterface()->LnnRegisterEventHandler(event, handler);
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return HeartBeatCtrlStaticInterface()->LnnSetHbAsMasterNodeState(isMasterNode);
}

int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type)
{
    return HeartBeatCtrlStaticInterface()->LnnUpdateSendInfoStrategy(type);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return HeartBeatCtrlStaticInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t LnnSetCloudAbility(const bool isEnableCloud)
{
    return HeartBeatCtrlStaticInterface()->LnnSetCloudAbility(isEnableCloud);
}

int32_t LnnDeleteSyncToDB(void)
{
    return HeartBeatCtrlStaticInterface()->LnnDeleteSyncToDB();
}

void LnnOnOhosAccountLogout(void)
{
    HeartBeatCtrlStaticInterface()->LnnOnOhosAccountLogout();
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    HeartBeatCtrlStaticInterface()->LnnUpdateOhosAccount(reason);
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    return HeartBeatCtrlStaticInterface()->AuthHasTrustedRelation();
}

bool IsEnableSoftBusHeartbeat(void)
{
    return HeartBeatCtrlStaticInterface()->IsEnableSoftBusHeartbeat();
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    return HeartBeatCtrlStaticInterface()->LnnSetMediumParamBySpecificType(param);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return HeartBeatCtrlStaticInterface()->LnnGetLocalNodeInfoSafe(info);
}

int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info, bool isAckSeq, char *peerudid)
{
    return HeartBeatCtrlStaticInterface()->LnnLedgerAllDataSyncToDB(info, isAckSeq, peerudid);
}

ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type)
{
    return HeartBeatCtrlStaticInterface()->LnnConvertHbTypeToConnAddrType(type);
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatCtrlStaticInterface()->LnnStopScreenChangeOfflineTiming(networkId, addrType);
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatCtrlStaticInterface()->LnnStartScreenChangeOfflineTiming(networkId, addrType);
}

void LnnMapDelete(Map *map)
{
    HeartBeatCtrlStaticInterface()->LnnMapDelete(map);
}

void ClearAuthLimitMap(void)
{
    HeartBeatCtrlStaticInterface()->ClearAuthLimitMap();
}

int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    return HeartBeatCtrlStaticInterface()->LnnStopHeartBeatAdvByTypeNow(registedHbType);
}

void RestartCoapDiscovery(void)
{
    HeartBeatCtrlStaticInterface()->RestartCoapDiscovery();
}

bool LnnIsLocalSupportBurstFeature(void)
{
    return HeartBeatCtrlStaticInterface()->LnnIsLocalSupportBurstFeature();
}

void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    return HeartBeatCtrlStaticInterface()->LnnNotifyAccountStateChangeEvent(state);
}

void AuthLoadDeviceKey(void)
{
    return HeartBeatCtrlStaticInterface()->AuthLoadDeviceKey();
}

int32_t LnnGenerateCeParams(bool isUnlocked)
{
    return HeartBeatCtrlStaticInterface()->LnnGenerateCeParams(isUnlocked);
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    return HeartBeatCtrlStaticInterface()->DfxRecordTriggerTime(reason, stage);
}

int32_t LnnHbMediumMgrInit(void)
{
    return HeartBeatCtrlStaticInterface()->LnnHbMediumMgrInit();
}

int32_t LnnStartNewHbStrategyFsm(void)
{
    return HeartBeatCtrlStaticInterface()->LnnStartNewHbStrategyFsm();
}

int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    return HeartBeatCtrlStaticInterface()->AuthSendKeepaliveOption(uuid, cycle);
}

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type)
{
    return HeartBeatCtrlStaticInterface()->LnnSetGearModeBySpecificType(callerId, mode, type);
}

void LnnDumpLocalBasicInfo(void)
{
    return HeartBeatCtrlStaticInterface()->LnnDumpLocalBasicInfo();
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return HeartBeatCtrlStaticInterface()->LnnGetOnlineStateById(id, type);
}

int32_t AuthFlushDevice(const char *uuid, AuthLinkType type)
{
    return HeartBeatCtrlStaticInterface()->AuthFlushDevice(uuid, type);
}

int32_t LnnHbStrategyInit(void)
{
    return HeartBeatCtrlStaticInterface()->LnnHbStrategyInit();
}

void LnnBleHbUnregDataLevelChangeCb(void)
{
    return HeartBeatCtrlStaticInterface()->LnnBleHbUnregDataLevelChangeCb();
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatCtrlStaticInterface()->LnnStopOfflineTimingStrategy(networkId, addrType);
}

int32_t HbBuildUserIdCheckSum(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len)
{
    return HeartBeatCtrlStaticInterface()->HbBuildUserIdCheckSum(userIdArray, num, custData, len);
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return HeartBeatCtrlStaticInterface()->LnnSetLocalByteInfo(key, info, len);
}

int32_t LnnStartHbByTypeAndStrategyEx(LnnProcessSendOnceMsgPara *msgPara)
{
    return HeartBeatCtrlStaticInterface()->LnnStartHbByTypeAndStrategyEx(msgPara);
}

int32_t LnnSyncBleOfflineMsg(void)
{
    return HeartBeatCtrlStaticInterface()->LnnSyncBleOfflineMsg();
}
void LnnRemoveV0BroadcastAndCheckDev(void)
{
    return HeartBeatCtrlStaticInterface()->LnnRemoveV0BroadcastAndCheckDev();
}

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    return HeartBeatCtrlStaticInterface()->UpdateRecoveryDeviceInfoFromDb();
}

int32_t LnnGetDLSleHbTimestamp(const char *networkId, uint64_t *timestamp)
{
    return HeartBeatCtrlStaticInterface()->LnnGetDLSleHbTimestamp(networkId, timestamp);
}

int32_t LnnSetDLSleHbTimestamp(const char *networkId, const uint64_t timestamp)
{
    return HeartBeatCtrlStaticInterface()->LnnSetDLSleHbTimestamp(networkId, timestamp);
}

int32_t LnnStartSleOfflineTimingStrategy(const char *networkId)
{
    return HeartBeatCtrlStaticInterface()->LnnStartSleOfflineTimingStrategy(networkId);
}

int32_t LnnStopSleOfflineTimingStrategy(const char *networkId)
{
    return HeartBeatCtrlStaticInterface()->LnnStopSleOfflineTimingStrategy(networkId);
}

struct WifiDirectManager* GetWifiDirectManager(void)
{
    return HeartBeatCtrlStaticInterface()->GetWifiDirectManager();
}
}
} // namespace OHOS
