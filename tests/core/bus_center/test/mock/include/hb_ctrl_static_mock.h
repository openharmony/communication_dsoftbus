/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HEARTBEAT_CTRL_STATIC_MOCK_H
#define HEARTBEAT_CTRL_STATIC_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_local_net_ledger.h"
#include "lnn_ohos_account.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_map.h"
#include "lnn_network_manager.h"

namespace OHOS {
class HeartBeatCtrlStaticInterface {
public:
    HeartBeatCtrlStaticInterface() {};
    virtual ~HeartBeatCtrlStaticInterface() {};

    virtual void LnnNotifyNetworkStateChanged(SoftBusNetworkState state) = 0;
    virtual int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategy, bool isRelay) = 0;
    virtual int32_t LnnStartHeartbeat(uint64_t delayMillis) = 0;
    virtual int32_t LnnStopHeartbeatByType(LnnHeartbeatType type) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnSetHbAsMasterNodeState(bool isMasterNode) = 0;
    virtual int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual int32_t LnnSetCloudAbility(const bool isEnableCloud) = 0;
    virtual int32_t LnnDeleteSyncToDB(void) = 0;
    virtual void LnnOnOhosAccountLogout(void) = 0;
    virtual void LnnUpdateOhosAccount(bool isNeedUpdateHeartbeat) = 0;
    virtual TrustedReturnType AuthHasTrustedRelation(void) = 0;
    virtual bool IsEnableSoftBusHeartbeat(void) = 0;
    virtual int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info) = 0;
    virtual ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type) = 0;
    virtual int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual void LnnMapDelete(Map *map) = 0;
    virtual void ClearAuthLimitMap(void) = 0;
    virtual int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType) = 0;
    virtual void RestartCoapDiscovery(void) = 0;
    virtual bool LnnIsLocalSupportBurstFeature(void) = 0;
    virtual void AuthLoadDeviceKey(void) = 0;
    virtual int32_t LnnGenerateCeParams(void) = 0;
};
class HeartBeatCtrlStaticInterfaceMock : public HeartBeatCtrlStaticInterface {
public:
    HeartBeatCtrlStaticInterfaceMock();
    ~HeartBeatCtrlStaticInterfaceMock() override;

    MOCK_METHOD1(LnnNotifyNetworkStateChanged, void (SoftBusNetworkState));
    MOCK_METHOD2(LnnEnableHeartbeatByType, int32_t (LnnHeartbeatType, bool));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t (LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD1(LnnStartHeartbeat, int32_t (uint64_t));
    MOCK_METHOD1(LnnStopHeartbeatByType, int32_t (LnnHeartbeatType));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t (LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnSetHbAsMasterNodeState, int32_t (bool));
    MOCK_METHOD1(LnnUpdateSendInfoStrategy, int32_t (LnnHeartbeatUpdateInfoType));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD1(LnnSetCloudAbility, int32_t (const bool));
    MOCK_METHOD0(LnnDeleteSyncToDB, int32_t ());
    MOCK_METHOD0(LnnOnOhosAccountLogout, void (void));
    MOCK_METHOD1(LnnUpdateOhosAccount, void (bool));
    MOCK_METHOD0(AuthHasTrustedRelation, TrustedReturnType (void));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool (void));
    MOCK_METHOD1(LnnSetMediumParamBySpecificType, int32_t (const LnnHeartbeatMediumParam *));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t (NodeInfo *info));
    MOCK_METHOD1(LnnLedgerAllDataSyncToDB, int32_t (NodeInfo *info));
    MOCK_METHOD1(LnnConvertHbTypeToConnAddrType, ConnectionAddrType (LnnHeartbeatType type));
    MOCK_METHOD2(LnnStopScreenChangeOfflineTiming, int32_t (const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStartScreenChangeOfflineTiming, int32_t (const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnMapDelete, void (Map *));
    MOCK_METHOD0(ClearAuthLimitMap, void (void));
    MOCK_METHOD1(LnnStopHeartBeatAdvByTypeNow, int32_t (LnnHeartbeatType));
    MOCK_METHOD0(RestartCoapDiscovery, void (void));
    MOCK_METHOD0(LnnIsLocalSupportBurstFeature, bool (void));
    MOCK_METHOD0(AuthLoadDeviceKey, void (void));
    MOCK_METHOD0(LnnGenerateCeParams, int32_t (void));
};
} // namespace OHOS
#endif // OHOS_LNN_CTRL_STATIC_MOCK_H