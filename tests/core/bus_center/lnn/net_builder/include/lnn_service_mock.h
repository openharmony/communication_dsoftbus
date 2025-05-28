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

#ifndef LNN_SERVICE_MOCK_H
#define LNN_SERVICE_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_settingdata_event_monitor.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_feature_config.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
class LnnServiceInterface {
public:
    LnnServiceInterface() {};
    virtual ~LnnServiceInterface() {};
    virtual int32_t LnnInitBusCenterEvent(void) = 0;
    virtual void LnnDeinitBusCenterEvent(void) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode) = 0;
    virtual void LnnNotifyLeaveResult(const char *networkId, int32_t retCode) = 0;
    virtual void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info) = 0;
    virtual void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type) = 0;
    virtual void LnnNotifyWlanStateChangeEvent(void *state) = 0;
    virtual void LnnNotifyBtStateChangeEvent(void *state) = 0;
    virtual void LnnNotifyLnnRelationChanged(
        const char *udid, ConnectionAddrType type, uint8_t relation, bool isJoin) = 0;
    virtual void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual void AuthHandleLeaveLNN(AuthHandle authHandle) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num) = 0;
    virtual int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig) = 0;
    virtual int32_t SoftBusDisconnectDevice(void) = 0;
    virtual ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type) = 0;
    virtual void UpdateProfile(const NodeInfo *info) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategy, bool isRelay) = 0;
    virtual bool SoftBusIsWifiTripleMode(void) = 0;
    virtual SoftBusBand SoftBusGetLinkBand(void) = 0;
    virtual SoftBusWifiDetailState SoftBusGetWifiState(void) = 0;
    virtual bool SoftBusHasWifiDirectCapability(void) = 0;
    virtual char *SoftBusGetWifiInterfaceCoexistCap(void) = 0;
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis);
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len) = 0;
    virtual int32_t LnnGetDeviceDisplayName(
        const char *nickName, const char *defaultName, char *deviceName, uint32_t len);
    virtual int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len);
    virtual int32_t LnnGetUnifiedDefaultDeviceName(char *unifiedDefaultName, uint32_t len);
    virtual int32_t GetCurrentAccount(int64_t *account);
    virtual int32_t LnnSetLocalUnifiedName(const char *unifiedName);
    virtual void LnnNotifyLocalNetworkIdChanged(void);
    virtual int32_t LnnGetSettingNickName(
        const char *defaultName, const char *unifiedName, char *nickName, uint32_t len);
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual int32_t LnnSubscribeAccountBootEvent(AccountEventHandle handle) = 0;
    virtual void LnnNotifyOnlineNetType(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state) = 0;
};

class LnnServicetInterfaceMock : public LnnServiceInterface {
public:
    LnnServicetInterfaceMock();
    ~LnnServicetInterfaceMock() override;
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t(void));
    MOCK_METHOD0(LnnDeinitBusCenterEvent, void(void));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD3(LnnNotifyJoinResult, void(ConnectionAddr *, const char *, int32_t));
    MOCK_METHOD2(LnnNotifyLeaveResult, void(const char *, int32_t));
    MOCK_METHOD2(LnnNotifyOnlineState, void(bool, NodeBasicInfo *));
    MOCK_METHOD2(LnnNotifyBasicInfoChanged, void(NodeBasicInfo *, NodeBasicInfoType));
    MOCK_METHOD1(LnnNotifyWlanStateChangeEvent, void(void *));
    MOCK_METHOD1(LnnNotifyBtStateChangeEvent, void(void *));
    MOCK_METHOD4(LnnNotifyLnnRelationChanged, void(const char *, ConnectionAddrType, uint8_t, bool));
    MOCK_METHOD3(LnnNotifyMasterNodeChanged, void(bool, const char *, int32_t));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnOfflineTimingByHeartbeat, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD0(AuthGenRequestId, uint32_t());
    MOCK_METHOD1(AuthHandleLeaveLNN, void(AuthHandle));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t(int64_t, char *, uint16_t));
    MOCK_METHOD2(SoftBusGetWifiDeviceConfig, int32_t(SoftBusWifiDevConf *, uint32_t *));
    MOCK_METHOD1(SoftBusConnectToDevice, int32_t(const SoftBusWifiDevConf *));
    MOCK_METHOD0(SoftBusDisconnectDevice, int32_t());
    MOCK_METHOD1(LnnDiscTypeToConnAddrType, ConnectionAddrType(DiscoveryType));
    MOCK_METHOD1(UpdateProfile, void(const NodeInfo *));
    MOCK_METHOD2(IsFeatureSupport, bool(uint64_t, FeatureCapability));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD0(SoftBusIsWifiTripleMode, bool());
    MOCK_METHOD0(SoftBusGetLinkBand, SoftBusBand());
    MOCK_METHOD0(SoftBusGetWifiState, SoftBusWifiDetailState());
    MOCK_METHOD0(SoftBusHasWifiDirectCapability, bool());
    MOCK_METHOD0(SoftBusGetWifiInterfaceCoexistCap, char *());
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t(unsigned char *, uint32_t));
    MOCK_METHOD4(LnnGetDeviceDisplayName, int32_t(const char *, const char *, char *, uint32_t));
    MOCK_METHOD2(LnnGetUnifiedDeviceName, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnGetUnifiedDefaultDeviceName, int32_t(char *, uint32_t));
    MOCK_METHOD1(GetCurrentAccount, int32_t(int64_t *));
    MOCK_METHOD1(LnnSetLocalUnifiedName, int32_t(const char *));
    MOCK_METHOD0(LnnNotifyLocalNetworkIdChanged, void());
    MOCK_METHOD4(LnnGetSettingNickName, int32_t(const char *, const char *, char *, uint32_t));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD1(LnnSubscribeAccountBootEvent, int32_t(AccountEventHandle handle));
    MOCK_METHOD2(LnnNotifyOnlineNetType, void(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnNotifyDeviceInfoChanged, void(SoftBusDeviceInfoState));
    static int32_t ActionOfLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    static inline std::map<LnnEventType, LnnEventHandler> g_lnnEventHandlers;
};
} // namespace OHOS
#endif // LNN_SERVICE_MOCK_H