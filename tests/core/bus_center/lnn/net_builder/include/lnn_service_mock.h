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
#include "softbus_common.h"
#include "softbus_bus_center.h"
#include "lnn_settingdata_event_monitor.h"

namespace OHOS {
class LnnServiceInterface {
public:
    LnnServiceInterface() {};
    virtual ~LnnServiceInterface() {};
    virtual int32_t LnnInitBusCenterEvent(void) = 0;
    virtual void LnnDeinitBusCenterEvent(void) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnNotifyJoinResult(ConnectionAddr *addr,
        const char *networkId, int32_t retCode) = 0;
    virtual void LnnNotifyLeaveResult(const char *networkId, int32_t retCode) = 0;
    virtual void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info) = 0;
    virtual void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type) = 0;
    virtual void LnnNotifyWlanStateChangeEvent(SoftBusWifiState state) = 0;
    virtual void LnnNotifyBtStateChangeEvent(void *state) = 0;
    virtual void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type,
        uint8_t relation, bool isJoin) = 0;
    virtual void LnnNotifyMasterNodeChanged(bool isMaster, const char* masterNodeUdid,
        int32_t weight) = 0;
    virtual int32_t LnnInitGetDeviceName(LnnDeviceNameHandler handler) = 0;
    virtual void RegisterNameMonitor(void) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnGetSettingDeviceName(char *deviceName, uint32_t len) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual void AuthHandleLeaveLNN(int64_t authId) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
};

class LnnServicetInterfaceMock : public LnnServiceInterface {
public:
    LnnServicetInterfaceMock();
    ~LnnServicetInterfaceMock() override;
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t (void));
    MOCK_METHOD0(LnnDeinitBusCenterEvent, void (void));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t (LnnEventType, LnnEventHandler));
    MOCK_METHOD3(LnnNotifyJoinResult, void (ConnectionAddr *, const char *, int32_t));
    MOCK_METHOD2(LnnNotifyLeaveResult, void (const char *, int32_t));
    MOCK_METHOD2(LnnNotifyOnlineState, void (bool, NodeBasicInfo *));
    MOCK_METHOD2(LnnNotifyBasicInfoChanged, void (NodeBasicInfo *, NodeBasicInfoType));
    MOCK_METHOD1(LnnNotifyWlanStateChangeEvent, void (SoftBusWifiState));
    MOCK_METHOD1(LnnNotifyBtStateChangeEvent, void (void *));
    MOCK_METHOD4(LnnNotifyLnnRelationChanged, void (const char *, ConnectionAddrType, uint8_t, bool));
    MOCK_METHOD3(LnnNotifyMasterNodeChanged, void (bool, const char*, int32_t));
    MOCK_METHOD1(LnnInitGetDeviceName, int32_t (LnnDeviceNameHandler));
    MOCK_METHOD0(RegisterNameMonitor, void (void));
    MOCK_METHOD2(LnnUnregisterEventHandler, void (LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnOfflineTimingByHeartbeat, int32_t (const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnGetSettingDeviceName, int32_t (char *, uint32_t));
    MOCK_METHOD0(AuthGenRequestId, uint32_t ());
    MOCK_METHOD1(AuthHandleLeaveLNN, void (int64_t));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t (int64_t, char*, uint16_t));
    static int32_t ActionOfLnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    static int32_t ActionOfLnnInitGetDeviceName(LnnDeviceNameHandler handler);
    static int32_t ActionOfLnnGetSettingDeviceName(char *deviceName, uint32_t len);
    static inline std::map<LnnEventType, LnnEventHandler> g_lnnEventHandlers;
    static inline LnnDeviceNameHandler g_deviceNameHandler;
};
} // namespace OHOS
#endif // LNN_SERVICE_MOCK_H