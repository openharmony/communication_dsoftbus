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

#ifndef BUS_CENTER_MANAGER_DEPS_MOCK_H
#define BUS_CENTER_MANAGER_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "softbus_utils.h"
#include "message_handler.h"
#include "lnn_async_callback_utils.h"

namespace OHOS {
class BusCenterManagerDepsInterface {
public:
    BusCenterManagerDepsInterface() {};
    virtual ~BusCenterManagerDepsInterface() {};

    virtual bool GetWatchdogFlag(void) = 0;
    virtual SoftBusLooper *GetLooper(int32_t looper);
    virtual SoftBusLooper *CreateNewLooper(const char *name);
    virtual int32_t LnnInitNetLedger(void);
    virtual int32_t LnnInitDecisionCenter(uint32_t version);
    virtual int32_t LnnInitBusCenterEvent(void);
    virtual int32_t LnnInitEventMonitor(void);
    virtual int32_t LnnInitDiscoveryManager(void);
    virtual int32_t LnnInitNetworkManager(void);
    virtual int32_t LnnInitNetBuilder(void);
    virtual int32_t LnnInitMetaNode(void);
    virtual bool IsActiveOsAccountUnlocked(void);
    virtual void RestoreLocalDeviceInfo(void);
    virtual void SoftBusRunPeriodicalTask(const char *name, void (*task)(void), uint64_t interval, uint64_t delay);
    virtual int32_t LnnInitLaneHub(void);
    virtual int32_t InitDecisionCenter(void);
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis);
    virtual void LnnCoapConnectInit(void);
    virtual int32_t LnnInitNetLedgerDelay(void);
    virtual int32_t LnnInitEventMoniterDelay(void);
    virtual int32_t LnnInitNetworkManagerDelay(void);
    virtual int32_t LnnInitNetBuilderDelay(void);
    virtual int32_t LnnInitLaneHubDelay(void);
};

class BusCenterManagerDepsInterfaceMock : public BusCenterManagerDepsInterface {
public:
    BusCenterManagerDepsInterfaceMock();
    ~BusCenterManagerDepsInterfaceMock() override;

    MOCK_METHOD0(GetWatchdogFlag, bool (void));
    MOCK_METHOD1(GetLooper, SoftBusLooper * (int));
    MOCK_METHOD1(CreateNewLooper, SoftBusLooper * (const char *));
    MOCK_METHOD0(LnnInitNetLedger, int32_t (void));
    MOCK_METHOD1(LnnInitDecisionCenter, int32_t (uint32_t));
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t (void));
    MOCK_METHOD0(LnnInitEventMonitor, int32_t (void));
    MOCK_METHOD0(LnnInitDiscoveryManager, int32_t (void));
    MOCK_METHOD0(LnnInitNetworkManager, int32_t (void));
    MOCK_METHOD0(LnnInitNetBuilder, int32_t (void));
    MOCK_METHOD0(LnnInitMetaNode, int32_t (void));
    MOCK_METHOD0(IsActiveOsAccountUnlocked, bool (void));
    MOCK_METHOD0(RestoreLocalDeviceInfo, void (void));
    MOCK_METHOD4(SoftBusRunPeriodicalTask, void(const char*, void(*task)(void), uint64_t, uint64_t));
    MOCK_METHOD0(LnnInitLaneHub, int32_t (void));
    MOCK_METHOD0(InitDecisionCenter, int32_t (void));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD0(LnnCoapConnectInit, void (void));
    MOCK_METHOD0(LnnInitNetLedgerDelay, int32_t (void));
    MOCK_METHOD0(LnnInitEventMoniterDelay, int32_t (void));
    MOCK_METHOD0(LnnInitNetworkManagerDelay, int32_t (void));
    MOCK_METHOD0(LnnInitNetBuilderDelay, int32_t (void));
    MOCK_METHOD0(LnnInitLaneHubDelay, int32_t (void));
};
} // namespace OHOS
#endif // BUS_CENTER_MANAGER_DEPS_MOCK_H
