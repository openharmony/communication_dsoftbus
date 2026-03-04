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
 
#ifndef LNN_COMMON_EVENT_MOCK_H
#define LNN_COMMON_EVENT_MOCK_H
 
#include <gmock/gmock.h>
 
#include "bus_center_event.h"
#include "g_enhance_lnn_func.h"
#include "lnn_ohos_account.h"
 
namespace OHOS {
class LnnCommonEventInterface {
public:
    LnnCommonEventInterface() {};
    virtual ~LnnCommonEventInterface() {};
    virtual void LnnNotifySysTimeChangeEvent(void) = 0;
    virtual void LnnNotifyDeviceRiskStateChangeEvent(void) = 0;
    virtual void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state) = 0;
    virtual LnnEnhanceFuncList *LnnEnhanceFuncListGet(void) = 0;
    virtual void LnnNotifyUserSwitchEvent(SoftBusUserSwitchState state) = 0;
    virtual void LnnNotifyScreenLockStateChangeEvent(SoftBusScreenLockState state) = 0;
    virtual void LnnNotifyDataShareStateChangeEvent(SoftBusDataShareState state) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
};
class LnnCommonEventInterfaceMock : public LnnCommonEventInterface {
public:
    LnnCommonEventInterfaceMock();
    ~LnnCommonEventInterfaceMock() override;
    MOCK_METHOD0(LnnNotifySysTimeChangeEvent, void(void));
    MOCK_METHOD0(LnnNotifyDeviceRiskStateChangeEvent, void(void));
    MOCK_METHOD1(LnnNotifyScreenStateChangeEvent, void(SoftBusScreenState));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t(void));
    MOCK_METHOD1(LnnNotifyAccountStateChangeEvent, void(SoftBusAccountState));
    MOCK_METHOD0(LnnEnhanceFuncListGet, LnnEnhanceFuncList * (void));
    MOCK_METHOD1(LnnNotifyUserSwitchEvent, void(SoftBusUserSwitchState));
    MOCK_METHOD1(LnnNotifyScreenLockStateChangeEvent, void(SoftBusScreenLockState));
    MOCK_METHOD1(LnnNotifyDataShareStateChangeEvent, void(SoftBusDataShareState));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t(void));
};
} // namespace OHOS
#endif // LNN_COMMON_EVENT_MOCK_H