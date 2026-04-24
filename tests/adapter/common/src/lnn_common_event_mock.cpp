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
 
#include "lnn_common_event_mock.h"
 
using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
void *g_lnnCommonEventMock;
LnnCommonEventInterfaceMock::LnnCommonEventInterfaceMock()
{
    g_lnnCommonEventMock = reinterpret_cast<void *>(this);
}
 
LnnCommonEventInterfaceMock::~LnnCommonEventInterfaceMock()
{
    g_lnnCommonEventMock = nullptr;
}
 
extern "C" {
static LnnCommonEventInterface *LnnCommonEventInterface(void)
{
    return reinterpret_cast<LnnCommonEventInterfaceMock *>(g_lnnCommonEventMock);
}
 
void LnnNotifySysTimeChangeEvent(void)
{
    return LnnCommonEventInterface()->LnnNotifySysTimeChangeEvent();
}
 
void LnnNotifyDeviceRiskStateChangeEvent(void)
{
    return LnnCommonEventInterface()->LnnNotifyDeviceRiskStateChangeEvent();
}
 
void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state)
{
    return LnnCommonEventInterface()->LnnNotifyScreenStateChangeEvent(state);
}
 
int32_t GetActiveOsAccountIds(void)
{
    return LnnCommonEventInterface()->GetActiveOsAccountIds();
}
 
void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    return LnnCommonEventInterface()->LnnNotifyAccountStateChangeEvent(state);
}
 
LnnEnhanceFuncList *LnnEnhanceFuncListGet(void)
{
    return LnnCommonEventInterface()->LnnEnhanceFuncListGet();
}
 
void LnnNotifyUserSwitchEvent(SoftBusUserSwitchState state)
{
    return LnnCommonEventInterface()->LnnNotifyUserSwitchEvent(state);
}
 
void LnnNotifyScreenLockStateChangeEvent(SoftBusScreenLockState state)
{
    return LnnCommonEventInterface()->LnnNotifyScreenLockStateChangeEvent(state);
}
 
void LnnNotifyDataShareStateChangeEvent(SoftBusDataShareState state)
{
    return LnnCommonEventInterface()->LnnNotifyDataShareStateChangeEvent(state);
}
 
int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return LnnCommonEventInterface()->JudgeDeviceTypeAndGetOsAccountIds();
}
}
} // namespace OHOS