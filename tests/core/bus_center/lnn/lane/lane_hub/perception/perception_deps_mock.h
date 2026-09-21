/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PERCEPTION_DEPS_MOCK_H
#define PERCEPTION_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_event_struct.h"
#include "bus_center_info_key_struct.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_perception.h"
#include "perception_advertiser.h"
#include "perception_scanner.h"

namespace OHOS {
class PerceptionDepsInterface {
public:
    virtual ~PerceptionDepsInterface() = default;

    virtual int32_t PerceptionAdvertiserInit(void) = 0;
    virtual void PerceptionAdvertiserDeinit(void) = 0;
    virtual int32_t PerceptionScannerInit(void) = 0;
    virtual void PerceptionScannerDeinit(void) = 0;
    virtual int32_t PerceptionAdvStart(PerceptionType type, const PerceptionAdvParam *param) = 0;
    virtual int32_t PerceptionAdvSetHighFreq(PerceptionType type, const PerceptionAdvParam *param) = 0;
    virtual int32_t PerceptionAdvStop(void) = 0;
    virtual int32_t PerceptionScanStart(PerceptionType type, PerceptionCycle cycle) = 0;
    virtual int32_t PerceptionScanStop(void) = 0;
    virtual int32_t PerceptionScanGetDeviceList(PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count) = 0;
    virtual int32_t PerceptionEnhanceInitPacked(void) = 0;
    virtual void PerceptionEnhanceDeinitPacked(void) = 0;
    virtual bool IsSupportLpFeaturePacked(void) = 0;
    virtual bool LnnIsLocalSupportBurstFeature(void) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void PerceptionAdvOnBtStateChanged(bool isBtOn) = 0;
    virtual void PerceptionScanOnBtStateChanged(bool isBtOn) = 0;
    virtual void PerceptionScanOnScreenStateChanged(bool isScreenOn) = 0;
};

class PerceptionDepsMock : public PerceptionDepsInterface {
public:
    PerceptionDepsMock();
    ~PerceptionDepsMock() override;

    MOCK_METHOD0(PerceptionAdvertiserInit, int32_t(void));
    MOCK_METHOD0(PerceptionAdvertiserDeinit, void(void));
    MOCK_METHOD0(PerceptionScannerInit, int32_t(void));
    MOCK_METHOD0(PerceptionScannerDeinit, void(void));
    MOCK_METHOD2(PerceptionAdvStart, int32_t(PerceptionType, const PerceptionAdvParam *));
    MOCK_METHOD2(PerceptionAdvSetHighFreq, int32_t(PerceptionType, const PerceptionAdvParam *));
    MOCK_METHOD0(PerceptionAdvStop, int32_t(void));
    MOCK_METHOD2(PerceptionScanStart, int32_t(PerceptionType, PerceptionCycle));
    MOCK_METHOD0(PerceptionScanStop, int32_t(void));
    MOCK_METHOD3(PerceptionScanGetDeviceList, int32_t(PerceptionType, PerceptionDeviceInfo **, uint32_t *));
    MOCK_METHOD0(PerceptionEnhanceInitPacked, int32_t(void));
    MOCK_METHOD0(PerceptionEnhanceDeinitPacked, void(void));
    MOCK_METHOD0(IsSupportLpFeaturePacked, bool(void));
    MOCK_METHOD0(LnnIsLocalSupportBurstFeature, bool(void));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(PerceptionAdvOnBtStateChanged, void(bool));
    MOCK_METHOD1(PerceptionScanOnBtStateChanged, void(bool));
    MOCK_METHOD1(PerceptionScanOnScreenStateChanged, void(bool));
};
} // namespace OHOS
#endif // PERCEPTION_DEPS_MOCK_H
