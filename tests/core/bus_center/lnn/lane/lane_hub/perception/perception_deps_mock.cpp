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

#include "perception_deps_mock.h"

#include "softbus_error_code.h"

namespace OHOS {
void *g_perceptionDepsInterface;

PerceptionDepsMock::PerceptionDepsMock()
{
    g_perceptionDepsInterface = reinterpret_cast<void *>(this);
}

PerceptionDepsMock::~PerceptionDepsMock()
{
    g_perceptionDepsInterface = nullptr;
}

static PerceptionDepsInterface *GetPerceptionDepsInterface()
{
    if (g_perceptionDepsInterface == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<PerceptionDepsInterface *>(g_perceptionDepsInterface);
}

extern "C" {
int32_t PerceptionAdvertiserInit(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionAdvertiserInit();
}

void PerceptionAdvertiserDeinit(void)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionAdvertiserDeinit();
    }
}

int32_t PerceptionScannerInit(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionScannerInit();
}

void PerceptionScannerDeinit(void)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionScannerDeinit();
    }
}

int32_t PerceptionAdvStart(PerceptionType type, const PerceptionAdvParam *param)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionAdvStart(type, param);
}

int32_t PerceptionAdvSetHighFreq(PerceptionType type, const PerceptionAdvParam *param)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionAdvSetHighFreq(type, param);
}

int32_t PerceptionAdvStop(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionAdvStop();
}

int32_t PerceptionScanStart(PerceptionType type, PerceptionCycle cycle)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionScanStart(type, cycle);
}

int32_t PerceptionScanStop(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionScanStop();
}

int32_t PerceptionScanGetDeviceList(PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->PerceptionScanGetDeviceList(type, list, count);
}

int32_t PerceptionEnhanceInitPacked(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_NOT_IMPLEMENT : p->PerceptionEnhanceInitPacked();
}

void PerceptionEnhanceDeinitPacked(void)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionEnhanceDeinitPacked();
    }
}

bool IsSupportLpFeaturePacked(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? false : p->IsSupportLpFeaturePacked();
}

bool LnnIsLocalSupportBurstFeature(void)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? false : p->LnnIsLocalSupportBurstFeature();
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->LnnGetLocalNumInfo(key, info);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    auto *p = GetPerceptionDepsInterface();
    return p == nullptr ? SOFTBUS_ERR : p->LnnRegisterEventHandler(event, handler);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->LnnUnregisterEventHandler(event, handler);
    }
}

void PerceptionAdvOnBtStateChanged(bool isBtOn)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionAdvOnBtStateChanged(isBtOn);
    }
}

void PerceptionScanOnBtStateChanged(bool isBtOn)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionScanOnBtStateChanged(isBtOn);
    }
}

void PerceptionScanOnScreenStateChanged(bool isScreenOn)
{
    auto *p = GetPerceptionDepsInterface();
    if (p != nullptr) {
        p->PerceptionScanOnScreenStateChanged(isScreenOn);
    }
}
}
} // namespace OHOS
