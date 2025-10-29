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

#include "lnn_init_monitor.h"

bool IsLnnInitCheckSucceed(uint32_t netType)
{
    (void)netType;
    return true;
}
void LnnInitMonitorInit(void) { }

void LnnModuleInitMonitorCheckStart(void) { }

void LnnInitModuleStatusSet(uint32_t module, InitDepsStatus status)
{
    (void)module;
    (void)status;
}

void LnnInitModuleReturnSet(uint32_t module, int32_t ret)
{
    (void)module;
    (void)ret;
}

void LnnInitDeviceInfoStatusSet(uint32_t module, InitDepsStatus status)
{
    (void)module;
    (void)status;
}

int32_t LnnInitModuleNotifyWithRetrySync(uint32_t module, ModuleInitCallBack callback, uint32_t retry, uint32_t delay)
{
    (void)module;
    (void)callback;
    (void)retry;
    (void)delay;
    return SOFTBUS_OK;
}

int32_t LnnInitModuleNotifyWithRetryAsync(uint32_t module, ModuleInitCallBack callback, uint32_t retryMax,
    uint32_t delay, bool isFirstDelay)
{
    (void)module;
    (void)callback;
    (void)retryMax;
    (void)delay;
    (void)isFirstDelay;
    return SOFTBUS_OK;
}

void LnnRestartNetwork(void) { }

void LnnInitSetDeviceInfoReady(void) { }