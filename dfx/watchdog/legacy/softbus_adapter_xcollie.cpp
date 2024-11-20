/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "legacy/softbus_adapter_xcollie.h"

#include "comm_log.h"
#include "softbus_error_code.h"
#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"

int32_t SoftBusSetWatchdogTimer(const char *name, uint32_t timeout, void (*func)(void *), void *args)
{
    if (name == nullptr || func == nullptr || args == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "SoftBus Set Watchdog Timer param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    return OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(
        name, timeout, func, args, OHOS::HiviewDFX::XCOLLIE_FLAG_LOG);
}

void SoftBusCancelWatchdogTimer(int32_t id)
{
    OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(id);
}

void SoftBusRunOneShotTask(const char *name, void (*task)(void), uint64_t delay)
{
    if (name == nullptr || task == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "SoftBus Run Shot Watchdog Task param is invalid.");
        return;
    }
    OHOS::HiviewDFX::Watchdog::GetInstance().RunOneShotTask(name, task, delay);
}

void SoftBusRunPeriodicalTask(const char *name, void (*task)(void), uint64_t interval, uint64_t delay)
{
    if (name == nullptr || task == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "SoftBus Run Periodical Watchdog Task param is invalid");
        return;
    }
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(name, task, interval, delay);
}
