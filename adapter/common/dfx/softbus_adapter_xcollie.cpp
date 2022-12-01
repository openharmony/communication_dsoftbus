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

#include "softbus_adapter_xcollie.h"

#include <cstdint>

#include "softbus_adapter_log.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"

NO_SANITIZE("cfi") int32_t SoftBusSetWatchdogTimer(const char *name, uint32_t timeout, void(*func)(void*), void *args)
{
    if (name == NULL || func == NULL || args == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBus Set Watchdog Timer param is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    return OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, func,
        args, OHOS::HiviewDFX::XCOLLIE_FLAG_LOG);
}

NO_SANITIZE("cfi") void SoftBusCancelWatchdogTimer(int32_t id)
{
    OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(id);
}

NO_SANITIZE("cfi") void SoftBusRunOneShotTask(const char *name, void(*task)(void), uint64_t delay)
{
    if (name == NULL || task == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBus Run Shot Watchdog Task param is invalid.");
        return;
    }
    OHOS::HiviewDFX::Watchdog::GetInstance().RunOneShotTask(name, task, delay);
}

NO_SANITIZE("cfi") void SoftBusRunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay)
{
    if (name == NULL || task == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBus Run Periodical Watchdog Task param is invalid");
        return;
    }
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(name, task, interval, delay);
}
