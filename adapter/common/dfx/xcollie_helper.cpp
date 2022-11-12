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
#include "xcollie_helper.h"
#include <cstdint>
#include "softbus_log.h"

#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"

int SetTimer(const char *name, unsigned int timeout, void(*func)(void*), void *args)
{
    return OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, func,
        args, OHOS::HiviewDFX::XCOLLIE_FLAG_LOG);
}

void CancelTimer(int id)
{
    return OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(id);
}

void RunOneShotTask(const char *name, void(*task)(void), uint64_t delay)
{
    return OHOS::HiviewDFX::Watchdog::GetInstance().RunOneShotTask(name, task, delay);
}

void RunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay)
{
    return OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(name, task, interval, delay);
}
