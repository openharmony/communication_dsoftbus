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

int32_t SoftBusSetWatchdogTimer(const char *name, uint32_t timeout, void(*func)(void*), void *args)
{
    (void)name;
    (void)timeout;
    (void)func;
    (void)args;
    return -1;
}

void SoftBusCancelWatchdogTimer(int32_t id)
{
    (void)id;
}

void SoftBusRunOneShotTask(const char *name, void(*task)(void), uint64_t delay)
{
    (void)name;
    (void)task;
    (void)delay;
}

void SoftBusRunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay)
{
    (void)name;
    (void)task;
    (void)interval;
    (void)delay;
}
