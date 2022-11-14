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
#include <cstdint>
#include "xcollie_helper.h"
int SetTimer(const char *name, unsigned int timeout, void(*func)(void*), void *args)
{
    (void)name;
    (void)timeout;
    (void)func;
    (void)args;
    return -1;
}

void CancelTimer(int id)
{
    (void)id;
    return;
}

void RunOneShotTask(const char *name, void(*task)(void), uint64_t delay)
{
    (void)name;
    (void)task;
    (void)delay;
    return;
}

void RunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay)
{
    (void)name;
    (void)task;
    (void)interval;
    (void)delay;
    return;
}
