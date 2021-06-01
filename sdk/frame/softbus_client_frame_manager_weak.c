/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_client_frame_manager_weak.h"
#include "softbus_errcode.h"

int __attribute__ ((weak)) EventClientInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak))EventClientDeinit(void)
{
}

int __attribute__ ((weak)) BusCenterClientInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak))BusCenterClientDeinit(void)
{
}

int __attribute__ ((weak)) DiscClientInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak)) DiscClientDeinit(void)
{
}

int __attribute__ ((weak)) TransClientInit(void)
{
    return SOFTBUS_OK;
}

void __attribute__ ((weak))TransClientDeinit(void)
{
}

