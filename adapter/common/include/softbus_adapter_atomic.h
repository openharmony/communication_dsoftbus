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

#ifndef SOFTBUS_ADAPTER_ATOMIC_H
#define SOFTBUS_ADAPTER_ATOMIC_H

#include "stdbool.h"
#include "stdint.h"
#include "stdio.h"

static inline void SoftBusAtomicAdd32(volatile uint32_t* ptr, uint32_t value)
{
#ifdef _WIN32
    InterlockedExchangeAdd(ptr, value);
#elif defined __linux__ || defined __LITEOS__ || defined __APPLE__
    __sync_fetch_and_add(ptr, value);
#endif
}

static inline uint32_t SoftBusAtomicAddAndFetch32(volatile uint32_t* ptr, uint32_t value)
{
#ifdef _WIN32
    return InterlockedExchangeAdd(ptr, value) + value;
#elif defined __linux__ || defined __LITEOS__ || defined __APPLE__
    return __sync_add_and_fetch(ptr, value);
#else
    return -1;
#endif
}

static inline void SoftBusAtomicAdd64(uint64_t* ptr, uint64_t value)
{
#ifdef _WIN32
    InterlockedExchangeAdd64((volatile long long*)ptr, value);
#elif defined __linux__ || defined __LITEOS__ || defined __APPLE__
    __sync_fetch_and_add(ptr, value);
#endif
}

static inline bool SoftBusAtomicCmpAndSwap32(volatile uint32_t* ptr, uint32_t oldValue, uint32_t newValue)
{
#ifdef _WIN32
    uint32_t initial = InterlockedCompareExchange(ptr, newValue, oldValue);
    return initial == oldValue;
#elif defined __linux__ || defined __LITEOS__ || defined __APPLE__
    return __sync_bool_compare_and_swap(ptr, oldValue, newValue);
#else
    return false;
#endif
}
#endif // SOFTBUS_ADAPTER_ATOMIC_H