/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_CPU_H
#define SOFTBUS_ADAPTER_CPU_H

#ifndef _WIN32
#include <sched.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _WIN32
#define BARRIER()
#define MB() BARRIER()
#define WMB() BARRIER()
#define RMB() BARRIER()
#elif defined(__ICCARM__) || defined(__x86_64__)
#define MB()
#define WMB()
#define RMB()
#elif defined __linux__ || defined __LITEOS__ || defined __APPLE__
#define DSB() __asm__ volatile("dsb" ::: "memory")
#ifdef __riscv
#define DMB() __asm__ __volatile__ ("fence iorw,iorw" ::: "memory")
#elif __aarch64__
#define DMB() __asm__ volatile("DMB ISHLD" : : : "memory")
#else
#define DMB() __asm__ volatile("dmb" ::: "memory")
#endif
#define ISB() __asm__ volatile("isb" ::: "memory")
#define BARRIER() __asm__ volatile("" ::: "memory")

#define MB() DMB()
#define WMB() DMB()
#define RMB() DMB()
#else
#define MB()
#define WMB()
#define RMB()
#endif

#ifdef _WIN32
#define SoftBusYieldCpu()
#else
#define SoftBusYieldCpu() sched_yield()
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif // SOFTBUS_ADAPTER_CPU_H