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

#include <dlfcn.h>
#include "stdint.h"
#include "stdbool.h"
#include "softbus_error_code.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef SOFTBUS_INIT_COMMON_H
#define SOFTBUS_INIT_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

bool SoftbusServerPluginLoadedFlagGet(void);
bool SoftbusClientPluginLoadedFlagGet(void);
void SoftbusServerPluginLoadedFlagSet(bool soLoadFlag);
void SoftbusClientPluginLoadedFlagSet(bool soLoadFlag);
int32_t SoftBusDlopen(const char *DllName, void **DllHandle);
int32_t SoftBusDlsym(const void *DllHandle, const char *funcName, void **funcHandle);
void SoftBusDlclose(const void *DllHandle);
int32_t LnnCheckFuncPointer(void *func);
int32_t ConnCheckFuncPointer(void *func);
int32_t DiscCheckFuncPointer(void *func);
int32_t TransCheckFuncPointer(void *func);
int32_t AuthCheckFuncPointer(void *func);
int32_t AdapterCheckFuncPointer(void *func);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_INIT_COMMON_H */