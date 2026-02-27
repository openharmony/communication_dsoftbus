/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef BR_PROXY_STORAGE_H
#define BR_PROXY_STORAGE_H

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "softbus_adapter_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NAME_MAX_LEN        256

typedef struct {
    char bundleName[NAME_MAX_LEN];
    char abilityName[NAME_MAX_LEN];
    int32_t appIndex;
    int32_t userId;
    int32_t uid;
} TransBrProxyStorageInfo;

typedef struct {
    const char *filepath;
    SoftBusMutex mutex;
    bool loaded;
    TransBrProxyStorageInfo info;
} TransBrProxyStorage;

TransBrProxyStorage *TransBrProxyStorageGetInstance(void);
bool TransBrProxyStorageRead(TransBrProxyStorage *instance, TransBrProxyStorageInfo *info);
void TransBrProxyStorageWrite(TransBrProxyStorage *instance, const TransBrProxyStorageInfo *info);
void TransBrProxyStorageClear(TransBrProxyStorage *instance);

#ifdef __cplusplus
}
#endif

#endif // BR_PROXY_STORAGE_H