/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LNN_KV_ADAPTER_WRAPPER_H
#define LNN_KV_ADAPTER_WRAPPER_H

#include "lnn_data_cloud_sync.h"
#ifdef __cplusplus

extern "C" {
#endif
int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen);
int32_t LnnDestroyKvAdapter(int32_t dbId);
void LnnRegisterDataChangeListener(int32_t dbId, const char *appId, int32_t appIdLen, const char *storeId,
    int32_t storeIdLen);
void LnnUnRegisterDataChangeListener(int32_t dbId);
int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen);
int32_t LnnDeleteDBData(int32_t dbId, const char *key, int32_t keyLen);
int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen);
// *value need to be free by caller
int32_t LnnGetDBData(int32_t dbId, const char *key, int32_t keyLen, char **value);
int32_t LnnCloudSync(int32_t dbId);
int32_t LnnSetCloudAbilityInner(int32_t dbId, const bool isEnableCloud);
void LnnClearRedundancyCache(void);
bool LnnSubcribeKvStoreService(void);
#ifdef __cplusplus
};
#endif

#endif // LNN_KV_ADAPTER_WRAPPER_H
