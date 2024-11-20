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

#include "lnn_kv_adapter_wrapper.h"
#include "softbus_error_code.h"

int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen)
{
    (void)dbId;
    (void)appId;
    (void)appIdLen;
    (void)storeId;
    (void)storeIdLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDestroyKvAdapter(int32_t dbId)
{
    (void)dbId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen)
{
    (void)dbId;
    (void)key;
    (void)keyLen;
    (void)value;
    (void)valueLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteDBData(int32_t dbId, const char *key, int32_t keyLen)
{
    (void)dbId;
    (void)key;
    (void)keyLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetDBData(int32_t dbId, const char *key, int32_t keyLen, char **value)
{
    (void)dbId;
    (void)key;
    (void)keyLen;
    (void)value;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen)
{
    (void)dbId;
    (void)keyPrefix;
    (void)keyPrefixLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnCloudSync(int32_t dbId)
{
    (void)dbId;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRegisterDataChangeListener(int32_t dbId, const char *appId, int32_t appIdLen, const char *storeId,
    int32_t storeIdLen)
{
    (void)dbId;
    (void)appId;
    (void)appIdLen;
    (void)storeId;
    (void)storeIdLen;
}

void LnnUnRegisterDataChangeListener(int32_t dbId)
{
    (void)dbId;
}

bool LnnSubcribeKvStoreService(void)
{
    return false;
}

int32_t LnnSetCloudAbilityInner(int32_t dbId, const bool isEnableCloud)
{
    (void)dbId;
    (void)isEnableCloud;
    return SOFTBUS_NOT_IMPLEMENT;
}