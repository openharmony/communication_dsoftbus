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

#include "lnn_data_cloud_sync.h"

#include "softbus_error_code.h"

void LnnInitCloudSyncModule(void)
{
    return;
}

void LnnDeInitCloudSyncModule(void)
{
    return;
}

int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnAsyncCallLedgerAllDataSyncToDB(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength)
{
    (void)key;
    (void)value;
    (void)valueLength;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteSyncToDB(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType)
{
    (void)key;
    (void)value;
    (void)changeType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize)
{
    (void)key;
    (void)value;
    (void)keySize;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDBDataChangeSyncToCacheInner(const char *key, const char *value)
{
    (void)key;
    (void)value;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetCloudAbility(const bool isEnableCloud)
{
    (void)isEnableCloud;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteDevInfoSyncToDB(const char *udid, int64_t accountId)
{
    (void)udid;
    (void)accountId;
    return SOFTBUS_NOT_IMPLEMENT;
}