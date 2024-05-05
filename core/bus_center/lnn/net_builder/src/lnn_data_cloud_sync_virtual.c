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

#include "lnn_log.h"
#include "softbus_errcode.h"

void LnnInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnInitCloudSyncModule not supported");
    return;
}

void LnnDeInitCloudSyncModule(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnDeInitCloudSyncModule not supported");
    return;
}

int32_t LnnLedgerAllDataSyncToDB(const NodeInfo *info)
{
    (void) info;
    LNN_LOGI(LNN_BUILDER, "LnnLedgerAllDataSyncToDB not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength)
{
    (void) key;
    (void) value;
    (void) valueLength;
    LNN_LOGI(LNN_BUILDER, "LnnLedgerDataChangeSyncToDB not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteSyncToDB(void)
{
    LNN_LOGI(LNN_BUILDER, "LnnDeleteSyncToDB not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType)
{
    (void) key;
    (void) value;
    (void) changeType;
    LNN_LOGI(LNN_BUILDER, "LnnDBDataChangeSyncToCache not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize)
{
    (void) key;
    (void) value;
    (void) keySize;
    LNN_LOGI(LNN_BUILDER, "LnnDBDataAddChangeSyncToCache not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAccountIdfromLocalCache(int64_t *buf)
{
    (void) buf;
    LNN_LOGI(LNN_BUILDER, "LnnGetAccountIdfromLocalCache not supported");
    return SOFTBUS_NOT_IMPLEMENT;
}