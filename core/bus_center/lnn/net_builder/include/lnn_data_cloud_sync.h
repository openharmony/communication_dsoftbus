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

#ifndef LNN_DATA_CLOUD_SYNC_H
#define LNN_DATA_CLOUD_SYNC_H

#include "lnn_node_info.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"
#include "lnn_data_cloud_sync_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

void LnnInitCloudSyncModule(void);
void LnnDeInitCloudSyncModule(void);
int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info, bool isAckSeq, char *peerudid);
int32_t LnnAsyncCallLedgerAllDataSyncToDB(NodeInfo *info);
int32_t LnnLedgerDataChangeSyncToDB(const char *key, const char *value, size_t valueLength);
int32_t LnnDeleteSyncToDB(void);
int32_t LnnDeleteDevInfoSyncToDB(const char *udid, int64_t accountId);
int32_t LnnDBDataChangeSyncToCache(const char *key, const char *value, ChangeType changeType);
int32_t LnnDBDataAddChangeSyncToCache(const char **key, const char **value, int32_t keySize);
int32_t LnnDBDataChangeSyncToCacheInner(const char *key, const char *value);
int32_t LnnSetCloudAbility(const bool isEnableCloud);
#ifdef __cplusplus
}
#endif

#endif // LNN_DATA_CLOUD_SYNC_H
