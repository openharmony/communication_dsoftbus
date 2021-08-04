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

#ifndef LNN_SYNC_LEDGER_ITEM_INFO_H
#define LNN_SYNC_LEDGER_ITEM_INFO_H

#include <stdint.h>
#include "lnn_distributed_net_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    INFO_TYPE_CAPABILITY = 0,
    INFO_TYPE_CONNECTION_INFO,
    INFO_TYPE_DEVICE_NAME,
    INFO_TYPE_BATTERY_INFO,
    INFO_TYPE_SCREEN_STATUS,
    INFO_TYPE_OFFLINE,
    INFO_TYPE_P2P_INFO,
    INFO_TYPE_MASTER_ELECT,
    INFO_TYPE_COUNT,
} SyncItemType;

typedef struct {
    char udid[UDID_BUF_LEN];
    SyncItemType type;
    uint8_t *buf;
    uint32_t bufLen;
} SyncItemInfo;

typedef struct {
    SyncItemType type;
    SyncItemInfo *(*get)(const char* networkId, DiscoveryType type);
    int32_t (*receive)(uint8_t *msg, uint32_t len, const SyncItemInfo *info);
} ItemFunc;

int32_t LnnSyncLedgerItemInfo(const char *networkId, DiscoveryType discoveryType, SyncItemType itemType);
int32_t LnnInitSyncLedgerItem(void);
void LnnDeinitSyncLedgerItem(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_SYNC_LEDGER_ITEM_INFO_H
