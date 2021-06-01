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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_H
#define LNN_DISTRIBUTED_NET_LEDGER_H

#include <pthread.h>
#include <stdint.h>

#include "bus_center_info_key.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INT_TO_STR_SIZE 12
#define INVALID_CONNECTION_CODE_VALUE -1

typedef struct {
    InfoKey key;
    int32_t (*getInfo)(const char *netWorkId, void *info, uint32_t len);
} DistributedLedgerKey;

typedef enum {
    CATEGORY_UDID,
    CATEGORY_UUID,
    CATEGORY_NETWORK_ID,
} IdCategory;

int32_t LnnInitDistributedLedger(void);
void LnnDeinitDistributedLedger(void);
void LnnAddOnlineNode(NodeInfo *info);
void LnnSetNodeOffline(const char *udid);
void LnnRemoveNode(const char *udid);
NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
bool LnnSetDLDeviceInfoName(const char *udid, const char *name);
const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
int32_t LnnGetDLStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len);
int32_t LnnGetDLNumInfo(const char *networkId, InfoKey key, int32_t *info);
short LnnGetCnnCode(const char *uuid, DiscoveryType type);
int32_t LnnGetDistributedNodeInfo(NodeBasicInfo **info, int32_t *infoNum);

#ifdef __cplusplus
}
#endif

#endif // LNN_DISTRIBUTED_NET_LEDGER_H