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

#ifndef LNN_SLE_CAPABILITY_H
#define LNN_SLE_CAPABILITY_H

#include <stdint.h>
#include "lnn_node_info.h"
#include "lnn_sync_info_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_KEY_SLE_MAC "SLE_MAC"
#define JSON_KEY_SLE_CAP "SLE_CAP"

int32_t SetSleRangeCapToLocalLedger(void);
int32_t SetSleAddrToLocalLedger(void);

int32_t LocalLedgerInitSleCapacity(NodeInfo *nodeInfo);
void LocalLedgerDeinitSleCapacity(void);
void OnReceiveSleMacChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size);
void LnnSendSleInfoForAllNode(void);

int32_t LnnInitSleInfo(void);
void LnnDeinitSleInfo(void);

#ifdef __cplusplus
}
#endif
#endif // LNN_SLE_CAPABILITY_H