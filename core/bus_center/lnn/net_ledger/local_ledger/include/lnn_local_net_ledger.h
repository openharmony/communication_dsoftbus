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

#ifndef LNN_LOCAL_NET_LEDGER_H
#define LNN_LOCAL_NET_LEDGER_H

#include <pthread.h>
#include <stdint.h>

#include "bus_center_info_key.h"
#include "lnn_device_info.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LL_INIT_UNKNOWN = 0,
    LL_INIT_FAIL,
    LL_INIT_SUCCESS,
} LocalLedgerStatus;

typedef struct {
    InfoKey key;
    int32_t maxLen;
    int32_t (*getInfo)(void *info, uint32_t len);
    int32_t (*setInfo)(const void *info);
} LocalLedgerKey;

int32_t LnnInitLocalLedger(void);
void LnnDeinitLocalLedger(void);
const NodeInfo *LnnGetLocalNodeInfo(void);
int32_t LnnGetLocalLedgerStrInfo(InfoKey key, char *info, uint32_t len);
int32_t LnnGetLocalLedgerNumInfo(InfoKey key, int32_t *info);
int32_t LnnSetLocalLedgerStrInfo(InfoKey key, const char *info);
int32_t LnnSetLocalLedgerNumInfo(InfoKey key, int32_t info);

#ifdef __cplusplus
}
#endif

#endif // LNN_LOCAL_NET_LEDGER_H