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

#ifndef LNN_LOCAL_NET_LEDGER_STRUCT_H
#define LNN_LOCAL_NET_LEDGER_STRUCT_H

#include <stdint.h>

#include "bus_center_info_key_struct.h"

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

typedef struct {
    InfoKey key;
    int32_t maxLen;
    int32_t (*getInfo)(void *info, uint32_t len, int32_t ifnameIdx);
    int32_t (*setInfo)(const void *info, int32_t ifnameIdx);
} LocalLedgerKeyByIfname;

typedef enum {
    UPDATE_ACCOUNT_LONG = 1,
    UPDATE_DEV_NAME = 2,
    UPDATE_DEV_UNIFIED_NAME = 4,
    UPDATE_DEV_UNIFIED_DEFAULT_NAME = 8,
    UPDATE_DEV_NICK_NAME = 16,
    UPDATE_NETWORKID = 32,
    UPDATE_CONCURRENT_AUTH = 64,
    UPDATE_CIPHERKEY = 128,
    UPDATE_SLE_CAP = 256,
} StateVersionChangeReason;

#ifdef __cplusplus
}
#endif

#endif // LNN_LOCAL_NET_LEDGER_STRUCT_H