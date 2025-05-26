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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_STRUCT_H
#define LNN_DISTRIBUTED_NET_LEDGER_STRUCT_H

#include <stdint.h>
#include "bus_center_info_key_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INT_TO_STR_SIZE 12
#define INVALID_CONNECTION_CODE_VALUE (-1)
#define SHORT_UDID_HASH_LEN 8
#define SHORT_UDID_HASH_HEX_LEN 16
typedef struct {
    InfoKey key;
    int32_t (*getInfo)(const char *netWorkId, bool checkOnline, void *info, uint32_t len);
} DistributedLedgerKey;

typedef struct {
    InfoKey key;
    int32_t (*getInfo)(const char *netWorkId, bool checkOnline, void *info, uint32_t len, int32_t ifnameIdx);
} DistributedLedgerKeyByIfname;

typedef enum {
    CATEGORY_UDID,
    CATEGORY_UUID,
    CATEGORY_NETWORK_ID,
} IdCategory;

typedef enum {
    REPORT_NONE,
    REPORT_CHANGE,
    REPORT_ONLINE,
    REPORT_OFFLINE,
} ReportCategory;

#ifdef __cplusplus
}
#endif

#endif // LNN_DISTRIBUTED_NET_LEDGER_STRUCT_H