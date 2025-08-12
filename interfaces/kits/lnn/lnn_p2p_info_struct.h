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

#ifndef LNN_P2P_INFO_STRUCT_H
#define LNN_P2P_INFO_STRUCT_H

#include <stdint.h>

#include "common_list.h"
#include "lnn_node_info_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSG_FLAG_REQUEST 0
#define MES_FLAG_REPLY 1

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char ptk[PTK_DEFAULT_LEN];
    ListNode node;
} PtkSyncInfo;

typedef struct {
    char udid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    char ptk[PTK_DEFAULT_LEN];
    uint64_t createTime;
    uint64_t endTime;
    ListNode node;
} LocalPtkList;

typedef struct {
    uint32_t connId;
    char ptk[PTK_DEFAULT_LEN];
    ListNode node;
} LocalMetaList;

#ifdef __cplusplus
}
#endif

#endif // LNN_P2P_INFO_STRUCT_H