/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_P2P_INFO_H
#define LNN_P2P_INFO_H

#include <stdint.h>

#include "common_list.h"
#include "lnn_node_info.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char udid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    uint64_t createTime;
    uint64_t endTime;
    char ptk[PTK_DEFAULT_LEN];
    ListNode node;
} LocalPtkList;

int32_t LnnInitP2p(void);
void LnnDeinitP2p(void);
int32_t LnnInitLocalP2pInfo(NodeInfo *info);
int32_t LnnSyncP2pInfo(void);
int32_t LnnSyncWifiDirectAddr(void);
int32_t LnnInitWifiDirect(void);
void LnnDeinitWifiDirect(void);
int32_t LnnInitPtk(void);
void LnnDeinitPtk(void);
int32_t LnnGetLocalPtkByUdid(const char *udid, char *localPtk, uint32_t len);
int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
void LnnLoadPtkInfo(void);
int32_t LnnSyncPtk(char *networkId);
int32_t UpdateLocalPtkIfValid(char *udid);
int32_t LnnSetLocalPtkConn(char *udid);
int32_t LnnGenerateLocalPtk(char *udid, char *uuid);

#ifdef __cplusplus
}
#endif

#endif // LNN_P2P_INFO_H