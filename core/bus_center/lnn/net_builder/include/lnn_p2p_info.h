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
#include "softbus_common.h"
#include "softbus_json_utils.h"

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
int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len);
void LnnLoadPtkInfo(void);
int32_t LnnSyncPtk(const char *networkId);
int32_t UpdateLocalPtkIfValid(char *udid);
int32_t LnnSetLocalPtkConn(char *udid);
int32_t LnnGenerateLocalPtk(char *udid, char *uuid);
int32_t LnnGenerateMetaPtk(uint32_t connId);
int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len);
int32_t LnnDeleteMetaPtk(uint32_t connectionId);
int32_t UpdatePtkByAuth(char *networkId, AuthHandle authHandle);

#ifdef __cplusplus
}
#endif

#endif // LNN_P2P_INFO_H