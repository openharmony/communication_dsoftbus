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

#ifndef TRANS_UK_MANAGER_H
#define TRANS_UK_MANAGER_H

#include "auth_uk_manager.h"
#include "cJSON.h"
#include "softbus_app_info.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NO_NEED_UK   0
#define USE_NEGO_UK  1

typedef struct {
    int32_t myId;
    int32_t peerId;
} UkIdInfo;

typedef struct {
    ListNode node;
    uint32_t requestId;
    int32_t channelId;
    uint32_t connId;
    int32_t pid;
    uint64_t seq;
    AuthHandle authHandle;
    AuthACLInfo aclInfo;
} UkRequestNode;

char *PackUkRequest(const AppInfo *appInfo);
int32_t UnPackUkRequest(const cJSON *msg, AuthACLInfo *aclInfo, char *sessionName);
char *PackUkReply(const AuthACLInfo *aclInfo, int32_t ukId);
int32_t UnPackUkReply(const cJSON *msg, AuthACLInfo *aclInfo, int32_t *sinkUkId);

int32_t TransUkRequestMgrInit(void);
void TransUkRequestMgrDeinit(void);
int32_t TransUkRequestAddItem(
    uint32_t requestId, int32_t channelId, int32_t connId, int32_t pid, const AuthACLInfo *aclInfo);
int32_t TransUkRequestSetAuthHandleAndSeq(uint32_t requestId, const AuthHandle *authHandle, uint64_t seq);
int32_t TransUkRequestGetTcpInfoByRequestId(uint32_t requestId, AuthACLInfo *aclInfo, int32_t *channelId);
int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest);
int32_t TransUkRequestDeleteItem(uint32_t requestId);

int32_t GetUkPolicy(const AppInfo *appInfo);
int32_t GetSourceAndSinkUdid(const char *peerNetWorkId, char *sourceUdid, char *sinkUdid);
int32_t FillSinkAclInfo(const char *sessionName, AuthACLInfo *aclInfo, int32_t *pid);
bool SpecialSaCanUseDeviceKey(uint64_t tokenId);
bool IsValidUkInfo(const UkIdInfo *ukIdInfo);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_UK_MANAGER_H