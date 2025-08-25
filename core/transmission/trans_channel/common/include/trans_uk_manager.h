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
#define ENCRYPT_KEY_LENGTH 60 // User Key encrypt SessionKey length
#define BASE64_SESSION_KEY_LEN 45
#define BASE64_ENCRYPT_KEY_LENGTH 83
#define INVALID_USER_ID (-1)

typedef struct {
    int32_t myId;
    int32_t peerId;
} UkIdInfo;

typedef struct {
    ListNode node;
    uint32_t requestId;
    int32_t channelId;
    int32_t channelType;
} UkRequestNode;

int32_t TransUkRequestMgrInit(void);
void TransUkRequestMgrDeinit(void);
int32_t TransUkRequestAddItem(uint32_t requestId, int32_t channelId, int32_t channelType);
int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest);
int32_t TransUkRequestDeleteItem(uint32_t requestId);

int32_t GetUkPolicy(const AppInfo *appInfo);
void FillHapSinkAclInfoToAppInfo(AppInfo *appInfo);

bool IsValidUkInfo(const UkIdInfo *ukIdInfo);

int32_t GetLocalAccountUidByUserId(char *id, uint32_t idLen, uint32_t *len, int32_t userId);
int32_t EncryptAndAddSinkSessionKey(cJSON *msg, const AppInfo *appInfo);
int32_t DecryptAndAddSinkSessionKey(const cJSON *msg, AppInfo *appInfo);
int32_t GetUserkeyIdByAClInfo(
    const AppInfo *appInfo, int32_t channelId, int32_t channelType, int32_t *userKeyId, AuthGenUkCallback *callback);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_UK_MANAGER_H