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

#ifndef AUTH_UK_MANAGER_H
#define AUTH_UK_MANAGER_H

#include <securec.h>
#include <stdbool.h>
#include <stdint.h>
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACCOUNT_ID_BUF_LEN 65
#define UK_ENCRYPT_INDEX_LEN (ENCRYPT_INDEX_LEN * 2)
#define UK_ENCRYPT_OVER_HEAD_LEN (OVERHEAD_LEN + UK_ENCRYPT_INDEX_LEN)

typedef struct {
    bool isServer;
    int32_t sourceUserId;
    int32_t sinkUserId;
    int64_t sourceTokenId;
    int64_t sinkTokenId;
    char sourceUdid[UDID_BUF_LEN];
    char sinkUdid[UDID_BUF_LEN];
    char sourceAccountId[ACCOUNT_ID_BUF_LEN];
    char sinkAccountId[ACCOUNT_ID_BUF_LEN];
} AuthACLInfo;

typedef struct {
    bool isRecvSessionKeyEvent;
    bool isRecvFinishEvent;
    bool isRecvCloseAckEvent;
} UkNegotiateInfo;

typedef struct {
    void (*onGenSuccess)(uint32_t requestId, int32_t ukId);
    void (*onGenFailed)(uint32_t requestId, int32_t reason);
} AuthGenUkCallback;

int32_t AuthFindUkIdByAclInfo(const AuthACLInfo *acl, int32_t *ukId);
int32_t AuthGenUkIdByAclInfo(const AuthACLInfo *acl, uint32_t requestId, const AuthGenUkCallback *genCb);
uint32_t AuthGetUkEncryptSize(uint32_t inLen);
uint32_t AuthGetUkDecryptSize(uint32_t inLen);
int32_t AuthEncryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);
int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);
uint32_t GenUkSeq(void);
bool CompareByAllAcl(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide);
bool CompareByAclDiffAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide);
bool CompareByAclDiffAccountWithUserLevel(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide);
bool CompareByAclSameAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide);
bool AuthIsUkExpired(uint64_t time);
int32_t UkNegotiateInit(void);
void UkNegotiateDeinit(void);
void UkNegotiateSessionInit(void);
void PrintfAuthAclInfo(uint32_t requestId, uint32_t channelId, const AuthACLInfo *info);

#ifdef __cplusplus
}
#endif

#endif // AUTH_UK_MANAGER_H