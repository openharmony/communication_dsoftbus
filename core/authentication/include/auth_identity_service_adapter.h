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

#ifndef AUTH_IDENTITY_SERVICE_ADAPTER_H
#define AUTH_IDENTITY_SERVICE_ADAPTER_H

#include "auth_hichain.h"
#include "device_auth.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int32_t credIdType;
    int32_t subject;
    char udid[UDID_BUF_LEN];
    char userId[MAX_ACCOUNT_HASH_LEN];
} SoftBusCredInfo;

int32_t IdServiceRegCredMgr(void);
void IdServiceUnRegCredMgr(void);
bool IdServiceIsPotentialTrustedDevice(const char *udidHash, const char *accountIdHash, bool isSameAccount);

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList);
int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList);
char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam);
int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *cb);
int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb);
char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList);
void IdServiceDestroyCredentialList(char **returnData);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_IDENTITY_SERVICE_ADAPTER_H */