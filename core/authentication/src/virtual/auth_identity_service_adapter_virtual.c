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

#include "auth_identity_service_adapter.h"
#include "auth_log.h"
#include "softbus_error_code.h"

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    (void)userId;
    (void)udidHash;
    (void)accountidHash;
    (void)isSameAccount;
    (void)credList;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    (void)peerUserId;
    (void)udidHash;
    (void)accountidHash;
    (void)isSameAccount;
    (void)credList;
    return SOFTBUS_NOT_IMPLEMENT;
}

void IdServiceDestroyCredentialList(char **returnData)
{
    (void)returnData;
    return;
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    (void)userId;
    (void)credList;
    return NULL;
}

char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam)
{
    (void)hiChainParam;
    return NULL;
}

int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb)
{
    (void)userId;
    (void)authReqId;
    (void)authParams;
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    (void)authSeq;
    (void)data;
    (void)len;
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IdServiceIsPotentialTrustedDevice(const char *udidHash, const char *accountIdHash, bool isSameAccount)
{
    (void)udidHash;
    (void)accountIdHash;
    (void)isSameAccount;
    return false;
}

int32_t IdServiceRegCredMgr(void)
{
    AUTH_LOGI(AUTH_HICHAIN, "id service reg cred manager not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

void IdServiceUnRegCredMgr(void)
{
    AUTH_LOGI(AUTH_HICHAIN, "id service unreg cred manager not implement");
    return;
}