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

#include "lnn_identity_service_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_identityServiceInterface;

LnnIdentityServiceInterfaceMock::LnnIdentityServiceInterfaceMock()
{
    g_identityServiceInterface = reinterpret_cast<void *>(this);
}

LnnIdentityServiceInterfaceMock::~LnnIdentityServiceInterfaceMock()
{
    g_identityServiceInterface = nullptr;
}

static LnnIdentityServiceInterface *GetIdentityServiceInterface()
{
    return reinterpret_cast<LnnIdentityServiceInterfaceMock *>(g_identityServiceInterface);
}

extern "C" {
int32_t IdServiceRegCredMgr(void)
{
    return GetIdentityServiceInterface()->IdServiceRegCredMgr();
}

void IdServiceUnRegCredMgr(void)
{
    return GetIdentityServiceInterface()->IdServiceUnRegCredMgr();
}

bool IdServiceIsPotentialTrustedDevice(const char *shortUdidHash, const char *shortAccountIdHash, bool isSameAccount)
{
    return GetIdentityServiceInterface()->IdServiceIsPotentialTrustedDevice(shortUdidHash,
        shortAccountIdHash, isSameAccount);
}

char *IdServiceGetCredIdByCredType(int32_t localUserId, int32_t peerUserId, int32_t credType, const char *udidHash)
{
    return GetIdentityServiceInterface()->IdServiceGetCredIdByCredType(localUserId,
        peerUserId, credType, udidHash);
}

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    return GetIdentityServiceInterface()->IdServiceQueryCredential(userId, udidHash,
        accountidHash, isSameAccount, credList);
}

int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    return GetIdentityServiceInterface()->AuthIdServiceQueryCredential(peerUserId, udidHash,
        accountidHash, isSameAccount, credList);
}

char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam)
{
    return GetIdentityServiceInterface()->IdServiceGenerateAuthParam(hiChainParam);
}

int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *cb)
{
    return GetIdentityServiceInterface()->IdServiceAuthCredential(userId, authReqId, authParams, cb);
}

int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    return GetIdentityServiceInterface()->IdServiceProcessCredData(authSeq, data, len, cb);
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    return GetIdentityServiceInterface()->IdServiceGetCredIdFromCredList(userId, credList);
}

void IdServiceDestroyCredentialList(char **returnData)
{
    return GetIdentityServiceInterface()->IdServiceDestroyCredentialList(returnData);
}

int32_t IdServiceGetCredTypeByCredId(int32_t userId, const char *credId, int32_t *credType)
{
    return GetIdentityServiceInterface()->IdServiceGetCredTypeByCredId(userId, credId, credType);
}

int32_t IdServiceGetCredInfoByUdid(const char *udid, SoftBusCredInfo *credInfo)
{
    return GetIdentityServiceInterface()->IdServiceGetCredInfoByUdid(udid, credInfo);
}
} // extern "C"
} // namespace OHOS
