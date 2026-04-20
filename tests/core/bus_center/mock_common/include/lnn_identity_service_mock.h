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

#ifndef LNN_IDENTITY_SERVICE_MOCK_H
#define LNN_IDENTITY_SERVICE_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_identity_service_adapter.h"
#include "device_auth.h"

namespace OHOS {
class LnnIdentityServiceInterface {
public:
    LnnIdentityServiceInterface() {};
    virtual ~LnnIdentityServiceInterface() {};

    virtual int32_t IdServiceRegCredMgr(void) = 0;
    virtual void IdServiceUnRegCredMgr(void) = 0;
    virtual bool IdServiceIsPotentialTrustedDevice(const char *shortUdidHash,
        const char *shortAccountIdHash, bool isSameAccount) = 0;
    virtual char *IdServiceGetCredIdByCredType(int32_t localUserId, int32_t peerUserId, int32_t credType,
        const char *udidHash) = 0;
    virtual int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam) = 0;
    virtual int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams,
        const DeviceAuthCallback *cb) = 0;
    virtual int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data,
        uint32_t len, DeviceAuthCallback *cb) = 0;
    virtual char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList) = 0;
    virtual void IdServiceDestroyCredentialList(char **returnData) = 0;
    virtual int32_t IdServiceGetCredTypeByCredId(int32_t userId, const char *credId, int32_t *credType) = 0;
    virtual int32_t IdServiceGetCredInfoByUdid(const char *udid, SoftBusCredInfo *credInfo) = 0;
};

class LnnIdentityServiceInterfaceMock : public LnnIdentityServiceInterface {
public:
    LnnIdentityServiceInterfaceMock();
    ~LnnIdentityServiceInterfaceMock() override;
    MOCK_METHOD0(IdServiceRegCredMgr, int32_t());
    MOCK_METHOD0(IdServiceUnRegCredMgr, void());
    MOCK_METHOD3(IdServiceIsPotentialTrustedDevice, bool(const char *, const char *, bool));
    MOCK_METHOD4(IdServiceGetCredIdByCredType, char *(int32_t, int32_t, int32_t, const char *));
    MOCK_METHOD5(IdServiceQueryCredential, int32_t(int32_t, const char *, const char *, bool, char **));
    MOCK_METHOD5(AuthIdServiceQueryCredential, int32_t(int32_t, const char *, const char *, bool, char **));
    MOCK_METHOD1(IdServiceGenerateAuthParam, char *(HiChainAuthParam *));
    MOCK_METHOD4(IdServiceAuthCredential, int32_t(int32_t, int64_t, const char *, const DeviceAuthCallback *));
    MOCK_METHOD4(IdServiceProcessCredData, int32_t(int64_t, const uint8_t *, uint32_t, DeviceAuthCallback *));
    MOCK_METHOD2(IdServiceGetCredIdFromCredList, char *(int32_t, const char *));
    MOCK_METHOD1(IdServiceDestroyCredentialList, void(char **));
    MOCK_METHOD3(IdServiceGetCredTypeByCredId, int32_t(int32_t, const char *, int32_t *));
    MOCK_METHOD2(IdServiceGetCredInfoByUdid, int32_t(const char *, SoftBusCredInfo *));
};
} // namespace OHOS
#endif // LNN_IDENTITY_SERVICE_MOCK_H
