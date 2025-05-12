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

#ifndef TRANS_UK_MANAGER_TEST_MOCK_H
#define TRANS_UK_MANAGER_TEST_MOCK_H

#include <gmock/gmock.h>

#include "auth_uk_manager.h"

namespace OHOS {
class TransUkManagerTestInterface {
public:
    TransUkManagerTestInterface() { };
    virtual ~TransUkManagerTestInterface() { };
    virtual int32_t AuthEncryptByUkId(
        int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen) = 0;
    virtual int32_t AuthDecryptByUkId(
        int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen) = 0;
    virtual int32_t AuthFindUkIdByAclInfo(const AuthACLInfo *acl, int32_t *ukId) = 0;
    virtual int32_t AuthGenUkIdByAclInfo(
        const AuthACLInfo *acl, uint32_t requestId, const AuthGenUkCallback *genCb) = 0;
    virtual int32_t SoftBusBase64Encode(
        unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual int32_t SoftBusBase64Decode(
        unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen) = 0;
};

class TransUkManagerTestInterfaceMock : public TransUkManagerTestInterface {
    public:
    TransUkManagerTestInterfaceMock();
    ~TransUkManagerTestInterfaceMock() override;
    MOCK_METHOD5(AuthEncryptByUkId,
        int32_t (int32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD5(AuthDecryptByUkId,
        int32_t (int32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD2(AuthFindUkIdByAclInfo, int32_t(const AuthACLInfo *, int32_t *));
    MOCK_METHOD3(
        AuthGenUkIdByAclInfo, int32_t(const AuthACLInfo *, uint32_t, const AuthGenUkCallback *));
    MOCK_METHOD5(SoftBusBase64Encode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
};
} // namespace OHOS
#endif // TRANS_UK_MANAGER_TEST_MOCK_H
