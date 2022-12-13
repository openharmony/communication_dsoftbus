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

#ifndef TRANS_COMMON_MOCK_H
#define TRANS_COMMON_MOCK_H

#include <gmock/gmock.h>

#include "softbus_utils.h"
#include "softbus_adapter_crypto.h"

namespace OHOS {
class TransCommInterface {
public:
    TransCommInterface() {};
    virtual ~TransCommInterface() {};

    virtual int32_t GenerateRandomStr(char *str, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len) = 0;

    virtual int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;

    virtual int32_t SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey,
        const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen, int32_t seqNum) = 0;

    virtual int32_t SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey,
        const unsigned char *input, uint32_t inLen,
        unsigned char *decryptData, uint32_t *decryptLen, int32_t seqNum) = 0;

    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
};

class TransCommInterfaceMock : public TransCommInterface {
public:
    TransCommInterfaceMock();
    ~TransCommInterfaceMock() override;

    MOCK_METHOD2(GenerateRandomStr, int32_t (char *, uint32_t));
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t (unsigned char *, uint32_t));

    MOCK_METHOD5(SoftBusBase64Encode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));

    MOCK_METHOD6(SoftBusEncryptDataWithSeq, int32_t (AesGcmCipherKey *, const unsigned char *, uint32_t,
        unsigned char *, uint32_t *, int32_t));
    MOCK_METHOD6(SoftBusDecryptDataWithSeq, int32_t (AesGcmCipherKey *, const unsigned char *, uint32_t,
        unsigned char *, uint32_t *, int32_t));

    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
};

} // namespace OHOS
#endif // TRANS_COMMON_MOCK_H
