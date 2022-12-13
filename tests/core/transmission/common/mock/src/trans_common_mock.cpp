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

#include "trans_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_commonInterface = nullptr;

TransCommInterfaceMock::TransCommInterfaceMock()
{
    g_commonInterface = reinterpret_cast<void *>(this);
}

TransCommInterfaceMock::~TransCommInterfaceMock()
{
    g_commonInterface = nullptr;
}

static TransCommInterfaceMock *GetCommonInterface()
{
    return reinterpret_cast<TransCommInterfaceMock *>(g_commonInterface);
}

extern "C" {
int32_t GenerateRandomStr(char *str, uint32_t len)
{
    return GetCommonInterface()->GenerateRandomStr(str, len);
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetCommonInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetCommonInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetCommonInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

int32_t SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen, int32_t seqNum)
{
    return GetCommonInterface()->SoftBusEncryptDataWithSeq(cipherKey, input, inLen, encryptData, encryptLen, seqNum);
}

int32_t SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen, int32_t seqNum)
{
    return GetCommonInterface()->SoftBusDecryptDataWithSeq(cipherKey, input, inLen, decryptData, decryptLen, seqNum);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetCommonInterface()->SoftBusGenerateStrHash(str, len, hash);
}
}
}
