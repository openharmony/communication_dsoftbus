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

#include "trans_uk_manager_test_mock.h"

namespace OHOS {
void *g_transUkManagerInterface = nullptr;
TransUkManagerTestInterfaceMock::TransUkManagerTestInterfaceMock()
{
    g_transUkManagerInterface = reinterpret_cast<void *>(this);
}

TransUkManagerTestInterfaceMock::~TransUkManagerTestInterfaceMock()
{
    g_transUkManagerInterface = nullptr;
}

static TransUkManagerTestInterface *GetTransUkManagerTestInterface()
{
    return reinterpret_cast<TransUkManagerTestInterface *>(g_transUkManagerInterface);
}

extern "C" {
int32_t AuthEncryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetTransUkManagerTestInterface()->AuthEncryptByUkId(ukId, inData, inLen, outData, outLen);
}

int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetTransUkManagerTestInterface()->AuthDecryptByUkId(ukId, inData, inLen, outData, outLen);
}

int32_t AuthFindUkIdByAclInfo(const AuthACLInfo *acl, int32_t *ukId)
{
    return GetTransUkManagerTestInterface()->AuthFindUkIdByAclInfo(acl, ukId);
}

int32_t AuthGenUkIdByAclInfo(const AuthACLInfo *acl, uint32_t requestId, const AuthGenUkCallback *genCb)
{
    return GetTransUkManagerTestInterface()->AuthGenUkIdByAclInfo(acl, requestId, genCb);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetTransUkManagerTestInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetTransUkManagerTestInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}
}
} // namespace OHOS