/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "auth_attest_interface.h"

#include "softbus_error_code.h"
#include "softbus_error_code.h"
#include <stdint.h>

bool IsSupportUDIDAbatement(void)
{
    return false;
}

bool IsNeedUDIDAbatement(const AuthSessionInfo *info)
{
    (void)info;
    return false;
}

bool CalcHKDF(const uint8_t *ikm, uint32_t ikmLen, uint8_t *out, uint32_t outLen)
{
    (void)ikm;
    (void)ikmLen;
    (void)out;
    (void)outLen;
    return false;
}

int32_t GenerateCertificate(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info)
{
    (void)softbusCertChain;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo, const AuthSessionInfo *info)
{
    (void)softbusCertChain;
    (void)nodeInfo;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    (void)softbusCertChain;
    return SOFTBUS_NOT_IMPLEMENT;
}

void FreeSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    (void)softbusCertChain;
}

bool IsCertAvailable(void)
{
    return true;
}
