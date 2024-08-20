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

#include "lnn_ohos_account_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneDepsInterface;
LnnOhosAccountInterfaceMock::LnnOhosAccountInterfaceMock()
{
    g_laneDepsInterface = reinterpret_cast<void *>(this);
}

LnnOhosAccountInterfaceMock::~LnnOhosAccountInterfaceMock()
{
    g_laneDepsInterface = nullptr;
}

static LnnOhosAccountInterface *GetLnnOhosAccountInterface()
{
    return reinterpret_cast<LnnOhosAccountInterface *>(g_laneDepsInterface);
}

extern "C" {
int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLnnOhosAccountInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len)
{
    return GetLnnOhosAccountInterface()->GetOsAccountId(id, idLen, len);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGetLocalByteInfo(key, info, len);
}

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    return GetLnnOhosAccountInterface()->UpdateRecoveryDeviceInfoFromDb();
}
}
} // namespace OHOS