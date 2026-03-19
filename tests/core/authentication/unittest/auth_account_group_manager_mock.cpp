/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_account_group_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_authAccountManagerMockInterface;
AuthAccountManagerMock::AuthAccountManagerMock()
{
    g_authAccountManagerMockInterface = reinterpret_cast<void *>(this);
}

AuthAccountManagerMock::~AuthAccountManagerMock()
{
    g_authAccountManagerMockInterface = nullptr;
}

static AuthAccountManagerMockInterface *GetMock()
{
    return reinterpret_cast<AuthAccountManagerMockInterface *>(g_authAccountManagerMockInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetMock()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetMock()->AddStringToJsonObject(json, string, value);
}

void cJSON_Delete(cJSON *json)
{
    (void)json;
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetMock()->cJSON_PrintUnformatted(json);
}

int32_t InitDeviceAuthService()
{
    return GetMock()->InitDeviceAuthService();
}

const LightAccountVerifier *GetLightAccountVerifierInstance()
{
    return GetMock()->GetLightAccountVerifierInstance();
}

int32_t JudgeDeviceTypeAndGetOsAccountIds()
{
    return GetMock()->JudgeDeviceTypeAndGetOsAccountIds();
}

} // extern "C"
} // namespace OHOS