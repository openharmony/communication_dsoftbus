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

#include "auth_hichain_id_service_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_hichainMockIdInterface;
AuthHichainIdServiceInterfaceMock::AuthHichainIdServiceInterfaceMock()
{
    g_hichainMockIdInterface = reinterpret_cast<void *>(this);
}

AuthHichainIdServiceInterfaceMock::~AuthHichainIdServiceInterfaceMock()
{
    g_hichainMockIdInterface = nullptr;
}

static AuthHichainIdServiceInterface *GetAuthHichainIdServiceInterfaceMock()
{
    return reinterpret_cast<AuthHichainIdServiceInterfaceMock *>(g_hichainMockIdInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetAuthHichainIdServiceInterfaceMock()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetAuthHichainIdServiceInterfaceMock()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetAuthHichainIdServiceInterfaceMock()->AddNumberToJsonObject(json, string, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetAuthHichainIdServiceInterfaceMock()->cJSON_PrintUnformatted(json);
}

int32_t InitDeviceAuthService()
{
    return GetAuthHichainIdServiceInterfaceMock()->InitDeviceAuthService();
}

const CredManager *GetCredMgrInstance()
{
    return GetAuthHichainIdServiceInterfaceMock()->GetCredMgrInstance();
}

const CredAuthManager *GetCredAuthInstance()
{
    return GetAuthHichainIdServiceInterfaceMock()->GetCredAuthInstance();
}

void GetSoftbusHichainAuthErrorCode(uint32_t hichainErrCode, uint32_t *softbusErrCode)
{
    *softbusErrCode = hichainErrCode;
    return;
}

} // extern "C"
} // namespace OHOS