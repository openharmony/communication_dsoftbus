/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "auth_channel_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authChannelInterface;
AuthChannelInterfaceMock::AuthChannelInterfaceMock()
{
    g_authChannelInterface = reinterpret_cast<void *>(this);
}

AuthChannelInterfaceMock::~AuthChannelInterfaceMock()
{
    g_authChannelInterface = nullptr;
}

static AuthChannelInterface *GetAuthChannelInterface()
{
    return reinterpret_cast<AuthChannelInterface *>(g_authChannelInterface);
}

extern "C" {
int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback)
{
    return GetAuthChannelInterface()->LnnServerJoinExt(addr, callback);
}

bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num)
{
    return GetAuthChannelInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t GenerateRandomStr(char *str, uint32_t size)
{
    return GetAuthChannelInterface()->GenerateRandomStr(str, size);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetAuthChannelInterface()->AddStringToJsonObject(json, string, value);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetAuthChannelInterface()->cJSON_PrintUnformatted(json);
}
}
}
