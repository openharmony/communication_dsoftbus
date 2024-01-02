/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "json_mock.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_wifiDirectInterface;
WifiDirectMock::WifiDirectMock()
{
    g_wifiDirectInterface = reinterpret_cast<void *>(this);
}

WifiDirectMock::~WifiDirectMock()
{
    g_wifiDirectInterface = nullptr;
}

static WifiDirectInterface *GetWifiDirectInterface()
{
    return reinterpret_cast<WifiDirectMock *>(g_wifiDirectInterface);
}

extern "C" {
bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetWifiDirectInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
{
    return GetWifiDirectInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value)
{
    return GetWifiDirectInterface()->AddBoolToJsonObject(json, string, value);
}
} // extern "C"
} // namespace OHOS
