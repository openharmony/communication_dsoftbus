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

#include "trans_tcp_direct_json_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_transTcpDirectJsonInterface;
TransTcpDirectJsonInterfaceMock::TransTcpDirectJsonInterfaceMock()
{
    g_transTcpDirectJsonInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectJsonInterfaceMock::~TransTcpDirectJsonInterfaceMock()
{
    g_transTcpDirectJsonInterface = nullptr;
}

static TransTcpDirectJsonInterface *GetTransTcpDirectJsonInterface()
{
    return reinterpret_cast<TransTcpDirectJsonInterface *>(g_transTcpDirectJsonInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetTransTcpDirectJsonInterface()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetTransTcpDirectJsonInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num)
{
    return GetTransTcpDirectJsonInterface()->AddNumberToJsonObject(json, string, num);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetTransTcpDirectJsonInterface()->GetJsonObjectNumberItem(json, string, target);
}

bool GetJsonObjectStringItem(
    const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetTransTcpDirectJsonInterface()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target)
{
    return GetTransTcpDirectJsonInterface()->GetJsonObjectInt32Item(json, string, target);
}

bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target)
{
    return GetTransTcpDirectJsonInterface()->GetJsonObjectBoolItem(json, string, target);
}

void cJSON_Delete(cJSON *json) {}
}
}

