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

#include "softbus_conn_br_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBrInterface;
ConnectionBrInterfaceMock::ConnectionBrInterfaceMock()
{
    g_connectionBrInterface = reinterpret_cast<void *>(this);
}

ConnectionBrInterfaceMock::~ConnectionBrInterfaceMock()
{
    g_connectionBrInterface = nullptr;
}

static ConnectionBrInterface *GetConnectionBrInterface()
{
    return reinterpret_cast<ConnectionBrInterface *>(g_connectionBrInterface);
}

extern "C" {
bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetConnectionBrInterface()->GetJsonObjectSignedNumberItem(json, string, target);
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    return GetConnectionBrInterface()->GetJsonObjectNumber64Item(json, string, target);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetConnectionBrInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num)
{
    return GetConnectionBrInterface()->AddNumber64ToJsonObject(json, string, num);
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return GetConnectionBrInterface()->cJSON_ParseWithLength(value, buffer_length);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetConnectionBrInterface()->GetJsonObjectNumberItem(json, string, target);
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetConnectionBrInterface()->SoftBusGetBtMacAddr(mac);
}
}
}