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

#include "conn_ble_trans_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connBleTransInterface;

ConnBleTransInterfaceMock::ConnBleTransInterfaceMock()
{
    g_connBleTransInterface = reinterpret_cast<void *>(this);
}

ConnBleTransInterfaceMock::~ConnBleTransInterfaceMock()
{
    g_connBleTransInterface = nullptr;
}

static ConnBleTransInterface *GetConnBleTransInterface()
{
    return reinterpret_cast<ConnBleTransInterface *>(g_connBleTransInterface);
}

extern "C"
{
ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId)
{
    return GetConnBleTransInterface()->ConnBleGetConnectionById(connectionId);
}

int32_t ConnBleSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return GetConnBleTransInterface()->ConnBleSend(connection, data, dataLen, module);
}

bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num)
{
    return GetConnBleTransInterface()->AddNumberToJsonObject(json, string, num);
}

cJSON *cJSON_CreateObject()
{
    return GetConnBleTransInterface()->cJSON_CreateObject();
}

bool AddNumber16ToJsonObject(cJSON *json, const char *const string, uint16_t num)
{
    return GetConnBleTransInterface()->AddNumber16ToJsonObject(json, string, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetConnBleTransInterface()->cJSON_PrintUnformatted(json);
}
}
}
