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

#include "softbus_conn_ble_trans_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBleTransInterface;
ConnectionBleTransInterfaceMock::ConnectionBleTransInterfaceMock()
{
    g_connectionBleTransInterface = reinterpret_cast<void *>(this);
}

ConnectionBleTransInterfaceMock::~ConnectionBleTransInterfaceMock()
{
    g_connectionBleTransInterface = nullptr;
}

static ConnectionBleTransInterface *GetConnectionBleTransInterface()
{
    return reinterpret_cast<ConnectionBleTransInterface *>(g_connectionBleTransInterface);
}

extern "C"
{
ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId)
{
    return GetConnectionBleTransInterface()->ConnBleGetConnectionById(connectionId);
}

int32_t ConnBleSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return GetConnectionBleTransInterface()->ConnBleSend(connection, data, dataLen, module);
}

bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num)
{
    return GetConnectionBleTransInterface()->AddNumberToJsonObject(json, string, num);
}

cJSON *cJSON_CreateObject()
{
    return GetConnectionBleTransInterface()->cJSON_CreateObject();
}

bool AddNumber16ToJsonObject(cJSON *json, const char *const string, uint16_t num)
{
    return GetConnectionBleTransInterface()->AddNumber16ToJsonObject(json, string, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetConnectionBleTransInterface()->cJSON_PrintUnformatted(json);
}
}
}