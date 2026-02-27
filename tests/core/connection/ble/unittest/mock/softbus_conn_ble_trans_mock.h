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

#ifndef CONNECTION_BLE_TRANS_MOCK_H
#define CONNECTION_BLE_TRANS_MOCK_H

#include <gmock/gmock.h>
#include "conn_log.h"
#include "softbus_conn_ble_connection.h"

namespace OHOS {
class ConnectionBleTransInterface {
public:
    ConnectionBleTransInterface(){};
    virtual ~ConnectionBleTransInterface(){};

    virtual ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId) = 0;
    virtual int32_t ConnBleSend(
        ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num) = 0;
    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddNumber16ToJsonObject(cJSON *json, const char *const string, uint16_t num) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
};

class ConnectionBleTransInterfaceMock : public ConnectionBleTransInterface {
public:
    ConnectionBleTransInterfaceMock();
    ~ConnectionBleTransInterfaceMock() override;

    MOCK_METHOD(ConnBleConnection *, ConnBleGetConnectionById, (uint32_t), (override));
    MOCK_METHOD(int32_t, ConnBleSend, (ConnBleConnection *, const uint8_t *, uint32_t, int32_t), (override));
    MOCK_METHOD(bool, AddNumberToJsonObject, (cJSON *, const char *const, int32_t), (override));
    MOCK_METHOD(cJSON *, cJSON_CreateObject, (), (override));
    MOCK_METHOD(bool, AddNumber16ToJsonObject, (cJSON *, const char *const, uint16_t), (override));
    MOCK_METHOD(char *, cJSON_PrintUnformatted, (const cJSON *), (override));
};
} // namespace OHOS
#endif // CONNECTION_BLE_TRANS_MOCK_H