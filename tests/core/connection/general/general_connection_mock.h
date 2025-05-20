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

#ifndef GENERAL_CONNECTION_MOCK_H
#define GENERAL_CONNECTION_MOCK_H

#include <gmock/gmock.h>

#include "conn_log.h"
#include "softbus_conn_ble_connection.h"
#include "bus_center_info_key.h"

namespace OHOS {
class GeneralConnectionInterface {
public:
    GeneralConnectionInterface() {};
    virtual ~GeneralConnectionInterface() {};
    virtual ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t BleConnectDeviceMock(const ConnectOption *option,
        uint32_t requestId, const ConnectResult *result) = 0;
    virtual int32_t ConnBlePostBytesMock(uint32_t connectionId, uint8_t *data,
        uint32_t dataLen, int32_t pid, int32_t flag, int32_t module, int64_t seq) = 0;
};

class GeneralConnectionInterfaceMock : public GeneralConnectionInterface {
public:
    GeneralConnectionInterfaceMock();
    ~GeneralConnectionInterfaceMock() override;
    MOCK_METHOD(ConnBleConnection *, ConnBleGetConnectionById, (uint32_t), (override));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey key, char *info, uint32_t len), (override));
    MOCK_METHOD(int32_t, BleConnectDeviceMock, (const ConnectOption *option,
        uint32_t requestId, const ConnectResult *result), (override));
    MOCK_METHOD(int32_t, ConnBlePostBytesMock, (uint32_t connectionId, uint8_t *data,
        uint32_t dataLen, int32_t pid, int32_t flag, int32_t module, int64_t seq), (override));
};
} // namespace OHOS
#endif // GENERAL_CONNECTION_MOCK_H