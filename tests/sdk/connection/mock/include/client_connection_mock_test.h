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
#ifndef CLIENT_CONNECTION_MOCK_TEST_H
#define CLIENT_CONNECTION_MOCK_TEST_H
#include <gmock/gmock.h>

#include "general_client_connection.h"
#include "softbus_adapter_thread.h"

namespace OHOS {
class ClientConnectionInterface {
public:
    ClientConnectionInterface() {};
    virtual ~ClientConnectionInterface() {};
    virtual int32_t InitSoftBus(const char *pkgName);
    virtual int32_t ServerIpcCreateServer(const char *pkgName, const char *name);
    virtual int32_t ServerIpcRemoveServer(const char *pkgName, const char *name);
    virtual int32_t ServerIpcConnect(const char *pkgName, const char *name, const Address *address);
    virtual int32_t ServerIpcDisconnect(uint32_t handle);
    virtual int32_t ServerIpcSend(uint32_t handle, const uint8_t *data, uint32_t len);
    virtual int32_t ServerIpcGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len);
};

class ClientConnectionInterfaceMock : public ClientConnectionInterface {
public:
    ClientConnectionInterfaceMock();
    ~ClientConnectionInterfaceMock() override;
    MOCK_METHOD1(InitSoftBus, int32_t(const char *pkgName));
    MOCK_METHOD2(ServerIpcCreateServer, int32_t(const char *pkgName, const char *name));
    MOCK_METHOD2(ServerIpcRemoveServer, int32_t(const char *pkgName, const char *name));
    MOCK_METHOD3(ServerIpcConnect, int32_t(const char *pkgName, const char *name, const Address *address));
    MOCK_METHOD1(ServerIpcDisconnect, int32_t(uint32_t handle));
    MOCK_METHOD3(ServerIpcSend, int32_t(uint32_t handle, const uint8_t *data, uint32_t len));
    MOCK_METHOD3(ServerIpcGetPeerDeviceId, int32_t(uint32_t handle, char *deviceId, uint32_t len));
};
} // namespace OHOS
#endif // CLIENT_CONNECTION_MOCK_TEST_H