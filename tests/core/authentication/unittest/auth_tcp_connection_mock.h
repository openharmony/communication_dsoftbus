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

#ifndef AUTH_TCP_CONNECTION_MOCK_H
#define AUTH_TCP_CONNECTION_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_tcp_connection.h"

namespace OHOS {
class AuthTcpConnetionInterface {
public:
    AuthTcpConnetionInterface() {};
    virtual ~AuthTcpConnetionInterface() {};

    virtual int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode) = 0;
};
class AuthTcpConnectionInterfaceMock : public AuthTcpConnetionInterface {
public:
    AuthTcpConnectionInterfaceMock();
    ~AuthTcpConnectionInterfaceMock() override;

    MOCK_METHOD3(SocketConnectDevice, int32_t(const char *, int32_t, bool));
};
} // namespace OHOS
#endif // AUTH_TCP_CONNECTION_MOCK_H