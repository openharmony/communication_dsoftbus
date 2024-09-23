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

#include "auth_tcp_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authTcpConnetionInterface;
AuthTcpConnectionInterfaceMock::AuthTcpConnectionInterfaceMock()
{
    g_authTcpConnetionInterface = reinterpret_cast<void *>(this);
}

AuthTcpConnectionInterfaceMock::~AuthTcpConnectionInterfaceMock()
{
    g_authTcpConnetionInterface = nullptr;
}

static AuthTcpConnetionInterface *GetAuthTcpConnetionInterface()
{
    return reinterpret_cast<AuthTcpConnectionInterfaceMock *>(g_authTcpConnetionInterface);
}

extern "C" {
int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode)
{
    return GetAuthTcpConnetionInterface()->SocketConnectDevice(ip, port, isBlockMode);
}
}
} // namespace OHOS