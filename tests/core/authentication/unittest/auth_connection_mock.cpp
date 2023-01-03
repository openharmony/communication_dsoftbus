/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connInterface;
AuthConnectInterfaceMock::AuthConnectInterfaceMock()
{
    g_connInterface = reinterpret_cast<void *>(this);
}

AuthConnectInterfaceMock::~AuthConnectInterfaceMock()
{
    g_connInterface = nullptr;
}

static AuthConnectInterface *GetConnInterface()
{
    return reinterpret_cast<AuthConnectInterfaceMock *>(g_connInterface);
}

extern "C" {
int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetConnInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    return GetConnInterface()->ConnSetConnectCallback(moduleId, callback);
}

void ConnUnSetConnectCallback(ConnModule moduleId)
{
    GetConnInterface()->ConnUnSetConnectCallback(moduleId);
}

int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    return GetConnInterface()->ConnConnectDevice(option, requestId, result);
}

int32_t ConnDisconnectDevice(uint32_t connectionId)
{
    return GetConnInterface()->ConnDisconnectDevice(connectionId);
}

uint32_t ConnGetHeadSize(void)
{
    return GetConnInterface()->ConnGetHeadSize();
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    return GetConnInterface()->ConnPostBytes(connectionId, data);
}

bool CheckActiveConnection(const ConnectOption *option)
{
    return GetConnInterface()->CheckActiveConnection(option);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetConnInterface()->ConnStartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetConnInterface()->ConnStopLocalListening(info);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetConnInterface()->ConnGetNewRequestId(moduleId);
}

int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option)
{
    return GetConnInterface()->ConnUpdateConnection(connectionId, option);
}

}
}