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

#include "wrapper_br_interface_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_wrapperBrInterface;
WrapperBrInterfaceMock::WrapperBrInterfaceMock()
{
    g_wrapperBrInterface = reinterpret_cast<void *>(this);
}

WrapperBrInterfaceMock::~WrapperBrInterfaceMock()
{
    g_wrapperBrInterface = nullptr;
}

static WrapperBrInterface *GetWrapperBrInterface()
{
    return reinterpret_cast<WrapperBrInterface *>(g_wrapperBrInterface);
}

extern "C" {
int SppServerCreate(BtCreateSocketPara *socketPara, const char *name, unsigned int len)
{
    return GetWrapperBrInterface()->SppServerCreate(socketPara, name, len);
}

int32_t SppServerClose(int32_t serverFd)
{
    return GetWrapperBrInterface()->SppServerClose(serverFd);
}

int32_t SocketConnectEx(const BluetoothCreateSocketPara *socketPara, const BdAddr *bdAddr,
    int32_t psm, BtSocketConnectionCallback *callback)
{
    return GetWrapperBrInterface()->SocketConnectEx(socketPara, bdAddr, psm, callback);
}

int32_t SppDisconnect(int32_t clientFd)
{
    return GetWrapperBrInterface()->SppDisconnect(clientFd);
}

bool IsSppConnected(int32_t clientFd)
{
    return GetWrapperBrInterface()->IsSppConnected(clientFd);
}

int32_t SppServerAccept(int32_t serverFd)
{
    return GetWrapperBrInterface()->SppServerAccept(serverFd);
}

int SppWrite(int clientId, const char *data, const unsigned int len)
{
    return GetWrapperBrInterface()->SppWrite(clientId, data, len);
}

int SppRead(int clientId, char *buf, const unsigned int bufLen)
{
    return GetWrapperBrInterface()->SppRead(clientId, buf, bufLen);
}

int32_t SppGetRemoteAddr(int32_t clientFd, BdAddr *remoteAddr)
{
    return GetWrapperBrInterface()->SppGetRemoteAddr(clientFd, remoteAddr);
}

int32_t SocketGetScn(int32_t serverFd)
{
    return GetWrapperBrInterface()->SocketGetScn(serverFd);
}

int32_t SetConnectionPriority(const BdAddr *bdAddr, BtSocketPriority priority)
{
    return GetWrapperBrInterface()->SetConnectionPriority(bdAddr, priority);
}
}
} // namespace OHOS