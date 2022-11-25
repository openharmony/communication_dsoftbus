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

#include "trans_conn_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_connectInterface = nullptr;

TransConnInterfaceMock::TransConnInterfaceMock()
{
    g_connectInterface = reinterpret_cast<void *>(this);
}

TransConnInterfaceMock::~TransConnInterfaceMock()
{
    g_connectInterface = nullptr;
}

static TransConnInterfaceMock *GetConnectInterface()
{
    return reinterpret_cast<TransConnInterfaceMock *>(g_connectInterface);
}

extern "C" {
int32_t P2pLinkGetRequestId(void)
{
    return GetConnectInterface()->P2pLinkGetRequestId();
}

int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info)
{
    return GetConnectInterface()->P2pLinkConnectDevice(info);
}

int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info)
{
    return GetConnectInterface()->P2pLinkDisconnectDevice(info);
}

int32_t P2pLinkInit(void)
{
    return GetConnectInterface()->P2pLinkInit();
}

void P2pLinkRegPeerDevStateChange(const P2pLinkPeerDevStateCb *cb)
{
    GetConnectInterface()->P2pLinkRegPeerDevStateChange(cb);
}

int32_t P2pLinkGetLocalIp(char *localIp, int32_t localIpLen)
{
    return GetConnectInterface()->P2pLinkGetLocalIp(localIp, localIpLen);
}

int32_t P2pLinkIsRoleConflict(const RoleIsConflictInfo *info)
{
    return GetConnectInterface()->P2pLinkIsRoleConflict(info);
}

int32_t P2pLinkGetPeerMacByPeerIp(const char *peerIp, char *peerMac, int32_t macLen)
{
    return GetConnectInterface()->P2pLinkGetPeerMacByPeerIp(peerIp, peerMac, macLen);
}

int32_t P2pLinkQueryDevIsOnline(const char *peerMac)
{
    return GetConnectInterface()->P2pLinkQueryDevIsOnline(peerMac);
}

int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    return GetConnectInterface()->ConnConnectDevice(option, requestId, result);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetConnectInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    return GetConnectInterface()->ConnPostBytes(connectionId, data);
}

int32_t ConnDisconnectDevice(uint32_t connectionId)
{
    return GetConnectInterface()->ConnDisconnectDevice(connectionId);
}

int32_t ConnTypeIsSupport(ConnectType type)
{
    return GetConnectInterface()->ConnTypeIsSupport(type);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetConnectInterface()->ConnGetNewRequestId(moduleId);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetConnectInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetConnectInterface()->ConnStartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetConnectInterface()->ConnStopLocalListening(info);
}

bool CheckActiveConnection(const ConnectOption *option)
{
    return GetConnectInterface()->CheckActiveConnection(option);
}

uint32_t ConnGetHeadSize(void)
{
    return GetConnectInterface()->ConnGetHeadSize();
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    return GetConnectInterface()->ConnSetConnectCallback(moduleId, callback);
}
}
}
