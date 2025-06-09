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

#include "trans_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transManagerMock;
TransManagerInterfaceMock::TransManagerInterfaceMock()
{
    g_transManagerMock = reinterpret_cast<void *>(this);
}

TransManagerInterfaceMock::~TransManagerInterfaceMock()
{
    g_transManagerMock = nullptr;
}

static TransManagerInterface *GetTransManagerInterface()
{
    return reinterpret_cast<TransManagerInterface *>(g_transManagerMock);
}

extern "C" {
int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetTransManagerInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo)
{
    return GetTransManagerInterface()->AuthCheckSessionKeyValidByConnInfo(networkId, connInfo);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetTransManagerInterface()->ConnGetConnectionInfo(connectionId, info);
}

uint64_t TransACLGetFirstTokenID()
{
    return GetTransManagerInterface()->TransACLGetFirstTokenID();
}

int32_t TransCommonGetAppInfo(const SessionParam *param, AppInfo *appInfo)
{
    return GetTransManagerInterface()->TransCommonGetAppInfo(param, appInfo);
}

int32_t TransAsyncGetLaneInfo(
    const SessionParam *param, uint32_t *laneHandle, uint64_t callingTokenId, int64_t timeStart)
{
    return GetTransManagerInterface()->TransAsyncGetLaneInfo(param, laneHandle, callingTokenId, timeStart);
}

int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneHandle)
{
    return GetTransManagerInterface()->TransGetLaneInfo(param, connInfo, laneHandle);
}

int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt)
{
    return GetTransManagerInterface()->TransGetConnectOptByConnInfo(info, connOpt);
}

int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    return GetTransManagerInterface()->TransOpenChannelProc(type, appInfo, connOpt, channelId);
}

int32_t TransProxyGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt)
{
    return GetTransManagerInterface()->TransProxyGetConnOptionByChanId(channelId, connOpt);
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return GetTransManagerInterface()->TransGetUidAndPid(sessionName, uid, pid);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetTransManagerInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    return GetTransManagerInterface()->TransGetPkgNameBySessionName(sessionName, pkgName, len);
}

int32_t TransCommonGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    return GetTransManagerInterface()->TransCommonGetLocalConfig(channelType, businessType, len);
}
}
}
