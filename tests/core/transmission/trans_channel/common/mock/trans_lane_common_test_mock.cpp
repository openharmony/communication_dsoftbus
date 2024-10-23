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

#include "trans_lane_common_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_transLaneCommonInterface = nullptr;
TransLaneCommonTestInterfaceMock::TransLaneCommonTestInterfaceMock()
{
    g_transLaneCommonInterface = reinterpret_cast<void *>(this);
}

TransLaneCommonTestInterfaceMock::~TransLaneCommonTestInterfaceMock()
{
    g_transLaneCommonInterface = nullptr;
}

static TransLaneCommonTestInterface *GetTransLaneCommonTestInterface()
{
    return reinterpret_cast<TransLaneCommonTestInterface *>(g_transLaneCommonInterface);
}

extern "C" {
int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetTransLaneCommonTestInterface()->SoftbusGetConfig(type, val, len);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetTransLaneCommonTestInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetTransLaneCommonTestInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetTransLaneCommonTestInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return GetTransLaneCommonTestInterface()->TransGetUidAndPid(sessionName, uid, pid);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    return GetTransLaneCommonTestInterface()->TransGetPkgNameBySessionName(sessionName, pkgName, len);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetTransLaneCommonTestInterface()->LnnGetLocalStrInfo(key, info, len);
}

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode)
{
    return GetTransLaneCommonTestInterface()->LnnGetProtocolListenerModule(protocol, mode);
}

int32_t TransOpenUdpChannel(AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    return GetTransLaneCommonTestInterface()->TransOpenUdpChannel(appInfo, connOpt, channelId);
}

int32_t TransProxyOpenProxyChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    return GetTransLaneCommonTestInterface()->TransProxyOpenProxyChannel(appInfo, connInfo, channelId);
}

int32_t TransOpenDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    return GetTransLaneCommonTestInterface()->TransOpenDirectChannel(appInfo, connInfo, channelId);
}
}
}
