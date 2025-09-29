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

#include "trans_udp_nego_static_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transUdpNegoStaticInterface;
TransUdpNegoStaticInterfaceMock::TransUdpNegoStaticInterfaceMock()
{
    g_transUdpNegoStaticInterface = reinterpret_cast<void *>(this);
}

TransUdpNegoStaticInterfaceMock::~TransUdpNegoStaticInterfaceMock()
{
    g_transUdpNegoStaticInterface = nullptr;
}

static TransUdpNegoStaticInterface *GetTransUdpNegoStaticInterface()
{
    return reinterpret_cast<TransUdpNegoStaticInterface *>(g_transUdpNegoStaticInterface);
}

extern "C" {
int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetTransUdpNegoStaticInterface()->LnnGetLocalStrInfoByIfnameIdx(key, info, len, ifIdx);
}

int32_t AddScenario(const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType)
{
    return GetTransUdpNegoStaticInterface()->AddScenario(localMac, peerMac, localPid, businessType);
}

int32_t DelScenario(const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType)
{
    return GetTransUdpNegoStaticInterface()->DelScenario(localMac, peerMac, localPid, businessType);
}

int32_t TransUnpackRequestUdpInfo(const cJSON *msg, AppInfo *appInfo)
{
    return GetTransUdpNegoStaticInterface()->TransUnpackRequestUdpInfo(msg, appInfo);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetTransUdpNegoStaticInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t TransSetUdpChannelStatus(int64_t seq, UdpChannelStatus status, bool isReply)
{
    return GetTransUdpNegoStaticInterface()->TransSetUdpChannelStatus(seq, status, isReply);
}

int32_t TransGetUdpChannelBySeq(int64_t seq, UdpChannelInfo *channel, bool isReply)
{
    return GetTransUdpNegoStaticInterface()->TransGetUdpChannelBySeq(seq, channel, isReply);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetTransUdpNegoStaticInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetTransUdpNegoStaticInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t AuthGetConnInfoBySide(const char *uuid, AuthConnInfo *connInfo, bool isMeta, bool isClient)
{
    return GetTransUdpNegoStaticInterface()->AuthGetConnInfoBySide(uuid, connInfo, isMeta, isClient);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransUdpNegoStaticInterface()->AuthGetP2pConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransUdpNegoStaticInterface()->AuthGetHmlConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetUsbConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransUdpNegoStaticInterface()->AuthGetUsbConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransUdpNegoStaticInterface()->AuthGetHmlConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    return GetTransUdpNegoStaticInterface()->AuthOpenConn(info, requestId, callback, isMeta);
}

int32_t TransGetUdpChannelByRequestId(uint32_t requestId, UdpChannelInfo *channel)
{
    return GetTransUdpNegoStaticInterface()->TransGetUdpChannelByRequestId(requestId, channel);
}

int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel)
{
    return GetTransUdpNegoStaticInterface()->TransGetUdpChannelById(channelId, channel);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return GetTransUdpNegoStaticInterface()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint64_t *laneId)
{
    return GetTransUdpNegoStaticInterface()->TransGetLaneIdByChannelId(channelId, laneId);
}

TransDeviceState TransGetDeviceState(const char *networkId)
{
    return GetTransUdpNegoStaticInterface()->TransGetDeviceState(networkId);
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
{
    return GetTransUdpNegoStaticInterface()->SoftBusGenerateSessionKey(key, len);
}

int32_t TransAddUdpChannel(UdpChannelInfo *channel)
{
    return GetTransUdpNegoStaticInterface()->TransAddUdpChannel(channel);
}

int32_t CheckCollabRelation(const AppInfo *appInfo, int32_t channelId, int32_t channelType)
{
    return GetTransUdpNegoStaticInterface()->CheckCollabRelation(appInfo, channelId, channelType);
}

int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest)
{
    return GetTransUdpNegoStaticInterface()->TransUkRequestGetRequestInfoByRequestId(requestId, ukRequest);
}

int32_t TransUkRequestDeleteItem(uint32_t requestId)
{
    return GetTransUdpNegoStaticInterface()->TransUkRequestDeleteItem(requestId);
}

int32_t TransUdpUpdateUdpPort(int32_t channelId, int32_t udpPort)
{
    return GetTransUdpNegoStaticInterface()->TransUdpUpdateUdpPort(channelId, udpPort);
}

int32_t TransUdpUpdateReplyCnt(int32_t channelId)
{
    return GetTransUdpNegoStaticInterface()->TransUdpUpdateReplyCnt(channelId);
}

int32_t TransDelUdpChannel(int32_t channelId)
{
    return GetTransUdpNegoStaticInterface()->TransDelUdpChannel(channelId);
}

int32_t AuthMetaGetLocalIpByMetaNodeIdPacked(const char *metaNodeId, char *localIp, int32_t len)
{
    return GetTransUdpNegoStaticInterface()->AuthMetaGetLocalIpByMetaNodeIdPacked(metaNodeId, localIp, len);
}
 
struct WifiDirectManager *GetWifiDirectManager(void)
{
    return GetTransUdpNegoStaticInterface()->GetWifiDirectManager();
}
 
int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetTransUdpNegoStaticInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}
}
}
