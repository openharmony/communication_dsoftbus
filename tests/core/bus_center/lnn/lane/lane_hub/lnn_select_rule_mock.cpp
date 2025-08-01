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

#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_select_rule_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_lnnSelectRuleInterface;
LnnSelectRuleInterfaceMock::LnnSelectRuleInterfaceMock()
{
    g_lnnSelectRuleInterface = static_cast<void *>(this);
}

LnnSelectRuleInterfaceMock::~LnnSelectRuleInterfaceMock()
{
    g_lnnSelectRuleInterface = nullptr;
}

static LnnSelectRuleInterface *GetLnnSelectRuleInterface()
{
    return static_cast<LnnSelectRuleInterface *>(g_lnnSelectRuleInterface);
}

extern "C" {
int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t LnnGetCurrChannelScorePacked(int32_t channelId)
{
    return GetLnnSelectRuleInterface()->LnnGetCurrChannelScorePacked(channelId);
}

int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource)
{
    return GetLnnSelectRuleInterface()->FindLaneResourceByLinkType(peerUdid, type, resource);
}

int32_t LnnGetLinkLedgerInfo(const char *udid, LinkLedgerInfo *info)
{
    return GetLnnSelectRuleInterface()->LnnGetLinkLedgerInfo(udid, info);
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteNumU64Info(networkId, key, info);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetLnnSelectRuleInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteNumInfo(networkId, key, info);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetLnnSelectRuleInterface()->LnnGetOnlineStateById(id, type);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return GetLnnSelectRuleInterface()->SoftBusGetWifiState();
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnSelectRuleInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLnnSelectRuleInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info)
{
    return GetLnnSelectRuleInterface()->LnnSetLocalNumU32Info(key, info);
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource)
{
    return GetLnnSelectRuleInterface()->FindLaneResourceByLaneId(laneId, resource);
}

int32_t LnnAddLinkLedgerInfo(const char *udid, const LinkLedgerInfo *info)
{
    return GetLnnSelectRuleInterface()->LnnAddLinkLedgerInfo(udid, info);
}

int32_t GetAllLinkWithDevId(const char *peerUdid, LaneLinkType **linkList, uint8_t *linkCnt)
{
    return GetLnnSelectRuleInterface()->GetAllLinkWithDevId(peerUdid, linkList, linkCnt);
}

int32_t LnnGetWlanLinkedInfoPacked(LnnWlanLinkedInfo *info)
{
    return GetLnnSelectRuleInterface()->LnnGetWlanLinkedInfoPacked(info);
}
}
} // namespace OHOS
