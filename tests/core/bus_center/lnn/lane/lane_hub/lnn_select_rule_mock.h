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

#ifndef LNN_SELECT_RULE_MOCK_H
#define LNN_SELECT_RULE_MOCK_H

#include <gmock/gmock.h>

#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_lane_link.h"
#include "lnn_lane_link_ledger.h"
#include "lnn_lane_score_struct.h"
#include "lnn_node_info.h"
#include "softbus_wifi_api_adapter.h"

typedef enum {
    LANE_MOCK_PARAM1 = 0,
    LANE_MOCK_PARAM2,
    LANE_MOCK_PARAM3,
    LANE_MOCK_PARAM4,
    LANE_MOCK_PARAM5,
    LANE_MOCK_PARAM_BUTT
} LaneMockParamIndex;

namespace OHOS {
class LnnSelectRuleInterface {
public:
    LnnSelectRuleInterface() {};
    virtual ~LnnSelectRuleInterface() {};

    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetCurrChannelScorePacked(int32_t channelId) = 0;
    virtual int32_t LnnGetLinkLedgerInfo(const char *udid, LinkLedgerInfo *info) = 0;
    virtual int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual SoftBusWifiDetailState SoftBusGetWifiState(void) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info) = 0;
    virtual int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource) = 0;
    virtual int32_t LnnAddLinkLedgerInfo(const char *udid, const LinkLedgerInfo *info) = 0;
    virtual int32_t GetAllLinkWithDevId(const char *peerUdid, LaneLinkType **linkList, uint8_t *linkCnt) = 0;
    virtual int32_t LnnGetWlanLinkedInfoPacked(LnnWlanLinkedInfo *info) = 0;
};

class LnnSelectRuleInterfaceMock : public LnnSelectRuleInterface {
public:
    LnnSelectRuleInterfaceMock();
    ~LnnSelectRuleInterfaceMock() override;

    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *, InfoKey, uint32_t *));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char*, InfoKey, char*, uint32_t));
    MOCK_METHOD1(LnnGetCurrChannelScorePacked, int32_t (int32_t));
    MOCK_METHOD2(LnnGetLinkLedgerInfo, int32_t (const char *, LinkLedgerInfo *));
    MOCK_METHOD3(FindLaneResourceByLinkType, int32_t (const char *, LaneLinkType, LaneResource *));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t (const char *, InfoKey, uint64_t *));
    MOCK_METHOD2(LnnGetOsTypeByNetworkId, int32_t (const char *, int32_t *));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t*));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char*, InfoKey, int32_t*));
    MOCK_METHOD2(LnnGetOnlineStateById, bool (const char*, IdCategory));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char*, IdCategory, NodeInfo *));
    MOCK_METHOD0(SoftBusGetWifiState, SoftBusWifiDetailState (void));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *info, DiscoveryType type));
    MOCK_METHOD2(LnnSetNetCapability, int32_t (uint32_t *capability, NetCapability type));
    MOCK_METHOD2(LnnSetLocalNumU32Info, int32_t (InfoKey key, uint32_t info));
    MOCK_METHOD2(FindLaneResourceByLaneId, int32_t (uint64_t laneId, LaneResource *resource));
    MOCK_METHOD2(LnnAddLinkLedgerInfo, int32_t (const char *udid, const LinkLedgerInfo *info));
    MOCK_METHOD3(GetAllLinkWithDevId, int32_t (const char *peerUdid, LaneLinkType **linkList, uint8_t *linkCnt));
    MOCK_METHOD1(LnnGetWlanLinkedInfoPacked, int32_t (LnnWlanLinkedInfo *info));
};
} // namespace OHOS
#endif // LNN_SELECT_RULE_MOCK_H
