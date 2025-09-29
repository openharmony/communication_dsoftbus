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

#ifndef TRANS_UDP_NEGO_STATIC_TEST_MOCK_H
#define TRANS_UDP_NEGO_STATIC_TEST_MOCK_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstdint>

#include "auth_interface_struct.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_scenario_manager.h"
#include "trans_channel_common.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation_exchange.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class TransUdpNegoStaticInterface {
public:
    TransUdpNegoStaticInterface() {};
    virtual ~TransUdpNegoStaticInterface() {};
    virtual int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t AddScenario(const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType)= 0;
    virtual int32_t DelScenario(const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType)= 0;
    virtual int32_t TransUnpackRequestUdpInfo(const cJSON *msg, AppInfo *appInfo) = 0;
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t TransSetUdpChannelStatus(int64_t seq, UdpChannelStatus status, bool isReply) = 0;
    virtual int32_t TransGetUdpChannelBySeq(int64_t seq, UdpChannelInfo *channel, bool isReply) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t AuthGetConnInfoBySide(const char *uuid, AuthConnInfo *connInfo, bool isMeta, bool isClient) = 0;
    virtual int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetUsbConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthOpenConn(
        const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) = 0;
    virtual int32_t TransGetUdpChannelByRequestId(uint32_t requestId, UdpChannelInfo *channel) = 0;
    virtual int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual int32_t TransGetLaneIdByChannelId(int32_t channelId, uint64_t *laneId) = 0;
    virtual TransDeviceState TransGetDeviceState(const char *networkId) = 0;
    virtual int32_t SoftBusGenerateSessionKey(char *key, uint32_t len) = 0;
    virtual int32_t TransAddUdpChannel(UdpChannelInfo *channel) = 0;
    virtual int32_t CheckCollabRelation(const AppInfo *appInfo, int32_t channelId, int32_t channelType) = 0;
    virtual int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest) = 0;
    virtual int32_t TransUkRequestDeleteItem(uint32_t requestId) = 0;
    virtual int32_t TransUdpUpdateUdpPort(int32_t channelId, int32_t udpPort) = 0;
    virtual int32_t TransUdpUpdateReplyCnt(int32_t channelId) = 0;
    virtual int32_t TransDelUdpChannel(int32_t channelId) = 0;
    virtual int32_t AuthMetaGetLocalIpByMetaNodeIdPacked(const char *metaNodeId, char *localIp, int32_t len) = 0;
    virtual struct WifiDirectManager *GetWifiDirectManager(void) = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
};

class TransUdpNegoStaticInterfaceMock : public TransUdpNegoStaticInterface {
public:
    TransUdpNegoStaticInterfaceMock();
    ~TransUdpNegoStaticInterfaceMock() override;
    MOCK_METHOD4(LnnGetLocalStrInfoByIfnameIdx, int32_t (InfoKey key, char *info, uint32_t len, int32_t ifIdx));
    MOCK_METHOD4(AddScenario, int32_t (
        const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType));
    MOCK_METHOD4(DelScenario, int32_t (
        const char *localMac, const char *peerMac, int32_t localPid, int32_t businessType));
    MOCK_METHOD2(TransUnpackRequestUdpInfo, int32_t (const cJSON *msg, AppInfo *appInfo));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t (int64_t authId, char *uuid, uint16_t size));
    MOCK_METHOD3(TransSetUdpChannelStatus, int32_t (int64_t seq, UdpChannelStatus status, bool isReply));
    MOCK_METHOD3(TransGetUdpChannelBySeq, int32_t (int64_t seq, UdpChannelInfo *channel, bool isReply));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *id, IdCategory type, NodeInfo *info));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey key, char *info, uint32_t len));
    MOCK_METHOD4(AuthGetConnInfoBySide, int32_t (
        const char *uuid, AuthConnInfo *connInfo, bool isMeta, bool isClient));
    MOCK_METHOD3(AuthGetP2pConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD3(AuthGetHmlConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD3(AuthGetUsbConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD4(AuthOpenConn, int32_t (
        const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta));
    MOCK_METHOD2(TransGetUdpChannelByRequestId, int32_t (uint32_t requestId, UdpChannelInfo *channel));
    MOCK_METHOD2(TransGetUdpChannelById, int32_t (int32_t channelId, UdpChannelInfo *channel));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *uuid, char *buf, uint32_t len));
    MOCK_METHOD2(TransGetLaneIdByChannelId, int32_t (int32_t channelId, uint64_t *laneId));
    MOCK_METHOD1(TransGetDeviceState, TransDeviceState (const char *networkId));
    MOCK_METHOD2(SoftBusGenerateSessionKey, int32_t (char *key, uint32_t len));
    MOCK_METHOD1(TransAddUdpChannel, int32_t (UdpChannelInfo *channel));
    MOCK_METHOD3(CheckCollabRelation, int32_t (const AppInfo *appInfo, int32_t channelId, int32_t channelType));
    MOCK_METHOD2(TransUkRequestGetRequestInfoByRequestId, int32_t (uint32_t requestId, UkRequestNode *ukRequest));
    MOCK_METHOD1(TransUkRequestDeleteItem, int32_t (uint32_t requestId));
    MOCK_METHOD2(TransUdpUpdateUdpPort, int32_t (int32_t channelId, int32_t udpPort));
    MOCK_METHOD1(TransUdpUpdateReplyCnt, int32_t (int32_t channelId));
    MOCK_METHOD1(TransDelUdpChannel, int32_t (int32_t channelId));
    MOCK_METHOD3(AuthMetaGetLocalIpByMetaNodeIdPacked, int32_t (const char *metaNodeId, char *localIp, int32_t len));
    MOCK_METHOD0(GetWifiDirectManager, struct WifiDirectManager * (void));
    MOCK_METHOD2(LnnGetOsTypeByNetworkId, int32_t (const char *networkId, int32_t *osType));
};
} // namespace OHOS
#endif // TRANS_UDP_NEGO_STATIC_TEST_MOCK_H
