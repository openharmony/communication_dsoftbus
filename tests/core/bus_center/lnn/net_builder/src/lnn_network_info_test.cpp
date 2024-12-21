/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_net_builder_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_network_info.c"
#include "lnn_network_info.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char UUID[SHA_256_HEX_HASH_LEN] = "abc";
constexpr uint8_t MSG[] = "63";
constexpr char NETWORKID[] = "123456789";
constexpr char COEXISTCAP1[] = "[[{\"IF\":\"if1\",\"MODE\":1}],[{\"IF\":\"if2\",\"MODE\":2}]]";
constexpr char COEXISTCAP2[] = "[[{\"IF\":\"if1\",\"MODE\":2}],[{\"IF\":\"if2\",\"MODE\":8}]]";
constexpr char COEXISTCAP3[] = "{\"IF\":\"if1\",\"MODE\":2}";
constexpr char COEXISTCAP4[] = "[{\"IF\":\"if1\",\"MODE\":2}]";
constexpr uint32_t TYPE_0 = 0;
constexpr uint32_t TYPE_1 = 1;
constexpr uint32_t TYPE_2 = 2;
constexpr uint32_t TYPE_4 = 4;
constexpr uint32_t TYPE_8 = 8;
constexpr uint32_t TYPE_16 = 16;
constexpr uint32_t TYPE_63 = 63;
constexpr uint32_t TYPE_128 = 128;
constexpr uint32_t DISCOVERY_TYPE = 13111;

class LNNNetworkInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetworkInfoTest::SetUpTestCase() { }

void LNNNetworkInfoTest::TearDownTestCase() { }

void LNNNetworkInfoTest::SetUp() { }

void LNNNetworkInfoTest::TearDown() { }

/*
 * @tc.name: LNN_INIT_NETWORK_INFO_TEST_001
 * @tc.desc: test LnnInitNetworkInfo
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetworkInfoTest, LNN_INIT_NETWORK_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftBusHasWifiDirectCapability).WillRepeatedly(Return(true));
    EXPECT_CALL(serviceMock, SoftBusGetWifiInterfaceCoexistCap).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(serviceMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnSyncInfoInterfaceMock> syncInfoMock;
    EXPECT_CALL(syncInfoMock, LnnRegSyncInfoHandler)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnHasCapability).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const char *networkId = NETWORKID;
    uint32_t capability = TYPE_128;
    HandlePeerNetCapchanged(networkId, capability);
    HandlePeerNetCapchanged(networkId, capability);
    HandlePeerNetCapchanged(networkId, capability);
    HandlePeerNetCapchanged(networkId, capability);
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    HandlePeerNetCapchanged(networkId, capability);
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnHasCapability).WillOnce(Return(true)).WillRepeatedly(Return(false));
    HandlePeerNetCapchanged(networkId, capability);
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnHasCapability).WillOnce(Return(true)).WillRepeatedly(Return(false));
    HandlePeerNetCapchanged(networkId, capability);
    EXPECT_CALL(netLedgerMock, LnnGetBasicInfoByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    UpdateNetworkInfo(UUID);
    UpdateNetworkInfo(UUID);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_OK);
}

/*
 * @tc.name: CONVERT_MSG_TO_CAPABILITY_TEST_001
 * @tc.desc: test ConvertMsgToCapability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_CAPABILITY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    PostNetchangedInfo(nullptr, CONNECTION_ADDR_ETH);
    PostNetchangedInfo(nullptr, CONNECTION_ADDR_ETH);
    uint32_t capability;
    uint32_t len = BITS - 1;
    uint32_t ret = ConvertMsgToCapability(nullptr, MSG, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertMsgToCapability(&capability, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertMsgToCapability(&capability, MSG, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConvertMsgToCapability(&capability, MSG, BITS);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IS_P2P_AVAILABLE_TEST_001
 * @tc.desc: test IsP2pAvailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, IS_P2P_AVAILABLE_TEST_001, TestSize.Level1)
{
    const char *networkId = NETWORKID;
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_DEVICE_NAME, networkId, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, nullptr, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, nullptr, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, 0);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NodeInfo info = {
        .discoveryType = DISCOVERY_TYPE,
    };
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<2>(info), Return(SOFTBUS_OK)));
    EXPECT_CALL(netLedgerMock, LnnGetBasicInfoByUdid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(netLedgerMock, LnnSetDLConnCapability).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, UpdateProfile).WillRepeatedly(Return());
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, BITS);
    OnReceiveCapaSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, networkId, MSG, BITS);
    EXPECT_CALL(serviceMock, SoftBusIsWifiTripleMode).WillRepeatedly(Return(true));
    bool ret = IsP2pAvailable(true);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: WIFI_STATE_EVENT_HANDLER_TEST_002
 * @tc.desc: test WifiStateEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, WIFI_STATE_EVENT_HANDLER_TEST_002, TestSize.Level1)
{
    LnnMonitorWlanStateChangedEvent event = { .basic.event = LNN_EVENT_IP_ADDR_CHANGED,
        .status = SOFTBUS_WIFI_UNKNOWN };
    const LnnEventBasicInfo *info = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    WifiStateEventHandler(nullptr);
    WifiStateEventHandler(info);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    event.basic.event = LNN_EVENT_WIFI_STATE_CHANGED;
    const LnnEventBasicInfo *info1 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    WifiStateEventHandler(info1);
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    WifiStateEventHandler(info1);
    const char *coexistCap2 = COEXISTCAP2;
    EXPECT_EQ(IsSupportApCoexist(coexistCap2), false);
}

/*
 * @tc.name: BT_STATE_CHANGE_EVENT_HANDLER_TEST_001
 * @tc.desc: test BtStateChangeEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, BT_STATE_CHANGE_EVENT_HANDLER_TEST_001, TestSize.Level1)
{
    LnnMonitorHbStateChangedEvent event = {
        .basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = SOFTBUS_BT_UNKNOWN,
    };
    const LnnEventBasicInfo *info = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(nullptr);
    BtStateChangeEventHandler(info);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    event.basic.event = LNN_EVENT_BT_STATE_CHANGED;
    const LnnEventBasicInfo *info1 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info1);
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    event.status = SOFTBUS_BR_TURN_ON;
    EXPECT_CALL(netLedgerMock, LnnSetNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnClearNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR));
    const LnnEventBasicInfo *info2 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info2);
    event.status = SOFTBUS_BLE_TURN_ON;
    const LnnEventBasicInfo *info3 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info3);
    event.status = SOFTBUS_BR_TURN_OFF;
    const LnnEventBasicInfo *info4 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info4);
    event.status = SOFTBUS_BLE_TURN_OFF;
    const LnnEventBasicInfo *info5 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info5);
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR));
    BtStateChangeEventHandler(info5);
    event.status = SOFTBUS_BR_TURN_OFF;
    const LnnEventBasicInfo *info6 = reinterpret_cast<const LnnEventBasicInfo *>(&event);
    BtStateChangeEventHandler(info6);
    const char *coexistCap1 = COEXISTCAP1;
    EXPECT_EQ(IsSupportApCoexist(coexistCap1), false);
}

/*
 * @tc.name: CONVERT_CAPABILITY_TO_MSG_TEST_001
 * @tc.desc: test ConvertCapabilityToMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_CAPABILITY_TO_MSG_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo);
    EXPECT_CALL(netLedgerMock, LnnIsLSANode).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo).WillOnce(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    WifiStateProcess(TYPE_63, true);
    WifiStateProcess(TYPE_63, false);
    SendNetCapabilityToRemote(TYPE_63, TYPE_1);
    uint8_t *ret = ConvertCapabilityToMsg(TYPE_63);
    EXPECT_TRUE(ret != nullptr);
    SoftBusFree(ret);
}

/*
 * @tc.name: IS_NEED_TO_SEND_TEST_001
 * @tc.desc: test IsNeedToSend
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, IS_NEED_TO_SEND_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(false));
    NiceMock<LnnSyncInfoInterfaceMock> syncInfoMock;
    EXPECT_CALL(syncInfoMock, LnnSendSyncInfoMsg).WillRepeatedly(Return(SOFTBUS_OK));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeBasicInfo netInfo;
    (void)memset_s(&netInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_EQ(EOK, strcpy_s(netInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID));
    uint32_t netCapability = TYPE_0;
    uint32_t tmpMsg = TYPE_63;
    uint8_t *msg = reinterpret_cast<uint8_t *>(&tmpMsg);
    DoSendCapability(nodeInfo, netInfo, msg, netCapability, TYPE_8);
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(true));
    EXPECT_CALL(serviceMock, LnnStartHbByTypeAndStrategy).WillRepeatedly(Return(SOFTBUS_OK));
    DoSendCapability(nodeInfo, netInfo, msg, netCapability, TYPE_8);
    DoSendCapability(nodeInfo, netInfo, msg, netCapability, TYPE_2);
    EXPECT_CALL(netLedgerMock, LnnSetNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnClearNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    LnnClearNetBandCapability(&netCapability);
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(BAND_24G));
    LnnSetNetBandCapability(&netCapability);
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(BAND_5G));
    LnnSetNetBandCapability(&netCapability);
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(BAND_UNKNOWN));
    LnnSetNetBandCapability(&netCapability);
    bool ret = IsNeedToSend(&nodeInfo, TYPE_8);
    EXPECT_EQ(ret, true);
    ret = IsNeedToSend(&nodeInfo, TYPE_4);
    EXPECT_EQ(ret, true);
    ret = IsNeedToSend(&nodeInfo, TYPE_2);
    EXPECT_EQ(ret, true);
    ret = IsNeedToSend(&nodeInfo, TYPE_16);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: GET_NETWORK_CAPABILITY_TEST_001
 * @tc.desc: test GetNetworkCapability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, GET_NETWORK_CAPABILITY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(netLedgerMock, LnnSetNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnClearNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, IsFeatureSupport).WillRepeatedly(Return(BAND_24G));
    EXPECT_CALL(serviceMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(serviceMock, SoftBusIsWifiTripleMode).WillRepeatedly(Return(true));
    uint32_t capability;
    bool needSync = false;
    GetNetworkCapability(SOFTBUS_WIFI_OBTAINING_IPADDR, &capability, &needSync);
    EXPECT_EQ(needSync, false);
    GetNetworkCapability(SOFTBUS_WIFI_ENABLED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_WIFI_CONNECTED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_WIFI_DISCONNECTED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_WIFI_DISABLED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_AP_ENABLED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_AP_DISABLED, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    GetNetworkCapability(SOFTBUS_WIFI_SEMI_ACTIVE, &capability, &needSync);
    EXPECT_EQ(needSync, true);
    EXPECT_CALL(serviceMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_UNKNOWN));
    LnnSetP2pNetCapability(&capability);
    EXPECT_EQ(needSync, true);
}

/*
 * @tc.name: IS_SUPPORT_AP_COEXIST_TEST_001
 * @tc.desc: test IsSupportApCoexist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, IS_SUPPORT_AP_COEXIST_TEST_001, TestSize.Level1)
{
    const char *coexistCap3 = COEXISTCAP3;
    EXPECT_EQ(IsSupportApCoexist(coexistCap3), false);
    const char *coexistCap4 = COEXISTCAP4;
    EXPECT_EQ(IsSupportApCoexist(coexistCap4), false);
}
} // namespace OHOS
