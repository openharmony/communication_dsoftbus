/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
constexpr uint8_t USER_ID_MSG[] = "100";
constexpr uint32_t LEN = 10;

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

int32_t TestLnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason)
{
    (void)networkId;
    (void)addrType;
    (void)leaveReason;
    return SOFTBUS_OK;
}

/*
 * @tc.name: LNN_INIT_NETWORK_INFO_TEST_001
 * @tc.desc: test LnnInitNetworkInfo
 * @tc.type: FUNC
 * @tc.level: Level1
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
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    UpdateNetworkInfo(UUID);
    UpdateNetworkInfo(UUID);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_OK);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_OK);
}

/*
 * @tc.name: CONVERT_MSG_TO_CAPABILITY_TEST_001
 * @tc.desc: test ConvertMsgToCapability
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
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
 * @tc.level: Level1
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
    bool ret = IsP2pAvailable();
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: WIFI_STATE_EVENT_HANDLER_TEST_002
 * @tc.desc: test WifiStateEventHandler
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_CAPABILITY_TO_MSG_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo);
    EXPECT_CALL(netLedgerMock, LnnIsLSANode).WillRepeatedly(Return(true));
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumInfo)
        .WillOnce(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    WifiStateProcess(TYPE_63, true);
    WifiStateProcess(TYPE_63, false);
    SendNetCapabilityToRemote(TYPE_63, TYPE_1, false);
    uint8_t *ret = ConvertCapabilityToMsg(TYPE_63);
    EXPECT_TRUE(ret != nullptr);
    SoftBusFree(ret);
}

/*
 * @tc.name: IS_NEED_TO_SEND_TEST_001
 * @tc.desc: test IsNeedToSend
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, IS_SUPPORT_AP_COEXIST_TEST_001, TestSize.Level1)
{
    const char *coexistCap3 = COEXISTCAP3;
    EXPECT_EQ(IsSupportApCoexist(coexistCap3), false);
    const char *coexistCap4 = COEXISTCAP4;
    EXPECT_EQ(IsSupportApCoexist(coexistCap4), false);
}

/*
 * @tc.name: CONVERT_MSG_TO_USER_ID_TEST_001
 * @tc.desc: test ConvertMsgToUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USER_ID_TEST_001, TestSize.Level1)
{
    uint32_t len = BITLEN - 1;
    EXPECT_EQ(ConvertMsgToUserId(nullptr, nullptr, len), SOFTBUS_INVALID_PARAM);
    int32_t userId = 0;
    EXPECT_EQ(ConvertMsgToUserId(&userId, nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(ConvertMsgToUserId(&userId, USER_ID_MSG, len), SOFTBUS_INVALID_PARAM);
    len = BITLEN;
    EXPECT_EQ(ConvertMsgToUserId(&userId, USER_ID_MSG, len), SOFTBUS_OK);
}

/*
 * @tc.name: ON_RECEIVE_USER_ID_SYNCINFO_MSG_TEST_001
 * @tc.desc: test OnReceiveUserIdSyncInfoMsg
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, ON_RECEIVE_USER_ID_SYNCINFO_MSG_TEST_001, TestSize.Level1)
{
    LnnSyncInfoType type = LNN_INFO_TYPE_PTK;
    uint32_t len = BITLEN;
    const char *networkId = NETWORKID;
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, USER_ID_MSG, len));
    type = LNN_INFO_TYPE_USERID;
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, nullptr, USER_ID_MSG, len));
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, nullptr, len));
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, USER_ID_MSG, 0));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnSetDLConnUserId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, USER_ID_MSG, len));
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, USER_ID_MSG, len));
    EXPECT_NO_FATAL_FAILURE(OnReceiveUserIdSyncInfoMsg(type, networkId, USER_ID_MSG, len));
}

/*
 * @tc.name: ON_LNN_PROCESS_USER_CHANGE_MSG_DELAY_TEST_001
 * @tc.desc: test OnLnnProcessUserChangeMsgDelay
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, ON_LNN_PROCESS_USER_CHANGE_MSG_DELAY_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(OnLnnProcessUserChangeMsgDelay(nullptr));
    void *para = static_cast<void *>(SoftBusCalloc(sizeof(SendSyncInfoParam)));
    if (para == nullptr) {
        return;
    }
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(OnLnnProcessUserChangeMsgDelay(para));
}

/*
 * @tc.name: LNN_ASYNC_SEND_USER_ID_TEST_001
 * @tc.desc: test LnnAsyncSendUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, LNN_ASYNC_SEND_USER_ID_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnAsyncSendUserId(nullptr));
    SendSyncInfoParam *data = reinterpret_cast<SendSyncInfoParam *>(SoftBusCalloc(sizeof(SendSyncInfoParam)));
    if (data == nullptr) {
        return;
    }
    data->msg = nullptr;
    void *param = reinterpret_cast<void *>(data);
    EXPECT_NO_FATAL_FAILURE(LnnAsyncSendUserId(param));
    SendSyncInfoParam *data1 = reinterpret_cast<SendSyncInfoParam *>(SoftBusCalloc(sizeof(SendSyncInfoParam)));
    if (data1 == nullptr) {
        return;
    }
    data1->len = LEN;
    data1->msg = reinterpret_cast<uint8_t *>(SoftBusCalloc(data1->len));
    if (data1->msg == nullptr) {
        SoftBusFree(data1);
        return;
    }
    NiceMock<LnnSyncInfoInterfaceMock> syncInfoMock;
    EXPECT_CALL(syncInfoMock, LnnSendSyncInfoMsg).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    void *param1 = reinterpret_cast<void *>(data1);
    EXPECT_NO_FATAL_FAILURE(LnnAsyncSendUserId(param1));
}

/*
 * @tc.name: DO_SEND_USER_ID_TEST_001
 * @tc.desc: test DoSendUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DO_SEND_USER_ID_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NETWORKID));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<2>(info), Return(SOFTBUS_OK)));
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillOnce(Return(true)).WillRepeatedly(Return(false));
    const char *udid = "udidTest";
    EXPECT_NO_FATAL_FAILURE(DoSendUserId(udid, const_cast<uint8_t *>(USER_ID_MSG)));
    EXPECT_NO_FATAL_FAILURE(DoSendUserId(udid, const_cast<uint8_t *>(USER_ID_MSG)));
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusMalloc(sizeof(SendSyncInfoParam));
    if (data == nullptr) {
        return;
    }
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillOnce(Return(nullptr)).WillRepeatedly(Return(data));
    EXPECT_NO_FATAL_FAILURE(DoSendUserId(udid, const_cast<uint8_t *>(USER_ID_MSG)));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(DoSendUserId(udid, const_cast<uint8_t *>(USER_ID_MSG)));
}

/*
 * @tc.name: CONVERT_USER_ID_TO_MSG_TEST_001
 * @tc.desc: test ConvertUserIdToMsg
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_USER_ID_TO_MSG_TEST_001, TestSize.Level1)
{
    EXPECT_NE(ConvertUserIdToMsg(100), nullptr);
}

/*
 * @tc.name: NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_001
 * @tc.desc: test NotifyRemoteDevOffLineByUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NodeInfo info = { .userId = 101 };
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<2>(info), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(NotifyRemoteDevOffLineByUserId(DP_INACTIVE_DEFAULT_USERID, nullptr));
    EXPECT_NO_FATAL_FAILURE(NotifyRemoteDevOffLineByUserId(100, nullptr));
}

/*
 * @tc.name: NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_002
 * @tc.desc: test NotifyRemoteDevOffLineByUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NodeInfo info = { .userId = 0 };
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NETWORKID));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(DoAll(SetArgPointee<2>(info), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(NotifyRemoteDevOffLineByUserId(0, nullptr));
}

/*
 * @tc.name: NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_003
 * @tc.desc: test NotifyRemoteDevOffLineByUserId
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NOTIFY_REMOTE_DEV_OFFLINE_BY_USER_ID_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NodeInfo info = { .userId = 100 };
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NETWORKID));
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(DoAll(SetArgPointee<2>(info), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(NotifyRemoteDevOffLineByUserId(100, nullptr));
}

/*
 * @tc.name: IS_SUPPORT_AP_COEXIST_TEST_002
 * @tc.desc: test IsSupportApCoexist
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, IS_SUPPORT_AP_COEXIST_TEST_002, TestSize.Level1)
{
    const char *coexistCap3 = COEXISTCAP3;
    EXPECT_EQ(IsSupportApCoexist(coexistCap3), false);
    const char *coexistCap4 = COEXISTCAP4;
    EXPECT_EQ(IsSupportApCoexist(coexistCap4), false);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_001
 * @tc.desc: Test case for ConvertMsgToUserId with valid input.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(userId, 0xFFFFFFFF);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_002
 * @tc.desc: Test case for ConvertMsgToUserId with all zeros in the
 * message.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_002, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0x00, 0x00, 0x00 };
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(userId, 0x0);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_003
 * @tc.desc: Test case for ConvertMsgToUserId with the first two bytes set
 * to FF.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_003, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0xFF, 0xFF, 0x00, 0x00 };
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_004
 * @tc.desc: Test case for ConvertMsgToUserId with the last two bytes set
 * to FF.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_004, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_005
 * @tc.desc: Test case for ConvertMsgToUserId with len one less than
 * BITLEN.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_005, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0x00, 0x00, 0x00 };
    uint32_t len = BITLEN - 1;
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_006
 * @tc.desc: Test case for ConvertMsgToUserId with userId as
 * NULL.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_006, TestSize.Level1)
{
    uint8_t msg[BITLEN] = { 0x00, 0x00, 0x00, 0x00 };
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(nullptr, msg, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_007
 * @tc.desc: Test case for ConvertMsgToUserId with msg as
 * NULL.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_007, TestSize.Level1)
{
    int32_t userId = 0;
    uint32_t len = BITLEN;
    uint32_t ret = ConvertMsgToUserId(&userId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CONVERT_MSG_TO_USERID_TEST_008
 * @tc.desc: Test case for ConvertMsgToUserId and
 * OnReceiveUserIdSyncInfoMsg with valid input.
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, CONVERT_MSG_TO_USERID_TEST_008, TestSize.Level1)
{
    const char *networkId = NETWORKID;
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_CONNECTION_INFO, networkId, msg, len);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, nullptr, msg, len);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, nullptr, len);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, 0);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, len - 1);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, len);
    EXPECT_CALL(netBuilderMock, LnnSetDLConnUserId)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, len);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, len);
    OnReceiveUserIdSyncInfoMsg(LNN_INFO_TYPE_USERID, networkId, msg, len);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(userId, 0xFFFFFFFF);
}

/*
 * @tc.name: LnnProcessUserChangeMsg_Test_001
 * @tc.desc: Test LnnProcessUserChangeMsg with all possible
 * conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, LnnProcessUserChangeMsg_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *networkId = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(Return(SOFTBUS_OK));
    LnnProcessUserChangeMsg(LNN_INFO_TYPE_DEVICE_NAME, networkId, msg, len);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnLnnProcessUserChangeMsgDelay_Test_001
 * @tc.desc: Test OnLnnProcessUserChangeMsgDelay with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, OnLnnProcessUserChangeMsgDelay_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    OnLnnProcessUserChangeMsgDelay(nullptr);
    LnnAsyncSendUserId(nullptr);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnAsyncSendUserId_Test_001
 * @tc.desc: Test LnnAsyncSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, LnnAsyncSendUserId_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    SendSyncInfoParam *dataInfo = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(dataInfo, nullptr);
    LnnAsyncSendUserId(dataInfo);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnAsyncSendUserId_Test_002
 * @tc.desc: Test LnnAsyncSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, LnnAsyncSendUserId_Test_002, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    NiceMock<LnnSyncInfoInterfaceMock> syncInfoMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(syncInfoMock, LnnSendSyncInfoMsg)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    SendSyncInfoParam *dataInfo = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(dataInfo, nullptr);
    dataInfo->msg = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    if (dataInfo->msg == nullptr) {
        SoftBusFree(dataInfo);
        return;
    }
    LnnAsyncSendUserId(dataInfo);

    dataInfo = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(dataInfo, nullptr);
    dataInfo->msg = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    if (dataInfo->msg == nullptr) {
        SoftBusFree(dataInfo);
        return;
    }
    LnnAsyncSendUserId(dataInfo);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DoSendUserId_Test_001
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_001, TestSize.Level1)
{
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);

    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    DoSendUserId(udid, msg);
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    DoSendUserId(udid, msg);
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(data);
}

/*
 * @tc.name: DoSendUserId_Test_002
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_002, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DoSendUserId_Test_003
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_003, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(nullptr));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DoSendUserId_Test_004
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_004, TestSize.Level1)
{
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_OK));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: DoSendUserId_Test_005
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:LnnAsyncCallbackHelper return SOFTBUS_INVALID_PARAM
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_005, TestSize.Level1)
{
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DoSendUserId_Test_006
 * @tc.desc: Test DoSendUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require: LnnAsyncCallbackDelayHelper return SOFTBUS_INVALID_PARAM
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, DoSendUserId_Test_006, TestSize.Level1)
{
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);

    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    DoSendUserId(udid, msg);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: NotifyRemoteDevOffLineByUserId_Test_001
 * @tc.desc: TestNotifyRemoteDevOffLineByUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NotifyRemoteDevOffLineByUserId_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    userId = BITLEN;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(testing::Invoke([](const char *id, IdCategory type, NodeInfo *nodeInfo) {
            if (nodeInfo != nullptr) {
                nodeInfo->userId = BITS;
            }
            return SOFTBUS_OK;
        }));
    NotifyRemoteDevOffLineByUserId(userId, udid);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NotifyRemoteDevOffLineByUserId_Test_002
 * @tc.desc: TestNotifyRemoteDevOffLineByUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NotifyRemoteDevOffLineByUserId_Test_002, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    userId = DP_INACTIVE_DEFAULT_USERID;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(testing::Invoke([](const char *id, IdCategory type, NodeInfo *nodeInfo) {
            if (nodeInfo != nullptr) {
                nodeInfo->userId = 123;
            }
            return SOFTBUS_INVALID_PARAM;
        }));
    NotifyRemoteDevOffLineByUserId(userId, udid);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NotifyRemoteDevOffLineByUserId_Test_003
 * @tc.desc: TestNotifyRemoteDevOffLineByUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NotifyRemoteDevOffLineByUserId_Test_003, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(nullptr));

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    userId = BITS;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(testing::Invoke([](const char *id, IdCategory type, NodeInfo *nodeInfo) {
            if (nodeInfo != nullptr) {
                nodeInfo->userId = BITS;
            }
            return SOFTBUS_OK;
        }));
    NotifyRemoteDevOffLineByUserId(userId, udid);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NotifyRemoteDevOffLineByUserId_Test_004
 * @tc.desc: TestNotifyRemoteDevOffLineByUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NotifyRemoteDevOffLineByUserId_Test_004, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(nullptr));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    userId = BITS;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(testing::Invoke([](const char *id, IdCategory type, NodeInfo *nodeInfo) {
            if (nodeInfo != nullptr) {
                nodeInfo->userId = 0;
            }
            return SOFTBUS_OK;
        }));
    NotifyRemoteDevOffLineByUserId(userId, udid);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: NotifyRemoteDevOffLineByUserId_Test_005
 * @tc.desc: TestNotifyRemoteDevOffLineByUserId with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, NotifyRemoteDevOffLineByUserId_Test_005, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    const char *udid = NETWORKID;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(netBuilderMock, LnnRequestLeaveSpecific).WillRepeatedly(TestLnnRequestLeaveSpecific);
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(nullptr));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    userId = DP_INACTIVE_DEFAULT_USERID;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(testing::Invoke([](const char *id, IdCategory type, NodeInfo *nodeInfo) {
            if (nodeInfo != nullptr) {
                nodeInfo->userId = 0;
            }
            return SOFTBUS_OK;
        }));
    NotifyRemoteDevOffLineByUserId(userId, udid);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConvertUserIdToMsg_Test_001
 * @tc.desc: TestConvertUserIdToMsg with all possible conditions
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, ConvertUserIdToMsg_Test_001, TestSize.Level1)
{
    int32_t userId = 0;
    uint8_t msg[BITLEN] = { 0x00, 0xFF, 0xFF, 0xFF };
    uint32_t len = BITLEN;
    uint8_t *rettest = ConvertUserIdToMsg(userId);
    EXPECT_NE(rettest, nullptr);
    uint32_t ret = ConvertMsgToUserId(&userId, msg, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

static HmlCapabilityCode GetHmlCapabilityCodeFunc1(void)
{
    return CONN_HML_SUPPORT;
}

static HmlCapabilityCode GetHmlCapabilityCodeFunc2(void)
{
    return CONN_HML_NOT_SUPPORT;
}

static HmlCapabilityCode GetHmlCapabilityCodeFunc3(void)
{
    return CONN_HML_CAP_UNKNOWN;
}

static VspCapabilityCode GetVspCapabilityCodeFunc1(void)
{
    return CONN_VSP_SUPPORT;
}

static VspCapabilityCode GetVspCapabilityCodeFunc2(void)
{
    return CONN_VSP_CAP_UNKNOWN;
}

static VspCapabilityCode GetVspCapabilityCodeFunc3(void)
{
    return CONN_VSP_NOT_SUPPORT;
}

/*
 * @tc.name: UpdateLocalFeatureByWifiVspRes_Test_001
 * @tc.desc: UpdateLocalFeatureByWifiVspRes test
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, UpdateLocalFeatureByWifiVspRes_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnSetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, GetWifiDirectManager).WillOnce(Return(nullptr));
    int32_t ret = UpdateLocalFeatureByWifiVspRes();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);
    struct WifiDirectManager invalidManager = {
        .getVspCapabilityCode = nullptr,
    };
    EXPECT_CALL(serviceMock, GetWifiDirectManager)
        .WillOnce(Return(&invalidManager))
        .WillOnce(Return(&invalidManager));
    ret = UpdateLocalFeatureByWifiVspRes();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);
    struct WifiDirectManager manager = {
        .getVspCapabilityCode = GetVspCapabilityCodeFunc1,
    };
    EXPECT_CALL(serviceMock, GetWifiDirectManager).WillRepeatedly(Return(&manager));
    ret = UpdateLocalFeatureByWifiVspRes();
    EXPECT_EQ(ret, SOFTBUS_OK);
    manager.getVspCapabilityCode = GetVspCapabilityCodeFunc2,
    ret = UpdateLocalFeatureByWifiVspRes();
    EXPECT_EQ(ret, SOFTBUS_OK);
    manager.getVspCapabilityCode = GetVspCapabilityCodeFunc3,
    ret = UpdateLocalFeatureByWifiVspRes();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UpdateHmlStaticCap_Test_001
 * @tc.desc: UpdateHmlStaticCap test get hmlCap failed
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, UpdateHmlStaticCap_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, GetWifiDirectManager).WillOnce(Return(nullptr));
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);
    struct WifiDirectManager invalidManager = {
        .getHmlCapabilityCode = nullptr,
    };
    EXPECT_CALL(serviceMock, GetWifiDirectManager)
        .WillOnce(Return(&invalidManager))
        .WillOnce(Return(&invalidManager));
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_INIT_FAILED);
}

/*
 * @tc.name: UpdateHmlStaticCap_Test_002
 * @tc.desc: UpdateHmlStaticCap test get hmlCap success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, UpdateHmlStaticCap_Test_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnSetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    struct WifiDirectManager manager = {
        .getHmlCapabilityCode = GetHmlCapabilityCodeFunc1,
    };
    EXPECT_CALL(serviceMock, GetWifiDirectManager).WillRepeatedly(Return(&manager));
    EXPECT_CALL(netLedgerMock, LnnSetStaticNetCap).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_OK);

    manager.getHmlCapabilityCode = GetHmlCapabilityCodeFunc2,
    EXPECT_CALL(netLedgerMock, LnnClearStaticNetCap).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_OK);

    manager.getHmlCapabilityCode = GetHmlCapabilityCodeFunc3,
    ret = UpdateHmlStaticCap();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClearHmlFeatureCap_Test_001
 * @tc.desc: ClearHmlFeatureCap test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetworkInfoTest, ClearHmlFeatureCap_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetBuilderInterfaceMock> netBuilderMock;
    EXPECT_CALL(netBuilderMock, LnnSetLocalByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(ClearHmlFeatureCap());
}

/*
 * @tc.name: WifiServiceOnStartHandle_Test_001
 * @tc.desc: WifiServiceOnStartHandle test
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, WifiServiceOnStartHandle_Test_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    LnnEventBasicInfo info = { .event = LNN_EVENT_TYPE_MAX, };
    EXPECT_NO_FATAL_FAILURE(WifiServiceOnStartHandle(nullptr));
    EXPECT_NO_FATAL_FAILURE(WifiServiceOnStartHandle(&info));
    info.event = LNN_EVENT_WIFI_SERVICE_START;
    EXPECT_CALL(netLedgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    struct WifiDirectManager manager = {
        .getVspCapabilityCode = GetVspCapabilityCodeFunc2,
    };
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, GetWifiDirectManager).WillRepeatedly(Return(&manager));
    EXPECT_NO_FATAL_FAILURE(WifiServiceOnStartHandle(&info));
}

/*
 * @tc.name: LnnSetNetBandCapability_Test_001
 * @tc.desc: LnnSetNetBandCapability test
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNNetworkInfoTest, LnnSetNetBandCapability_Test_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftBusGetLinkBand)
        .WillOnce(Return(BAND_24G))
        .WillOnce(Return(BAND_5G))
        .WillRepeatedly(Return(BAND_UNKNOWN));
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnClearNetCapability).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t capability = 0;
    EXPECT_NO_FATAL_FAILURE(LnnSetNetBandCapability(&capability));
    EXPECT_NO_FATAL_FAILURE(LnnSetNetBandCapability(&capability));
}
} // namespace OHOS
