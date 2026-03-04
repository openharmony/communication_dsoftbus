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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_ledger.h"
#include "lnn_lane_select_mock.h"
#include "lnn_lane_select.h"
#include "lnn_select_rule.h"
#include "lnn_wifi_adpter_mock.h"
#include "softbus_adapter_bt_common_struct.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr uint32_t DEFAULT_QOSINFO_MIN_BW = 10;
constexpr uint32_t DEFAULT_QOSINFO_MAX_LATENCY = 10000;
constexpr uint32_t DEFAULT_QOSINFO_MIN_LATENCY = 2500;
constexpr uint32_t LOW_BW = 384 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;
constexpr uint32_t FREQUENCY_2G_FIRST = 2412;
constexpr uint32_t LANE_PREFERRED_LINK_NUM = 2;
constexpr uint32_t WIFI_DIRECT_EXT_CAP_VALID_TIME = 10000;
constexpr uint32_t ALL_CAPABILITYS = 511;

static NodeInfo g_NodeInfo = {
    .p2pInfo.p2pRole = 1,
    .p2pInfo.p2pMac = "abc",
    .p2pInfo.goMac = "abc",
};

class LNNLaneSelectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneSelectTest::SetUpTestCase()
{
    int32_t ret = InitLaneSelectRule();
    EXPECT_EQ(ret, SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneSelectTest start";
}

void LNNLaneSelectTest::TearDownTestCase()
{
    DeinitLaneSelectRule();
    GTEST_LOG_(INFO) << "LNNLaneSelectTest end";
}

void LNNLaneSelectTest::SetUp()
{
}

void LNNLaneSelectTest::TearDown()
{
}

/*
 * @tc.name: LNN_SELECT_LANE_001
 * @tc.desc: The SelectLane function was tested for behavior when the node is offline and
 *           when the parameters are invalid, by simulating dependency interfaces and
 *           passing different parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList = {};
    uint32_t listNum = 0;
    LaneSelectParam selectParam = {};

    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    ret = SelectLane(nullptr, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectLane(NODE_NETWORK_ID, nullptr, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, nullptr, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SELECT_LANE_002
 * @tc.desc: The dependency behavior of the SelectLane function in the LNNLaneSelectTest class
 *           was simulated using mock objects, and the return values of the SelectLane function
 *           under different conditions were verified to meet the expected results
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList = {};
    uint32_t listNum = 0;
    LaneSelectParam selectParam = {};
    NodeInfo node = {};

    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 7;
    selectParam.list.linkType[0] = LANE_P2P;
    selectParam.list.linkType[1] = LANE_ETH;
    selectParam.list.linkType[2] = LANE_P2P_REUSE;
    selectParam.list.linkType[3] = LANE_BLE_DIRECT;
    selectParam.list.linkType[4] = LANE_BLE_REUSE;
    selectParam.list.linkType[5] = LANE_COC;
    selectParam.list.linkType[6] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    node.discoveryType = DISCOVERY_TYPE_BR;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(node), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
 * @tc.name: LNN_SELECT_LANE_003
 * @tc.desc: SelectLane, HmlIsExist == true
 *           By setting up mock objects and expected behaviors, the function behavior
 *           under specific conditions was verified to meet the expected outcomes
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_003, TestSize.Level1)
{
    LaneSelectParam request = {};
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_HML;

    LanePreferredLinkList recommendList = {};
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(8), Return(SOFTBUS_OK)));

    int32_t ret = SelectLane(NODE_NETWORK_ID, &request, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SELECT_LANE_004
 * @tc.desc: SelectLane, HmlIsExist == false && LaneAddHml
 *           By setting up mock objects and expected behaviors, the function behavior
 *           under specific conditions was verified to meet the expected outcomes
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_004, TestSize.Level1)
{
    LaneSelectParam request = {};
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;

    LanePreferredLinkList recommendList = {};
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(8), Return(SOFTBUS_OK)));

    int32_t ret = SelectLane(NODE_NETWORK_ID, &request, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SELECT_LANE_005
 * @tc.desc: The behavior of the SelectLane function under specific conditions was tested, and the returned
 *           values were verified to meet the expected results
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_005, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    uint32_t listNum = 0;
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_2P4G;
    selectParam.list.linkType[1] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.frequency = 1;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SELECT_LANE_006
 * @tc.desc: Mock dependencies and set expected behaviors to test the behavior of the SelectLane function
 *           under specific conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_006, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    uint32_t listNum = 0;
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_2P4G;
    selectParam.list.linkType[1] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.frequency = FREQUENCY_2G_FIRST + 1;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SELECT_LANE_007
 * @tc.desc: lane select fileTransLane by LNN
 *           Mock dependencies and set expected behaviors to test the behavior of the SelectLane function
 *           under specific conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_007, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 4);
}

/*
 * @tc.name: LNN_SELECT_LANE_008
 * @tc.desc: lane select fileTransLane by LNN
 *           The behavior of the SelectLane function under specific conditions was tested to ensure
 *           it correctly selects the recommended link type under these conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_008, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = LANE_PREFERRED_LINK_NUM;
    selectParam.list.linkType[0] = LANE_WLAN_5G;
    selectParam.list.linkType[1] = LANE_BR;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 2);
}

/*
 * @tc.name: LNN_SELECT_LANE_009
 * @tc.desc: selectlane preferlink test
 *           Simulate the expected behavior of the object, call the SelectLane function, and verify
 *           the return value and the number of items in the recommendation list
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_009, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ALL_CAPABILITYS), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ALL_CAPABILITYS), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1 << BIT_SUPPORT_SLE_CAPABILITY), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1 << BIT_SUPPORT_SLE_CAPABILITY), Return(SOFTBUS_OK)));
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    selectParam.list.linkTypeNum = 0;
    selectParam.list.linkType[(selectParam.list.linkTypeNum++)] = LANE_ETH;
    selectParam.list.linkType[(selectParam.list.linkTypeNum++)] = LANE_USB;
    selectParam.list.linkType[(selectParam.list.linkTypeNum++)] = LANE_SLE;
    selectParam.list.linkType[(selectParam.list.linkTypeNum++)] = LANE_SLE_DIRECT;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 3);
}

/*
 * @tc.name: LNN_SELECT_LANE_010
 * @tc.desc: selectlane defaultlink test
 *           The behavior of the SelectLane function under specific conditions was tested, and the return
 *           value and output parameters were verified to meet the expected results
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_010, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    selectParam.list.linkTypeNum = LANE_LINK_TYPE_BUTT + 1;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 4);
}

/*
 * @tc.name: LNN_SELECT_LANE_011
 * @tc.desc: selectlane p2p and add hml success test
 *           The logic for selecting a P2P channel was verified under the condition of network semi-activation
 *           and support for wifi Direct enhanced features
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_LANE_011, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info)
        .WillRepeatedly(
            DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(
            DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY), Return(SOFTBUS_OK)));
    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    selectParam.list.linkTypeNum = 1;
    selectParam.list.linkType[0] = LANE_P2P;
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(listNum, 1);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_001
 * @tc.desc: To test the error handling capability of the SelectExpectLanesByQos function
 *           when invalid parameters are received
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_001, TestSize.Level1)
{
    LanePreferredLinkList recommendList = {};
    LaneSelectParam selectParam = {};
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = SelectExpectLanesByQos(nullptr, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, nullptr, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_002
 * @tc.desc: Verify whether the function can correctly select the network channel that meets the criteria
 *           under different network conditions and Qos parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + LOW_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + HIGH_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_003
 * @tc.desc: Verify the error handling logic when the function selects a network channel
 *           under Qos requirements
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;

    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_004
 * @tc.desc: Check whether the function correctly returns the SOFTBUS_LANE_WIFI_OFF error code
 *           when the wifi is inactive and a low RTT is required
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;

    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));

    selectParam.qosRequire.rttLevel = LANE_RTT_LEVEL_LOW;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_005
 * @tc.desc: lane select fileTransLane by qos
 *           Verify whether the function can correctly select communication channels that meet the criteria
 *           under different Qos parameter settings, such as bandwidth and latency
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_005, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;

    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
            .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
            .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    selectParam.qosRequire.minBW = 0;
    selectParam.qosRequire.maxLaneLatency = 0;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = 0;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_006
 * @tc.desc: lane select fileTransLane by qos
 *           Verify the function of selecting the desired lane under Qos requirements
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: I5FBFG
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_EXPECT_LANES_BY_QOS_006, TestSize.Level1)
{
    LanePreferredLinkList recommendList;
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
            .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
            .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(63), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_BYTE;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_LANE_ADJUST_LINK_PRIORITY_FOR_RTT_001
 * @tc.desc: test adjustLinkPriorityForRtt with wifidirect ext cap
 *           It verifies whether the system correctly selects the P2P link as the preferred transmission
 *           method under certain conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_LANE_ADJUST_LINK_PRIORITY_FOR_RTT_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneSelectInterfaceMock> selectMock;
    EXPECT_CALL(laneMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(HO_OS_TYPE), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillRepeatedly(
        DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(PEER_UDID, PEER_UDID + UDID_BUF_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetLocalNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(127), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(127), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetLocalNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));

    EXPECT_EQ(SOFTBUS_OK, UpdateP2pAvailability(PEER_UDID, false));
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {
        .transType = LANE_T_FILE,
        .qosRequire.minBW = HIGH_BW,
        .qosRequire.rttLevel = LANE_RTT_LEVEL_LOW,
    };
    EXPECT_CALL(selectMock, SoftBusGetSysTimeMs).WillOnce(Return(0))
        .WillOnce(Return(WIFI_DIRECT_EXT_CAP_VALID_TIME));
    EXPECT_EQ(SOFTBUS_OK, SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList));
    EXPECT_EQ(LANE_P2P, linkList.linkType[linkList.linkTypeNum - 1]);
    EXPECT_EQ(SOFTBUS_OK, SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList));
    EXPECT_EQ(LANE_P2P, linkList.linkType[0]);
}

/*
 * @tc.name: LNN_LANE_ADJUST_LINK_PRIORITY_FOR_RTT_002
 * @tc.desc: test adjustLinkPriorityForRtt with other conditions
 *           To verify whether the system correctly selects P2P as the preferred link type
 *           under certain conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_LANE_ADJUST_LINK_PRIORITY_FOR_RTT_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneSelectInterfaceMock> selectMock;
    EXPECT_CALL(laneMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneMock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(OH_OS_TYPE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(HO_OS_TYPE), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(
        DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(PEER_UDID, PEER_UDID + UDID_BUF_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetLocalNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(127), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(127), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetLocalNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, LnnGetRemoteNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(selectMock, SoftBusGetSysTimeMs).WillOnce(Return(0));

    EXPECT_EQ(SOFTBUS_OK, UpdateP2pAvailability(PEER_UDID, false));
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {
        .transType = LANE_T_FILE,
        .qosRequire.minBW = HIGH_BW,
        .qosRequire.rttLevel = LANE_RTT_LEVEL_LOW,
    };
    EXPECT_EQ(SOFTBUS_OK, SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList));
    EXPECT_EQ(LANE_P2P, linkList.linkType[0]);
    EXPECT_EQ(SOFTBUS_OK, SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList));
    EXPECT_EQ(LANE_P2P, linkList.linkType[0]);
}

/*
 * @tc.name: LNN_SELECT_AUTH_LANE_TEST_001
 * @tc.desc: Test the behavior and error handling capability of the SelectAuthLane function
 *           under different input parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, LNN_SELECT_AUTH_LANE_TEST_001, TestSize.Level1)
{
    const char *networkId = "testnetworkid123";
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    LanePreferredLinkList recommendList = {};
    LanePreferredLinkList request = {};

    request.linkTypeNum = 4;
    request.linkType[0] = LANE_P2P;
    request.linkType[1] = LANE_BLE;
    request.linkType[2] = LANE_BR;
    request.linkType[3] = LANE_HML;

    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));

    int32_t ret = SelectAuthLane(nullptr, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectAuthLane(networkId, nullptr, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectAuthLane(networkId, &recommendList, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectAuthLane(networkId, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    recommendList.linkTypeNum = LANE_LINK_TYPE_BUTT + 1;
    ret = SelectAuthLane(networkId, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_ERR_CODE_01
 * @tc.desc: Test the logic of the GetErrCodeOfLink function for returning error codes
 *           under different network conditions
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLaneSelectTest, GET_ERR_CODE_01, TestSize.Level1)
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneDepsInterfaceMock> mock;

    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    int32_t ret = GetErrCodeOfLink("networkId", LANE_WLAN_2P4G);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_P2P_REUSE);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_DEACTIVATING));
    ret = GetErrCodeOfLink("networkId", LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_P2P_REUSE);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(mock, SoftBusGetBtState).WillRepeatedly(Return(BLE_DISABLE));
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BR), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_DIRECT), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_REUSE), SOFTBUS_LANE_BT_OFF);

    EXPECT_CALL(mock, SoftBusGetBtState).WillRepeatedly(Return(BLE_ENABLE));
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BR), SOFTBUS_LANE_LOCAL_NO_BR_STATIC_CAP);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE), SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_DIRECT), SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP);
}
} // namespace OHOS