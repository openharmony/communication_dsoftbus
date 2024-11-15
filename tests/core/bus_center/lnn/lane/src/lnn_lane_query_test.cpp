/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "lnn_lane_query.c"
#include "lnn_lane_query.h"
#include "lnn_lane_query_deps_mock.h"
#include "lnn_lane.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr uint32_t LOW_BW = 500 * 1024;
constexpr uint32_t MID_BW = 1000 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;

class LNNLaneQueryTest : public testing::Test {
public:
    LNNLaneQueryTest()
    {
    }
    ~LNNLaneQueryTest()
    {
    }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

void LNNLaneQueryTest::SetUpTestCase(void)
{
}

void LNNLaneQueryTest::TearDownTestCase(void)
{
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    GTEST_LOG_(INFO) << "PrejudgeAvailability Enter";
    return SOFTBUS_OK;
}

static int32_t PrejudgeAvailabilityForP2p(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    GTEST_LOG_(INFO) << "PrejudgeAvailabilityForP2p Enter";
    return V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static int32_t PrejudgeAvailabilityForHml(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    GTEST_LOG_(INFO) << "PrejudgeAvailabilityForHml Enter";
    return ERROR_LOCAL_THREE_VAP_CONFLICT;
}

struct WifiDirectManager g_manager = {
    .prejudgeAvailability = PrejudgeAvailability,
};

struct WifiDirectManager g_managerp2p = {
    .prejudgeAvailability = PrejudgeAvailabilityForP2p,
};

struct WifiDirectManager g_managerhml = {
    .prejudgeAvailability = PrejudgeAvailabilityForHml,
};

/*
* @tc.name: LNN_QUERY_LANE_001
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_001, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    QosInfo qosInfo = {0};
    int32_t ret = LnnQueryLaneResource(nullptr, &qosInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneQueryInfo query;
    memset_s(&query, sizeof(LaneQueryInfo), 0, sizeof(LaneQueryInfo));
    query.transType = LANE_T_BYTE;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);

    ret = LnnQueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnQueryLaneResource(&query, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnQueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = LnnQueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_002
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_002, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    QosInfo qosInfo = {0};
    int32_t ret = QueryLaneResource(nullptr, &qosInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneQueryInfo query;
    query.transType = LANE_T_BYTE;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    ret = QueryLaneResource(&query, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    qosInfo.minBW = LOW_BW;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    qosInfo.minBW = MID_BW;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_003
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_003, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_MSG;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);

    qosInfo.minBW = LOW_BW;
    int32_t ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    qosInfo.minBW = MID_BW;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_004
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_004, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_FILE;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);

    qosInfo.minBW = LOW_BW;
    int32_t ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    qosInfo.minBW = MID_BW;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    qosInfo.minBW = HIGH_BW;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_005
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_005, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_RAW_STREAM;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);

    qosInfo.minBW = MID_BW;
    int32_t ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    query.transType = LANE_T_COMMON_VIDEO;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    query.transType = LANE_T_COMMON_VOICE;
    ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_006
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_006, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_RAW_STREAM;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    qosInfo.minBW = 0;
    int32_t ret = QueryLaneResource(&query, &qosInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_007
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_007, TestSize.Level1)
{
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT];
    (void)memset_s(linkList, sizeof(linkList), -1, sizeof(linkList));
    uint32_t listNum = 0;
    GetFileLaneLink(linkList, &listNum, false);
    GetMsgLaneLink(linkList, &listNum, false);
    GetBytesLaneLink(linkList, &listNum, false);
    LaneTransType transType = LANE_T_MIX;
    int32_t ret = GetLaneResource(transType, linkList, &listNum, false);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_008
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_008, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNumU32Info)
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t local;
    uint32_t remote;
    bool ret = GetNetCap(NODE_NETWORK_ID, &local, &remote);
    EXPECT_FALSE(ret);
    ret = GetNetCap(NODE_NETWORK_ID, &local, &remote);
    EXPECT_TRUE(ret);
}

/*
* @tc.name: LNN_QUERY_LANE_009
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_009, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArgPointee<1>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_BR), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNumU32Info)
        .WillOnce(DoAll(SetArgPointee<2>(1 << BIT_BR), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << BIT_BR), Return(SOFTBUS_OK)));
    int32_t ret = BrLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = BrLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_BLUETOOTH_OFF);
    ret = BrLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_BLUETOOTH_OFF);
    ret = BrLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_010
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_010, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArgPointee<1>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_BLE), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNumU32Info)
        .WillOnce(DoAll(SetArgPointee<2>(1 << BIT_BLE), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << BIT_BLE), Return(SOFTBUS_OK)));
    int32_t ret = BleLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = BleLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_BLUETOOTH_OFF);
    ret = BleLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_BLUETOOTH_OFF);
    ret = BleLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_011
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_011, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, SoftBusIsWifiActive)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_NETWORK_GET_NODE_INFO_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkQueryMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(linkQueryMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArgPointee<1>(BIT_BR), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_WIFI), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNumU32Info)
        .WillOnce(DoAll(SetArgPointee<2>(1 << BIT_WIFI), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(BIT_BR), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << BIT_WIFI), Return(SOFTBUS_OK)));
    int32_t ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DISCONNECT);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DISCONNECT);
    EXPECT_CALL(linkQueryMock, LnnHasDiscoveryType)
        .WillOnce(Return(false)).WillOnce(Return(false)).WillOnce(Return(true))
        .WillOnce(Return(false)).WillOnce(Return(true)).WillRepeatedly(Return(true));
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WlanLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_QUERY_LANE_012
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_012, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager)
        .WillOnce(Return(NULL))
        .WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkQueryMock, SoftBusGetWifiState)
        .WillOnce(Return(SOFTBUS_WIFI_STATE_INACTIVE))
        .WillOnce(Return(SOFTBUS_WIFI_STATE_DEACTIVATING))
        .WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVE));
    EXPECT_CALL(linkQueryMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArgPointee<1>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1 << BIT_WIFI_P2P), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteNumU32Info)
        .WillOnce(DoAll(SetArgPointee<2>(1 << BIT_WIFI_P2P), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(BIT_BLE), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << BIT_WIFI_P2P), Return(SOFTBUS_OK)));
    int32_t ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_P2P_NOT_SUPPORT);
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_OFF);
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_OFF);
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_P2P_NOT_SUPPORT);
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_P2P_NOT_SUPPORT);
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager)
        .WillOnce(Return(&g_managerp2p))
        .WillRepeatedly(Return(&g_manager));
    ret = P2pLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_P2P_ROLE_CONFLICT);
}

/*
* @tc.name: LNN_QUERY_LANE_013
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_013, TestSize.Level1)
{
    NiceMock<LaneQueryDepsInterfaceMock> linkQueryMock;
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager)
        .WillOnce(Return(NULL))
        .WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkQueryMock, SoftBusGetWifiState)
        .WillOnce(Return(SOFTBUS_WIFI_STATE_INACTIVE))
        .WillOnce(Return(SOFTBUS_WIFI_STATE_DEACTIVATING))
        .WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVE));
    EXPECT_CALL(linkQueryMock, IsFeatureSupport)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(linkQueryMock, LnnGetRemoteBoolInfo)
        .WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkQueryMock, LnnGetFeatureCapabilty)
        .WillRepeatedly(Return(1));
    int32_t ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_HML_NOT_SUPPORT);
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_OFF);
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_WIFI_OFF);
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_HML_NOT_SUPPORT);
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    EXPECT_CALL(linkQueryMock, LnnGetRemoteBoolInfo)
        .WillOnce(DoAll(SetArgPointee<2>(false), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(true), Return(SOFTBUS_OK)));
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_HML_NOT_SUPPORT);
    EXPECT_CALL(linkQueryMock, GetWifiDirectManager)
        .WillOnce(Return(&g_managerhml))
        .WillRepeatedly(Return(&g_manager));
    ret = HmlLinkState(NODE_NETWORK_ID);
    EXPECT_EQ(ret, SOFTBUS_HML_THREE_VAP_CONFLIC);
}

/*
* @tc.name: LNN_QUERY_LANE_014
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_014, TestSize.Level1)
{
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    (void)memset_s(&query, sizeof(LaneQueryInfo), 0, sizeof(LaneQueryInfo));
    query.transType = LANE_T_MIX;
    EXPECT_EQ(strncpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    int32_t ret = QueryByRequireLink(&query, &qosInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = QueryByDefaultLink(&query);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_QUERY_LANE_015
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_QUERY_LANE_015, TestSize.Level1)
{
    QosInfo qosInfo = {0};
    int32_t ret = IsValidLaneLink(NODE_NETWORK_ID, LANE_LINK_TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    qosInfo.minBW = HIGH_BW;
    bool isHighBand = false;
    EXPECT_TRUE(isHighRequire(&qosInfo, &isHighBand));
}
}