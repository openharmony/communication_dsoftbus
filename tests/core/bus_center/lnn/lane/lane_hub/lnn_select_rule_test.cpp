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

#include "lnn_feature_capability.h"
#include "lnn_lane_link.h"
#include "lnn_select_rule.h"
#include "lnn_select_rule_mock.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "networkId";
constexpr char NODE_PEER_UDID[] = "udid";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr uint32_t DEFAULT_QOSINFO_MIN_BW = 10;
constexpr uint32_t DEFAULT_QOSINFO_MAX_LATENCY = 10000;
constexpr uint32_t DEFAULT_QOSINFO_MIN_LATENCY = 2500;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;
constexpr uint32_t LOCAL_NUM = 8192;
constexpr uint32_t ROM_NUM = 8;
constexpr uint32_t ROM_NUM2 = 2;

class LNNSelectRuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSelectRuleTest::SetUpTestCase()
{
    int32_t ret = InitLaneSelectRule();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNSelectRuleTest::TearDownTestCase()
{
    EXPECT_NO_FATAL_FAILURE(DeinitLaneSelectRule());
}

void LNNSelectRuleTest::SetUp()
{
}

void LNNSelectRuleTest::TearDown()
{
}

static int32_t ActionOfLnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    (void)netWorkId;
    (void)key;
    if (info == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(info, len, NODE_PEER_UDID) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

/*
* @tc.name: GET_SUPPORT_BAND_WIDTH_TEST_001
* @tc.desc: GetSupportBandWidth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_SUPPORT_BAND_WIDTH_TEST_001, TestSize.Level1)
{
    LaneTransType transType = LANE_T_MSG;
    uint32_t supportBw = BW_TYPE_BUTT;

    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    EXPECT_CALL(ruleMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(ruleMock, LnnGetRemoteNumU32Info).WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));

    int32_t ret = GetSupportBandWidth(nullptr, transType, &supportBw);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSupportBandWidth(NODE_NETWORK_ID, transType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSupportBandWidth(NODE_NETWORK_ID, transType, &supportBw);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
    EXPECT_EQ(supportBw, BW_TYPE_BUTT);
}

/*
* @tc.name: GET_SUPPORT_BAND_WIDTH_TEST_002
* @tc.desc: GetSupportBandWidth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_SUPPORT_BAND_WIDTH_TEST_002, TestSize.Level1)
{
    LaneTransType transType = LANE_T_MSG;
    uint32_t supportBw = BW_TYPE_BUTT;

    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    uint32_t cap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(ruleMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(cap), Return(SOFTBUS_OK)));
    EXPECT_CALL(ruleMock, LnnGetRemoteNumU32Info).WillRepeatedly(DoAll(SetArgPointee<2>(cap), Return(SOFTBUS_OK)));

    int32_t ret = GetSupportBandWidth(NODE_NETWORK_ID, transType, &supportBw);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(supportBw, LOW_BAND_WIDTH);
}

/*
* @tc.name: GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_001
* @tc.desc: GetAllSupportReuseBandWidth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_001, TestSize.Level1)
{
    LaneTransType transType = LANE_T_MSG;
    uint32_t *supportBw = nullptr;
    uint8_t bwCnt = 0;

    int32_t ret = GetAllSupportReuseBandWidth(nullptr, transType, &supportBw, &bwCnt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, nullptr, &bwCnt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, &supportBw, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    EXPECT_CALL(ruleMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, &supportBw, &bwCnt);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    EXPECT_EQ(supportBw, nullptr);
}

/*
* @tc.name: GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_002
* @tc.desc: GetAllSupportReuseBandWidth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_002, TestSize.Level1)
{
    LaneTransType transType = LANE_T_MSG;
    uint32_t *supportBw = nullptr;
    uint8_t bwCnt = 0;

    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    EXPECT_CALL(ruleMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ruleMock, GetAllLinkWithDevId).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, &supportBw, &bwCnt);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
    EXPECT_EQ(supportBw, nullptr);
}

/*
* @tc.name: GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_003
* @tc.desc: GetAllSupportReuseBandWidth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_ALL_SUPPORT_REUSE_BAND_WIDTH_TEST_003, TestSize.Level1)
{
    LaneTransType transType = LANE_T_MSG;
    uint32_t *supportBw = nullptr;
    uint8_t bwCnt = 0;

    LaneLinkType *tmpLinkList = (LaneLinkType *)SoftBusCalloc(1 * sizeof(LaneLinkType));
    ASSERT_NE(tmpLinkList, nullptr);
    tmpLinkList[0] = LANE_HML;
    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    EXPECT_CALL(ruleMock, LnnGetRemoteStrInfo).WillRepeatedly(Invoke(ActionOfLnnGetRemoteStrInfo));
    EXPECT_CALL(ruleMock, GetAllLinkWithDevId).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(tmpLinkList),
        SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    int32_t ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, &supportBw, &bwCnt);
    ASSERT_NE(supportBw, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(supportBw[0], HIGH_BAND_WIDTH);
    SoftBusFree(supportBw);
}

/*
* @tc.name: LNN_LANE_DECIDE_01
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_01, TestSize.Level1)
{
    LaneSelectParam request;
    LanePreferredLinkList recommendList;

    int32_t ret = DecideAvailableLane("test", nullptr, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecideAvailableLane("test", &request, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_DECIDE_02
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_02, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList;
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(laneLinkMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));

    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
* @tc.name: LNN_LANE_DECIDE_03
* @tc.desc: deciede aviable lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_03, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam request;
    LanePreferredLinkList recommendList;

    request.qosRequire.minLaneLatency = 0;
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = DecideAvailableLane("test", &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    request.transType = LANE_T_FILE;
    request.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    request.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    request.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(laneLinkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(laneLinkMock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    int32_t osType = OH_OS_TYPE;
    EXPECT_CALL(laneLinkMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
* @tc.name: LNN_LANE_DECIDE_04
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_04, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));

    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_DECIDE_05
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_05, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
}

/*
* @tc.name: LNN_LANE_DECIDE_06
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDE_06, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = HIGH_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
}

/*
* @tc.name: LNN_SELECT_NO_CAP_LINK_001
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_SELECT_NO_CAP_LINK_001, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = HIGH_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    uint32_t hmlStaticCap = 1 << STATIC_CAP_BIT_ENHANCED_P2P;
    uint64_t hmlFeatureCap = 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY;
    uint32_t hmlDynamicCap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(hmlStaticCap | hmlDynamicCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(hmlStaticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(hmlFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(hmlFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_USB_STATIC_CAP);
}

/*
* @tc.name: LNN_SELECT_NO_CAP_LINK_002
* @tc.desc: deciede available lane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_SELECT_NO_CAP_LINK_002, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> laneLinkMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    LinkLedgerInfo info = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = HIGH_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    uint32_t hmlStaticCap = 1 << STATIC_CAP_BIT_ENHANCED_P2P;
    uint64_t hmlFeatureCap = 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY;
    uint32_t hmlDynamicCap = 1 << BIT_WIFI_P2P;
    EXPECT_CALL(laneLinkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(hmlStaticCap | hmlDynamicCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(hmlStaticCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetLocalNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(hmlFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteNumU64Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(hmlFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, LnnGetRemoteStrInfo).WillRepeatedly(
        DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(PEER_UDID, PEER_UDID + UDID_BUF_LEN), Return(SOFTBUS_OK)));

    EXPECT_CALL(laneLinkMock, LnnGetLinkLedgerInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_USB_STATIC_CAP);

    info.lastTryBuildTime = 1;
    EXPECT_CALL(laneLinkMock, LnnGetLinkLedgerInfo).WillRepeatedly(DoAll(SetArgPointee<1>(info), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.lastTryBuildTime = SoftBusGetSysTimeMs();
    EXPECT_CALL(laneLinkMock, LnnGetLinkLedgerInfo).WillRepeatedly(DoAll(SetArgPointee<1>(info), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_USB_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_01
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_SELECT_RULE_01, TestSize.Level1)
{
    LaneLinkType linkList;
    uint32_t listNum = 0;
    LanePreferredLinkList recommendList;
    int32_t ret = FinalDecideLinkType(nullptr, &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FinalDecideLinkType(nullptr, nullptr, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FinalDecideLinkType(nullptr, nullptr, listNum, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listNum = LANE_LINK_TYPE_BUTT;
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_02
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_SELECT_RULE_02, TestSize.Level1)
{
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT];
    uint32_t listNum = 1;
    LanePreferredLinkList recommendList;

    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));

    linkList[0] = LANE_P2P;
    int32_t ret = FinalDecideLinkType("test", linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_03
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_SELECT_RULE_03, TestSize.Level1)
{
    LaneLinkType linkList;
    uint32_t listNum = 1;
    LanePreferredLinkList recommendList;

    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_NETWORK_NOT_FOUND)));

    int32_t ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(-1), Return(SOFTBUS_OK)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_INVALID_PARAM)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(-1), Return(SOFTBUS_OK)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: GET_WLAN_LINKED_FREQUENCY_TEST_001
* @tc.desc: LnnQueryLaneResource test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, GET_WLAN_LINKED_FREQUENCY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetWlanLinkedInfoPacked).WillRepeatedly(Return(SOFTBUS_LANE_SELECT_FAIL));
    int32_t ret = GetWlanLinkedFrequency();
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
    EXPECT_CALL(linkMock, LnnGetWlanLinkedInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetWlanLinkedFrequency();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_UPDATE_P2P_AVAILABILITY_001
* @tc.desc: test updateP2pAvailability for create new node
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_UPDATE_P2P_AVAILABILITY_001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateP2pAvailability(nullptr, false));
    EXPECT_EQ(SOFTBUS_OK, UpdateP2pAvailability(PEER_UDID, false));
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_01
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_01, TestSize.Level1)
{
    const char *networkId = "test";
    int32_t ret = LaneCheckLinkValid(nullptr, LANE_BR, LANE_T_MSG);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneCheckLinkValid(networkId, LANE_LINK_TYPE_BUTT, LANE_T_MSG);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_LANE_LOCAL_NO_BR_STATIC_CAP));
    ret = LaneCheckLinkValid(networkId, LANE_BR, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_BR_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_02
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_02, TestSize.Level1)
{
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    LaneLinkType linkType = LANE_ETH;
    int32_t ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_ETH_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_03
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_03, TestSize.Level1)
{
    LaneLinkType linkType = LANE_COC_DIRECT;
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(LOCAL_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(LOCAL_NUM), Return(SOFTBUS_OK)));
    int32_t ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_COC_FEATURE);
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_04
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_04, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_DEACTIVATING));
    int32_t ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_P2P_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_05
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_05, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    int32_t ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_P2P_STATIC_CAP);
}

/*
* @tc.name: LNN_LANE_CHECK_VALID_LANE_06
* @tc.desc: SelectLaneRule check valid lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_CHECK_VALID_LANE_06, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    int32_t ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_P2P_REUSE_FEATURE);
    EXPECT_CALL(linkMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM2), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM2), Return(SOFTBUS_OK)));
    ret = LaneCheckLinkValid(NODE_NETWORK_ID, linkType, LANE_T_BUTT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_DECIDEREUSELANE_01
* @tc.desc: DecideReuseLane check valid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDEREUSELANE_01, TestSize.Level1)
{
    LaneSelectParam request = {};
    LanePreferredLinkList laneLinkList = {
        .linkType[0] = LANE_BR,
        .linkTypeNum = 1,
    };
    int32_t ret = DecideReuseLane(nullptr, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecideReuseLane(NODE_NETWORK_ID, nullptr, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecideReuseLane(NODE_NETWORK_ID, &request, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DecideReuseLane(NODE_NETWORK_ID, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_DECIDEREUSELANE_02
* @tc.desc: DecideReuseLane test br support reuse
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSelectRuleTest, LNN_LANE_DECIDEREUSELANE_02, TestSize.Level1)
{
    LaneSelectParam request = {
        .transType = LANE_T_RAW_STREAM,
    };
    LanePreferredLinkList laneLinkList = {};
    NiceMock<LnnSelectRuleInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(TYPE_WATCH_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = DecideReuseLane(NODE_NETWORK_ID, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);

    EXPECT_CALL(linkMock, FindLaneResourceByLinkType)
        .WillOnce(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = DecideReuseLane(NODE_NETWORK_ID, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    uint32_t brCap = (1 << STATIC_CAP_BIT_BR) | (1 << BIT_BR);
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM2>(brCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info).WillRepeatedly(
        DoAll(SetArgPointee<LANE_MOCK_PARAM3>(brCap), Return(SOFTBUS_OK)));
    ret = DecideReuseLane(NODE_NETWORK_ID, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_TRANS_TYPE_NOT_MATCH);

    request.transType = LANE_T_MSG;
    ret = DecideReuseLane(NODE_NETWORK_ID, &request, &laneLinkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
