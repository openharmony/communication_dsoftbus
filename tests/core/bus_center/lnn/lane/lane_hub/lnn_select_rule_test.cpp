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

#include "lnn_lane_link.h"
#include "lnn_select_rule.h"
#include "lnn_select_rule_mock.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "networkId";
constexpr char NODE_PEER_UDID[] = "udid";

class LNNSelectRuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSelectRuleTest::SetUpTestCase()
{
    int32_t ret = InitLaneLink();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNSelectRuleTest::TearDownTestCase()
{
    DeinitLaneLink();
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
    if (info == nullptr || len > UDID_BUF_LEN || len <= strlen(NODE_PEER_UDID)) {
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

    LaneLinkInfo info = {};
    ASSERT_EQ(strcpy_s(info.peerUdid, UDID_BUF_LEN, NODE_PEER_UDID), EOK);
    uint64_t laneId = 1111;
    info.type = LANE_HML;
    int32_t ret = AddLaneResourceToPool(&info, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnSelectRuleInterfaceMock> ruleMock;
    EXPECT_CALL(ruleMock, LnnGetRemoteStrInfo).WillRepeatedly(Invoke(ActionOfLnnGetRemoteStrInfo));
    ret = GetAllSupportReuseBandWidth(NODE_NETWORK_ID, transType, &supportBw, &bwCnt);
    ASSERT_TRUE(supportBw != nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(supportBw[0], HIGH_BAND_WIDTH);
    SoftBusFree(supportBw);

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
