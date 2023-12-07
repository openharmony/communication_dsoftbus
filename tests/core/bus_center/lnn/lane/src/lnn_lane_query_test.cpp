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

#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "lnn_lane_query.h"
#include "lnn_lane.h"

using namespace testing::ext;

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

/*
* @tc.name: LNN_QUERY_LANE_001
* @tc.desc: QueryLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneQueryTest, LNN_LANE_QUERY_001, TestSize.Level1)
{
    QosInfo qosInfo = {0};
    int32_t ret = LnnQueryLaneResource(nullptr, &qosInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneQueryInfo query;
    memset_s(&query, sizeof(LaneQueryInfo), 0, sizeof(LaneQueryInfo));
    query.transType = LANE_T_BYTE;
    (void)memcpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));

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
    QosInfo qosInfo = {0};
    int32_t ret = QueryLaneResource(nullptr, &qosInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneQueryInfo query;
    query.transType = LANE_T_BYTE;
    (void)memcpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
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
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_MSG;
    (void)memcpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));

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
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_FILE;
    (void)memcpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));

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
    QosInfo qosInfo = {0};
    LaneQueryInfo query;
    query.transType = LANE_T_RAW_STREAM;
    (void)memcpy_s(query.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));

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
}