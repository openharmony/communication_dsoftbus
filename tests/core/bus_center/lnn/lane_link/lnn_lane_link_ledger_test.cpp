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
#include <thread>
#include <securec.h>
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_ledger.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint64_t TEST_TIME = 1234567;
constexpr char PEER_UDID[] = "111122223333abcdef";

class LNNLaneLinkLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkLedgerTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkLedgerTest start";
    int32_t ret = InitLinkLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNLaneLinkLedgerTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkLedgerTest end";
    DeinitLinkLedger();
}

void LNNLaneLinkLedgerTest::SetUp()
{
}

void LNNLaneLinkLedgerTest::TearDown()
{
}

/*
* @tc.name: LNN_ADD_LINK_BUILD_INFO_TEST_001
* @tc.desc: test lane add link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_ADD_LINK_BUILD_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnAddLinkLedgerInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_ADD_LINK_BUILD_INFO_TEST_002
* @tc.desc: test lane add link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_ADD_LINK_BUILD_INFO_TEST_002, TestSize.Level1)
{
    LinkLedgerInfo info = {
        .lastTryBuildTime = TEST_TIME,
    };
    int32_t ret = LnnAddLinkLedgerInfo(PEER_UDID, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(PEER_UDID));
}

/*
* @tc.name: LNN_GET_LINK_BUILD_INFO_TEST_001
* @tc.desc: test lane get link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_BUILD_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnGetLinkLedgerInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLinkLedgerInfo(PEER_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_LINK_BUILD_INFO_TEST_002
* @tc.desc: test lane get link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_BUILD_INFO_TEST_002, TestSize.Level1)
{
    LinkLedgerInfo queryInfo;
    (void)memset_s(&queryInfo, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    int32_t ret = LnnGetLinkLedgerInfo(PEER_UDID, &queryInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
* @tc.name: LNN_GET_LINK_BUILD_INFO_TEST_003
* @tc.desc: test lane get link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_BUILD_INFO_TEST_003, TestSize.Level1)
{
    LinkLedgerInfo info = {
        .lastTryBuildTime = TEST_TIME,
    };
    int32_t ret = LnnAddLinkLedgerInfo(PEER_UDID, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LinkLedgerInfo queryInfo;
    (void)memset_s(&queryInfo, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(PEER_UDID, &queryInfo);
    EXPECT_EQ(info.lastTryBuildTime, queryInfo.lastTryBuildTime);
    EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(PEER_UDID));
}

/*
* @tc.name: LNN_GET_LINK_BUILD_INFO_TEST_004
* @tc.desc: test lane get link build info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_BUILD_INFO_TEST_004, TestSize.Level1)
{
    LinkLedgerInfo info = {
        .lastTryBuildTime = TEST_TIME,
    };
    int32_t ret = LnnAddLinkLedgerInfo(PEER_UDID, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeleteLinkLedgerInfo(nullptr);
    LnnDeleteLinkLedgerInfo(PEER_UDID);
    LinkLedgerInfo queryInfo;
    (void)memset_s(&queryInfo, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(PEER_UDID, &queryInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}
} // namespace OHOS