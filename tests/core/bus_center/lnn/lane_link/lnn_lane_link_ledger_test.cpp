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
constexpr uint32_t MAX_NODE_SIZE = 20;

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
* @tc.name: LNN_ADD_LINK_LEDGER_INFO_TEST_001
* @tc.desc: test lane add link ledger info invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_ADD_LINK_LEDGER_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnAddLinkLedgerInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnAddLinkLedgerInfo(PEER_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_DELETE_LINK_LEDGER_INFO_TEST_001
* @tc.desc: test lane delete link ledger info invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_DELETE_LINK_LEDGER_INFO_TEST_001, TestSize.Level1)
{
    LinkLedgerInfo info = {
        .lastTryBuildTime = TEST_TIME,
    };
    int32_t ret = LnnAddLinkLedgerInfo(PEER_UDID, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(PEER_UDID));
}

/*
* @tc.name: LNN_GET_LINK_LEDGER_INFO_TEST_001
* @tc.desc: test lane get link ledger info invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_LEDGER_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnGetLinkLedgerInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLinkLedgerInfo(PEER_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_LINK_LEDGER_INFO_TEST_002
* @tc.desc: test lane get link ledger info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_GET_LINK_LEDGER_INFO_TEST_002, TestSize.Level1)
{
    LinkLedgerInfo queryInfo;
    (void)memset_s(&queryInfo, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    int32_t ret = LnnGetLinkLedgerInfo(PEER_UDID, &queryInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
* @tc.name: LNN_LINK_LEDGER_INFO_FUNC_TEST_001
* @tc.desc: test lane get link ledger info func
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_LINK_LEDGER_INFO_FUNC_TEST_001, TestSize.Level1)
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

static void AddLinkLedgerNodesByCount(const char *baseUdid, uint64_t baseTime, uint32_t count)
{
    char udid[UDID_BUF_LEN] = {0};
    LinkLedgerInfo info = {};
    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = sprintf_s(udid, sizeof(udid), "%s_%d", baseUdid, i);
        EXPECT_TRUE(ret != EOK);
        info.lastTryBuildTime = baseTime + i;
        ret = LnnAddLinkLedgerInfo(udid, &info);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

static void DeleteLinkLedgerNodesByCount(const char *baseUdid, uint32_t count)
{
    char udid[UDID_BUF_LEN] = {0};
    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = sprintf_s(udid, sizeof(udid), "%s_%d", baseUdid, i);
        EXPECT_TRUE(ret != EOK);
        EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(udid));
    }
}

/*
* @tc.name: LNN_LINK_LEDGER_MULTI_NODE_TEST_001
* @tc.desc: test link ledger multi node
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_LINK_LEDGER_MULTI_NODE_TEST_001, TestSize.Level1)
{
    LinkLedgerInfo info = {};
    char udid[UDID_BUF_LEN] = {0};
    char firstUdid[UDID_BUF_LEN] = {0};

    AddLinkLedgerNodesByCount(PEER_UDID, TEST_TIME, MAX_NODE_SIZE);
    int32_t ret = sprintf_s(firstUdid, sizeof(firstUdid), "%s_%d", PEER_UDID, 0);
    EXPECT_TRUE(ret != EOK);
    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(firstUdid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(info.lastTryBuildTime, TEST_TIME);

    info.lastTryBuildTime = TEST_TIME + MAX_NODE_SIZE;
    ret = sprintf_s(udid, sizeof(udid), "%s_%d", PEER_UDID, MAX_NODE_SIZE);
    EXPECT_TRUE(ret != EOK);
    ret = LnnAddLinkLedgerInfo(udid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(udid));

    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(firstUdid, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = sprintf_s(udid, sizeof(udid), "%s_%d", PEER_UDID, 1);
    EXPECT_TRUE(ret != EOK);
    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(udid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(info.lastTryBuildTime, TEST_TIME + 1);

    DeleteLinkLedgerNodesByCount(PEER_UDID, MAX_NODE_SIZE);
}

/*
* @tc.name: LNN_LINK_LEDGER_MULTI_NODE_TEST_001
* @tc.desc: test link ledger multi node
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkLedgerTest, LNN_LINK_LEDGER_MULTI_NODE_TEST_002, TestSize.Level1)
{
    LinkLedgerInfo info = {};
    char udid[UDID_BUF_LEN] = {0};
    char firstUdid[UDID_BUF_LEN] = {0};
    int32_t ret = sprintf_s(firstUdid, sizeof(firstUdid), "%s_%d", PEER_UDID, 0);
    EXPECT_TRUE(ret != EOK);

    AddLinkLedgerNodesByCount(PEER_UDID, TEST_TIME, MAX_NODE_SIZE);
    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(firstUdid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(info.lastTryBuildTime, TEST_TIME);

    uint64_t updateTime = TEST_TIME + MAX_NODE_SIZE;
    info.lastTryBuildTime = updateTime;
    ret = LnnAddLinkLedgerInfo(firstUdid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.lastTryBuildTime = TEST_TIME + MAX_NODE_SIZE + 1;
    ret = sprintf_s(udid, sizeof(udid), "%s_%d", PEER_UDID, MAX_NODE_SIZE);
    EXPECT_TRUE(ret != EOK);
    ret = LnnAddLinkLedgerInfo(udid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnDeleteLinkLedgerInfo(udid));

    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(firstUdid, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(info.lastTryBuildTime, updateTime);

    ret = sprintf_s(udid, sizeof(udid), "%s_%d", PEER_UDID, 1);
    EXPECT_TRUE(ret != EOK);
    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(udid, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    DeleteLinkLedgerNodesByCount(PEER_UDID, MAX_NODE_SIZE);
}
} // namespace OHOS