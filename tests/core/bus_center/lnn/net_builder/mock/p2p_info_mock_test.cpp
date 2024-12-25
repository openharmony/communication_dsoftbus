/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "net_ledger_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
class P2pInfoMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void P2pInfoMockTest::SetUpTestCase()
{
    LooperInit();
}

void P2pInfoMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void P2pInfoMockTest::SetUp() { }

void P2pInfoMockTest::TearDown() { }

/*
 * @tc.name: P2P_INFO_MOCK_TEST_001
 * @tc.desc: test LnnInitLocalP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pInfoMockTest, P2P_INFO_MOCK_TEST_001, TestSize.Level1)
{
    NetLedgerMock netLedgerMock;
    netLedgerMock.SetupDefaultResult();
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    int32_t ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pRole(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pMac(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pGoMac(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetWifiDirectAddr(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_002
 * @tc.desc: test LnnSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pInfoMockTest, P2P_INFO_MOCK_TEST_002, TestSize.Level1)
{
    NetLedgerMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncP2pInfo();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(500);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_003
 * @tc.desc: test LnnInitP2p
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pInfoMockTest, P2P_INFO_MOCK_TEST_003, TestSize.Level1)
{
    int32_t ret = LnnInitP2p();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitP2p();
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_004
 * @tc.desc: test LnnInitWifiDirect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pInfoMockTest, P2P_INFO_MOCK_TEST_004, TestSize.Level1)
{
    int32_t ret = LnnInitWifiDirect();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitP2p();
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_005
 * @tc.desc: test LnnSyncWifiDirectAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pInfoMockTest, P2P_INFO_MOCK_TEST_005, TestSize.Level1)
{
    NetLedgerMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncWifiDirectAddr();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(500);
}
} // namespace OHOS
