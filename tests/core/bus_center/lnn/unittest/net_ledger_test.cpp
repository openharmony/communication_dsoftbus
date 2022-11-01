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

#include <gtest/gtest.h>
#include <securec.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "auth_interface.h"
#include "lnn_decision_db.h"
#include "lnn_decision_db.c"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_manager.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_errcode.h"
#include "softbus_conn_interface.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 10;
constexpr uint8_t DEFAULT_SIZE = 5;

class NetLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetLedgerTest::SetUpTestCase()
{
}

void NetLedgerTest::TearDownTestCase()
{
}

void NetLedgerTest::SetUp()
{
    LOG_INFO("NetLedgerTest start.");
}

void NetLedgerTest::TearDown()
{
}

/*
* @tc.name: BUILD_TRUSTED_DEV_INFO_RECORD_Test_001
* @tc.desc: build trusted dev info record test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, BUILD_TRUSTED_DEV_INFO_RECORD_Test_001, TestSize.Level1)
{
    const char *udid = "testdata";
    TrustedDevInfoRecord record;
    int32_t ret;

    (void)memset_s(&record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord));
    ret = BuildTrustedDevInfoRecord(udid, &record);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001
* @tc.desc: lnn get trusted dev info from db test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, LNN_GET_TRUSTED_DEV_INFO_FROM_DB_Test_001, TestSize.Level1)
{
    uint32_t num = 0;
    int32_t ret;

    char *udidArray = new char[TEST_DATA_LEN];
    ret = LnnGetTrustedDevInfoFromDb(&udidArray, &num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    delete[] udidArray;
}

/*
* @tc.name: DL_GET_Test_001
* @tc.desc: Dl Get Auth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, DL_GET_Test_001, TestSize.Level0)
{
    char networkId[DEFAULT_SIZE] = "1234";
    int32_t info = 1234;
    EXPECT_TRUE(LnnGetRemoteNumInfo(nullptr, NUM_KEY_SESSION_PORT, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, STRING_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, &info) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_END, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetRemoteNumInfo(networkId, NUM_KEY_AUTH_PORT, &info) == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_ADD_META_INFO_Test_001
* @tc.desc: Lnn Add Meta Info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, LNN_ADD_META_INFO_Test_001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(LnnAddMetaInfo(&info) == SOFTBUS_OK);
}

/*
* @tc.name: LNN_DELETE_META_INFO_Test_001
* @tc.desc: Lnn Delete Meta Info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, LNN_DELETE_META_INFO_Test_001, TestSize.Level0)
{
    char udid[DEFAULT_SIZE] = "1234";
    ConnectionAddrType type = CONNECTION_ADDR_WLAN;
    EXPECT_TRUE(LnnDeleteMetaInfo(udid, type) == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_ADD_ONLINE_NODE_Test_001
* @tc.desc: Lnn Add Online Node test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, LNN_ADD_ONLINE_NODE_Test_001, TestSize.Level0)
{
    NodeInfo *info = nullptr;
    EXPECT_TRUE(LnnAddOnlineNode(info) == REPORT_NONE);
    NodeInfo infoValue;
    (void)memset_s(&infoValue, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_TRUE(LnnAddOnlineNode(&infoValue) == REPORT_ONLINE);
}

/*
* @tc.name: GET_ALL_ONLINE_AND_META_NODE_INFO_Test_001
* @tc.desc: Get All Online And Meta Node Info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(NetLedgerTest, GET_ALL_ONLINE_AND_META_NODE_INFO_Test_001, TestSize.Level0)
{
    NodeBasicInfo base;
    NodeBasicInfo *info = nullptr;
    int32_t infoNum = 0;
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(nullptr, &infoNum) == SOFTBUS_ERR);
    info = &base;
    (void)memset_s(info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, nullptr) == SOFTBUS_ERR);
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) == SOFTBUS_OK);
    infoNum = DEFAULT_SIZE;
    EXPECT_TRUE(LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) == SOFTBUS_OK);
}
} // namespace OHOS
