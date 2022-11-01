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

#include "bus_center_info_key.h"
#include "lnn_net_ledger.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_network_id.h"
#include "bus_center_manager.h"
#include "client_bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_node_info.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_adapter_mem.h"
#include "lnn_net_ledger.c"

namespace OHOS {
using namespace testing::ext;

class LnnNetLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetLedgerTest::SetUpTestCase()
{
}

void LnnNetLedgerTest::TearDownTestCase()
{
}

void LnnNetLedgerTest::SetUp()
{
}

void LnnNetLedgerTest::TearDown()
{
}

/*
* @tc.name: LNN_SET_NODE_DATA_CHANGE_FLAG_Test_001
* @tc.desc: Lnn Set Node Data Change Flag test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, LNN_SET_NODE_DATA_CHANGE_FLAG_Test_001, TestSize.Level0)
{
    char *networkId = nullptr;
    char networkIdSecond[NETWORK_ID_BUF_LEN] = "1234";
    uint16_t dataChangeFlag = 0;
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(networkId, dataChangeFlag) == SOFTBUS_ERR);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(networkIdSecond, dataChangeFlag) == SOFTBUS_ERR);
}

/*
* @tc.name: SOFTBUS_DUMP_PRINT_NET_CAPACITY_Test_001
* @tc.desc: SoftbusDumpPrintNetCapacity test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, SOFTBUS_DUMP_PRINT_NET_CAPACITY_Test_001, TestSize.Level0)
{
    int fd = 0;
    NodeBasicInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(SoftbusDumpPrintNetCapacity(fd, &nodeInfo) == SOFTBUS_OK);
}

/*
* @tc.name: SOFTBUS_DUMP_PRINT_NET_TYPE_Test_001
* @tc.desc: SoftbusDumpPrintNetType test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, SOFTBUS_DUMP_PRINT_NET_TYPE_Test_001, TestSize.Level0)
{
    int fd = 0;
    NodeBasicInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_TRUE(SoftbusDumpPrintNetType(fd, &nodeInfo) == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SET_DATA_CHANGE_FLAG_Test_001
* @tc.desc: Lnn Set Data Change Flag test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, LNN_SET_DATA_CHANGE_FLAG_Test_001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo *nodeinfo = nullptr;
    uint16_t dataChangeFlag = 0;
    EXPECT_TRUE(LnnSetDataChangeFlag(nodeinfo, dataChangeFlag) == SOFTBUS_INVALID_PARAM);
    nodeinfo = &info;
    EXPECT_TRUE(LnnSetDataChangeFlag(nodeinfo, dataChangeFlag) == SOFTBUS_OK);
}

/*
* @tc.name: LNN_GET_DATA_CHANGE_FLAG_Test_001
* @tc.desc: Lnn Get Data Change Flag test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, LNN_GET_DATA_CHANGE_FLAG_Test_001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo *nodeinfo = nullptr;
    EXPECT_TRUE(LnnGetDataChangeFlag(nodeinfo) == 0);
    nodeinfo = &info;
    EXPECT_TRUE(LnnGetDataChangeFlag(nodeinfo) == 0);
}

/*
* @tc.name: LNN_GET_LOCAL_STR_INFO_Test_001
* @tc.desc: Lnn Get Local Str Info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, LNN_GET_LOCAL_STR_INFO_Test_001, TestSize.Level0)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char *nodeInfo = reinterpret_cast<char*>(&info);
    uint32_t len = 0;
    EXPECT_TRUE(LnnSetLocalStrInfo(NUM_KEY_DATA_CHANGE_FLAG, nodeInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_AUTH_PORT, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_SESSION_PORT, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_PROXY_PORT, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_NET_CAP, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_DISCOVERY_TYPE, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_DEV_TYPE_ID, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_MASTER_NODE_WEIGHT, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_P2P_ROLE, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetLocalStrInfo(NUM_KEY_DATA_CHANGE_FLAG, nodeInfo, len) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_INIT_LOCAL_LEDGER_DELAY_Test_001
* @tc.desc: Lnn Init Local Ledger Delay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetLedgerTest, LNN_INIT_LOCAL_LEDGER_DELAY_Test_001, TestSize.Level0)
{
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_OK);
}
} // namespace OHOS
