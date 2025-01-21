/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bus_center_server_proxy.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
constexpr char BR_MAC[BT_MAC_LEN] = "01:02:03:04:05:06";

class BusCenterServerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterServerTest::SetUpTestCase()
{
    SetAccessTokenPermission("busCenterTest");
    int32_t ret = BusCenterServerProxyInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void BusCenterServerTest::TearDownTestCase() { }

void BusCenterServerTest::SetUp() { }

void BusCenterServerTest::TearDown() { }

/*
 * @tc.name: SERVER_IPC_JOIN_LNN_TEST_001
 * @tc.desc: server ipc join lnn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_JOIN_LNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    ConnectionAddr addr = {
        .type = CONNECTION_ADDR_BR,
        .peerUid = "001",
    };

    EXPECT_TRUE(strncpy_s(addr.info.br.brMac, BT_MAC_LEN, BR_MAC, BT_MAC_LEN) == EOK);
    int32_t ret = ServerIpcJoinLNN(pkgName, static_cast<void *>(&addr), sizeof(ConnectionAddr));
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SERVER_IPC_LEAVE_LNN_TEST_001
 * @tc.desc: server ipc leave lnn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_LEAVE_LNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    const char *networkId = "1234";

    int32_t ret = ServerIpcLeaveLNN(pkgName, networkId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: SERVER_IPC_STOP_TIME_SYNC_TEST_001
 * @tc.desc: server ipc stop time sync test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_STOP_TIME_SYNC_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    const char *targetNetworkId = "1234";

    int32_t ret = ServerIpcStartTimeSync(pkgName, targetNetworkId, NORMAL_ACCURACY, BIT_NETWORK_TYPE_WIFI);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = ServerIpcStopTimeSync(pkgName, targetNetworkId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SERVER_IPC_ACTIVE_META_NODE_TEST_001
 * @tc.desc: server ipc active meta node test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_ACTIVE_META_NODE_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    char udid[] = "123456789987654321001234567899876543210012345678998765432100123";
    MetaNodeConfigInfo info;
    char metaNodeId[NETWORK_ID_BUF_LEN] = { 0 };

    (void)memset_s(&info, sizeof(MetaNodeConfigInfo), 0, sizeof(MetaNodeConfigInfo));
    info.addrNum = 1;
    EXPECT_TRUE(strncpy_s(info.udid, UDID_BUF_LEN, udid, UDID_BUF_LEN) == EOK);
    int32_t ret = ServerIpcActiveMetaNode(pkgName, &info, metaNodeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: SERVER_IPC_DEACTIVE_META_NODE_TEST_001
 * @tc.desc: server ipc deactive meta node test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_DEACTIVE_META_NODE_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    char metaNodeId[NETWORK_ID_BUF_LEN] = { 0 };

    int32_t ret = ServerIpcDeactiveMetaNode(pkgName, metaNodeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: SERVER_IPC_GET_ALL_META_NODE_INFO_TEST_001
 * @tc.desc: server ipc get all meta node info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_GET_ALL_META_NODE_INFO_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    MetaNodeInfo infos;
    int32_t infoNum = 1;

    (void)memset_s(&infos, sizeof(MetaNodeInfo), 0, sizeof(MetaNodeInfo));
    int32_t ret = ServerIpcGetAllMetaNodeInfo(pkgName, &infos, &infoNum);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: SERVER_IPC_SHIFT_LNN_GEAR_TEST_001
 * @tc.desc: server ipc shift lnn gear test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerTest, SERVER_IPC_SHIFT_LNN_GEAR_TEST_001, TestSize.Level1)
{
    const char *pkgName = "000";
    const char *callerId = "1234";
    const char *targetNetworkId = nullptr;
    GearMode mode = {
        .cycle = MID_FREQ_CYCLE,
        .duration = DEFAULT_DURATION,
        .wakeupFlag = false,
    };

    int32_t ret = ServerIpcShiftLNNGear(pkgName, callerId, targetNetworkId, &mode);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
}
} // namespace OHOS
