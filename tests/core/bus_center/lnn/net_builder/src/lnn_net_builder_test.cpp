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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_builder.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

constexpr char NETWORKID[] = "ABCDEFG";
constexpr char OLD_NETWORKID[] = "ABCDEFG";
constexpr char MASTER_UDID[] = "0123456";
constexpr uint16_t CONN_FSM_ID = 1;
constexpr int32_t MASTER_WEIGHT = 1;
constexpr uint32_t TYPE_LEN = 1;
constexpr char IP[IP_STR_MAX_LEN] = "127.0.0.1";
constexpr uint16_t PORT = 1000;
constexpr char PEERUID[MAX_ACCOUNT_HASH_LEN] = "021315ASD";

namespace OHOS {
using namespace testing::ext;

class LnnNetBuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetBuilderTest::SetUpTestCase()
{
    LooperInit();
}

void LnnNetBuilderTest::TearDownTestCase()
{
    LooperDeinit();
}

void LnnNetBuilderTest::SetUp()
{
}

void LnnNetBuilderTest::TearDown()
{
    LnnDeinitNetBuilder();
}

/*
* @tc.name: LNN_NOTIFY_DISCOVERY_DEVICE_TEST_001
* @tc.desc: test LnnNotifyDiscoveryDevice
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_NOTIFY_DISCOVERY_DEVICE_TEST_001, TestSize.Level0)
{
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT
    };
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    int32_t ret = LnnNotifyDiscoveryDevice(&target);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_REQUEST_LEAVE_BY_ADDRTYPE_TEST_001
* @tc.desc: test LnnRequestLeaveByAddrType
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_REQUEST_LEAVE_BY_ADDRTYPE_TEST_001, TestSize.Level0)
{
    const bool type[CONNECTION_ADDR_MAX] = {true, true, true, true, true};
    int32_t ret = LnnRequestLeaveByAddrType(type, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveByAddrType(type, TYPE_LEN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_REQUEST_LEAVE_SPECIFIC_TEST_001
* @tc.desc: test LnnRequestLeaveSpecific
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_REQUEST_LEAVE_SPECIFIC_TEST_001, TestSize.Level0)
{
    char *networkId = nullptr;
    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnRequestLeaveSpecific(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveSpecific(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_REQUEST_LEAVE_INVALID_CONN_TEST_001
* @tc.desc: test LnnRequestLeaveInvalidConn
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_REQUEST_LEAVE_INVALID_CONN_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnRequestLeaveInvalidConn(OLD_NETWORKID, CONNECTION_ADDR_WLAN, NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveInvalidConn(OLD_NETWORKID, CONNECTION_ADDR_WLAN, NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_REQUEST_CLEAN_CONN_FSM_TEST_001
* @tc.desc: test LnnRequestCleanConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_REQUEST_CLEAN_CONN_FSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnRequestCleanConnFsm(CONN_FSM_ID);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestCleanConnFsm(CONN_FSM_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_NOTIFY_NODE_STATE_CHANGED_TEST_001
* @tc.desc: test LnnNotifyNodeStateChanged
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_NOTIFY_NODE_STATE_CHANGED_TEST_001, TestSize.Level0)
{
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT
    };
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    int32_t ret = LnnNotifyNodeStateChanged(&target);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnNotifyNodeStateChanged(&target);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_NOTIFY_MASTER_ELECT_TEST_001
* @tc.desc: test LnnNotifyMasterElect
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_NOTIFY_MASTER_ELECT_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnNotifyMasterElect(NETWORKID, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    char *networkId = nullptr;
    ret = LnnNotifyMasterElect(networkId, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnNotifyMasterElect(NETWORKID, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_UPDATE_NODE_ADDR_TEST_001
* @tc.desc: test LnnUpdateNodeAddr
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetBuilderTest, LNN_UPDATE_NODE_ADDR_TEST_001, TestSize.Level0)
{
    char *addr = nullptr;
    int32_t ret = LnnUpdateNodeAddr(addr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnUpdateNodeAddr(MASTER_UDID);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnUpdateNodeAddr(MASTER_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: META_NODE_SERVER_JOIN_TEST_001
* @tc.desc: test MetaNodeServerJoin
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderTest, META_NODE_SERVER_JOIN_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT
    };
    CustomData customData = {
        .type = PROXY_TRANSMISION,
        .data = {0},
    };
    int32_t ret;

    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = MetaNodeServerJoin(&addr, &customData);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: META_NODE_SERVER_LEAVE_TEST_001
* @tc.desc: test MetaNodeServerLeave
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnNetBuilderTest, META_NODE_SERVER_LEAVE_TEST_001, TestSize.Level0)
{
    const char *networkId = "1234";
    int32_t ret;

    ret = MetaNodeServerLeave(networkId);
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = MetaNodeServerLeave(networkId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
