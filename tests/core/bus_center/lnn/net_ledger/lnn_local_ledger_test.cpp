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
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_local_ledger_deps_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_common.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
constexpr char LOCAL_UDID[] = "123456LOCALTEST";
constexpr char LOCAL_DEVTYPE[] = "TYPE_WATCH";
constexpr char LOCAL_BT_MAC[] = "56789TUT";
constexpr char LOCAL_WLAN_IP[] = "10.146.181.134";
constexpr char LOCAL_NET_IF_NAME[] = "LOCAL";
constexpr char MASTER_NODE_UDID[] = "234567LOCALTEST";
constexpr char LOCAL_NODE_ADDR[] = "ADDR";
constexpr char LOCAL_P2P_MAC[] = "11:22:33:44:55";
constexpr char LOCAL_GO_MAC[] = "22:33:44:55:66";
constexpr uint32_t LOCAL_SESSION_PORT = 5000;
constexpr uint32_t LOCAL_AUTH_PORT = 6000;
constexpr uint32_t LOCAL_PROXY_PORT = 7000;
constexpr uint32_t LOCAL_CAPACITY = 3;
constexpr int32_t MASTER_WEIGHT = 10;
constexpr int32_t P2P_ROLE = 1;
constexpr uint32_t CAPABILTY = 17;
using namespace testing;
class LocalLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LocalLedgerTest::SetUpTestCase()
{
}

void LocalLedgerTest::TearDownTestCase()
{
}

void LocalLedgerTest::SetUp()
{
    LOG_INFO("LocalLedgerTest start.");
}

void LocalLedgerTest::TearDown()
{
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_001
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_002
* @tc.desc: local ledger init and deinit test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_002, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        GetCommonDevInfo(_, NotNull(), _)).WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
    int32_t ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_003
* @tc.desc: local ledger delay init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_003, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_004
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_004, TestSize.Level1)
{
    static InfoKey getLocalStringInfoKeyTable[] = {
        STRING_KEY_HICE_VERSION,
        STRING_KEY_DEV_UDID,
        STRING_KEY_NETWORKID,
        STRING_KEY_UUID,
        STRING_KEY_DEV_TYPE,
        STRING_KEY_DEV_NAME,
        STRING_KEY_BT_MAC,
        STRING_KEY_WLAN_IP,
        STRING_KEY_NET_IF_NAME,
        STRING_KEY_MASTER_NODE_UDID,
        STRING_KEY_NODE_ADDR,
        STRING_KEY_P2P_MAC,
        STRING_KEY_P2P_GO_MAC,
        STRING_KEY_OFFLINE_CODE
    };
    char buf[UDID_BUF_LEN] = {0};
    int32_t ret;
    uint32_t i;
    LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID);
    for (i = 0; i < sizeof(getLocalStringInfoKeyTable) / sizeof(InfoKey); i++) {
        ret = LnnGetLocalStrInfo(getLocalStringInfoKeyTable[i], nullptr, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    }
    for (i = 0; i < sizeof(getLocalStringInfoKeyTable) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetLocalStrInfo(getLocalStringInfoKeyTable[i], buf, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_005
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_005, TestSize.Level1)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_TYPE, LOCAL_DEVTYPE);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnSetLocalStrInfo(STRING_KEY_BT_MAC, LOCAL_BT_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, LOCAL_WLAN_IP);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_NET_IF_NAME, LOCAL_NET_IF_NAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, MASTER_NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_NODE_ADDR, LOCAL_NODE_ADDR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, LOCAL_P2P_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, LOCAL_GO_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_006
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_006, TestSize.Level1)
{
    static InfoKey getLocalNumInfoKeyTable[] = {
        NUM_KEY_SESSION_PORT,
        NUM_KEY_AUTH_PORT,
        NUM_KEY_PROXY_PORT,
        NUM_KEY_NET_CAP,
        NUM_KEY_DISCOVERY_TYPE,
        NUM_KEY_DEV_TYPE_ID,
        NUM_KEY_MASTER_NODE_WEIGHT,
        NUM_KEY_P2P_ROLE
    };
    int32_t ret, info;
    LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT);
    for (uint32_t i = 0; i < sizeof(getLocalNumInfoKeyTable) / sizeof(InfoKey); i++) {
        info = 0;
        ret = LnnGetLocalNumInfo(getLocalNumInfoKeyTable[i], &info);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_007
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_007, TestSize.Level1)
{
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, LOCAL_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, LOCAL_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, LOCAL_CAPACITY);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, P2P_ROLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_008
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_008, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_009
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_009, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_010
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_010, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_011
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_011, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_012
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_012, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_OK);
}
} // namespace OHOS
