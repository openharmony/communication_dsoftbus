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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "distribute_net_ledger_mock.h"
#include "hb_fsm_mock.h"
#include "hb_strategy_mock.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_connection_mock.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_state_machine.h"
#include "message_handler.h"
#include "softbus_common.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

#define TEST_NETWORK_ID  "6542316a57d"

class HeartBeatUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HeartBeatUtilsTest::SetUpTestCase() { }

void HeartBeatUtilsTest::TearDownTestCase() { }

void HeartBeatUtilsTest::SetUp() { }

void HeartBeatUtilsTest::TearDown() { }

/*
 * @tc.name: LnnConvertConnAddrTypeToHbTypeTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnConvertConnAddrTypeToHbTypeTest_01, TestSize.Level1)
{
    uint32_t ret;

    LnnConvertConnAddrTypeToHbType(CONNECTION_ADDR_MAX);
    ret = LnnConvertConnAddrTypeToHbType(CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == HEARTBEAT_TYPE_UDP);
    ret = LnnConvertConnAddrTypeToHbType(CONNECTION_ADDR_BR);
    EXPECT_TRUE(ret == HEARTBEAT_TYPE_BLE_V1);
}

/*
 * @tc.name: LnnConvertHbTypeToConnAddrTypeTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnConvertHbTypeToConnAddrTypeTest_01, TestSize.Level1)
{
    uint32_t ret;

    LnnConvertHbTypeToConnAddrType(CONNECTION_ADDR_MAX);
    ret = LnnConvertHbTypeToConnAddrType(HEARTBEAT_TYPE_UDP);
    EXPECT_TRUE(ret == CONNECTION_ADDR_WLAN);
    ret = LnnConvertHbTypeToConnAddrType(HEARTBEAT_TYPE_BLE_V1);
    EXPECT_TRUE(ret == CONNECTION_ADDR_BLE);
}

/*
 * @tc.name: LnnConvertHbTypeToIdTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnConvertHbTypeToIdTest_01, TestSize.Level1)
{
    uint32_t ret;

    ret = LnnConvertHbTypeToId(0);
    EXPECT_TRUE(ret == HB_INVALID_TYPE_ID);
    ret = LnnConvertHbTypeToId(HEARTBEAT_TYPE_MAX);
    EXPECT_TRUE(ret == HB_INVALID_TYPE_ID);
    ret = LnnConvertHbTypeToId(HEARTBEAT_TYPE_MIN);
    EXPECT_TRUE(ret == 0);
}

/*
 * @tc.name: LnnHasActiveConnectionTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnHasActiveConnectionTest_01, TestSize.Level1)
{
    bool ret = false;

    ret = LnnHasActiveConnection(nullptr, CONNECTION_ADDR_WLAN);
    EXPECT_FALSE(ret);
    ret = LnnHasActiveConnection(TEST_NETWORK_ID, CONNECTION_ADDR_MAX);
    EXPECT_FALSE(ret);

    LnnHasActiveConnection(TEST_NETWORK_ID, CONNECTION_ADDR_WLAN);
    LnnHasActiveConnection(TEST_NETWORK_ID, CONNECTION_ADDR_SESSION);
}

/*
 * @tc.name: LnnCheckSupportedHbTypeTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnCheckSupportedHbTypeTest_01, TestSize.Level1)
{
    bool ret = false;
    uint32_t srcType = 0;
    uint32_t dstType = 0;

    ret = LnnCheckSupportedHbType(nullptr, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnCheckSupportedHbType(&srcType, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnCheckSupportedHbType(&srcType, &dstType);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnGenerateHexStringHashTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGenerateHexStringHashTest_01, TestSize.Level1)
{
    uint32_t ret;
    uint8_t str[SHA_256_HASH_LEN] = {0};

    ret = LnnGenerateHexStringHash(nullptr, nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateHexStringHash(str, nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGetShortAccountHashTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGetShortAccountHashTest_01, TestSize.Level1)
{
    uint32_t ret;
    uint8_t accountHash = 0;

    ret = LnnGetShortAccountHash(nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetShortAccountHash(&accountHash, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetShortAccountHash(&accountHash, SHA_256_HEX_HASH_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGenerateBtMacHashTest_01
 * @tc.desc: common utils use cases are used in networking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGenerateBtMacHashTest_01, TestSize.Level1)
{
    uint32_t ret;
    char brMacHash;

    ret = LnnGenerateBtMacHash(nullptr, 0, nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, nullptr, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, &brMacHash, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, BT_MAC_LEN, &brMacHash, 0);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, &brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
} // namespace OHOS
