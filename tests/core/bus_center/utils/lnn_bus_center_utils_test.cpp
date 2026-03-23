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

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_connection_addr_utils.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
constexpr char NODE1_BR_MAC[] = "12345TTU";
constexpr char NODE1_BLE_MAC[] = "23456TTU";
constexpr uint8_t NODE1_UDID_HASH[] = "node1hash";
constexpr char NODE1_IP[] = "10.146.181.134";
constexpr uint16_t NODE1_PORT = 10;
constexpr int32_t NODE1_SESSION_ID = 100;
constexpr int32_t NODE1_CHANNEL_ID = 100;
constexpr int32_t NODE1_SESSION_TYPE = 100;
constexpr char NODE2_BR_MAC[] = "56789TTU";
constexpr char NODE2_BLE_MAC[] = "67890TTU";
constexpr uint8_t NODE2_UDID_HASH[] = "node2hash";
constexpr char NODE2_IP[] = "10.147.182.135";
constexpr uint16_t NODE2_PORT = 20;
constexpr int32_t NODE2_SESSION_ID = 200;
constexpr int32_t NODE2_CHANNEL_ID = 200;
constexpr int32_t NODE2_SESSION_TYPE = 200;
class LNNConnAddrUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNConnAddrUtilsTest::SetUpTestCase() { }

void LNNConnAddrUtilsTest::TearDownTestCase() { }

void LNNConnAddrUtilsTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNConnAddrUtilsTest start");
}

void LNNConnAddrUtilsTest::TearDown() { }

/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_001
 * @tc.desc: lnn is same connection addr test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_001, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)strcpy_s(addr1.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(addr1.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)memcpy_s(addr1.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr1.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr1.info.ip.port = NODE1_PORT;
    addr1.info.session.sessionId = NODE1_SESSION_ID;
    addr1.info.session.channelId = NODE1_CHANNEL_ID;
    addr1.info.session.type = NODE1_SESSION_TYPE;
    (void)strcpy_s(addr2.info.br.brMac, BT_MAC_LEN, NODE2_BR_MAC);
    (void)strcpy_s(addr2.info.ble.bleMac, BT_MAC_LEN, NODE2_BLE_MAC);
    (void)memcpy_s(addr2.info.ble.udidHash, UDID_HASH_LEN, NODE2_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr2.info.ip.ip, IP_STR_MAX_LEN, NODE2_IP);
    addr2.info.ip.port = NODE2_PORT;
    addr2.info.session.sessionId = NODE2_SESSION_ID;
    addr2.info.session.channelId = NODE2_CHANNEL_ID;
    addr2.info.session.type = NODE2_SESSION_TYPE;
    addr1.type = CONNECTION_ADDR_BR;
    addr2.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(nullptr, nullptr, false));
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_BR;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr1, false));
    addr1.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr1, false));
    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_WLAN;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr1, false));
    addr1.type = CONNECTION_ADDR_ETH;
    addr2.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr1, false));
    addr1.type = CONNECTION_ADDR_SESSION;
    addr2.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr1, false));
    addr1.type = CONNECTION_ADDR_MAX;
    addr2.type = CONNECTION_ADDR_MAX;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
}

/*
 * @tc.name: LNN_CONVERT_ADDR_TO_OPTION_Test_001
 * @tc.desc: lnn convert addr to option test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_ADDR_TO_OPTION_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)memcpy_s(addr.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    EXPECT_TRUE(!LnnConvertAddrToOption(nullptr, nullptr));
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    addr.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    addr.type = CONNECTION_ADDR_WLAN;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    addr.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    addr.type = CONNECTION_ADDR_MAX;
    EXPECT_TRUE(!LnnConvertAddrToOption(&addr, &option));
}

/*
 * @tc.name: LNN_CONVERT_OPTION_TO_ADDR_Test_001
 * @tc.desc: lnn convert option to addr test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_OPTION_TO_ADDR_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)strcpy_s(option.socketOption.addr, IP_STR_MAX_LEN, NODE1_IP);
    option.socketOption.protocol = LNN_PROTOCOL_IP;
    option.socketOption.port = NODE1_PORT;
    EXPECT_TRUE(!LnnConvertOptionToAddr(nullptr, nullptr, CONNECTION_ADDR_BR));
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BR));
    option.type = CONNECT_BLE;
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BR));
    option.type = CONNECT_TCP;
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BR));
    option.socketOption.protocol = LNN_PROTOCOL_BLE;
    EXPECT_TRUE(!LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BR));
    option.type = CONNECT_TYPE_MAX;
    EXPECT_TRUE(!LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BR));
}

/*
 * @tc.name: LNN_CONV_ADDR_TYPE_TO_DISC_TYPE_Test_001
 * @tc.desc: lnn convert option to addr test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONV_ADDR_TYPE_TO_DISC_TYPE_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_WLAN) == DISCOVERY_TYPE_WIFI);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_ETH) == DISCOVERY_TYPE_WIFI);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_BR) == DISCOVERY_TYPE_BR);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_BLE) == DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_SESSION) == DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_MAX) == DISCOVERY_TYPE_COUNT);
}

/*
 * @tc.name: LNN_DISC_TYPE_TO_CONN_ADDR_TYPE_Test_001
 * @tc.desc: lnn disc type to conn addr type test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_DISC_TYPE_TO_CONN_ADDR_TYPE_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_WIFI) == CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_BLE) == CONNECTION_ADDR_BLE);
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_BR) == CONNECTION_ADDR_BR);
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_COUNT) == CONNECTION_ADDR_MAX);
}

/*
 * @tc.name: LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_001
 * @tc.desc: lnn conver addr to auth conn info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)memcpy_s(addr.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    EXPECT_TRUE(!LnnConvertAddrToAuthConnInfo(nullptr, nullptr));
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    addr.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    addr.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    addr.type = CONNECTION_ADDR_WLAN;
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    addr.type = CONNECTION_ADDR_MAX;
    EXPECT_TRUE(!LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
}

/*
 * @tc.name: LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_001
 * @tc.desc: lnn conver addr to auth conn info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)strcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_STR_MAX_LEN, NODE1_IP);
    connInfo.info.ipInfo.port = NODE1_PORT;
    EXPECT_TRUE(!LnnConvertAuthConnInfoToAddr(nullptr, nullptr, CONNECTION_ADDR_WLAN));
    connInfo.type = AUTH_LINK_TYPE_BR;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
    connInfo.type = AUTH_LINK_TYPE_P2P;
    EXPECT_TRUE(!LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
}

/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_002
 * @tc.desc: lnn is same connection addr test with isShort parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_002, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_BLE;
    addr2.type = CONNECTION_ADDR_BLE;
    (void)memcpy_s(addr1.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)memcpy_s(addr2.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr1.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)strcpy_s(addr2.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, true));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, false));
    (void)memcpy_s(addr2.info.ble.udidHash, UDID_HASH_LEN, NODE2_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr2.info.ble.bleMac, BT_MAC_LEN, NODE2_BLE_MAC);
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, true));
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    (void)memcpy_s(addr2.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    (void)strcpy_s(addr2.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, true));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, false));
}


/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_004
 * @tc.desc: lnn is same connection addr test for SESSION_WITH_KEY type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_004, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    addr2.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    addr1.info.session.sessionId = NODE1_SESSION_ID;
    addr2.info.session.sessionId = NODE1_SESSION_ID;
    addr1.info.session.channelId = NODE1_CHANNEL_ID;
    addr2.info.session.channelId = NODE1_CHANNEL_ID;
    addr1.info.session.type = NODE1_SESSION_TYPE;
    addr2.info.session.type = NODE1_SESSION_TYPE;
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.info.session.sessionId = NODE2_SESSION_ID;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.info.session.sessionId = NODE1_SESSION_ID;
    addr2.info.session.channelId = NODE2_CHANNEL_ID;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.info.session.channelId = NODE1_CHANNEL_ID;
    addr2.info.session.type = NODE2_SESSION_TYPE;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
}

/*
 * @tc.name: LNN_CONVERT_ADDR_TO_OPTION_Test_002
 * @tc.desc: lnn convert addr to option test for NCM type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_ADDR_TO_OPTION_Test_002, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    addr.type = CONNECTION_ADDR_NCM;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    EXPECT_TRUE(option.type == CONNECT_TCP);
    EXPECT_TRUE(option.socketOption.protocol == LNN_PROTOCOL_USB);
    EXPECT_TRUE(option.socketOption.moduleId == AUTH_USB);
}

/*
 * @tc.name: LNN_CONVERT_OPTION_TO_ADDR_Test_002
 * @tc.desc: lnn convert option to addr test with different hint types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_OPTION_TO_ADDR_Test_002, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_TCP;
    option.socketOption.protocol = LNN_PROTOCOL_IP;
    (void)strcpy_s(option.socketOption.addr, IP_STR_MAX_LEN, NODE1_IP);
    option.socketOption.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_WLAN));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_ETH));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_ETH);
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_NCM));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_NCM);
}

/*
 * @tc.name: LNN_CONVERT_OPTION_TO_ADDR_Test_003
 * @tc.desc: lnn convert option to addr test with BLE and protocol
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_OPTION_TO_ADDR_Test_003, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_BLE;
    (void)strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_BLE));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_BLE);
    EXPECT_TRUE(strcmp(addr.info.ble.bleMac, NODE1_BLE_MAC) == 0);
}

/*
 * @tc.name: LNN_CONV_ADDR_TYPE_TO_DISC_TYPE_Test_002
 * @tc.desc: lnn convert addr type to disc type test for new types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONV_ADDR_TYPE_TO_DISC_TYPE_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_SESSION_WITH_KEY) == DISCOVERY_TYPE_SESSION_KEY);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_NCM) == DISCOVERY_TYPE_USB);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_USB) == DISCOVERY_TYPE_COUNT);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_SLE) == DISCOVERY_TYPE_COUNT);
    EXPECT_TRUE(LnnConvAddrTypeToDiscType(CONNECTION_ADDR_NFC) == DISCOVERY_TYPE_COUNT);
}

/*
 * @tc.name: LNN_DISC_TYPE_TO_CONN_ADDR_TYPE_Test_002
 * @tc.desc: lnn disc type to conn addr type test for new types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_DISC_TYPE_TO_CONN_ADDR_TYPE_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_SESSION_KEY) == CONNECTION_ADDR_SESSION_WITH_KEY);
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_USB) == CONNECTION_ADDR_NCM);
    EXPECT_TRUE(LnnDiscTypeToConnAddrType(DISCOVERY_TYPE_COUNT) == CONNECTION_ADDR_MAX);
}

/*
 * @tc.name: LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_002
 * @tc.desc: lnn conver addr to auth conn info test for NCM type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_002, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    addr.type = CONNECTION_ADDR_NCM;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    (void)memcpy_s(addr.info.ip.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    EXPECT_TRUE(connInfo.type == AUTH_LINK_TYPE_USB);
    EXPECT_TRUE(connInfo.info.ipInfo.port == NODE1_PORT);
}

/*
 * @tc.name: LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_003
 * @tc.desc: lnn conver addr to auth conn info test for BLE with protocol and psm
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_003, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    addr.type = CONNECTION_ADDR_BLE;
    (void)strcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)memcpy_s(addr.info.ble.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    addr.info.ble.protocol = BLE_GATT;
    addr.info.ble.psm = 100;
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    EXPECT_TRUE(connInfo.type == AUTH_LINK_TYPE_BLE);
    EXPECT_TRUE(connInfo.info.bleInfo.protocol == BLE_GATT);
    EXPECT_TRUE(connInfo.info.bleInfo.psm == 100);
}

/*
 * @tc.name: LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_002
 * @tc.desc: lnn conver auth conn info to addr test for USB type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_002, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_USB;
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_STR_MAX_LEN, NODE1_IP);
    connInfo.info.ipInfo.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_NCM));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_NCM);
    EXPECT_TRUE(addr.info.ip.port == NODE1_PORT);
}

/*
 * @tc.name: LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_003
 * @tc.desc: lnn conver auth conn info to addr test for SESSION_KEY type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_003, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_SESSION_KEY;
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_STR_MAX_LEN, NODE1_IP);
    connInfo.info.ipInfo.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_SESSION_WITH_KEY);
    EXPECT_TRUE(addr.info.ip.port == NODE1_PORT);
}

/*
 * @tc.name: LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_004
 * @tc.desc: lnn conver auth conn info to addr test for BLE with protocol and psm
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_AUTH_CONN_INFO_TO_ADDR_Test_004, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    (void)strcpy_s(connInfo.info.bleInfo.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    connInfo.info.bleInfo.protocol = BLE_COC;
    connInfo.info.bleInfo.psm = 200;
    EXPECT_TRUE(LnnConvertAuthConnInfoToAddr(&addr, &connInfo, CONNECTION_ADDR_WLAN));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_BLE);
    EXPECT_TRUE(addr.info.ble.protocol == BLE_COC);
    EXPECT_TRUE(addr.info.ble.psm == 200);
}

/*
 * @tc.name: LNN_IS_CONNECTION_ADDR_INVALID_Test_001
 * @tc.desc: lnn is connection addr invalid test for valid addresses
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_CONNECTION_ADDR_INVALID_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_NCM;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_BLE;
    (void)strcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
}

/*
 * @tc.name: LNN_PRINT_CONNECTION_ADDR_Test_001
 * @tc.desc: lnn print connection addr test for various types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_PRINT_CONNECTION_ADDR_Test_001, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    EXPECT_TRUE(strcmp(LnnPrintConnectionAddr(nullptr), "Addr=") == 0);
    addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    const char *result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "Ip=") != nullptr);
    addr.type = CONNECTION_ADDR_ETH;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "Ip=") != nullptr);
    addr.type = CONNECTION_ADDR_NCM;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "Ip=") != nullptr);
}

/*
 * @tc.name: LNN_PRINT_CONNECTION_ADDR_Test_003
 * @tc.desc: lnn print connection addr test for invalid addresses
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_PRINT_CONNECTION_ADDR_Test_003, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = CONNECTION_ADDR_MAX;
    const char *result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
    addr.type = CONNECTION_ADDR_SESSION;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
    addr.type = CONNECTION_ADDR_USB;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
    addr.type = CONNECTION_ADDR_WLAN;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
    addr.type = CONNECTION_ADDR_BR;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
    addr.type = CONNECTION_ADDR_BLE;
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(strcmp(result, "Addr=") == 0);
}

/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_005
 * @tc.desc: lnn is same connection addr test for edge cases
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_005, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr1.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr1.info.ip.port = NODE1_PORT;
    (void)strcpy_s(addr2.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr2.info.ip.port = NODE1_PORT;
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, false));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, true));
    addr2.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr1.type = CONNECTION_ADDR_ETH;
    addr2.type = CONNECTION_ADDR_NCM;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_ETH;
    addr2.info.ip.port = NODE2_PORT;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
}

/*
 * @tc.name: LNN_CONVERT_ADDR_TO_OPTION_Test_003
 * @tc.desc: lnn convert addr to option test for edge cases
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_ADDR_TO_OPTION_Test_003, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    EXPECT_TRUE(option.type == CONNECT_TCP);
    EXPECT_TRUE(option.socketOption.protocol == LNN_PROTOCOL_IP);
    EXPECT_TRUE(option.socketOption.moduleId == AUTH);
    addr.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(LnnConvertAddrToOption(&addr, &option));
    EXPECT_TRUE(option.socketOption.protocol == LNN_PROTOCOL_IP);
    addr.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(!LnnConvertAddrToOption(&addr, &option));
}

/*
 * @tc.name: LNN_CONVERT_OPTION_TO_ADDR_Test_004
 * @tc.desc: lnn convert option to addr test for edge cases
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVERT_OPTION_TO_ADDR_Test_004, TestSize.Level1)
{
    ConnectionAddr addr;
    ConnectOption option;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_TCP;
    option.socketOption.protocol = LNN_PROTOCOL_IP;
    (void)strcpy_s(option.socketOption.addr, IP_STR_MAX_LEN, NODE1_IP);
    option.socketOption.port = NODE1_PORT;
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_MAX));
    EXPECT_TRUE(addr.type == CONNECTION_ADDR_MAX);
    EXPECT_TRUE(LnnConvertOptionToAddr(&addr, &option, CONNECTION_ADDR_WLAN));
    EXPECT_TRUE(strcmp(addr.info.ip.ip, NODE1_IP) == 0);
    EXPECT_TRUE(addr.info.ip.port == NODE1_PORT);
}

/*
 * @tc.name: LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_004
 * @tc.desc: lnn conver addr to auth conn info test for WLAN and ETH
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_CONVER_ADDR_TO_AUTH_CONN_INFO_Test_004, TestSize.Level1)
{
    ConnectionAddr addr;
    AuthConnInfo connInfo;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    addr.info.ip.port = NODE1_PORT;
    (void)memcpy_s(addr.info.ip.udidHash, UDID_HASH_LEN, NODE1_UDID_HASH, UDID_HASH_LEN);
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    EXPECT_TRUE(connInfo.type == AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(connInfo.info.ipInfo.port == NODE1_PORT);
    addr.type = CONNECTION_ADDR_ETH;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    EXPECT_TRUE(LnnConvertAddrToAuthConnInfo(&addr, &connInfo));
    EXPECT_TRUE(connInfo.type == AUTH_LINK_TYPE_WIFI);
}

/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_006
 * @tc.desc: lnn is same connection addr test for BR type
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_006, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_BR;
    addr2.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr1.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(addr2.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    EXPECT_TRUE(LnnIsSameConnectionAddr(&addr1, &addr2, false));
    (void)strcpy_s(addr2.info.br.brMac, BT_MAC_LEN, NODE2_BR_MAC);
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr1.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
}

/*
 * @tc.name: LNN_IS_CONNECTION_ADDR_INVALID_Test_004
 * @tc.desc: lnn is connection addr invalid test for SESSION types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_CONNECTION_ADDR_INVALID_Test_004, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
    addr.info.session.sessionId = NODE1_SESSION_ID;
    addr.info.session.channelId = NODE1_CHANNEL_ID;
    addr.info.session.type = NODE1_SESSION_TYPE;
    EXPECT_TRUE(!LnnIsConnectionAddrInvalid(&addr));
}

/*
 * @tc.name: LNN_PRINT_CONNECTION_ADDR_Test_004
 * @tc.desc: lnn print connection addr test for valid addresses
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_PRINT_CONNECTION_ADDR_Test_004, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = CONNECTION_ADDR_WLAN;
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, "192.168.1.1");
    const char *result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "Ip=") != nullptr);
    addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, "00:11:22:33:44:55");
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "BrMac=") != nullptr);
    addr.type = CONNECTION_ADDR_BLE;
    (void)strcpy_s(addr.info.ble.bleMac, BT_MAC_LEN, "00:AA:BB:CC:DD:EE");
    result = LnnPrintConnectionAddr(&addr);
    EXPECT_TRUE(result != nullptr);
    EXPECT_TRUE(strstr(result, "BleMac=") != nullptr);
}

/*
 * @tc.name: LNN_IS_SAME_CONNECTION_ADDR_Test_007
 * @tc.desc: lnn is same connection addr test for different types
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNConnAddrUtilsTest, LNN_IS_SAME_CONNECTION_ADDR_Test_007, TestSize.Level1)
{
    ConnectionAddr addr1;
    ConnectionAddr addr2;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_BR;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_NCM;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
    addr2.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    EXPECT_TRUE(!LnnIsSameConnectionAddr(&addr1, &addr2, false));
}
} // namespace OHOS
