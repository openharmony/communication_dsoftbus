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
#include "hb_heartbeat_utils_mock.h"
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

#define TEST_NETWORK_ID "6542316a57d"

constexpr char BT_MAC[] = "11:22";

static bool IsDeviceOnline(const char *remoteMac)
{
    (void)remoteMac;
    return false;
}

static int32_t GetLocalIpByUuid(const char *uuid, char *localIp, int32_t localIpSize)
{
    (void)uuid;
    (void)localIp;
    (void)localIpSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

class HeartBeatUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static bool VisitHbTypeCbForTrue(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    return true;
}

static bool VisitHbTypeCbForFalse(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    return false;
}

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
    NiceMock<HbHeartbeatUtilsInterfaceMock> heartbeatUtilsMock;
    uint32_t ret;
    uint8_t str[SHA_256_HASH_LEN] = { 0 };
    EXPECT_CALL(heartbeatUtilsMock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, &brMacHash, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, BT_MAC_LEN, &brMacHash, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(TEST_NETWORK_ID, 0, &brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnGenerateBtMacHashTest_02
 * @tc.desc: lnn generate bt mac hash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGenerateBtMacHashTest_02, TestSize.Level1)
{
    char brMacHash;
    NiceMock<DistributeLedgerInterfaceMock> disLedgerMock;
    EXPECT_CALL(disLedgerMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGenerateBtMacHash(nullptr, BT_MAC_LEN, nullptr, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(BT_MAC, BT_MAC_LEN, &brMacHash, BT_MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGenerateBtMacHash(BT_MAC, BT_MAC_LEN, &brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MAC_TO_BIN_ERR);
    ret = LnnGenerateBtMacHash(BT_MAC, BT_MAC_LEN, &brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MAC_TO_BIN_ERR);
}

/*
 * @tc.name: LnnVisitHbTypeSetTest_01
 * @tc.desc: lnn visit hb type set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnVisitHbTypeSetTest_01, TestSize.Level1)
{
    LnnHeartbeatType typeSet = HEARTBEAT_TYPE_BLE_V1;
    bool ret = LnnVisitHbTypeSet(VisitHbTypeCbForTrue, &typeSet, nullptr);
    EXPECT_TRUE(ret == true);
    ret = LnnVisitHbTypeSet(VisitHbTypeCbForFalse, &typeSet, nullptr);
    EXPECT_TRUE(ret == false);
    ret = LnnVisitHbTypeSet(VisitHbTypeCbForTrue, &typeSet, nullptr);
    EXPECT_TRUE(ret == true);
}

/*
 * @tc.name: LnnIsSupportHeartbeatCapTest_01
 * @tc.desc: LnnIsSupportHeartbeatCap test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnIsSupportHeartbeatCapTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    int32_t infoNum = 0;
    NodeBasicInfo *nodeBasicInfo = nullptr;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(LnnDumpOnlineDeviceInfo());
    bool ret = LnnIsSupportHeartbeatCap((1 << BIT_SUPPORT_DIRECT_TRIGGER), BIT_SUPPORT_DIRECT_TRIGGER);
    EXPECT_TRUE(ret);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(LnnDumpOnlineDeviceInfo());
    ret = LnnIsSupportHeartbeatCap((1 << BIT_SUPPORT_DIRECT_TRIGGER), BIT_SUPPORT_SCREEN_STATUS);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GenerateRandomNumForHbTest_01
 * @tc.desc: GenerateRandomNumForHb test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, GenerateRandomNumForHbTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<HbHeartbeatUtilsInterfaceMock> heartbeatUtilsMock;
    NiceMock<DistributeLedgerInterfaceMock> distributeLedgerMock;
    int32_t infoNum = 8;
    NodeBasicInfo *nodeBasicInfo = (NodeBasicInfo *)SoftBusCalloc(sizeof(NodeBasicInfo) * infoNum);
    ASSERT_TRUE(nodeBasicInfo != NULL);
    (void)memset_s(nodeBasicInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(
        DoAll(SetArgPointee<0>(nodeBasicInfo), SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_DEV_UDID), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_UUID), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_BT_MAC), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_WLAN_IP), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, LnnGetRemoteNumU32Info(_, Eq(NUM_KEY_NET_CAP), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, Eq(NUM_KEY_DISCOVERY_TYPE), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnDumpOnlineDeviceInfo());
    uint32_t ret = GenerateRandomNumForHb(HB_ADV_RANDOM_TIME_600, HB_ADV_RANDOM_TIME_300);
    EXPECT_EQ(ret, HB_ADV_RANDOM_TIME_300);
    ret = GenerateRandomNumForHb(HB_ADV_RANDOM_TIME_300, HB_ADV_RANDOM_TIME_50);
    EXPECT_NE(ret, HB_ADV_RANDOM_TIME_50);
}

/*
 * @tc.name: LnnIsLocalSupportBurstFeatureTest_01
 * @tc.desc: LnnIsLocalSupportBurstFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnIsLocalSupportBurstFeatureTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsLocalSupportBurstFeature();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnIsSupportBurstFeatureTest_01
 * @tc.desc: LnnIsSupportBurstFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnIsSupportBurstFeatureTest_01, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<DistributeLedgerInterfaceMock> distributeLedgerMock;
    char networkId[] = "networkId";
    bool ret = LnnIsSupportBurstFeature(NULL);
    EXPECT_FALSE(ret);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnIsSupportBurstFeature(networkId);
    EXPECT_FALSE(ret);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info).WillOnce(Return(SOFTBUS_OK));
    ret = LnnIsSupportBurstFeature(networkId);
    EXPECT_FALSE(ret);
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnIsSupportBurstFeature(networkId);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnGenerateBtMacHashTest_03
 * @tc.desc: LnnGenerateBtMacHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGenerateBtMacHashTest_03, TestSize.Level1)
{
    NiceMock<DistributeLedgerInterfaceMock> distributeLedgerMock;
    NiceMock<HbHeartbeatUtilsInterfaceMock> heartbeatUtilsMock;
    char btMac[] = "btMac";
    char brMacHash[] = "brMacHash";
    EXPECT_CALL(distributeLedgerMock, ConvertBtMacToBinary).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, ConvertBtMacToStrNoColon)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MAC_TO_STR_ERR);
    EXPECT_CALL(heartbeatUtilsMock, StringToUpperCase)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_STR_TO_UPPER_ERR);
    EXPECT_CALL(heartbeatUtilsMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);
    EXPECT_CALL(heartbeatUtilsMock, ConvertBytesToHexString)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);
    EXPECT_CALL(heartbeatUtilsMock, StringToUpperCase)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_STR_TO_UPPER_ERR);
    EXPECT_CALL(heartbeatUtilsMock, StringToUpperCase).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenerateBtMacHash(btMac, BT_MAC_LEN, brMacHash, BT_MAC_HASH_STR_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetShortAccountHashTest_02
 * @tc.desc: LnnGetShortAccountHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGetShortAccountHashTest_02, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    uint8_t shortAccountHash[HB_SHORT_ACCOUNT_HASH_LEN];
    (void)memset_s(&shortAccountHash, HB_SHORT_ACCOUNT_HASH_LEN, 0, HB_SHORT_ACCOUNT_HASH_LEN);
    EXPECT_CALL(ledgerMock, LnnGetLocalByteInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGetShortAccountHash(shortAccountHash, HB_SHORT_ACCOUNT_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}

/*
 * @tc.name: LnnGenerateHexStringHashTest_02
 * @tc.desc: LnnGenerateHexStringHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnGenerateHexStringHashTest_02, TestSize.Level1)
{
    NiceMock<HbHeartbeatUtilsInterfaceMock> heartbeatUtilsMock;
    unsigned char str[10] = {0};
    char hashStr[] = "1234";
    uint32_t len = 5;
    EXPECT_CALL(heartbeatUtilsMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGenerateHexStringHash(str, hashStr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnHasActiveConnectionTest_02
 * @tc.desc: LnnHasActiveConnection test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HeartBeatUtilsTest, LnnHasActiveConnectionTest_02, TestSize.Level1)
{
    NiceMock<HbHeartbeatUtilsInterfaceMock> heartbeatUtilsMock;
    NiceMock<DistributeLedgerInterfaceMock> distributeLedgerMock;
    NiceMock<LnnConnectInterfaceMock> lnnConnectMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    char networkId[] = "networkId";
    struct WifiDirectManager wifiDirectManager;
    wifiDirectManager.isDeviceOnline = IsDeviceOnline;
    wifiDirectManager.getLocalIpByUuid = GetLocalIpByUuid;
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_BT_MAC), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_DEV_UDID), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, GetWifiDirectManager).WillRepeatedly(Return(NULL));
    bool ret = LnnHasActiveConnection(networkId, CONNECTION_ADDR_BLE);
    EXPECT_FALSE(ret);
    EXPECT_CALL(distributeLedgerMock, ConvertBtMacToBinary)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(heartbeatUtilsMock, GetWifiDirectManager).WillRepeatedly(Return(&wifiDirectManager));
    EXPECT_CALL(distributeLedgerMock, LnnGetRemoteStrInfo(_, Eq(STRING_KEY_P2P_MAC), _, _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, Eq(CATEGORY_NETWORK_ID), _))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnHasActiveConnection(networkId, CONNECTION_ADDR_BLE);
    EXPECT_FALSE(ret);
    EXPECT_CALL(lnnConnectMock, CheckActiveConnection).WillRepeatedly(Return(false));
    ret = LnnHasActiveConnection(networkId, CONNECTION_ADDR_BLE);
    EXPECT_FALSE(ret);
}
} // namespace OHOS
