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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "g_enhance_lnn_func.h"
#include "g_reg_lnn_func.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger_manager_mock.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_init_common.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "123456ABCDEF";
constexpr uint64_t DEFAULT_VALUE = 10;
constexpr int64_t LFINDER_UDID_LEN = 32;
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";
constexpr char NODE1_UUID[] = "235689BNHFCC";
constexpr char NODE1_BT_MAC[] = "56789TTU";
constexpr int64_t AUTH_SEQ = 1;
constexpr uint64_t TIME_STAMP = 5000;
constexpr uint32_t DISCOVERY_TYPE = 62;

class LNNDistributedNetLedgerManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

int32_t LnnRetrieveDeviceInfoByUdidStub(const char *udid, NodeInfo *deviceInfo)
{
    (void)udid;
    (void)deviceInfo;
    static bool gRetry = false;
    if (!gRetry) {
        gRetry = true;
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnSaveRemoteDeviceInfoStub(const NodeInfo *deviceInfo)
{
    (void)deviceInfo;
    return SOFTBUS_OK;
}

void LNNDistributedNetLedgerManagerTest::SetUpTestCase() { }

void LNNDistributedNetLedgerManagerTest::TearDownTestCase() { }

void LNNDistributedNetLedgerManagerTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNDistributedNetLedgerManagerTest start");
    int32_t ret = LnnInitDistributedLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
    (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC, strlen(NODE1_BT_MAC));
    info.authSeq[0] = AUTH_SEQ;
    info.heartbeatTimestamp = TIME_STAMP;
    info.deviceInfo.osType = HO_OS_TYPE;

    NiceMock<LnnDistributedNetLedgerManagerInterfaceMock> mock;
    EXPECT_CALL(mock, LnnRetrieveDeviceInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(REPORT_ONLINE, LnnAddOnlineNode(&info));
}

void LNNDistributedNetLedgerManagerTest::TearDown()
{
    LNN_LOGI(LNN_TEST, "LNNDistributedNetLedgerManagerTest end");
    LnnDeinitDistributedLedger();
}

/*
 * @tc.name: LNN_SET_DL_WIFI_DIRECT_ADDR_TEST_001
 * @tc.desc: Verify LnnSetDLWifiDirectAddr sets wifi direct address with
 *           null and valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_WIFI_DIRECT_ADDR_TEST_001, TestSize.Level1)
{
    char wifiDirectAddr[MAC_LEN] = "11223344";
    bool ret = LnnSetDLWifiDirectAddr(NODE_NETWORK_ID, wifiDirectAddr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLWifiDirectAddr(nullptr, wifiDirectAddr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE_NETWORK_ID, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, wifiDirectAddr);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LNN_SET_DL_P2P_IP_TEST_001
 * @tc.desc: Verify LnnSetDLP2pIp sets P2P IP address with null and
 *           valid UUID and IP parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_P2P_IP_TEST_001, TestSize.Level1)
{
    const char *peerUuid = "testUuid";
    const char *p2pIp = "10.50.140.1";
    int32_t ret = LnnSetDLP2pIp(nullptr, CATEGORY_UUID, p2pIp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLP2pIp(peerUuid, CATEGORY_UUID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLP2pIp(peerUuid, CATEGORY_UUID, p2pIp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    const char *peerUuidNew = "235689BNHFCC";
    ret = LnnSetDLP2pIp(peerUuidNew, CATEGORY_UUID, p2pIp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_AUTH_PORT_TEST_001
 * @tc.desc: Verify LnnSetDLAuthPort sets auth port with null and
 *           valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_AUTH_PORT_TEST_001, TestSize.Level1)
{
    int32_t authPort = 10;
    int32_t ret = LnnSetDLAuthPort(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, authPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLAuthPort(nullptr, CATEGORY_NETWORK_ID, authPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLAuthPort(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, authPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_SESSION_PORT_TEST_001
 * @tc.desc: Verify LnnSetDLSessionPort sets session port with null and
 *           valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_SESSION_PORT_TEST_001, TestSize.Level1)
{
    int32_t sessionPort = 10;
    int32_t ret = LnnSetDLSessionPort(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, sessionPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLSessionPort(nullptr, CATEGORY_NETWORK_ID, sessionPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLSessionPort(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, sessionPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_PROXY_PORT_TEST_001
 * @tc.desc: Verify LnnSetDLProxyPort sets proxy port with null and
 *           valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_PROXY_PORT_TEST_001, TestSize.Level1)
{
    int32_t proxyPort = 10;
    int32_t ret = LnnSetDLProxyPort(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, proxyPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLProxyPort(nullptr, CATEGORY_NETWORK_ID, proxyPort);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLProxyPort(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, proxyPort);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_NODE_ADDR_TEST_001
 * @tc.desc: Verify LnnSetDLNodeAddr sets node address with null and
 *           valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_NODE_ADDR_TEST_001, TestSize.Level1)
{
    const char *nodeAddress = "address";
    int32_t ret = LnnSetDLNodeAddr(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, nodeAddress);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLNodeAddr(nullptr, CATEGORY_NETWORK_ID, nodeAddress);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLNodeAddr(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, nodeAddress);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_BSS_TRANS_INFO_TEST_001
 * @tc.desc: Verify LnnSetDLBssTransInfo sets BSS transition info with
 *           null and valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_BSS_TRANS_INFO_TEST_001, TestSize.Level1)
{
    BssTransInfo info;
    (void)memset_s(&info, sizeof(BssTransInfo), 0, sizeof(BssTransInfo));

    int32_t ret = LnnSetDLBssTransInfo(nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBssTransInfo(NODE_NETWORK_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBssTransInfo(NODE_NETWORK_ID, &info);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLBssTransInfo(NODE1_NETWORK_ID, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_BATTERY_INFO_TEST_001
 * @tc.desc: Verify LnnSetDLBatteryInfo sets battery info with null and
 *           valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_BATTERY_INFO_TEST_001, TestSize.Level1)
{
    BatteryInfo battery;
    (void)memset_s(&battery, sizeof(BatteryInfo), 0, sizeof(BatteryInfo));

    int32_t ret = LnnSetDLBatteryInfo(nullptr, &battery);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBatteryInfo(NODE_NETWORK_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBatteryInfo(NODE_NETWORK_ID, &battery);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLBatteryInfo(NODE1_NETWORK_ID, &battery);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_CONN_USER_ID_TEST_001
 * @tc.desc: Verify LnnSetDLConnUserId sets connection user ID with
 *           null and valid network ID parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_CONN_USER_ID_TEST_001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    ASSERT_TRUE(pfnLnnEnhanceFuncList != nullptr);
    pfnLnnEnhanceFuncList->lnnSaveRemoteDeviceInfo = nullptr;
    int32_t userId = 0;
    int32_t ret = LnnSetDLConnUserId(nullptr, userId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLConnUserId(NODE_NETWORK_ID, userId);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLConnUserId(NODE1_NETWORK_ID, userId);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_SET_DL_CONN_USER_ID_CHECK_SUM_TEST_001
 * @tc.desc: LnnSetDLConnUserIdCheckSum test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_CONN_USER_ID_CHECK_SUM_TEST_001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    ASSERT_TRUE(pfnLnnEnhanceFuncList != nullptr);
    pfnLnnEnhanceFuncList->lnnSaveRemoteDeviceInfo = nullptr;
    int32_t userIdCheckSum = 0;
    int32_t ret = LnnSetDLConnUserIdCheckSum(nullptr, userIdCheckSum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLConnUserIdCheckSum(NODE_NETWORK_ID, userIdCheckSum);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLConnUserIdCheckSum(NODE1_NETWORK_ID, userIdCheckSum);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_SET_DL_CONN_CAPABILITY_TEST_001
 * @tc.desc: LnnSetDLConnCapability test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_CONN_CAPABILITY_TEST_001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    ASSERT_TRUE(pfnLnnEnhanceFuncList != nullptr);
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfoByUdid = LnnRetrieveDeviceInfoByUdidStub;
    pfnLnnEnhanceFuncList->lnnSaveRemoteDeviceInfo = LnnSaveRemoteDeviceInfoStub;
    uint32_t connCapability = 0;
    int32_t ret = LnnSetDLConnCapability(NODE_NETWORK_ID, connCapability);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfoByUdid = nullptr;
    pfnLnnEnhanceFuncList->lnnSaveRemoteDeviceInfo = nullptr;
    ret = LnnSetDLConnCapability(NODE_NETWORK_ID, connCapability);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLConnCapability(NODE1_NETWORK_ID, connCapability);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LNN_SET_DL_BLE_DIRECT_TIMESTAMP_TEST_001
 * @tc.desc: LnnSetDLBleDirectTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_BLE_DIRECT_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnSetDLBleDirectTimestamp(NODE_NETWORK_ID, timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLBleDirectTimestamp(nullptr, timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLBleDirectTimestamp(NODE1_NETWORK_ID, timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DL_AUTH_CAPACITY_TEST_001
 * @tc.desc: LnnGetDLAuthCapacity test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_DL_AUTH_CAPACITY_TEST_001, TestSize.Level1)
{
    uint32_t authCapacity = 0;
    int32_t ret = LnnGetDLAuthCapacity(NODE_NETWORK_ID, &authCapacity);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLAuthCapacity(nullptr, &authCapacity);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLAuthCapacity(NODE1_NETWORK_ID, &authCapacity);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DL_UPDATE_TIMESTAMP_TEST_001
 * @tc.desc: LnnGetDLUpdateTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_DL_UPDATE_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnGetDLUpdateTimestamp(nullptr, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetDLUpdateTimestamp(NODE_NETWORK_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetDLUpdateTimestamp(NODE_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetDLUpdateTimestamp(NODE1_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_GET_DL_BLE_DIRECT_TIMESTAMP_TEST_001
 * @tc.desc: LnnGetDLBleDirectTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_DL_BLE_DIRECT_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnGetDLBleDirectTimestamp(nullptr, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetDLBleDirectTimestamp(NODE_NETWORK_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetDLBleDirectTimestamp(NODE1_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_HEARTBEAT_TIMESTAMP_TEST_001
 * @tc.desc: LnnSetDLHeartbeatTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_HEARTBEAT_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnSetDLHeartbeatTimestamp(NODE_NETWORK_ID, timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLHeartbeatTimestamp(nullptr, timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLHeartbeatTimestamp(NODE1_NETWORK_ID, timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DL_HEARTBEAT_TIMESTAMP_TEST_001
 * @tc.desc: LnnGetDLHeartbeatTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_DL_HEARTBEAT_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnGetDLHeartbeatTimestamp(NODE_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLHeartbeatTimestamp(nullptr, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLHeartbeatTimestamp(NODE1_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DL_ONLINE_TIMESTAMP_TEST_001
 * @tc.desc: LnnGetDLOnlineTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_DL_ONLINE_TIMESTAMP_TEST_001, TestSize.Level1)
{
    uint64_t timestamp = DEFAULT_VALUE;
    int32_t ret = LnnGetDLOnlineTimestamp(NODE_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLOnlineTimestamp(nullptr, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetDLOnlineTimestamp(NODE1_NETWORK_ID, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_CONN_SUB_FEATURE_BY_UDIDHASH_STR_TEST_001
 * @tc.desc: LnnGetConnSubFeatureByUdidHashStr test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_CONN_SUB_FEATURE_BY_UDIDHASH_STR_TEST_001, TestSize.Level1)
{
    const char *udidHashStr = "deviceudid";
    uint64_t connSubFeature = DEFAULT_VALUE;
    int32_t ret = LnnGetConnSubFeatureByUdidHashStr(nullptr, &connSubFeature);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetConnSubFeatureByUdidHashStr(udidHashStr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetConnSubFeatureByUdidHashStr(udidHashStr, &connSubFeature);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTE_INFO_TEST_001
 * @tc.desc: LnnGetRemoteByteInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_BYTE_INFO_TEST_001, TestSize.Level1)
{
    unsigned char irk[LFINDER_IRK_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_PUB_MAC, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_PUB_MAC, nullptr, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_PUB_MAC, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_PUB_MAC, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTE_INFO_TEST_002
 * @tc.desc: LnnGetRemoteByteInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_BYTE_INFO_TEST_002, TestSize.Level1)
{
    unsigned char irk[LFINDER_UDID_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_ACCOUNT_HASH, irk, LFINDER_UDID_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_ACCOUNT_HASH, nullptr, LFINDER_UDID_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_ACCOUNT_HASH, irk, LFINDER_UDID_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_ACCOUNT_HASH, irk, LFINDER_UDID_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTE_INFO_TEST_003
 * @tc.desc: LnnGetRemoteByteInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_BYTE_INFO_TEST_003, TestSize.Level1)
{
    unsigned char irk[LFINDER_UDID_HASH_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_REMOTE_PTK, irk, LFINDER_UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_REMOTE_PTK, irk, LFINDER_UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE_NETWORK_ID, BYTE_KEY_REMOTE_PTK, nullptr, LFINDER_UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_REMOTE_PTK, irk, LFINDER_UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_BOOL_INFO_IGNORE_ONLINE_TEST_001
 * @tc.desc: LnnGetRemoteBoolInfoIgnoreOnline test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_BOOL_INFO_IGNORE_ONLINE_TEST_001, TestSize.Level1)
{
    bool result = false;
    int32_t ret = LnnGetRemoteBoolInfoIgnoreOnline(nullptr, BOOL_KEY_SCREEN_STATUS, &result);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE_NETWORK_ID, BOOL_KEY_SCREEN_STATUS, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE_NETWORK_ID, BOOL_KEY_SCREEN_STATUS, &result);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE1_NETWORK_ID, BOOL_KEY_SCREEN_STATUS, &result);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_SUPPORT);

    ret = LnnGetRemoteBoolInfo(NODE1_NETWORK_ID, BOOL_KEY_SCREEN_STATUS, &result);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_SUPPORT);
}

/*
 * @tc.name: LNN_GET_REMOTE_BOOL_INFO_IGNORE_ONLINE_TEST_002
 * @tc.desc: LnnGetRemoteBoolInfoIgnoreOnline test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_BOOL_INFO_IGNORE_ONLINE_TEST_002, TestSize.Level1)
{
    bool result = false;
    int32_t ret = LnnGetRemoteBoolInfoIgnoreOnline(nullptr, BOOL_KEY_TLV_NEGOTIATION, &result);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE_NETWORK_ID, BOOL_KEY_TLV_NEGOTIATION, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE_NETWORK_ID, BOOL_KEY_TLV_NEGOTIATION, &result);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteBoolInfoIgnoreOnline(NODE1_NETWORK_ID, BOOL_KEY_TLV_NEGOTIATION, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnGetRemoteBoolInfo(NODE1_NETWORK_ID, BOOL_KEY_TLV_NEGOTIATION, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_PTK_TEST_001
 * @tc.desc: LnnSetDlPtk test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_PTK_TEST_001, TestSize.Level1)
{
    const char *remotePtk = "testRemotePtk";
    bool ret = LnnSetDlPtk(nullptr, remotePtk);
    EXPECT_FALSE(ret);
    ret = LnnSetDlPtk(NODE_NETWORK_ID, nullptr);
    EXPECT_FALSE(ret);

    ret = LnnSetDlPtk(NODE_NETWORK_ID, remotePtk);
    EXPECT_FALSE(ret);

    ret = LnnSetDlPtk(NODE1_NETWORK_ID, remotePtk);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_BROADCAST_CIPHERIV_TEST_001
 * @tc.desc: LnnSetDLDeviceBroadcastCipherIv test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_BROADCAST_CIPHERIV_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    const char *devUdidInvalid = "123456789ABCDEFG";
    const char *cipherIv = "iviviviviviv";
    int32_t ret = LnnSetDLDeviceBroadcastCipherIv(devUdidInvalid, cipherIv);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLDeviceBroadcastCipherIv(nullptr, cipherIv);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLDeviceBroadcastCipherIv(devUdid, cipherIv);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_BROADCAST_CIPHER_KEY_TEST_001
 * @tc.desc: LnnSetDLDeviceBroadcastCipherKey test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_BROADCAST_CIPHER_KEY_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    const char *devUdidInvalid = "123456789ABCDEFG";
    const char *cipherKey = "keykeykeykey";
    int32_t ret = LnnSetDLDeviceBroadcastCipherKey(devUdidInvalid, (const void *)cipherKey);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLDeviceBroadcastCipherKey(nullptr, (const void *)cipherKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLDeviceBroadcastCipherKey(devUdid, (const void *)cipherKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_STATE_VERSION_TEST_001
 * @tc.desc: LnnSetDLDeviceStateVersion test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_STATE_VERSION_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    int32_t stateVersion = 0;
    int32_t ret = LnnSetDLDeviceStateVersion(devUdid, stateVersion);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetDLDeviceStateVersion(nullptr, stateVersion);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *udid = "123456ABCDEFGHIGKLMN";
    ret = LnnSetDLDeviceStateVersion(udid, stateVersion);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_NICK_NAME_BY_UDID_TEST_001
 * @tc.desc: LnnSetDLDeviceNickNameByUdid test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_NICK_NAME_BY_UDID_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    const char *devName = "deviceNickname";
    int32_t ret = LnnSetDLDeviceNickNameByUdid(nullptr, devName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLDeviceNickNameByUdid(devUdid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLDeviceNickNameByUdid(devUdid, devName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *udid = "123456ABCDEFGHIGKLMN";
    ret = LnnSetDLDeviceNickNameByUdid(udid, devName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_UNIFIED_DEFAULT_DEVICE_NAME_TEST_001
 * @tc.desc: LnnSetDLUnifiedDefaultDeviceName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_UNIFIED_DEFAULT_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    const char *devName = "deviceUnifiedDefaultName";
    int32_t ret = LnnSetDLUnifiedDefaultDeviceName(nullptr, devName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLUnifiedDefaultDeviceName(devUdid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLUnifiedDefaultDeviceName(devUdid, devName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *udid = "123456ABCDEFGHIGKLMN";
    ret = LnnSetDLUnifiedDefaultDeviceName(udid, devName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_UNIFIED_DEVICE_NAME_TEST_001
 * @tc.desc: LnnSetDLUnifiedDeviceName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_UNIFIED_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    const char *devUdid = "123456ABCDEF";
    const char *devName = "deviceUnifiedName";
    int32_t ret = LnnSetDLUnifiedDeviceName(nullptr, devName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLUnifiedDeviceName(devUdid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLUnifiedDeviceName(devUdid, devName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *udid = "123456ABCDEFGHIGKLMN";
    ret = LnnSetDLUnifiedDeviceName(udid, devName);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_NICK_NAME_TEST_001
 * @tc.desc: LnnSetDLDeviceNickName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_NICK_NAME_TEST_001, TestSize.Level1)
{
    const char *devNetworkId = "123456ABCDEF";
    const char *devName = "deviceNickName";
    bool ret = LnnSetDLDeviceNickName(nullptr, devName);
    EXPECT_FALSE(ret);
    ret = LnnSetDLDeviceNickName(devNetworkId, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLDeviceNickName(devNetworkId, devName);
    EXPECT_FALSE(ret);
    const char *networkId = "235689BNHFCF";
    ret = LnnSetDLDeviceNickName(networkId, devName);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_INFO_NAME_TEST_001
 * @tc.desc: LnnSetDLDeviceInfoName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_DL_DEVICE_INFO_NAME_TEST_001, TestSize.Level1)
{
    const char *devNetworkId = "123456ABCDEF";
    const char *devName = "deviceNickName";
    bool ret = LnnSetDLDeviceInfoName(nullptr, devName);
    EXPECT_FALSE(ret);
    ret = LnnSetDLDeviceInfoName(devNetworkId, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLDeviceInfoName(devNetworkId, devName);
    EXPECT_TRUE(ret);

    const char *devNameError = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij"
                               "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij";
    ret = LnnSetDLDeviceInfoName(devNetworkId, devNameError);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUM16_INFO_TEST_001
 * @tc.desc: LnnGetRemoteNum16Info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUM16_INFO_TEST_001, TestSize.Level1)
{
    int16_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNum16Info(nullptr, NUM_KEY_DATA_CHANGE_FLAG, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(NODE_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNum16Info(NODE_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNum16Info(NODE1_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_001
 * @tc.desc: LnnGetRemoteNumU32Info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_001, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_NET_CAP, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, INFO_KEY_MAX, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_CONN_SUB_FEATURE_CAPA, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_002
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_STA_FREQUENCY
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_002, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STA_FREQUENCY, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_STA_FREQUENCY, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STA_FREQUENCY, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_STA_FREQUENCY, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_003
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_STATE_VERSION
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_003, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATE_VERSION, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_STATE_VERSION, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATE_VERSION, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_STATE_VERSION, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_004
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_P2P_ROLE
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_004, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_P2P_ROLE, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_P2P_ROLE, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_P2P_ROLE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_P2P_ROLE, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_005
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_DEVICE_SECURITY_LEVEL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_005, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_DEVICE_SECURITY_LEVEL, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_DEVICE_SECURITY_LEVEL, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_DEVICE_SECURITY_LEVEL, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_DEVICE_SECURITY_LEVEL, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_006
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_STATIC_CAP_LEN
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_006, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATIC_CAP_LEN, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_STATIC_CAP_LEN, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATIC_CAP_LEN, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_STATIC_CAP_LEN, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMU32_INFO_TEST_007
 * @tc.desc: LnnGetRemoteNumU32Info test parameters is NUM_KEY_STATIC_NET_CAP
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUMU32_INFO_TEST_007, TestSize.Level1)
{
    uint32_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATIC_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU32Info(nullptr, NUM_KEY_STATIC_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE_NETWORK_ID, NUM_KEY_STATIC_NET_CAP, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_STATIC_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_001
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_CHAN_LIST_5G
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_001, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_CHAN_LIST_5G, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_CHAN_LIST_5G, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_CHAN_LIST_5G, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_CHAN_LIST_5G, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_002
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_WIFI_CFG
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_002, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_WIFI_CFG, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_WIFI_CFG, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_WIFI_CFG, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_WIFI_CFG, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_003
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_P2P_GO_MAC
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_003, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_P2P_GO_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_P2P_GO_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_P2P_GO_MAC, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_P2P_GO_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_004
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_NODE_ADDR
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_004, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_NODE_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_NODE_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_NODE_ADDR, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_NODE_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_005
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_WIFIDIRECT_ADDR
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_005, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_WIFIDIRECT_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_WIFIDIRECT_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_WIFIDIRECT_ADDR, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_WIFIDIRECT_ADDR, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_STR_INFO_TEST_006
 * @tc.desc: LnnGetRemoteStrInfo test parameters is STRING_KEY_P2P_MAC
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_STR_INFO_TEST_006, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_P2P_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_P2P_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE_NETWORK_ID, STRING_KEY_P2P_MAC, nullptr, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_P2P_MAC, udid, sizeof(udid));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_REMOTE_NUM64_INFO_TEST_001
 * @tc.desc: LnnGetRemoteNumU64Info test parameters is NUM_KEY_P2P_ROLE
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_GET_REMOTE_NUM64_INFO_TEST_001, TestSize.Level1)
{
    uint64_t remoteCap = 0;
    int32_t ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_END, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_STATIC_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_NET_CAP, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_DEVICE_SECURITY_LEVEL, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DL_GET_CONN_SUB_FEATURE_CAP_TEST_001
 * @tc.desc: DlGetConnSubFeatureCap test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, DL_GET_CONN_SUB_FEATURE_CAP_TEST_001, TestSize.Level1)
{
    uint64_t remoteCap = DEFAULT_VALUE;
    int32_t ret = LnnGetRemoteNumU64Info(NODE1_NETWORK_ID, NUM_KEY_CONN_SUB_FEATURE_CAPA, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_CONN_SUB_FEATURE_CAPA, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNumU64Info(nullptr, NUM_KEY_CONN_SUB_FEATURE_CAPA, &remoteCap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(NODE_NETWORK_ID, NUM_KEY_CONN_SUB_FEATURE_CAPA, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_REMOTE_SCREEN_STATUS_INFO_TEST_001
 * @tc.desc: LnnSetRemoteScreenStatusInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LNN_SET_REMOTE_SCREEN_STATUS_INFO_TEST_001, TestSize.Level1)
{
    const char *devNetworkId = "123456789";
    bool isScreenOn = false;
    bool ret = LnnSetRemoteScreenStatusInfo(nullptr, isScreenOn);
    EXPECT_FALSE(ret);
    ret = LnnSetRemoteScreenStatusInfo(devNetworkId, isScreenOn);
    EXPECT_FALSE(ret);
    const char *networkId = "235689BNHFCF";
    ret = LnnSetRemoteScreenStatusInfo(networkId, isScreenOn);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LnnSetDLSleRangeInfo_Test_001
 * @tc.desc: LnnSetDLSleRangeInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDistributedNetLedgerManagerTest, LnnSetDLSleRangeInfo_Test_001, TestSize.Level1)
{
    const char *addr = "123456789";
    int32_t sleCap = 1;
    int32_t ret = LnnSetDLSleRangeInfo(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, sleCap, addr);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnSetDLSleRangeInfo(nullptr, CATEGORY_NETWORK_ID, sleCap, addr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLSleRangeInfo(NODE_NETWORK_ID, CATEGORY_NETWORK_ID, sleCap, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLSleRangeInfo(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, sleCap, addr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}
} // namespace OHOS
