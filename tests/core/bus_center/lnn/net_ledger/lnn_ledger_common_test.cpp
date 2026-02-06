/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "g_enhance_lnn_func.h"
#include "lnn_decision_db.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_net_ledger.h"
#include "lnn_net_ledger_common_mock.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_adapter.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define ONE_BIT_MAX_HEX               15
#define DEVICE_TYPE_MAX_LENGTH        3
#define LEFT_SHIFT_DEVICE_TYPE_LENGTH (DEVICE_TYPE_MAX_LENGTH * 4)
#define DEFAUTL_LNN_FEATURE           0x3E2

#define LNN_SUPPORT_ENHANCE_FEATURE   0x3F7EA
#define ENHANCE_SUPPORT_AUTH_CAPACITY 0xFF

namespace OHOS {
using namespace testing::ext;
constexpr char NODE_DEVICE_NAME[] = "node1_test";
constexpr char INVALID_DEVICE_NAME[] = "ASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJK\
    LPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJ\
    KLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLP";
constexpr char DEVICE_TYPE[] = "PAD";
constexpr char INVALID_DEVICE_TYPE[] = "PADPAD";
constexpr int32_t PORT = 1;
constexpr uint64_t PROTOCOLS = 1;
constexpr char LOCAL_NETWORKID[] = "123456LOCAL";
constexpr char REMOTE_NETWORKID[] = "234567REMOTE";
constexpr uint32_t BUF_LEN = 128;
constexpr int32_t KEY_MAX_INDEX = NODE_KEY_SERVICE_FIND_CAP + 1;
constexpr int32_t KEY_EX_MAX_INDEX = NODE_KEY_SERVICE_FIND_CAP_EX + 1;
constexpr uint16_t DATA_CHANGE_FLAG = 1;
constexpr char LOCAL_UDID[] = "123456LOCALTEST";
constexpr char LOCAL_UUID[] = "235999LOCAL";
constexpr char LOCAL_BT_MAC[] = "56789TUT";
constexpr char LOCAL_WLAN_IP[] = "10.146.181.134";
constexpr int32_t DEFAULT_FD = 1;
constexpr char LOCAL_DEVTYPE[] = "TYPE_WATCH";
constexpr char LOCAL_NET_IF_NAME[] = "LOCAL";
constexpr char MASTER_NODE_UDID[] = "234567LOCALTEST";
constexpr char LOCAL_NODE_ADDR[] = "ADDR";
constexpr char LOCAL_P2P_MAC[] = "11:22:33:44:55";
constexpr char LOCAL_GO_MAC[] = "22:33:44:55:66";
constexpr char LOCAL_WIFIDIRECT_ADDR[] = "55:66:77:88:99";
constexpr uint32_t LOCAL_SESSION_PORT = 5000;
constexpr uint32_t LOCAL_AUTH_PORT = 6000;
constexpr uint32_t LOCAL_PROXY_PORT = 7000;
constexpr uint32_t LOCAL_CAPACITY = 3;
constexpr int32_t MASTER_WEIGHT = 10;
constexpr int32_t P2P_ROLE = 1;
constexpr int32_t STATIC_LEN = 10;
using namespace testing;
class LNNNetLedgerCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetLedgerCommonTest::SetUpTestCase() { }

void LNNNetLedgerCommonTest::TearDownTestCase() { }

void LNNNetLedgerCommonTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNNetLedgerCommonTest start");
}

void LNNNetLedgerCommonTest::TearDown() { }

/*
 * @tc.name: LNN_DEVICE_INFO_Test_001
 * @tc.desc: Verify LNN device info functions including LnnGetDeviceName,
 *           LnnSetDeviceName and LnnGetDeviceTypeId with different parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_DEVICE_INFO_Test_001, TestSize.Level1)
{
    DeviceBasicInfo info;
    uint16_t typeId = 0;
    int32_t ret = memset_s(&info, sizeof(DeviceBasicInfo), 0, sizeof(DeviceBasicInfo));
    EXPECT_TRUE(ret == EOK);
    EXPECT_TRUE(LnnGetDeviceName(nullptr) == nullptr);
    LnnGetDeviceName(&info);
    EXPECT_TRUE(LnnSetDeviceName(nullptr, NODE_DEVICE_NAME) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, INVALID_DEVICE_NAME) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, NODE_DEVICE_NAME) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetDeviceTypeId(nullptr, &typeId) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetDeviceTypeId(&info, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetDeviceTypeId(&info, &typeId) == SOFTBUS_OK);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(INVALID_DEVICE_TYPE, &typeId) == SOFTBUS_NETWORK_INVALID_DEV_INFO);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(DEVICE_TYPE, &typeId) == SOFTBUS_OK);
    typeId = 0;
    LnnConvertIdToDeviceType(TYPE_WATCH_ID);
    LnnConvertIdToDeviceType(typeId);
    typeId = ONE_BIT_MAX_HEX << LEFT_SHIFT_DEVICE_TYPE_LENGTH;
    EXPECT_TRUE(LnnConvertIdToDeviceType(typeId) != nullptr);
}

/*
 * @tc.name: LNN_HUKS_UTILS_Test_001
 * @tc.desc: Verify LNN huks utils functions including LnnGenerateKeyByHuks
 *           and LnnGenerateCeKeyByHuks with different parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_HUKS_UTILS_Test_001, TestSize.Level1)
{
    struct HksBlob keyAlias;
    (void)memset_s(&keyAlias, sizeof(HksBlob), 0, sizeof(HksBlob));
    EXPECT_TRUE(LnnGenerateKeyByHuks(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGenerateKeyByHuks(&keyAlias) == SOFTBUS_HUKS_GENERATE_KEY_ERR);
    EXPECT_TRUE(LnnDeleteKeyByHuks(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnDeleteKeyByHuks(&keyAlias) == SOFTBUS_OK);
    EXPECT_TRUE(LnnEncryptDataByHuks(nullptr, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnDecryptDataByHuks(nullptr, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_NET_CAPABILITY_Test_001
 * @tc.desc: Verify LnnSetNetCapability and LnnClearNetCapability
 *           handle null capability pointer correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_CAPABILITY_Test_001, TestSize.Level1)
{
    uint32_t capability = 0;
    EXPECT_TRUE(LnnSetNetCapability(nullptr, BIT_COUNT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnClearNetCapability(nullptr, BIT_COUNT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnClearNetCapability(&capability, BIT_BLE) == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NET_CAPABILITY_Test_002
 * @tc.desc: LNN net capability function test, LnnSetNetCapability, LnnHasCapability
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_CAPABILITY_Test_002, TestSize.Level1)
{
    uint32_t capability = 0;
    bool hasCapability = false;
    int32_t ret = LnnSetNetCapability(&capability, BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_BLE);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_BR);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_BR);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_WIFI);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_WIFI_P2P);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_WIFI_P2P);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_WIFI_24G);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_WIFI_24G);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_WIFI_5G);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_WIFI_5G);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetNetCapability(&capability, BIT_ETH);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_ETH);
    EXPECT_EQ(hasCapability, true);
}

/*
 * @tc.name: LNN_NET_CAPABILITY_Test_003
 * @tc.desc: LNN net capability function test, LnnSetNetCapability, LnnClearNetCapability
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_CAPABILITY_Test_003, TestSize.Level1)
{
    uint32_t capability = 0;
    bool hasCapability = false;
    int32_t ret = LnnSetNetCapability(&capability, BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_BLE);
    EXPECT_EQ(hasCapability, true);

    ret = LnnClearNetCapability(&capability, BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasCapability(capability, BIT_BLE);
    EXPECT_EQ(hasCapability, false);

    ret = LnnSetNetCapability(&capability, BIT_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    hasCapability = LnnHasCapability(capability, BIT_COUNT);
    EXPECT_EQ(hasCapability, false);
    ret = LnnClearNetCapability(&capability, BIT_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_STATIC_NET_CAPA_001
 * @tc.desc: LNN net static capability function test, LnnSetStaticNetCap, LnnHasStaticNetCap
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_STATIC_NET_CAPA_001, TestSize.Level1)
{
    uint32_t capability = 0;
    bool hasCapability = false;
    int32_t ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_BR);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_BR);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_WIFI);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_P2P);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_P2P);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_ENHANCED_P2P);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_ENHANCED_P2P);
    EXPECT_EQ(hasCapability, true);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_ETH);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_ETH);
    EXPECT_EQ(hasCapability, true);
}

/*
 * @tc.name: LNN_SET_STATIC_NET_CAPA_002
 * @tc.desc: Verify LnnSetStaticNetCap returns SOFTBUS_INVALID_PARAM
 *           with null capability pointer and SOFTBUS_OK with valid parameters
 * @tc.type: FUNC LnnSetStaticNetCap
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_STATIC_NET_CAPA_002, TestSize.Level1)
{
    uint32_t capability = 0;
    bool hasCapability = false;
    int32_t ret = LnnSetStaticNetCap(NULL, STATIC_CAP_BIT_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(hasCapability, true);
}

/*
 * @tc.name: LNN_SET_STATIC_NET_CAPA_003
 * @tc.desc: LNN net capability function test, LnnSetStaticNetCap, LnnClearStaticNetCap
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_STATIC_NET_CAPA_003, TestSize.Level1)
{
    uint32_t capability = 0;
    bool hasCapability = false;
    int32_t ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(hasCapability, true);

    ret = LnnClearStaticNetCap(&capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_BLE);
    EXPECT_EQ(hasCapability, false);

    ret = LnnSetStaticNetCap(&capability, STATIC_CAP_BIT_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    hasCapability = LnnHasStaticNetCap(capability, STATIC_CAP_BIT_COUNT);
    EXPECT_EQ(hasCapability, false);
    ret = LnnClearStaticNetCap(&capability, STATIC_CAP_BIT_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_001
 * @tc.desc: Verify LNN node info functions handle null pointer
 *           parameters correctly and return expected error codes
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnHasDiscoveryType(nullptr, DISCOVERY_TYPE_WIFI) == false);
    EXPECT_TRUE(LnnGetDeviceUdid(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetDeviceUdid(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDiscoveryType(nullptr, DISCOVERY_TYPE_WIFI) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnClearDiscoveryType(nullptr, DISCOVERY_TYPE_WIFI) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnIsNodeOnline(nullptr) == false);
    LnnSetNodeConnStatus(nullptr, STATUS_ONLINE);
    LnnGetBtMac(nullptr);
    LnnSetBtMac(nullptr, nullptr);
    LnnGetNetIfName(nullptr, WLAN_IF);
    LnnSetNetIfName(nullptr, nullptr, WLAN_IF);
    LnnGetWiFiIp(nullptr, WLAN_IF);
    LnnSetWiFiIp(nullptr, nullptr, WLAN_IF);
    EXPECT_TRUE(LnnGetMasterUdid(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetMasterUdid(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetAuthPort(nullptr, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetAuthPort(nullptr, PORT, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetSessionPort(nullptr, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetSessionPort(nullptr, PORT, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetProxyPort(nullptr, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetProxyPort(nullptr, PORT, WLAN_IF) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetP2pRole(nullptr, PORT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pRole(nullptr) == 0);
    EXPECT_TRUE(LnnSetP2pMac(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pMac(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetP2pGoMac(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetWifiDirectAddr(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetWifiDirectAddr(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pGoMac(nullptr) == nullptr);
    EXPECT_TRUE(LnnGetSupportedProtocols(nullptr) == 0);
    EXPECT_TRUE(LnnSetSupportedProtocols(nullptr, PROTOCOLS) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetStaticCapability(nullptr, nullptr, 0) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetStaticCapability(nullptr, nullptr, 0) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetPtk(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_002
 * @tc.desc: LNN node info function test, LnnSetDiscoveryType, LnnHasDiscoveryType, LnnClearDiscoveryType
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_002, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret = LnnSetDiscoveryType(&nodeInfo, DISCOVERY_TYPE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDiscoveryType(nullptr, DISCOVERY_TYPE_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDiscoveryType(&nodeInfo, DISCOVERY_TYPE_LSA);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasDiscoveryType = LnnHasDiscoveryType(nullptr, DISCOVERY_TYPE_LSA);
    EXPECT_EQ(hasDiscoveryType, false);
    hasDiscoveryType = LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_COUNT);
    EXPECT_EQ(hasDiscoveryType, false);
    hasDiscoveryType = LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_UNKNOWN);
    EXPECT_EQ(hasDiscoveryType, false);
    hasDiscoveryType = LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_LSA);
    EXPECT_EQ(hasDiscoveryType, true);

    ret = LnnClearDiscoveryType(nullptr, DISCOVERY_TYPE_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearDiscoveryType(&nodeInfo, DISCOVERY_TYPE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearDiscoveryType(&nodeInfo, DISCOVERY_TYPE_LSA);
    EXPECT_EQ(ret, SOFTBUS_OK);

    hasDiscoveryType = LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_LSA);
    EXPECT_EQ(hasDiscoveryType, false);
    ret = LnnClearDiscoveryType(&nodeInfo, DISCOVERY_TYPE_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    hasDiscoveryType = LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_UNKNOWN);
    EXPECT_EQ(hasDiscoveryType, false);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_003
 * @tc.desc: LNN node info function test, LnnSetDeviceUdid, LnnGetDeviceUdid
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_003, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret = LnnSetDeviceUdid(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDeviceUdid(nullptr, LOCAL_UDID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char *udid = (char *)SoftBusCalloc((UDID_BUF_LEN + 1) * sizeof(char));
    ret = LnnSetDeviceUdid(&nodeInfo, udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(udid);

    ret = LnnSetDeviceUdid(&nodeInfo, LOCAL_UDID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(strcmp(nodeInfo.deviceInfo.deviceUdid, LOCAL_UDID), 0);

    const char *deviceUdid = LnnGetDeviceUdid(nullptr);
    EXPECT_EQ(deviceUdid, nullptr);
    deviceUdid = LnnGetDeviceUdid(&nodeInfo);
    EXPECT_EQ(strcmp(deviceUdid, LOCAL_UDID), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_004
 * @tc.desc: LNN node info function test, LnnGetDeviceUuid
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_004, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret = strncpy_s(nodeInfo.uuid, UUID_BUF_LEN, LOCAL_UUID, strlen(LOCAL_UUID));
    EXPECT_EQ(ret, EOK);

    const char *uuid = LnnGetDeviceUuid(nullptr);
    EXPECT_EQ(uuid, nullptr);
    uuid = LnnGetDeviceUuid(&nodeInfo);
    EXPECT_EQ(strcmp(uuid, LOCAL_UUID), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_005
 * @tc.desc: LNN node info function testm, LnnSetBtMac, LnnGetBtMac
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_005, TestSize.Level1)
{
    NodeInfo nodeInfo;

    LnnSetBtMac(nullptr, LOCAL_BT_MAC);
    EXPECT_NE(strcmp(nodeInfo.connectInfo.macAddr, LOCAL_BT_MAC), 0);

    LnnSetBtMac(&nodeInfo, nullptr);
    EXPECT_NE(strcmp(nodeInfo.connectInfo.macAddr, LOCAL_BT_MAC), 0);

    LnnSetBtMac(&nodeInfo, LOCAL_BT_MAC);
    EXPECT_EQ(strcmp(nodeInfo.connectInfo.macAddr, LOCAL_BT_MAC), 0);

    const char *btMac = nullptr;
    btMac = LnnGetBtMac(&nodeInfo);
    EXPECT_EQ(strcmp(btMac, LOCAL_BT_MAC), 0);

    char *localBtMac = (char *)SoftBusCalloc((MAC_LEN + 1) * sizeof(char));
    LnnSetBtMac(&nodeInfo, localBtMac);
    EXPECT_EQ(strcmp(nodeInfo.connectInfo.macAddr, localBtMac), 0);
    SoftBusFree(localBtMac);

    btMac = LnnGetBtMac(nullptr);
    EXPECT_EQ(strcmp(btMac, DEFAULT_MAC), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_006
 * @tc.desc: LNN node info function test, LnnSetNetIfName, LnnGetNetIfName
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_006, TestSize.Level1)
{
    NodeInfo nodeInfo;
    constexpr char netIfName1[] = "wlan0";

    LnnSetNetIfName(nullptr, netIfName1, WLAN_IF);
    EXPECT_NE(strcmp(nodeInfo.connectInfo.ifInfo[WLAN_IF].netIfName, netIfName1), 0);

    LnnSetNetIfName(&nodeInfo, nullptr, WLAN_IF);
    EXPECT_NE(strcmp(nodeInfo.connectInfo.ifInfo[WLAN_IF].netIfName, netIfName1), 0);

    char *netIfName2 = (char *)SoftBusCalloc((NET_IF_NAME_LEN + 1) * sizeof(char));
    LnnSetNetIfName(&nodeInfo, netIfName2, WLAN_IF);
    SoftBusFree(netIfName2);

    LnnSetNetIfName(&nodeInfo, netIfName1, WLAN_IF);
    EXPECT_EQ(strcmp(nodeInfo.connectInfo.ifInfo[WLAN_IF].netIfName, netIfName1), 0);

    const char *netIfName = nullptr;
    netIfName = LnnGetNetIfName(&nodeInfo, WLAN_IF);
    EXPECT_EQ(strcmp(netIfName, netIfName1), 0);

    netIfName = LnnGetNetIfName(nullptr, WLAN_IF);
    EXPECT_EQ(strcmp(netIfName, DEFAULT_IFNAME), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_007
 * @tc.desc: LNN node info function test, LnnSetWiFiIp
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_007, TestSize.Level1)
{
    NodeInfo nodeInfo;

    LnnSetWiFiIp(nullptr, LOCAL_WLAN_IP, WLAN_IF);
    EXPECT_NE(strcmp(nodeInfo.connectInfo.ifInfo[WLAN_IF].deviceIp, LOCAL_WLAN_IP), 0);
    LnnSetWiFiIp(&nodeInfo, LOCAL_WLAN_IP, WLAN_IF);
    EXPECT_EQ(strcmp(nodeInfo.connectInfo.ifInfo[WLAN_IF].deviceIp, LOCAL_WLAN_IP), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_008
 * @tc.desc: LNN node info function test, LnnSetMasterUdid, LnnGetMasterUdid
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_008, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret = LnnSetMasterUdid(nullptr, MASTER_NODE_UDID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetMasterUdid(&nodeInfo, MASTER_NODE_UDID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *udid = LnnGetMasterUdid(nullptr);
    EXPECT_EQ(udid, nullptr);
    udid = LnnGetMasterUdid(&nodeInfo);
    EXPECT_EQ(strcmp(udid, MASTER_NODE_UDID), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_009
 * @tc.desc: LNN node info function test, LnnSetWifiCfg, LnnGetWifiCfg
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_009, TestSize.Level1)
{
    NodeInfo nodeInfo;
    char wifiCfg1[] = "wifiCfg test msg";

    int32_t ret = LnnSetWifiCfg(nullptr, wifiCfg1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetWifiCfg(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char *wifiCfg2 = (char *)SoftBusCalloc((WIFI_CFG_INFO_MAX_LEN + 1) * sizeof(char));
    ret = LnnSetWifiCfg(&nodeInfo, wifiCfg2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(wifiCfg2);

    ret = LnnSetWifiCfg(&nodeInfo, wifiCfg1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *wifiCfg = nullptr;
    wifiCfg = LnnGetWifiCfg(&nodeInfo);
    EXPECT_EQ(wifiCfg, nodeInfo.p2pInfo.wifiCfg);

    wifiCfg = LnnGetWifiCfg(nullptr);
    EXPECT_EQ(wifiCfg, nullptr);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_010
 * @tc.desc: LNN node info function test, LnnSetChanList5g, LnnGetChanList5g
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_010, TestSize.Level1)
{
    NodeInfo nodeInfo;
    char chanList5g1[CHANNEL_LIST_STR_LEN];
    int32_t ret = LnnSetChanList5g(nullptr, chanList5g1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetChanList5g(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char *chanList5g2 = (char *)SoftBusCalloc((CHANNEL_LIST_STR_LEN + 1) * sizeof(char));
    ret = LnnSetChanList5g(&nodeInfo, chanList5g2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(chanList5g2);

    ret = LnnSetChanList5g(&nodeInfo, chanList5g1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *chanList5g = nullptr;
    chanList5g = LnnGetChanList5g(&nodeInfo);
    EXPECT_EQ(chanList5g, nodeInfo.p2pInfo.chanList5g);

    chanList5g = LnnGetChanList5g(nullptr);
    EXPECT_EQ(chanList5g, nullptr);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_011
 * @tc.desc: LNN node info function test LnnSetP2pGoMac, LnnGetP2pGoMac
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_011, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t ret;
    const char *goMac = nullptr;

    ret = LnnSetP2pGoMac(nullptr, LOCAL_GO_MAC);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    goMac = LnnGetP2pGoMac(&nodeInfo);
    EXPECT_NE(strcmp(goMac, LOCAL_GO_MAC), 0);

    ret = LnnSetP2pGoMac(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    goMac = LnnGetP2pGoMac(&nodeInfo);
    EXPECT_NE(strcmp(goMac, LOCAL_GO_MAC), 0);

    ret = LnnSetP2pGoMac(&nodeInfo, LOCAL_GO_MAC);
    EXPECT_EQ(ret, SOFTBUS_OK);
    goMac = LnnGetP2pGoMac(&nodeInfo);
    EXPECT_EQ(strcmp(goMac, LOCAL_GO_MAC), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_012
 * @tc.desc: LNN node info function test, LnnSetStaFrequency, LnnGetStaFrequency
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_012, TestSize.Level1)
{
    NodeInfo nodeInfo;
    int32_t staFrequency = 1;

    int32_t ret = LnnSetStaFrequency(nullptr, staFrequency);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetStaFrequency(&nodeInfo, staFrequency);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t rst = LnnGetStaFrequency(&nodeInfo);
    EXPECT_EQ(rst, 1);

    rst = LnnGetStaFrequency(nullptr);
    EXPECT_EQ(rst, 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_013
 * @tc.desc: LNN node info function test, LnnSetP2pMac, LnnGetP2pMac
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_013, TestSize.Level1)
{
    NodeInfo nodeInfo;
    const char *mac = nullptr;

    int32_t ret = LnnSetP2pMac(nullptr, LOCAL_P2P_MAC);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetP2pMac(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetP2pMac(&nodeInfo, LOCAL_P2P_MAC);
    EXPECT_EQ(ret, SOFTBUS_OK);

    mac = LnnGetP2pMac(nullptr);
    EXPECT_EQ(mac, nullptr);
    mac = LnnGetP2pMac(&nodeInfo);
    EXPECT_EQ(strcmp(mac, LOCAL_P2P_MAC), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_014
 * @tc.desc: LNN node info function test, LnnSetDataDynamicLevel, LnnGetDataDynamicLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_014, TestSize.Level1)
{
    NodeInfo nodeInfo;
    uint16_t dataDynamicLevel = 1;

    int32_t ret = LnnSetDataDynamicLevel(nullptr, dataDynamicLevel);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetDataDynamicLevel(&nodeInfo, dataDynamicLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint16_t Level = LnnGetDataDynamicLevel(&nodeInfo);
    EXPECT_EQ(Level, 1);

    Level = LnnGetDataDynamicLevel(nullptr);
    EXPECT_NE(Level, 1);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_015
 * @tc.desc: LNN node info function test, LnnSetDataStaticLevel, LnnGetDataStaticLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_015, TestSize.Level1)
{
    NodeInfo nodeInfo;
    uint16_t dataStaticLevel = 1;

    int32_t ret = LnnSetDataStaticLevel(nullptr, dataStaticLevel);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetDataStaticLevel(&nodeInfo, dataStaticLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint16_t Level = LnnGetDataStaticLevel(&nodeInfo);
    EXPECT_EQ(Level, 1);

    Level = LnnGetDataStaticLevel(nullptr);
    EXPECT_NE(Level, 1);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_016
 * @tc.desc: LNN node info function test, LnnSetDataSwitchLevel, LnnGetDataSwitchLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_016, TestSize.Level1)
{
    NodeInfo nodeInfo;
    uint32_t dataSwitchLevel = 1;

    int32_t ret = LnnSetDataSwitchLevel(nullptr, dataSwitchLevel);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetDataSwitchLevel(&nodeInfo, dataSwitchLevel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t Level = LnnGetDataSwitchLevel(&nodeInfo);
    EXPECT_EQ(Level, 1);

    Level = LnnGetDataSwitchLevel(nullptr);
    EXPECT_NE(Level, 1);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_017
 * @tc.desc: LNN node info function test, LnnSetDataSwitchLength, LnnGetDataSwitchLength
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_017, TestSize.Level1)
{
    NodeInfo nodeInfo;
    uint16_t dataSwitchLength = 1;

    int32_t ret = LnnSetDataSwitchLength(nullptr, dataSwitchLength);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetDataSwitchLength(&nodeInfo, dataSwitchLength);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint16_t Level = LnnGetDataSwitchLength(&nodeInfo);
    EXPECT_EQ(Level, 1);

    Level = LnnGetDataSwitchLength(nullptr);
    EXPECT_NE(Level, 1);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_018
 * @tc.desc: LNN node info function test LnnSetWifiDirectAddr, LnnGetWifiDirectAddr
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_018, TestSize.Level1)
{
    NodeInfo nodeInfo;

    int32_t ret = LnnSetWifiDirectAddr(nullptr, LOCAL_WIFIDIRECT_ADDR);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetWifiDirectAddr(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetWifiDirectAddr(&nodeInfo, LOCAL_GO_MAC);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *wifiDirectAddr = LnnGetWifiDirectAddr(&nodeInfo);
    EXPECT_EQ(strcmp(wifiDirectAddr, LOCAL_GO_MAC), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_019
 * @tc.desc: LNN node info function test LnnSetStaticCapability, LnnGetStaticCapability
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_019, TestSize.Level1)
{
    NodeInfo nodeInfo;
    uint8_t capability = 4;

    int32_t ret = LnnSetStaticCapability(nullptr, &capability, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetStaticCapability(&nodeInfo, nullptr, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetStaticCapability(&nodeInfo, &capability, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetStaticCapability(&nodeInfo, &capability, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetStaticCapability(&nodeInfo, &capability, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t cap;
    ret = LnnGetStaticCapability(&nodeInfo, &cap, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnGetStaticCapability(nullptr, &cap, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetStaticCapability(&nodeInfo, nullptr, STATIC_CAP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetStaticCapability(&nodeInfo, &cap, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_020
 * @tc.desc: LNN node info function test LnnSetPtk
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_020, TestSize.Level1)
{
    NodeInfo nodeInfo;
    char remotePtk[PTK_DEFAULT_LEN] = { "12345567890" };
    char remotePtk2[10] = { "12345" };

    LnnDumpRemotePtk(remotePtk, remotePtk2, nullptr);
    int32_t ret = LnnSetPtk(nullptr, remotePtk);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetPtk(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetPtk(&nodeInfo, remotePtk2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnSetPtk(&nodeInfo, remotePtk);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(strcmp(remotePtk, nodeInfo.remotePtk), 0);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_021
 * @tc.desc: LNN node info function test LnnSetScreenStatus
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_021, TestSize.Level1)
{
    NodeInfo nodeInfo;

    int32_t ret = LnnSetScreenStatus(nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetScreenStatus(&nodeInfo, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(true, nodeInfo.isScreenOn);
    ret = LnnSetScreenStatus(&nodeInfo, false);
    EXPECT_EQ(false, nodeInfo.isScreenOn);
}

/*
 * @tc.name: LNN_NODE_INFO_Test_022
 * @tc.desc: LNN node info function test LnnSetScreenStatus
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NODE_INFO_Test_022, TestSize.Level1)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint8_t data[USERID_CHECKSUM_LEN];

    int32_t ret = LnnSetUserIdCheckSum(nullptr, data, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetUserIdCheckSum(&nodeInfo, nullptr, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetUserIdCheckSum(&nodeInfo, data, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetUserIdCheckSum(&nodeInfo, data, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnGetUserIdCheckSum(nullptr, data, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetUserIdCheckSum(&nodeInfo, nullptr, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetUserIdCheckSum(&nodeInfo, data, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnGetUserIdCheckSum(&nodeInfo, data, USERID_CHECKSUM_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NET_LEDGER_Test_001
 * @tc.desc: LNN net ledger function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_001, TestSize.Level1)
{
    int32_t i;
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    uint8_t info[BUF_LEN] = { 0 };
    uint8_t capacity[SERVICE_FIND_CAP_LEN] = { 0 };
    EXPECT_TRUE(LnnGetNodeKeyInfo(nullptr, 0, info, BUF_LEN) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetNodeKeyInfo(LOCAL_NETWORKID, 0, info, BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetNodeKeyInfo(LOCAL_NETWORKID, KEY_MAX_INDEX - 1, capacity, SERVICE_FIND_CAP_LEN) == SOFTBUS_OK);
    for (i = 1; i < KEY_MAX_INDEX - 1; i++) {
        EXPECT_TRUE(LnnGetNodeKeyInfo(LOCAL_NETWORKID, i, info, BUF_LEN) == SOFTBUS_OK);
    }
    for (i = 0; i < KEY_MAX_INDEX; i++) {
        LnnGetNodeKeyInfo(REMOTE_NETWORKID, i, info, BUF_LEN);
    }
    LnnDeinitNetLedger();
}

/*
 * @tc.name: LNN_NET_LEDGER_Test_002
 * @tc.desc: LNN net ledger function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(nullptr, DATA_CHANGE_FLAG) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(LOCAL_NETWORKID, DATA_CHANGE_FLAG) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(REMOTE_NETWORKID, DATA_CHANGE_FLAG) == SOFTBUS_NETWORK_INVALID_DEV_INFO);
    LnnDeinitNetLedger();
}

/*
 * @tc.name: LNN_NET_LEDGER_Test_003
 * @tc.desc: LNN net ledger function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_003, TestSize.Level1)
{
    static int32_t nodeKeyInfoLenTable[] = { UDID_BUF_LEN, UUID_BUF_LEN, UDID_BUF_LEN, MAC_LEN, IP_LEN,
        DEVICE_NAME_BUF_LEN, LNN_COMMON_LEN, LNN_COMMON_LEN, SOFTBUS_INVALID_NUM, DATA_CHANGE_FLAG_BUF_LEN,
        SHORT_ADDRESS_MAX_LEN, IP_LEN, LNN_COMMON_LEN, DATA_DEVICE_SCREEN_STATUS_LEN, SOFTBUS_INVALID_NUM,
        SERVICE_FIND_CAP_LEN };
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    for (int32_t i = 0; i < KEY_MAX_INDEX; i++) {
        int32_t result = LnnGetNodeKeyInfoLen(i);
        EXPECT_EQ(result, nodeKeyInfoLenTable[i]);
    }
    LnnDeinitNetLedger();
}

/*
 * @tc.name: LNN_NET_LEDGER_Test_004
 * @tc.desc: LNN net ledger function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_004, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_UUID, LOCAL_UUID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_BT_MAC, LOCAL_BT_MAC) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP, LOCAL_WLAN_IP, WLAN_IF) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalNumInfo(NUM_KEY_NET_CAP, 1 << BIT_BR) == SOFTBUS_OK);
    NodeBasicInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    (void)strncpy_s(nodeInfo.deviceName, DEVICE_NAME_BUF_LEN, NODE_DEVICE_NAME, strlen(NODE_DEVICE_NAME));
    (void)strncpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, LOCAL_NETWORKID, strlen(LOCAL_NETWORKID));
    SoftBusDumpBusCenterPrintInfo(DEFAULT_FD, nullptr);
    SoftBusDumpBusCenterPrintInfo(DEFAULT_FD, &nodeInfo);
    LnnDeinitNetLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_Test_001
 * @tc.desc: Verify LNN local key table get functions handle null buffer
 *           and return correct values for valid string keys
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    static InfoKey getLocalStringInfoKeyTable[] = { STRING_KEY_HICE_VERSION, STRING_KEY_DEV_UDID, STRING_KEY_NETWORKID,
        STRING_KEY_UUID, STRING_KEY_DEV_TYPE, STRING_KEY_DEV_NAME, STRING_KEY_BT_MAC, STRING_KEY_MASTER_NODE_UDID,
        STRING_KEY_NODE_ADDR, STRING_KEY_P2P_MAC, STRING_KEY_P2P_GO_MAC, STRING_KEY_OFFLINE_CODE,
        STRING_KEY_WIFIDIRECT_ADDR };
    char buf[UDID_BUF_LEN] = { 0 };
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
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_Test_002
 * @tc.desc: LNN local key table test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_TYPE, LOCAL_DEVTYPE);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
    ret = LnnSetLocalStrInfo(STRING_KEY_BT_MAC, LOCAL_BT_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP, LOCAL_WLAN_IP, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, LOCAL_NET_IF_NAME, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, MASTER_NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_NODE_ADDR, LOCAL_NODE_ADDR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, LOCAL_P2P_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, LOCAL_GO_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_WIFIDIRECT_ADDR, LOCAL_WIFIDIRECT_ADDR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_Test_003
 * @tc.desc: LNN local key table test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_003, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    static InfoKey getLocalNumInfoKeyTable[] = { NUM_KEY_NET_CAP, NUM_KEY_DISCOVERY_TYPE, NUM_KEY_DEV_TYPE_ID,
        NUM_KEY_MASTER_NODE_WEIGHT, NUM_KEY_P2P_ROLE, NUM_KEY_STATIC_CAP_LEN };
    int32_t ret, info;
    LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT);
    for (uint32_t i = 0; i < sizeof(getLocalNumInfoKeyTable) / sizeof(InfoKey); i++) {
        info = 0;
        ret = LnnGetLocalNumInfo(getLocalNumInfoKeyTable[i], &info);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_Test_004
 * @tc.desc: LNN local key table test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_004, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    int32_t ret = LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_SESSION_PORT, LOCAL_SESSION_PORT, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_PROXY_PORT, LOCAL_PROXY_PORT, WLAN_IF);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, LOCAL_CAPACITY);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, P2P_ROLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_STATIC_CAP_LEN, STATIC_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_Test_005
 * @tc.desc: LNN local key table test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_005, TestSize.Level1)
{
    int64_t info;
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    int32_t ret = LnnGetLocalNum64Info(NUM_KEY_TRANS_PROTOCOLS, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetLocalDeviceInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnIsMasterNode() == false);
    LnnDeinitLocalLedger();
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_BY_IFNAME_Test_001
 * @tc.desc: Verify LnnGetLocalStrInfoByIfnameIdx handles null buffer
 *           and returns correct values for valid string keys by interface name
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_BY_IFNAME_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    static InfoKey getLocalStringInfoKeyTable[] = { STRING_KEY_IP, STRING_KEY_NET_IF_NAME, STRING_KEY_IP6_WITH_IF };
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret;
    uint32_t i;
    LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_DEV_UDID, LOCAL_UDID, WLAN_IF);
    for (i = 0; i < sizeof(getLocalStringInfoKeyTable) / sizeof(InfoKey); i++) {
        ret = LnnGetLocalStrInfoByIfnameIdx(getLocalStringInfoKeyTable[i], nullptr, UDID_BUF_LEN, WLAN_IF);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    }
    for (i = 0; i < sizeof(getLocalStringInfoKeyTable) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetLocalStrInfoByIfnameIdx(getLocalStringInfoKeyTable[i], buf, UDID_BUF_LEN, WLAN_IF);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LOCAL_LEDGER_BY_IFNAME_Test_003
 * @tc.desc: Verify LnnGetLocalNumInfoByIfnameIdx returns correct values
 *           for valid numeric keys by interface name
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_BY_IFNAME_Test_003, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    static InfoKey getLocalNumInfoKeyTable[] = { NUM_KEY_SESSION_PORT, NUM_KEY_AUTH_PORT, NUM_KEY_PROXY_PORT };
    int32_t ret, info;
    LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT, WLAN_IF);
    for (uint32_t i = 0; i < sizeof(getLocalNumInfoKeyTable) / sizeof(InfoKey); i++) {
        info = 0;
        ret = LnnGetLocalNumInfoByIfnameIdx(getLocalNumInfoKeyTable[i], &info, WLAN_IF);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LNN_FEATURE_CAPABILTY_001
 * @tc.desc: Verify LnnSetFeatureCapability and LnnClearFeatureCapability
 *           handle null pointer and invalid feature bits correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_FEATURE_CAPABILTY_001, TestSize.Level1)
{
    uint64_t feature;
    int32_t ret = LnnSetFeatureCapability(nullptr, BIT_FEATURE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetFeatureCapability(nullptr, BIT_BR_DUP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetFeatureCapability(&feature, BIT_FEATURE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnSetFeatureCapability(&feature, BIT_BR_DUP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(IsFeatureSupport(feature, BIT_BR_DUP), true);

    ret = LnnClearFeatureCapability(nullptr, BIT_FEATURE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearFeatureCapability(nullptr, BIT_BR_DUP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnClearFeatureCapability(&feature, BIT_FEATURE_COUNT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnClearFeatureCapability(&feature, BIT_BR_DUP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(IsFeatureSupport(feature, BIT_BR_DUP), false);
}

/*
 * @tc.name: LNN_SET_DATA_LEVEL_001
 * @tc.desc: LNN node info function test LnnSetDataLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_DATA_LEVEL_001, TestSize.Level1)
{
    DataLevel dataLevel;
    dataLevel.dynamicLevel = 0;
    dataLevel.staticLevel = 0;
    dataLevel.switchLevel = 0;
    dataLevel.switchLength = 0;
    bool isSwitchLevelChanged = false;
    NetLedgerCommonInterfaceMock netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetLocalNumU16Info(_, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    uint32_t ret = LnnSetDataLevel(&dataLevel, &isSwitchLevelChanged);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
}

/*
 * @tc.name: LNN_SET_DATA_LEVEL_002
 * @tc.desc: LNN node info function test LnnSetDataLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_DATA_LEVEL_002, TestSize.Level1)
{
    DataLevel *dataLevel = nullptr;
    bool isSwitchLevelChanged = false;
    uint32_t ret = LnnSetDataLevel(dataLevel, &isSwitchLevelChanged);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_DATA_LEVEL_003
 * @tc.desc: LNN node info function test LnnSetDataLevel
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_DATA_LEVEL_003, TestSize.Level1)
{
    DataLevel dataLevel;
    dataLevel.dynamicLevel = 0;
    dataLevel.staticLevel = 0;
    dataLevel.switchLevel = 0;
    dataLevel.switchLength = 0;
    bool *isSwitchLevelChanged = nullptr;
    uint32_t ret = LnnSetDataLevel(&dataLevel, isSwitchLevelChanged);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnDumpSparkCheck_001
 * @tc.desc: Verify LnnDumpSparkCheck handles null pointer parameters
 *           and correctly processes spark check data
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LnnDumpSparkCheck_001, TestSize.Level1)
{
    unsigned char sparkCheck[SPARK_CHECK_LENGTH] = {0};
    EXPECT_NO_FATAL_FAILURE(LnnDumpSparkCheck(nullptr, nullptr));
    EXPECT_NO_FATAL_FAILURE(LnnDumpSparkCheck(sparkCheck, nullptr));
    EXPECT_NO_FATAL_FAILURE(LnnDumpSparkCheck(sparkCheck, "test"));
    sparkCheck[0] = 1;
    EXPECT_NO_FATAL_FAILURE(LnnDumpSparkCheck(sparkCheck, "test"));
}

/*
 * @tc.name: LNN_SET_NODE_KEY_INFO_Test_001
 * @tc.desc: LNN set node key info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNNetLedgerCommonTest, LNN_SET_NODE_KEY_INFO_Test_001, TestSize.Level1)
{
    char serviceFindCap[SERVICE_FIND_CAP_LEN] = "123456789";
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeKeyInfo(nullptr, 0, (uint8_t *)serviceFindCap, strlen(serviceFindCap))
        == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetNodeKeyInfo(LOCAL_NETWORKID, 0, (uint8_t *)serviceFindCap, strlen(serviceFindCap)) == SOFTBUS_OK);
    EXPECT_EQ(LnnSetNodeKeyInfo(LOCAL_NETWORKID, KEY_EX_MAX_INDEX, (uint8_t *)serviceFindCap, strlen(serviceFindCap)),
        SOFTBUS_INVALID_NUM);
    LnnDeinitNetLedger();
}
} // namespace OHOS