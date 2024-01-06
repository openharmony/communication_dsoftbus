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
#include <cstdint>

#include "bus_center_manager.h"
#include "lnn_decision_db.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_net_ledger.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define ONE_BIT_MAX_HEX 15
#define DEVICE_TYPE_MAX_LENGTH 3
#define LEFT_SHIFT_DEVICE_TYPE_LENGTH  (DEVICE_TYPE_MAX_LENGTH * 4)

namespace OHOS {
using namespace testing::ext;
constexpr char NODE_DEVICE_NAME[] = "node1_test";
constexpr char INVALID_DEVICE_NAME[] =
    "ASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJK\
    LPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJ\
    KLPASDFGHJKLPASDFGHJKLPASDFGHJKLPASDFGHJKLP";
constexpr char DEVICE_TYPE[] = "PAD";
constexpr char INVALID_DEVICE_TYPE[] = "PADPAD";
constexpr int32_t PORT = 1;
constexpr uint64_t PROTOCOLS = 1;
constexpr char LOCAL_NETWORKID[] = "123456LOCAL";
constexpr char REMOTE_NETWORKID[] = "234567REMOTE";
constexpr uint32_t BUF_LEN = 128;
constexpr int32_t KEY_MAX_INDEX = 11;
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

void LNNNetLedgerCommonTest::SetUpTestCase()
{
}

void LNNNetLedgerCommonTest::TearDownTestCase()
{
}

void LNNNetLedgerCommonTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNNetLedgerCommonTest start");
}

void LNNNetLedgerCommonTest::TearDown()
{
}

/*
* @tc.name: LNN_DEVICE_INFO_Test_001
* @tc.desc: lnn device info function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_DEVICE_INFO_Test_001, TestSize.Level1)
{
    DeviceBasicInfo info;
    uint16_t typeId = 0;
    int32_t ret = memset_s(&info, sizeof(DeviceBasicInfo), 0, sizeof(DeviceBasicInfo));
    EXPECT_TRUE(ret == EOK);
    EXPECT_TRUE(LnnGetDeviceName(nullptr) == NULL);
    LnnGetDeviceName(&info);
    EXPECT_TRUE(LnnSetDeviceName(nullptr, NODE_DEVICE_NAME) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, INVALID_DEVICE_NAME) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetDeviceName(&info, NODE_DEVICE_NAME) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetDeviceTypeId(nullptr, &typeId) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetDeviceTypeId(&info, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetDeviceTypeId(&info, &typeId) == SOFTBUS_OK);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(INVALID_DEVICE_TYPE, &typeId) == SOFTBUS_ERR);
    EXPECT_TRUE(LnnConvertDeviceTypeToId(DEVICE_TYPE, &typeId) == SOFTBUS_OK);
    typeId = 0;
    LnnConvertIdToDeviceType(TYPE_WATCH_ID);
    LnnConvertIdToDeviceType(typeId);
    typeId = ONE_BIT_MAX_HEX << LEFT_SHIFT_DEVICE_TYPE_LENGTH;
    EXPECT_TRUE(LnnConvertIdToDeviceType(typeId) != nullptr);
}

/*
* @tc.name: LNN_HUKS_UTILS_Test_001
* @tc.desc: lnn huks utils function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_HUKS_UTILS_Test_001, TestSize.Level1)
{
    struct HksBlob keyAlias;
    (void)memset_s(&keyAlias, sizeof(HksBlob), 0, sizeof(HksBlob));
    EXPECT_TRUE(LnnGenerateKeyByHuks(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGenerateKeyByHuks(&keyAlias) == SOFTBUS_ERR);
    EXPECT_TRUE(LnnDeleteKeyByHuks(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnDeleteKeyByHuks(&keyAlias) == SOFTBUS_OK);
    EXPECT_TRUE(LnnEncryptDataByHuks(nullptr, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnDecryptDataByHuks(nullptr, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_NET_CAPABILITY_Test_001
* @tc.desc: lnn net capability function test
* @tc.type: FUNC
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
* @tc.name: LNN_NODE_INFO_Test_001
* @tc.desc: lnn node info function test
* @tc.type: FUNC
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
    LnnGetNetIfName(nullptr);
    LnnSetNetIfName(nullptr, nullptr);
    LnnGetWiFiIp(nullptr);
    LnnSetWiFiIp(nullptr, nullptr);
    EXPECT_TRUE(LnnGetMasterUdid(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetMasterUdid(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetAuthPort(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetAuthPort(nullptr, PORT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetSessionPort(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetSessionPort(nullptr, PORT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetProxyPort(nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetProxyPort(nullptr, PORT) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetP2pRole(nullptr, PORT) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pRole(nullptr) == 0);
    EXPECT_TRUE(LnnSetP2pMac(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pMac(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetP2pGoMac(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetWifiDirectAddr(nullptr) == nullptr);
    EXPECT_TRUE(LnnSetWifiDirectAddr(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetP2pGoMac(nullptr) == nullptr);
    EXPECT_TRUE(LnnGetSupportedProtocols(nullptr) == 0);
    EXPECT_TRUE(LnnSetSupportedProtocols(nullptr, PROTOCOLS) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetStaticCapability(nullptr, nullptr, 0) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnGetStaticCapability(nullptr, nullptr, 0) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnSetPtk(nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_NET_LEDGER_Test_001
* @tc.desc: lnn net ledger function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_001, TestSize.Level1)
{
    int32_t i;
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    uint8_t info[BUF_LEN] = {0};
    EXPECT_TRUE(LnnGetNodeKeyInfo(nullptr, 0, info, BUF_LEN) != SOFTBUS_OK);
    EXPECT_TRUE(LnnGetNodeKeyInfo(LOCAL_NETWORKID, 0, info, BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetNodeKeyInfo(LOCAL_NETWORKID, KEY_MAX_INDEX - 1, info, BUF_LEN) == SOFTBUS_OK);
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
* @tc.desc: lnn net ledger function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(nullptr, DATA_CHANGE_FLAG) != SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(LOCAL_NETWORKID, DATA_CHANGE_FLAG) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetNodeDataChangeFlag(REMOTE_NETWORKID, DATA_CHANGE_FLAG) == SOFTBUS_ERR);
    LnnDeinitNetLedger();
}

/*
* @tc.name: LNN_NET_LEDGER_Test_003
* @tc.desc: lnn net ledger function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_003, TestSize.Level1)
{
    static int32_t nodeKeyInfoLenTable[] = {
        UDID_BUF_LEN,
        UUID_BUF_LEN,
        UDID_BUF_LEN,
        MAC_LEN,
        IP_LEN,
        DEVICE_NAME_BUF_LEN,
        LNN_COMMON_LEN,
        LNN_COMMON_LEN,
        SOFTBUS_ERR,
        DATA_CHANGE_FLAG_BUF_LEN,
        SHORT_ADDRESS_MAX_LEN
    };
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    for (int32_t i = 0; i < KEY_MAX_INDEX; i++) {
        EXPECT_TRUE(LnnGetNodeKeyInfoLen(i) == nodeKeyInfoLenTable[i]);
    }
    LnnDeinitNetLedger();
}

/*
* @tc.name: LNN_NET_LEDGER_Test_004
* @tc.desc: lnn net ledger function test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LNN_NET_LEDGER_Test_004, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitNetLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_UUID, LOCAL_UUID) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_BT_MAC, LOCAL_BT_MAC) == SOFTBUS_OK);
    EXPECT_TRUE(LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, LOCAL_WLAN_IP) == SOFTBUS_OK);
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
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
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
        STRING_KEY_OFFLINE_CODE,
        STRING_KEY_WIFIDIRECT_ADDR
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
    LnnDeinitLocalLedger();
}

/*
* @tc.name: LOCAL_LEDGER_Test_002
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_002, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
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
    ret = LnnSetLocalStrInfo(STRING_KEY_WIFIDIRECT_ADDR, LOCAL_WIFIDIRECT_ADDR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: LOCAL_LEDGER_Test_003
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_003, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    static InfoKey getLocalNumInfoKeyTable[] = {
        NUM_KEY_SESSION_PORT,
        NUM_KEY_AUTH_PORT,
        NUM_KEY_PROXY_PORT,
        NUM_KEY_NET_CAP,
        NUM_KEY_DISCOVERY_TYPE,
        NUM_KEY_DEV_TYPE_ID,
        NUM_KEY_MASTER_NODE_WEIGHT,
        NUM_KEY_P2P_ROLE,
        NUM_KEY_STATIC_CAP_LEN
    };
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
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNNetLedgerCommonTest, LOCAL_LEDGER_Test_004, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
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
    ret = LnnSetLocalNumInfo(NUM_KEY_STATIC_CAP_LEN, STATIC_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: LOCAL_LEDGER_Test_005
* @tc.desc: lnn local key table test
* @tc.type: FUNC
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
} // namespace OHOS