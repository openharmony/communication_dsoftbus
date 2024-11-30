/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bus_center_adapter.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "client_bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_net_ledger.c"
#include "lnn_net_ledger.h"
#include "lnn_network_id.h"
#include "lnn_node_info.h"
#include "lnn_sync_item_info.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;
constexpr char NODE1_DEVICE_NAME[] = "node1_test";
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";
constexpr char NODE1_UUID[] = "235689BNHFCC";
constexpr char NODE1_BT_MAC[] = "56789TTU";
constexpr uint32_t NODE1_AUTH_SEQ_NUM = 100;
constexpr char NODE2_DEVICE_NAME[] = "node2_test";
constexpr char NODE2_UDID[] = "123456ABCDEG";
constexpr char NODE2_NETWORK_ID[] = "235689BNHFCG";
constexpr char NODE2_UUID[] = "235689BNHFCD";
constexpr char NODE2_BT_MAC[] = "56789TYU";
constexpr char CHANGE_DEVICE_NAME[] = "change_test";
constexpr char NODE5_NETWORK_ID[] = "235689BNHFCZ";
constexpr uint32_t REMOTE_PROXY_PORT = 8080;
constexpr uint32_t REMOTE_AUTH_PORT = 7070;
constexpr uint32_t REMOTE_SESSION_PORT = 6060;
constexpr uint32_t NODE_NUM = 4;
constexpr char LOCAL_UDID[] = "123456LOCALTEST";
constexpr char LOCAL_NETWORKID[] = "235689LOCAL";
constexpr char LOCAL_UUID[] = "235999LOCAL";
constexpr char LOCAL_DEVNAME[] = "local_test";
constexpr char LOCAL_CHANAGE_DEVNAME[] = "local";
constexpr char LOCAL_BT_MAC[] = "56789TUT";
constexpr char LOCAL_WLAN_IP[] = "10.146.181.134";
constexpr char LOCAL_DEVTYPE[] = TYPE_WATCH;
constexpr uint32_t LOCAL_SESSION_PORT = 5000;
constexpr uint32_t LOCAL_AUTH_PORT = 6000;
constexpr uint32_t LOCAL_PROXY_PORT = 7000;
constexpr uint32_t BR_NUM = 0;
constexpr uint32_t WLAN2P4G_NUM = 1;
static NodeInfo g_nodeInfo[NODE_NUM];
constexpr uint32_t LOCAL_MAX_SIZE = 128;

class LedgerLaneHubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LedgerLaneHubTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LaneHubTest start.";
}

void LedgerLaneHubTest::TearDownTestCase()
{
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LooperDeinit();
    GTEST_LOG_(INFO) << "LaneHubTest end.";
}

void LedgerLaneHubTest::SetUp() { }

void LedgerLaneHubTest::TearDown() { }

static void ConstructBRNode(void)
{
    int32_t ret;
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_BR);
    g_nodeInfo[BR_NUM].netCapacity = cap;
    ret = LnnSetDeviceUdid(&g_nodeInfo[BR_NUM], NODE1_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetBtMac(&g_nodeInfo[BR_NUM], NODE1_BT_MAC);
    ret = LnnSetDeviceName(&g_nodeInfo[BR_NUM].deviceInfo, NODE1_DEVICE_NAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = strncpy_s(g_nodeInfo[BR_NUM].networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    ret = strncpy_s(g_nodeInfo[BR_NUM].uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
    EXPECT_TRUE(ret == EOK);
    g_nodeInfo[BR_NUM].authSeqNum = NODE1_AUTH_SEQ_NUM;
    ret = LnnSetDiscoveryType(&g_nodeInfo[BR_NUM], DISCOVERY_TYPE_BR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void ConstructWlan2P4GNode(void)
{
    int32_t ret;
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_WIFI_24G);
    g_nodeInfo[WLAN2P4G_NUM].netCapacity = cap;
    ret = LnnSetDeviceUdid(&g_nodeInfo[WLAN2P4G_NUM], NODE2_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetBtMac(&g_nodeInfo[WLAN2P4G_NUM], NODE2_BT_MAC);
    ret = LnnSetDeviceName(&g_nodeInfo[WLAN2P4G_NUM].deviceInfo, NODE2_DEVICE_NAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = strncpy_s(g_nodeInfo[WLAN2P4G_NUM].networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID, strlen(NODE2_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    ret = strncpy_s(g_nodeInfo[WLAN2P4G_NUM].uuid, UUID_BUF_LEN, NODE2_UUID, strlen(NODE2_UUID));
    EXPECT_TRUE(ret == EOK);
    g_nodeInfo[WLAN2P4G_NUM].authSeqNum = NODE1_AUTH_SEQ_NUM;
    ret = LnnSetDiscoveryType(&g_nodeInfo[WLAN2P4G_NUM], DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetProxyPort(&g_nodeInfo[WLAN2P4G_NUM], REMOTE_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetSessionPort(&g_nodeInfo[WLAN2P4G_NUM], REMOTE_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetWiFiIp(&g_nodeInfo[WLAN2P4G_NUM], LOCAL_WLAN_IP);
    ret = LnnSetAuthPort(&g_nodeInfo[WLAN2P4G_NUM], REMOTE_AUTH_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void ConstructCommonLocalInfo(void)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, LOCAL_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_NETWORKID, LOCAL_NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_UUID, LOCAL_UUID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_TYPE, LOCAL_DEVTYPE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, LOCAL_DEVNAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void ConstructBtLocalInfo(void)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_BT_MAC, LOCAL_BT_MAC);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, 1 << BIT_BR);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void ConstructWiFiLocalInfo(bool is5G)
{
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, LOCAL_AUTH_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, LOCAL_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, LOCAL_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    if (is5G) {
        ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, 1 << BIT_WIFI_5G);
    } else {
        ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, 1 << BIT_WIFI_24G);
    }
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, LOCAL_WLAN_IP);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void GetCommonLocalInfo(void)
{
    int32_t ret;
    char des[LOCAL_MAX_SIZE] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_UDID) == 0));
    ret = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_NETWORKID) == 0));
    ret = LnnGetLocalStrInfo(STRING_KEY_UUID, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_UUID) == 0));
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_DEVTYPE) == 0));
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_DEVNAME) == 0));
}

static void GetBTLocalInfo(void)
{
    int32_t ret;
    char des[LOCAL_MAX_SIZE] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_BT_MAC, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_BT_MAC) == 0));
}

static void GetWiFiLocalInfo(void)
{
    int32_t ret;
    int32_t port = 0;
    ret = LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &port);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (port == LOCAL_AUTH_PORT));
    ret = LnnGetLocalNumInfo(NUM_KEY_PROXY_PORT, &port);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (port == LOCAL_PROXY_PORT));
    ret = LnnGetLocalNumInfo(NUM_KEY_SESSION_PORT, &port);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (port == LOCAL_SESSION_PORT));
}

/*
 * @tc.name: SOFTBUS_DUMP_PRINT_NET_CAPACITY_Test_001
 * @tc.desc: SoftbusDumpPrintNetCapacity test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LedgerLaneHubTest, SOFTBUS_DUMP_PRINT_NET_CAPACITY_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    NodeBasicInfo nodeInfo;

    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    (void)strncpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, NODE5_NETWORK_ID, strlen(NODE5_NETWORK_ID));
    EXPECT_NE(SoftbusDumpPrintNetCapacity(fd, &nodeInfo), SOFTBUS_OK);

    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    (void)strncpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, LOCAL_NETWORKID, strlen(LOCAL_NETWORKID));
    EXPECT_EQ(SoftbusDumpPrintNetCapacity(fd, &nodeInfo), SOFTBUS_OK);
}

/*
 * @tc.name: SOFTBUS_DUMP_PRINT_NET_TYPE_Test_001
 * @tc.desc: SoftbusDumpPrintNetType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LedgerLaneHubTest, SOFTBUS_DUMP_PRINT_NET_TYPE_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    NodeBasicInfo nodeInfo;

    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    (void)strncpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, NODE5_NETWORK_ID, strlen(NODE5_NETWORK_ID));
    EXPECT_NE(SoftbusDumpPrintNetType(fd, &nodeInfo), SOFTBUS_OK);

    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    (void)memset_s(&nodeInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    (void)strncpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, LOCAL_NETWORKID, strlen(LOCAL_NETWORKID));
    EXPECT_EQ(SoftbusDumpPrintNetType(fd, &nodeInfo), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_NODE_DATA_CHANGE_FLAG_Test_001
 * @tc.desc: Lnn Set Node Data Change Flag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LedgerLaneHubTest, LNN_SET_NODE_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
{
    char *networkId = nullptr;
    char networkIdSecond[NETWORK_ID_BUF_LEN] = "1234";
    uint16_t dataChangeFlag = 0;
    EXPECT_NE(LnnSetNodeDataChangeFlag(networkId, dataChangeFlag), SOFTBUS_OK);
    EXPECT_EQ(LnnSetNodeDataChangeFlag(networkIdSecond, dataChangeFlag), SOFTBUS_NETWORK_INVALID_DEV_INFO);

    ConstructCommonLocalInfo();
    EXPECT_EQ(LnnSetNodeDataChangeFlag(LOCAL_NETWORKID, dataChangeFlag), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DATA_CHANGE_FLAG_Test_001
 * @tc.desc: Lnn Set Data Change Flag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LedgerLaneHubTest, LNN_SET_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
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
HWTEST_F(LedgerLaneHubTest, LNN_GET_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
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
HWTEST_F(LedgerLaneHubTest, LNN_GET_LOCAL_STR_INFO_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    char *nodeInfo = reinterpret_cast<char *>(&info);
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
HWTEST_F(LedgerLaneHubTest, LNN_INIT_LOCAL_LEDGER_DELAY_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_OK);
}

/*
 * @tc.name: LEDGER_GetDistributedLedgerNode_Test_001
 * @tc.desc: Get distributed ledger node info.
 * @tc.type: FUNC
 * @tc.require: AR000FK6J0
 */
HWTEST_F(LedgerLaneHubTest, LEDGER_GetDistributedLedgerNode_Test_001, TestSize.Level1)
{
    ConstructBRNode();
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);
    LnnRemoveNode(NODE1_UDID);
    LnnRemoveNode(NODE2_UDID);
}

/*
 * @tc.name: LEDGER_GetDistributedLedgerInfo_Test_001
 * @tc.desc:  test of the LnnGetRemoteStrInfo LnnGetDLNumInfo function
 * @tc.type: FUNC
 * @tc.require: AR000FK6J0
 */
HWTEST_F(LedgerLaneHubTest, LEDGER_GetDistributedLedgerInfo_Test_001, TestSize.Level1)
{
    char deviceName[DEVICE_NAME_BUF_LEN] = { 0 };
    char macAddr[MAC_LEN] = { 0 };
    int32_t ret;
    uint32_t cap = 0;
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);

    // STRING_KEY_DEV_NAME
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_DEV_NAME, deviceName, DEVICE_NAME_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_TRUE(strcmp(deviceName, NODE1_DEVICE_NAME) == 0);

    // STRING_KEY_BT_MAC
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_BT_MAC, macAddr, MAC_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_TRUE(strcmp(macAddr, NODE1_BT_MAC) == 0);

    // NUM_KEY_NET_CAP
    ret = LnnGetRemoteNumU32Info(NODE1_NETWORK_ID, NUM_KEY_NET_CAP, &cap);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_TRUE((cap & (1 << BIT_BR)) != 0);

    LnnRemoveNode(NODE1_UDID);
}

/*
 * @tc.name: LEDGER_DistributedLedgerChangeName_Test_001
 * @tc.desc:  test of the LnnGetRemoteStrInfo LnnSetDLDeviceInfoName function
 * @tc.type: FUNC
 * @tc.require: AR000FK6J0
 */
HWTEST_F(LedgerLaneHubTest, LEDGER_DistributedLedgerChangeName_Test_001, TestSize.Level1)
{
    char deviceName[DEVICE_NAME_BUF_LEN] = { 0 };
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);

    // change name
    bool result = LnnSetDLDeviceInfoName(NODE2_UDID, CHANGE_DEVICE_NAME);
    EXPECT_TRUE(result);
    // STRING_KEY_DEV_NAME
    int32_t ret = LnnGetRemoteStrInfo(NODE2_NETWORK_ID, STRING_KEY_DEV_NAME, deviceName, DEVICE_NAME_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_TRUE(strcmp(deviceName, CHANGE_DEVICE_NAME) == 0);
    LnnRemoveNode(NODE2_UDID);
}

/*
 * @tc.name: LEDGER_LocalLedgerGetInfo_Test_001
 * @tc.desc: Performance test of the LnnGetLocalLedgerStrInfo and NumInfo function.
 * @tc.type: FUNC
 * @tc.require: AR000FK6J0
 */
HWTEST_F(LedgerLaneHubTest, LEDGER_LocalLedgerGetInfo_Test_001, TestSize.Level1)
{
    char des[LOCAL_MAX_SIZE] = { 0 };
    int32_t ret;
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();
    ConstructWiFiLocalInfo(false);
    GetCommonLocalInfo();
    GetBTLocalInfo();
    GetWiFiLocalInfo();

    // change devicename
    ret = LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, LOCAL_CHANAGE_DEVNAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, des, LOCAL_MAX_SIZE);
    EXPECT_TRUE((ret == SOFTBUS_OK) && (strcmp(des, LOCAL_CHANAGE_DEVNAME) == 0));
}
} // namespace OHOS
