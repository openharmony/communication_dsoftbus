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

#include "bus_center_info_key.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_info.h"
#include "lnn_lane_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_sync_item_info.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
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
constexpr char NODE3_DEVICE_NAME[] = "node3_test";
constexpr char NODE3_UDID[] = "123456ABCDEX";
constexpr char NODE3_NETWORK_ID[] = "235689BNHFCX";
constexpr char NODE3_UUID[] = "235689BNHFCX";
constexpr char NODE3_BT_MAC[] = "56789TYX";
constexpr char NODE4_DEVICE_NAME[] = "node4_test";
constexpr char NODE4_UDID[] = "123456ABCDEY";
constexpr char NODE4_NETWORK_ID[] = "235689BNHFCY";
constexpr char NODE4_UUID[] = "235689BNHFCY";
constexpr char NODE4_BT_MAC[] = "56789TTY";
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
constexpr uint32_t WLAN5G_NUM = 2;
constexpr uint32_t LANES_NUM = 1;
static NodeInfo g_nodeInfo[NODE_NUM];
constexpr uint32_t LANE_HUB_USEC = 1000000;
constexpr uint32_t LANE_HUB_MSEC = 1000;
constexpr uint32_t LOCAL_MAX_SIZE = 128;
constexpr uint32_t ALL_CAPACITY = 3;
constexpr int32_t LANES_COUNT_MAX = 100;
constexpr int32_t DEFAULT_PID = 0;

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
    (void)LnnInitLaneManager();
    GTEST_LOG_(INFO) << "LaneHubTest start.";
}

void LedgerLaneHubTest::TearDownTestCase()
{
    LnnDeinitLocalLedger();
    LnnDeinitDistributedLedger();
    LooperDeinit();
    GTEST_LOG_(INFO) << "LaneHubTest end.";
}

void LedgerLaneHubTest::SetUp()
{
}

void LedgerLaneHubTest::TearDown()
{
}

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

static void ConstructWlan5GNode(void)
{
    int32_t ret;
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_WIFI_5G);
    g_nodeInfo[WLAN5G_NUM].netCapacity = cap;
    ret = LnnSetDeviceUdid(&g_nodeInfo[WLAN5G_NUM], NODE3_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetBtMac(&g_nodeInfo[WLAN5G_NUM], NODE3_BT_MAC);
    ret = LnnSetDeviceName(&g_nodeInfo[WLAN5G_NUM].deviceInfo, NODE3_DEVICE_NAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = strncpy_s(g_nodeInfo[WLAN5G_NUM].networkId, NETWORK_ID_BUF_LEN, NODE3_NETWORK_ID, strlen(NODE3_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    ret = strncpy_s(g_nodeInfo[WLAN5G_NUM].uuid, UUID_BUF_LEN, NODE3_UUID, strlen(NODE3_UUID));
    EXPECT_TRUE(ret == EOK);
    g_nodeInfo[WLAN5G_NUM].authSeqNum = NODE1_AUTH_SEQ_NUM;
    ret = LnnSetDiscoveryType(&g_nodeInfo[WLAN5G_NUM], DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetProxyPort(&g_nodeInfo[WLAN5G_NUM], REMOTE_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetSessionPort(&g_nodeInfo[WLAN5G_NUM], REMOTE_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetWiFiIp(&g_nodeInfo[WLAN5G_NUM], LOCAL_WLAN_IP);
    ret = LnnSetAuthPort(&g_nodeInfo[WLAN5G_NUM], REMOTE_AUTH_PORT);
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
    char des[LOCAL_MAX_SIZE] = {0};
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
    char des[LOCAL_MAX_SIZE] = {0};
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

static void ConstructALLCapacityNode(void)
{
    int32_t ret;
    uint32_t cap = 0;
    LnnSetNetCapability(&cap, BIT_WIFI_5G);
    LnnSetNetCapability(&cap, BIT_WIFI_24G);
    LnnSetNetCapability(&cap, BIT_BR);
    g_nodeInfo[ALL_CAPACITY].netCapacity = cap;
    ret = LnnSetDeviceUdid(&g_nodeInfo[ALL_CAPACITY], NODE4_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetBtMac(&g_nodeInfo[ALL_CAPACITY], NODE4_BT_MAC);
    ret = LnnSetDeviceName(&g_nodeInfo[ALL_CAPACITY].deviceInfo, NODE4_DEVICE_NAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = strncpy_s(g_nodeInfo[ALL_CAPACITY].networkId, NETWORK_ID_BUF_LEN, NODE4_NETWORK_ID, strlen(NODE4_NETWORK_ID));
    EXPECT_TRUE(ret == EOK);
    ret = strncpy_s(g_nodeInfo[ALL_CAPACITY].uuid, UUID_BUF_LEN, NODE4_UUID, strlen(NODE4_UUID));
    EXPECT_TRUE(ret == EOK);
    g_nodeInfo[ALL_CAPACITY].authSeqNum = NODE1_AUTH_SEQ_NUM;
    ret = LnnSetDiscoveryType(&g_nodeInfo[ALL_CAPACITY], DISCOVERY_TYPE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetProxyPort(&g_nodeInfo[ALL_CAPACITY], REMOTE_PROXY_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetSessionPort(&g_nodeInfo[ALL_CAPACITY], REMOTE_SESSION_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSetWiFiIp(&g_nodeInfo[ALL_CAPACITY], LOCAL_WLAN_IP);
    ret = LnnSetAuthPort(&g_nodeInfo[ALL_CAPACITY], REMOTE_AUTH_PORT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void ConstructAllCapacityLocalInfo()
{
    ConstructWiFiLocalInfo(false);
    ConstructBtLocalInfo();
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (1 << BIT_BR) | (1 << BIT_WIFI_24G) | (1 << BIT_WIFI_5G));
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_HUB_WLAN2P4G_MESSAGE_LANE_Test_001
* @tc.desc: Wlan2P4G message lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN2P4G_MESSAGE_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(false);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE2_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_2P4G && laneInfo);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN2P4G_BYTES_LANE_Test_001
* @tc.desc: Wlan2P4G bytes lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN2P4G_BYTES_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(false);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE2_NETWORK_ID, DEFAULT_PID,
        LNN_BYTES_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_2P4G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_SESSION_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN2P4G_FILE_LANE_Test_001
* @tc.desc: Wlan2P4G file lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN2P4G_FILE_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(false);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE2_NETWORK_ID, DEFAULT_PID,
        LNN_FILE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_2P4G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_AUTH_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN2P4G_STREAM_LANE_Test_001
* @tc.desc: Wlan2P4G stream lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN2P4G_STREAM_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(false);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE2_NETWORK_ID, DEFAULT_PID,
        LNN_STREAM_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_2P4G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_AUTH_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN5G_MESSAGE_LANE_Test_001
* @tc.desc: Wlan5G message lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN5G_MESSAGE_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan5GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN5G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE3_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G && laneInfo != nullptr);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN5G_BYTES_LANE_Test_001
* @tc.desc: Wlan5G bytes lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN5G_BYTES_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan5GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN5G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE3_NETWORK_ID, DEFAULT_PID,
        LNN_BYTES_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_SESSION_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN5G_FILE_LANE_Test_001
* @tc.desc: Wlan2P4G file lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN5G_FILE_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN5G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE3_NETWORK_ID, DEFAULT_PID,
        LNN_FILE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_AUTH_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_WLAN5G_STREAM_LANE_Test_001
* @tc.desc: Wlan5G stream lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_WLAN5G_STREAM_LANE_Test_001, TestSize.Level1)
{
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN5G_NUM]);
    ConstructCommonLocalInfo();
    ConstructWiFiLocalInfo(true);

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE3_NETWORK_ID, DEFAULT_PID,
        LNN_STREAM_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G && laneInfo != nullptr && laneInfo->isProxy == false &&
        laneInfo->conOption.type == CONNECTION_ADDR_WLAN &&
        strncmp(laneInfo->conOption.info.ip.ip, LOCAL_WLAN_IP, strlen(LOCAL_WLAN_IP)) == 0 &&
        laneInfo->conOption.info.ip.port == REMOTE_AUTH_PORT);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_BR_MESSAGE_LANE_Test_001
* @tc.desc: BR message lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_BR_MESSAGE_LANE_Test_001, TestSize.Level1)
{
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE1_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_BR && laneInfo != nullptr && laneInfo->isProxy &&
        laneInfo->conOption.type == CONNECTION_ADDR_BR &&
        strncmp(laneInfo->conOption.info.br.brMac, NODE1_BT_MAC, strlen(NODE1_BT_MAC)) == 0);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_BR_BYTES_LANE_Test_001
* @tc.desc: BR bytes lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_BR_BYTES_LANE_Test_001, TestSize.Level1)
{
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE1_NETWORK_ID, DEFAULT_PID,
        LNN_BYTES_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_BR && laneInfo != nullptr && laneInfo->isProxy &&
        laneInfo->conOption.type == CONNECTION_ADDR_BR &&
        strncmp(laneInfo->conOption.info.br.brMac, NODE1_BT_MAC, strlen(NODE1_BT_MAC)) == 0);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_BR_FILE_LANE_Test_001
* @tc.desc: BR file lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_BR_FILE_LANE_Test_001, TestSize.Level1)
{
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE1_NETWORK_ID,
        DEFAULT_PID, LNN_FILE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    const LnnLaneInfo *laneInfo = LnnGetLaneInfo(laneId);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_BR && laneInfo != nullptr && laneInfo->isProxy &&
        laneInfo->conOption.type == CONNECTION_ADDR_BR &&
        strncmp(laneInfo->conOption.info.br.brMac, NODE1_BT_MAC, strlen(NODE1_BT_MAC)) == 0);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_BR_STREAM_LANE_Test_001
* @tc.desc: BR stream lane test
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_BR_STREAM_LANE_Test_001, TestSize.Level1)
{
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();

    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE1_NETWORK_ID, DEFAULT_PID,
        LNN_STREAM_LANE, nullptr, LANES_NUM);
    EXPECT_TRUE(lanesObj == nullptr);
    LnnReleaseLanesObject(lanesObj);
}

/*
* @tc.name: LANE_HUB_LnnRequestLanesObject_Test_001
* @tc.desc: Performance test of the LnnRequestLanesObject function
* @tc.type: FUNC
* @tc.require: AR000FK6IU
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_LnnRequestLanesObject_Test_001, TestSize.Level1)
{
    struct timeval start;
    struct timeval end;
    ConstructBRNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    ConstructCommonLocalInfo();
    ConstructBtLocalInfo();

    int testCount = 1000;
    int times = 0;
    gettimeofday(&start, nullptr);
    while (testCount--) {
        LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE1_NETWORK_ID, DEFAULT_PID,
            LNN_FILE_LANE, nullptr, LANES_NUM);
        EXPECT_TRUE(lanesObj != nullptr);
        LnnReleaseLanesObject(lanesObj);
        times++;
    }
    gettimeofday(&end, nullptr);

    int interval = LANE_HUB_USEC * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    int threshold = LANE_HUB_MSEC * times;
    EXPECT_LT(interval, threshold);
}

/*
* @tc.name: LEDGER_GetDistributedLedgerNode_Test_001
* @tc.desc: Get distributed ledger node info.
* @tc.type: FUNC
* @tc.require: AR000FK6J0
*/
HWTEST_F(LedgerLaneHubTest, LEDGER_GetDistributedLedgerNode_Test_001, TestSize.Level1)
{
    NodeInfo *infoNetwork = nullptr;
    NodeInfo *infoUuid = nullptr;
    NodeInfo *infoUdid = nullptr;
    ConstructBRNode();
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[BR_NUM]);
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);

    // GET CATEGORY_NETWORK_ID and CATEGORY_UUID
    infoNetwork = LnnGetNodeInfoById(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID);
    infoUuid = LnnGetNodeInfoById(NODE1_UUID, CATEGORY_UUID);
    infoUdid = LnnGetNodeInfoById(NODE1_UDID, CATEGORY_UDID);
    EXPECT_TRUE((infoNetwork == infoUuid) && (infoNetwork == infoUdid));
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
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    char macAddr[MAC_LEN] = {0};
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
    ret = LnnGetRemoteNumInfo(NODE1_NETWORK_ID, NUM_KEY_NET_CAP, (int32_t *)&cap);
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
    char deviceName[DEVICE_NAME_BUF_LEN] = {0};
    ConstructWlan2P4GNode();
    LnnAddOnlineNode(&g_nodeInfo[WLAN2P4G_NUM]);

    // change name
    bool result = LnnSetDLDeviceInfoName(NODE2_UDID, CHANGE_DEVICE_NAME);
    EXPECT_TRUE(result);
    // STRING_KEY_DEV_NAME
    int ret = LnnGetRemoteStrInfo(NODE2_NETWORK_ID, STRING_KEY_DEV_NAME, deviceName, DEVICE_NAME_BUF_LEN);
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
    char des[LOCAL_MAX_SIZE] = {0};
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

/*
* @tc.name: LANE_HUB_PRELINK_LANE_Test_001
* @tc.desc: PreLink lane test
* @tc.type: FUNC
* @tc.require: AR000FN5VC
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_PRELINK_LANE_Test_001, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj1, 0);
    LnnSetLaneCount(laneId, 3); // LaneCount add 3
    EXPECT_TRUE(LnnGetLaneScore(laneId) == THRESHOLD_LANE_QUALITY_SCORE);
    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    LnnSetLaneCount(laneId, -3); // LaneCount subtract 3
    EXPECT_TRUE(LnnGetLaneCount(laneId) == 0);
}

/*
* @tc.name: LANE_HUB_PRELINK_LANE_Test_002
* @tc.desc: PreLink lane test
* @tc.type: FUNC
* @tc.require: AR000FN5VD
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_PRELINK_LANE_Test_002, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId1 = LnnGetLaneId(lanesObj1, 0);
    LnnSetLaneCount(laneId1, LANE_COUNT_THRESHOLD);
    EXPECT_TRUE(LnnGetLaneScore(laneId1) == THRESHOLD_LANE_QUALITY_SCORE);
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId2 = LnnGetLaneId(lanesObj2, 0);
    EXPECT_TRUE(laneId2 == LNN_LINK_TYPE_WLAN_5G);
    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    LnnSetLaneCount(laneId1, -LANES_COUNT_MAX);
    LnnSetLaneCount(laneId2, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(laneId1) == 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId2) == 0);
}

/*
* @tc.name: LANE_HUB_SCHEDULE_LANE_Test_001
* @tc.desc: Schedule lane test
* @tc.type: FUNC
* @tc.require: AR000FN5V9
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_SCHEDULE_LANE_Test_001, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId1 = LnnGetLaneId(lanesObj1, 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId1) == 1); // lane used 1 times
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId2 = LnnGetLaneId(lanesObj2, 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId1) == 2); // lane used 2 times
    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    EXPECT_TRUE(LnnGetLaneCount(laneId1) == 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId2) == 0);
}

static void ScheduleNotify5G(int32_t laneId, int32_t score)
{
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G && score == THRESHOLD_LANE_QUALITY_SCORE);
    printf("ScheduleNotify5G laneId %d, socre %d.\n", laneId, score);
}

/*
* @tc.name: LANE_HUB_SCHEDULE_LANE_Test_002
* @tc.desc: Schedule lane test
* @tc.type: FUNC
* @tc.require: AR000FN5VA
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_SCHEDULE_LANE_Test_002, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId1 = LnnGetLaneId(lanesObj1, 0);
    (void)LnnLaneQosObserverAttach(lanesObj1, ScheduleNotify5G);
    (void)LnnSetLaneCount(laneId1, LANE_COUNT_THRESHOLD);
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId2 = LnnGetLaneId(lanesObj2, 0);
    (void)LnnLaneQosObserverAttach(lanesObj2, ScheduleNotify5G);
    (void)LnnSetLaneCount(laneId2, LANE_COUNT_THRESHOLD);
    TriggerLaneMonitor();
    LnnLanesObject *lanesObj3 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId3 = LnnGetLaneId(lanesObj3, 0);
    EXPECT_TRUE(laneId3 == LNN_LINK_TYPE_WLAN_5G);

    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    LnnReleaseLanesObject(lanesObj3);
    LnnLaneQosObserverDetach(lanesObj1);
    LnnLaneQosObserverDetach(lanesObj2);
    LnnSetLaneCount(laneId1, -LANES_COUNT_MAX);
    LnnSetLaneCount(laneId2, -LANES_COUNT_MAX);
    LnnSetLaneCount(laneId3, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(laneId1) == 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId2) == 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId3) == 0);
}

/*
* @tc.name: LANE_HUB_MANAGER_LANE_Test_001
* @tc.desc: Manager lane test
* @tc.type: FUNC
* @tc.require: AR000FN5UO
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_MANAGER_LANE_Test_001, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj3 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj4 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj5 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj1, 0);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G);
    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    LnnReleaseLanesObject(lanesObj3);
    LnnReleaseLanesObject(lanesObj4);
    LnnReleaseLanesObject(lanesObj5);
    LnnSetLaneCount(laneId, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(laneId) == 0);
}

/*
* @tc.name: LANE_HUB_MANAGER_LANE_Test_002
* @tc.desc: Manager lane test
* @tc.type: FUNC
* @tc.require: AR000FN5UP
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_MANAGER_LANE_Test_002, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    LnnLanesObject *lanesObj1 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    LnnLanesObject *lanesObj2 = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj1, 0);
    EXPECT_TRUE(LnnGetLaneCount(laneId) == 2); // Lane used 2 times
    LnnReleaseLanesObject(lanesObj1);
    LnnReleaseLanesObject(lanesObj2);
    LnnSetLaneCount(laneId, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(laneId) == 0);
}

/*
* @tc.name: LANE_HUB_ANALYSE_LANE_Test_001
* @tc.desc: Analyse lane test
* @tc.type: FUNC
* @tc.require: AR000FNSVE
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_ANALYSE_LANE_Test_001, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    (void)LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, LANE_COUNT_THRESHOLD);
    LnnLanesObject *lanesObj = LnnRequestLanesObject(NODE4_NETWORK_ID, DEFAULT_PID,
        LNN_MESSAGE_LANE, nullptr, LANES_NUM);
    int32_t laneId = LnnGetLaneId(lanesObj, 0);
    EXPECT_TRUE(laneId == LNN_LINK_TYPE_WLAN_5G);
    LnnReleaseLanesObject(lanesObj);
    LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, -LANES_COUNT_MAX);
    LnnSetLaneCount(laneId, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(laneId) == 0);
}

/*
* @tc.name: LANE_HUB_ANALYSE_LANE_Test_002
* @tc.desc: Analyse lane test
* @tc.type: FUNC
* @tc.require: AR000FNSVG
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_ANALYSE_LANE_Test_002, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    (void)LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, LANE_COUNT_THRESHOLD);
    int32_t socre = LnnGetLaneScore(LNN_LINK_TYPE_WLAN_5G);
    EXPECT_TRUE(socre == THRESHOLD_LANE_QUALITY_SCORE);
    LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(LNN_LINK_TYPE_WLAN_5G) == 0);
}

/*
* @tc.name: LANE_HUB_ANALYSE_LANE_Test_003
* @tc.desc: Analyse lane test
* @tc.type: FUNC
* @tc.require: AR000FNSVF
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_ANALYSE_LANE_Test_003, TestSize.Level1)
{
    LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, LANE_COUNT_THRESHOLD);
    EXPECT_TRUE(LnnGetLaneCount(LNN_LINK_TYPE_WLAN_5G) == LANE_COUNT_THRESHOLD);
    LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(LNN_LINK_TYPE_WLAN_5G) == 0);
}

/*
* @tc.name: LANE_HUB_LOCALINFO_LANE_Test_001
* @tc.desc: local info lane test
* @tc.type: FUNC
* @tc.require: AR000FNSVF
*/
HWTEST_F(LedgerLaneHubTest, LANE_HUB_LOCALINFO_LANE_Test_001, TestSize.Level1)
{
    ConstructALLCapacityNode();
    LnnAddOnlineNode(&g_nodeInfo[ALL_CAPACITY]);
    ConstructCommonLocalInfo();
    ConstructAllCapacityLocalInfo();

    (void)LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, LANE_COUNT_THRESHOLD);
    int32_t socre = LnnGetLaneScore(LNN_LINK_TYPE_WLAN_5G);
    EXPECT_TRUE(socre == THRESHOLD_LANE_QUALITY_SCORE);
    (void)LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, -1); // LaneCount subtract 1
    socre = LnnGetLaneScore(LNN_LINK_TYPE_WLAN_5G);
    EXPECT_TRUE(socre == PASSING_LANE_QUALITY_SCORE);
    LnnSetLaneCount(LNN_LINK_TYPE_WLAN_5G, -LANES_COUNT_MAX);
    EXPECT_TRUE(LnnGetLaneCount(LNN_LINK_TYPE_WLAN_5G) == 0);
}
} // namespace OHOS
