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

#include "bus_center_manager.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.c"
#include "lnn_distributed_net_ledger.h"
#include "lnn_distributed_net_ledger_manager.c"
#include "lnn_fast_offline.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include <cstring>

namespace OHOS {
using namespace testing::ext;
constexpr char NODE1_DEVICE_NAME[] = "node1_test";
constexpr char NODE1_UDID[] = "123456ABCDEF";
constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";
constexpr char NODE1_UUID[] = "235689BNHFCC";
constexpr char NODE1_BT_MAC[] = "56789TTU";
constexpr char NODE2_DEVICE_NAME[] = "node2_test";
constexpr char NODE2_UDID[] = "123456ABCDEG";
constexpr char NODE2_NETWORK_ID[] = "235689BNHFCG";
constexpr char NODE2_UUID[] = "235689BNHFCD";
constexpr char NODE2_BT_MAC[] = "56789TYU";
constexpr char P2P_MAC[] = "11:22:33:44:55";
constexpr char GO_MAC[] = "22:33:44:55:66";
constexpr int32_t P2P_ROLE = 1;
constexpr uint32_t DISCOVERY_TYPE = 62;
constexpr int32_t AUTH_ID = 10;
constexpr uint64_t TIME_STAMP = 5000;
constexpr uint64_t CAPABILITY = 62;
constexpr uint64_t NEW_TIME_STAMP = 6000;
constexpr int64_t AUTH_SEQ = 1;
constexpr char NODE_ADDRESS[] = "address";
constexpr char RECV_UDID_HASH[] = "87654321";
using namespace testing;
class LNNDisctributedLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TestFunc(NodeBasicInfo *info)
{
    (void)info;
    return;
}

void LNNDisctributedLedgerTest::SetUpTestCase() { }

void LNNDisctributedLedgerTest::TearDownTestCase() { }

void LNNDisctributedLedgerTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LocalLedgerTest start");
    int32_t ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
    (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC, strlen(NODE1_BT_MAC));
    info.authSeq[0] = AUTH_SEQ;
    info.heartbeatTimestamp = TIME_STAMP;
    EXPECT_TRUE(REPORT_ONLINE == LnnAddOnlineNode(&info));
}

void LNNDisctributedLedgerTest::TearDown()
{
    LNN_LOGI(LNN_TEST, "LocalLedgerTest end");
    LnnDeinitDistributedLedger();
}

/*
 * @tc.name: LNN_ADD_ONLINE_NODE_Test_001
 * @tc.desc: lnn add online node test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_ADD_ONLINE_NODE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
    (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC, strlen(NODE1_BT_MAC));
    EXPECT_TRUE(REPORT_NONE == LnnAddOnlineNode(&info));
}

/*
 * @tc.name: LNN_GET_REMOTE_STRINFO_Test_001
 * @tc.desc: lnn get remote strInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_STRINFO_Test_001, TestSize.Level1)
{
    static InfoKey keyStringTable[] = { STRING_KEY_HICE_VERSION, STRING_KEY_DEV_UDID, STRING_KEY_UUID,
        STRING_KEY_DEV_TYPE, STRING_KEY_DEV_NAME, STRING_KEY_BT_MAC, STRING_KEY_WLAN_IP, STRING_KEY_MASTER_NODE_UDID,
        STRING_KEY_P2P_MAC, STRING_KEY_P2P_GO_MAC, STRING_KEY_NODE_ADDR, STRING_KEY_OFFLINE_CODE,
        STRING_KEY_WIFIDIRECT_ADDR };
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_HICE_VERSION, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_HICE_VERSION, nullptr, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, NUM_KEY_BEGIN, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uint32_t i;
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteStrInfo(NODE2_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMNFO_Test_002
 * @tc.desc: lnn get remote num info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_NUMNFO_Test_002, TestSize.Level1)
{
    static InfoKey keyNumTable[] = { NUM_KEY_META_NODE, NUM_KEY_SESSION_PORT, NUM_KEY_AUTH_PORT, NUM_KEY_PROXY_PORT,
        NUM_KEY_NET_CAP, NUM_KEY_DISCOVERY_TYPE, NUM_KEY_MASTER_NODE_WEIGHT, NUM_KEY_P2P_ROLE };
    int32_t ret;
    uint32_t i;
    int32_t len = LNN_COMMON_LEN;
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE1_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE2_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_TRUE(ret != SOFTBUS_OK);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTEINFO_Test_003
 * @tc.desc: lnn get remote byte info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_BYTEINFO_Test_003, TestSize.Level1)
{
    unsigned char irk[LFINDER_IRK_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_IRK, irk, LFINDER_IRK_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_IRK, nullptr, LFINDER_IRK_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_IRK, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char pubMac[LFINDER_MAC_ADDR_LEN] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_PUB_MAC, pubMac, LFINDER_MAC_ADDR_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_PUB_MAC, nullptr, LFINDER_MAC_ADDR_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_PUB_MAC, pubMac, LFINDER_MAC_ADDR_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char cipherKey[SESSION_KEY_LENGTH] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_LENGTH);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_KEY, nullptr, SESSION_KEY_LENGTH);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char cipherIv[BROADCAST_IV_LEN] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_IV, nullptr, BROADCAST_IV_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: LNN_GET_CNN_CODE_Test_001
 * @tc.desc: lnn get cnn code test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_CNN_CODE_Test_001, TestSize.Level1)
{
    DiscoveryType type = DISCOVERY_TYPE_WIFI;
    short ret = LnnGetCnnCode(nullptr, type);
    EXPECT_TRUE(ret == INVALID_CONNECTION_CODE_VALUE);
    ret = LnnGetCnnCode(NODE1_UUID, type);
    EXPECT_TRUE(ret == INVALID_CONNECTION_CODE_VALUE);
    ret = LnnGetCnnCode(NODE2_UUID, type);
    EXPECT_TRUE(ret == INVALID_CONNECTION_CODE_VALUE);
}

/*
 * @tc.name: LNN_UPDATE_NODE_INFO_Test_001
 * @tc.desc: lnn update node info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_NODE_INFO_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strncpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    int32_t ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strncpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE2_UDID, strlen(NODE2_UDID));
    ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_MAP_GET_FAILED);
}

/*
 * @tc.name: LNN_SET_NODE_OFFLINE_Test_001
 * @tc.desc: lnn set node offline test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_NODE_OFFLINE_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(REPORT_NONE == LnnSetNodeOffline(NODE1_UDID, CONNECTION_ADDR_WLAN, AUTH_ID));
    EXPECT_TRUE(REPORT_NONE == LnnSetNodeOffline(NODE2_UDID, CONNECTION_ADDR_WLAN, AUTH_ID));
    DfxRecordLnnSetNodeOfflineEnd(NODE1_UDID, 1, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_BASIC_INFO_BY_UDID_Test_001
 * @tc.desc: lnn get basic info by udid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_BASIC_INFO_BY_UDID_Test_001, TestSize.Level1)
{
    NodeBasicInfo basicInfo;
    (void)memset_s(&basicInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    int32_t ret = LnnGetBasicInfoByUdid(NODE1_UDID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetBasicInfoByUdid(NODE1_UDID, &basicInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_CONVERT_DLID_Test_001
 * @tc.desc: lnn convert dl id test
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LNNDisctributedLedgerTest, LNN_CONVERT_DLID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnConvertDlId(nullptr, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnConvertDlId(NODE1_UDID, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnConvertDlId(NODE2_UDID, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    ret = LnnConvertDlId(NODE2_UUID, CATEGORY_UUID, CATEGORY_UUID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    ret = LnnConvertDlId(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, CATEGORY_NETWORK_ID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DLP2P_INFO_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLP2P_INFO_Test_001, TestSize.Level1)
{
    P2pInfo info;
    (void)memset_s(&info, sizeof(P2pInfo), 0, sizeof(P2pInfo));
    (void)strncpy_s(info.p2pMac, MAC_LEN, P2P_MAC, strlen(P2P_MAC));
    (void)strncpy_s(info.goMac, MAC_LEN, GO_MAC, strlen(GO_MAC));
    info.p2pRole = P2P_ROLE;
    bool ret = LnnSetDLP2pInfo(nullptr, &info);
    EXPECT_TRUE(ret == false);
    ret = LnnSetDLP2pInfo(NODE1_NETWORK_ID, &info);
    EXPECT_TRUE(ret == true);
    ret = LnnSetDLP2pInfo(NODE2_NETWORK_ID, &info);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BYBTMAC_Test_001
 * @tc.desc: lnn get neteorkId by bt mac test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BYBTMAC_Test_001, TestSize.Level1)
{
    char buf[NETWORK_ID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByBtMac(nullptr, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByBtMac(NODE1_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByBtMac(NODE2_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BY_UUID_Test_001
 * @tc.desc: lnn get neteorkId by uuid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BY_UUID_Test_001, TestSize.Level1)
{
    char buf[UUID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByUuid(nullptr, buf, UUID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUuid(NODE1_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByUuid(NODE2_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BY_UDID_Test_001
 * @tc.desc: lnn get neteorkId by udid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BY_UDID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByUdid(nullptr, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUdid(NODE1_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByUdid(NODE2_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001
 * @tc.desc: lnn get dl heartbeat time stamp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp;
    int32_t ret = LnnGetDLHeartbeatTimestamp(NODE1_NETWORK_ID, &timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetDLHeartbeatTimestamp(NODE2_NETWORK_ID, &timeStamp);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001
 * @tc.desc: lnn set dl heartbeat time stamp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp = NEW_TIME_STAMP;
    int32_t ret = LnnSetDLHeartbeatTimestamp(NODE1_NETWORK_ID, timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDLHeartbeatTimestamp(NODE2_NETWORK_ID, timeStamp);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLCONN_CAPABILITY_Test_001
 * @tc.desc: lnn set dl conn capability test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLCONN_CAPABILITY_Test_001, TestSize.Level1)
{
    uint64_t connCapability = CAPABILITY;
    int32_t ret = LnnSetDLConnCapability(NODE2_NETWORK_ID, connCapability);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLNODE_ADDR_Test_001
 * @tc.desc: lnn set dl node addr test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLNODE_ADDR_Test_001, TestSize.Level1)
{
    int32_t ret = LnnSetDLNodeAddr(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDLNodeAddr(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_ONLINE_NODE_BY_UDID_HASH_Test_001
 * @tc.desc: lnn get online node by udid hash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_ONLINE_NODE_BY_UDID_HASH_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnGetOnlineNodeByUdidHash(RECV_UDID_HASH) == nullptr);
}

/*
 * @tc.name: LNN_GET_DATA_CHANGE_FLAG_Test_001
 * @tc.desc: lnn get data change flag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
{
    int16_t info = 0;
    int32_t ret = LnnGetRemoteNum16Info(NODE1_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetRemoteNum16Info(NODE2_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNum16Info(NODE2_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_CONVERT_DLID_TO_UDID_Test_001
 * @tc.desc: lnn convert dlid to udid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_CONVERT_DLID_TO_UDID_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnConvertDLidToUdid(nullptr, CATEGORY_NETWORK_ID) == nullptr);
    LnnConvertDLidToUdid(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID);
    EXPECT_TRUE(LnnConvertDLidToUdid(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID) == nullptr);
}

/*
 * @tc.name: LNN_GET_LNN_RELATION_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_LNN_RELATION_Test_001, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX] = { 0 };
    int32_t ret = LnnGetLnnRelation(nullptr, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetLnnRelation(NODE1_UDID, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetLnnRelation(NODE2_UDID, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_INFO_NAME_Test_001
 * @tc.desc: lnn set dl device info name test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DL_DEVICE_INFO_NAME_Test_001, TestSize.Level1)
{
    bool ret = LnnSetDLDeviceInfoName(nullptr, nullptr);
    EXPECT_TRUE(ret == false);
    ret = LnnSetDLDeviceInfoName(NODE1_UDID, NODE1_DEVICE_NAME);
    EXPECT_TRUE(ret == true);
    ret = LnnSetDLDeviceInfoName(NODE2_UDID, NODE2_DEVICE_NAME);
    EXPECT_TRUE(ret == false);
}

HWTEST_F(LNNDisctributedLedgerTest, GET_NODEINFO_FORMMAP_Test_001, TestSize.Level1)
{
    (void)GetCurrentTime();
    NodeInfo *res = GetNodeInfoFromMap(nullptr, nullptr);
    EXPECT_TRUE(res == nullptr);
}

HWTEST_F(LNNDisctributedLedgerTest, INIT_DISTRIBUTED_INFO_Test_001, TestSize.Level1)
{
    int32_t ret = InitDistributedInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = InitConnectionCode(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    (void)DeinitConnectionCode(nullptr);
}

HWTEST_F(LNNDisctributedLedgerTest, NEW_BRBLE_DISCOVERED_Test_001, TestSize.Level1)
{
    NodeInfo oldInfo;
    NodeInfo newInfo;
    (void)NewWifiDiscovered(nullptr, nullptr);
    (void)NewWifiDiscovered(&oldInfo, &newInfo);
    (void)NewBrBleDiscovered(nullptr, nullptr);
    (void)NewBrBleDiscovered(&oldInfo, &newInfo);
    (void)RetainOfflineCode(nullptr, nullptr);
    (void)ConvertNodeInfoToBasicInfo(nullptr, nullptr);
    bool ret = IsNetworkIdChanged(nullptr, nullptr);
    EXPECT_TRUE(ret == false);
    ret = IsNetworkIdChanged(&newInfo, &oldInfo);
    EXPECT_TRUE(ret == false);
}

HWTEST_F(LNNDisctributedLedgerTest, IS_META_NODE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    info.metaInfo.isMetaNode = true;
    bool ret = IsMetaNode(nullptr);
    EXPECT_TRUE(ret == false);
    ret = IsMetaNode(&info);
    EXPECT_TRUE(ret == true);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NODEINFO_BYID_Test_001, TestSize.Level1)
{
    INodeStateCb callBack;
    IdCategory type = CATEGORY_UDID;
    NodeInfo *ret = LnnGetNodeInfoById(nullptr, type);
    EXPECT_TRUE(ret == nullptr);
    callBack.onNodeOnline = nullptr;
    (void)PostOnlineNodesToCb(&callBack);
    callBack.onNodeOnline = TestFunc;
    (void)PostOnlineNodesToCb(&callBack);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_NODE_Test_001, TestSize.Level1)
{
    int32_t ret = LnnGetRemoteNodeInfoByKey(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *key = "dsoftBus";
    NodeInfo info;
    ret = LnnGetRemoteNodeInfoByKey(key, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_DEVICE_TYPEID_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    char bleMac = '0';
    uint32_t len = 0;
    int32_t ret = DlGetDeviceTypeId(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetNodeBleMac(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    (void)LnnUpdateNodeBleMac(nullptr, nullptr, len);
    (void)LnnUpdateNodeBleMac(networkId, &bleMac, len);
}

HWTEST_F(LNNDisctributedLedgerTest, DL_GET_WIFICFG_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetWifiCfg(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetChanList5g(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetP2pRole(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetStateVersion(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetStaFrequency(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = LNN_COMMON_LEN;
    ret = DlGetStateVersion(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetStaFrequency(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetNodeDataChangeFlag(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = DATA_CHANGE_FLAG_BUF_LEN;
    ret = DlGetNodeDataChangeFlag(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetMasterWeight(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetNetType(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetProxyPort(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetSessionPort(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetAuthPort(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_NODETTLV_NEGOFLAG_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetNodeTlvNegoFlag(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DlGetAccountHash(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = sizeof(bool);
    ret = DlGetNodeTlvNegoFlag(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = SHA_256_HASH_LEN;
    ret = DlGetAccountHash(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    (void)DestroyCnnCodeKey(nullptr);
    (void)DeinitDistributedInfo(nullptr);
}

HWTEST_F(LNNDisctributedLedgerTest, ADD_CNN_CODE_Test_001, TestSize.Level1)
{
    Map cnnCode;
    const char *uuid = "softBus";
    DiscoveryType type = DISCOVERY_TYPE_WIFI;
    int64_t authSeqNum = 0;
    int32_t ret = AddCnnCode(&cnnCode, nullptr, type, authSeqNum);
    EXPECT_TRUE(ret == SOFTBUS_MEM_ERR);
    ret = AddCnnCode(&cnnCode, uuid, type, authSeqNum);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    char *key = CreateCnnCodeKey(uuid, type);
    EXPECT_NE(key, nullptr);
    short* code = (short *)LnnMapGet(&cnnCode, key);
    EXPECT_NE(code, nullptr);

    (void)RemoveCnnCode(&cnnCode, nullptr, type);
    (void)RemoveCnnCode(&cnnCode, uuid, type);

    code = (short *)LnnMapGet(&cnnCode, key);
    EXPECT_EQ(code, nullptr);
}

HWTEST_F(LNNDisctributedLedgerTest, NOTIFY_MIGRATE_UPGRADE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    memset_s(info.deviceInfo.deviceUdid, sizeof(info.deviceInfo.deviceUdid), '\0', sizeof(info.deviceInfo.deviceUdid));
    (void)NotifyMigrateUpgrade(&info);
    int32_t ret = LnnUpdateAccountInfo(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_GROUPTYPE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    int32_t ret = LnnUpdateGroupType(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    char str[] = "softBus";
    strcpy_s(info.deviceInfo.deviceUdid, sizeof(str), str);
    ret = LnnUpdateGroupType(&info);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_MAP_GET_FAILED);

    const char *udid = "softBus";
    (void)NotifyMigrateDegrade(udid);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_BYTEINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BYTE_KEY_END;
    uint8_t info;
    uint32_t len = 0;
    int32_t ret = LnnGetRemoteByteInfo(nullptr, key, &info, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(networkId, key, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(networkId, key, &info, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    key = BYTE_KEY_BEGIN;
    ret = LnnGetRemoteByteInfo(networkId, key, &info, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_ISLSA_NODE_Test_001, TestSize.Level1)
{
    NodeBasicInfo info;
    memset_s(info.networkId, sizeof(info.networkId), '\0', sizeof(info.networkId));
    bool ret = LnnIsLSANode(&info);
    EXPECT_TRUE(ret == false);

    int32_t nodeNum = 0;
    int32_t res = LnnGetAllOnlineNodeNum(nullptr);
    EXPECT_TRUE(res == SOFTBUS_INVALID_PARAM);
    res = LnnGetAllOnlineNodeNum(&nodeNum);
    EXPECT_TRUE(res == SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GETNETWORKID_BYUDIDHASH_Test_001, TestSize.Level1)
{
    uint8_t udidHash[UDID_HASH_LEN] = {0};
    char buf = '0';
    uint32_t len = 0;
    int32_t ret = LnnGetNetworkIdByUdidHash(nullptr, len, nullptr, len, true);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUdidHash(udidHash, UDID_HASH_LEN, &buf, len, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GETDL_ONLINETIMESTAMP_Test_001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = LnnGetDLOnlineTimestamp(nullptr, &timestamp);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_BATTERYINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    BatteryInfo info;
    int32_t ret = LnnSetDLBatteryInfo(nullptr, &info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBatteryInfo(networkId, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_BSSTRANSINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    BssTransInfo info;
    int32_t ret = LnnSetDLBssTransInfo(nullptr, &info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBssTransInfo(networkId, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_PROXYPORT_Test_001, TestSize.Level1)
{
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t proxyPort = 0;
    int32_t ret = LnnSetDLProxyPort(nullptr, type, proxyPort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_SESSIONPORT_Test_001, TestSize.Level1)
{
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t sessionPort = 0;
    int32_t ret = LnnSetDLSessionPort(nullptr, type, sessionPort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_AUTHPORT_Test_001, TestSize.Level1)
{
    const char *id = "softBus";
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t authPort = 0;
    int32_t ret = LnnSetDLAuthPort(nullptr, type, authPort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnSetDLAuthPort(id, type, authPort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, SOFTBUS_DUMPBUSCENTER_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    int32_t ret = SoftBusDumpBusCenterRemoteDeviceInfo(fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_BOOLINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BOOL_KEY_END;
    bool info = false;
    int32_t ret = LnnGetRemoteBoolInfo(nullptr, key, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfo(networkId, key, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfo(networkId, key, &info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    key = BOOL_KEY_BEGIN;
    ret = LnnGetRemoteBoolInfo(networkId, key, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_NUMU64INFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BOOL_KEY_END;
    uint64_t info = 0;
    int32_t ret = LnnGetRemoteNumU64Info(nullptr, key, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(networkId, key, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(networkId, key, &info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    key = BOOL_KEY_BEGIN;
    ret = LnnGetRemoteNumU64Info(networkId, key, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_NODEINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    IdCategory type = CATEGORY_NETWORK_ID;
    NodeInfo info;
    int32_t ret = LnnGetRemoteNodeInfoById(networkId, type, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

HWTEST_F(LNNDisctributedLedgerTest, LNN_REFRESH_DEVICEONLINE_ANDINFO_Test_001, TestSize.Level1)
{
    DeviceInfo device;
    InnerDeviceInfoAddtions additions;
    (void)LnnRefreshDeviceOnlineStateAndDevIdInfo(nullptr, &device, &additions);

    (void)memset_s(device.devId, sizeof(device.devId), '\0', sizeof(device.devId));
    additions.medium = COAP;
    device.isOnline = true;
    (void)LnnRefreshDeviceOnlineStateAndDevIdInfo(nullptr, &device, &additions);
    EXPECT_TRUE(device.isOnline == false);

    additions.medium = BLE;
    device.isOnline = true;
    (void)LnnRefreshDeviceOnlineStateAndDevIdInfo(nullptr, &device, &additions);
    EXPECT_TRUE(device.isOnline == false);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_FEATURE_CAP_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    uint32_t len = 0;
    int32_t ret = DlGetFeatureCap(networkId, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = LNN_COMMON_LEN_64;
    ret = DlGetFeatureCap(networkId, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_DLWIFIDIRECT_ADDR_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLWIFIDIRECT_ADDR_Test_001, TestSize.Level1)
{
    bool ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, nullptr);
    EXPECT_TRUE(ret == false);
    char wifiDirectAddr1[MAC_LEN] = "11223344556677889";
    ret = LnnSetDLWifiDirectAddr(nullptr, wifiDirectAddr1);
    EXPECT_TRUE(ret == false);
    ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, wifiDirectAddr1);
    EXPECT_TRUE(ret == true);
    ret = LnnSetDLWifiDirectAddr(NODE2_NETWORK_ID, wifiDirectAddr1);
    EXPECT_TRUE(ret == false);

    char wifiDirectAddr2[MAC_LEN] = "11223344";
    ret = LnnSetDLWifiDirectAddr(nullptr, wifiDirectAddr2);
    EXPECT_TRUE(ret == false);
    ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, wifiDirectAddr2);
    EXPECT_TRUE(ret == true);
    ret = LnnSetDLWifiDirectAddr(NODE2_NETWORK_ID, wifiDirectAddr2);
    EXPECT_TRUE(ret == false);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_STATIC_CAP_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetStaticCap(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetStaticCap(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetStaticCap(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_STATIC_CAP_LEN_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetStaticCapLen(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetStaticCapLen(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetStaticCapLen(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

HWTEST_F(LNNDisctributedLedgerTest, DLGET_REMOTE_PTK_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetRemotePtk(nullptr, true, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetRemotePtk(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetRemotePtk(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnSetDLUnifiedDeviceName_Test_001
 * @tc.desc: LnnSetDLUnifiedDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLUnifiedDeviceName_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    char *name = nullptr;
    int32_t ret = LnnSetDLUnifiedDeviceName(udid, name);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "123456789";
    const char *devName = "devicename";
    ret = LnnSetDLUnifiedDeviceName(devUdid, devName);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLUnifiedDefaultDeviceName_Test_001
 * @tc.desc: LnnSetDLUnifiedDefaultDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLUnifiedDefaultDeviceName_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    char *name = nullptr;
    int32_t ret = LnnSetDLUnifiedDefaultDeviceName(udid, name);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "111111111";
    const char *devName = "devdefaultdevicename";
    ret = LnnSetDLUnifiedDefaultDeviceName(devUdid, devName);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLDeviceNickNameByUdid_Test_001
 * @tc.desc: LnnSetDLDeviceNickNameByUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLDeviceNickNameByUdid_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    char *name = nullptr;
    int32_t ret = LnnSetDLDeviceNickNameByUdid(udid, name);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "2222222222";
    const char *devName = "deviceNickname";
    ret = LnnSetDLDeviceNickNameByUdid(devUdid, devName);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLDeviceStateVersion_Test_001
 * @tc.desc: LnnSetDLDeviceStateVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLDeviceStateVersion_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    int32_t stateVersion = 0;
    int32_t ret = LnnSetDLDeviceStateVersion(udid, stateVersion);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "3333333333";
    ret = LnnSetDLDeviceStateVersion(devUdid, stateVersion);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLDeviceBroadcastCipherKey_Test_001
 * @tc.desc: LnnSetDLDeviceBroadcastCipherKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLDeviceBroadcastCipherKey_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    const char *cipherKey = "qqqqqqqqqqqq";
    int32_t ret = LnnSetDLDeviceBroadcastCipherKey(udid, cipherKey);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "123456789";
    ret = LnnSetDLDeviceBroadcastCipherKey(devUdid, cipherKey);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLDeviceBroadcastCipherIv_Test_001
 * @tc.desc: LnnSetDLDeviceBroadcastCipherIv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_DLDeviceBroadcastCipherIv_Test_001, TestSize.Level1)
{
    char *udid = nullptr;
    const char *cipherIv = "qqqqqqqqqqqq";
    int32_t ret = LnnSetDLDeviceBroadcastCipherIv(udid, cipherIv);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "123456789";
    ret = LnnSetDLDeviceBroadcastCipherIv(devUdid, cipherIv);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnUpdateDistributedNodeInfo_Test_001
 * @tc.desc: LnnUpdateDistributedNodeInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_UpdateDistributedNodeInfo_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *udid = nullptr;
    newInfo.accountId = 18390933952;
    int32_t ret = LnnUpdateDistributedNodeInfo(&newInfo, udid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *devUdid = "123456789";
    ret = LnnUpdateDistributedNodeInfo(&newInfo, devUdid);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnUpdateFileInfo_Test_001
 * @tc.desc: UpdateFileInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_UpdateFileInfo_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo oldInfo;
    memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)memcpy_s(newInfo.cipherInfo.key, SESSION_KEY_LENGTH, "newkey", strlen("newkey"));
    (void)memcpy_s(oldInfo.cipherInfo.key, SESSION_KEY_LENGTH, "oldkey", strlen("oldkey"));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)memcpy_s(newInfo.cipherInfo.key, SESSION_KEY_LENGTH, "samekey", strlen("samekey"));
    (void)memcpy_s(oldInfo.cipherInfo.key, SESSION_KEY_LENGTH, "samekey", strlen("samekey"));
    (void)memcpy_s(newInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "newiv", strlen("newiv"));
    (void)memcpy_s(oldInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "oldiv", strlen("oldiv"));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)memcpy_s(newInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "sameiv", strlen("sameiv"));
    (void)memcpy_s(oldInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "sameiv", strlen("sameiv"));
    (void)memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "newpeerIrk", strlen("newpeerIrk"));
    (void)memcpy_s(oldInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "oldIrk", strlen("oldIrk"));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "sameIrk", strlen("sameIrk"));
    (void)memcpy_s(oldInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "sameIrk", strlen("sameIrk"));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
