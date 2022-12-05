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

#include "lnn_distributed_net_ledger.h"

#include <gtest/gtest.h>
#include <securec.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "lnn_connection_addr_utils.h"
#include "lnn_fast_offline.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_hidumper_buscenter.h"
#include "bus_center_manager.h"

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
constexpr int32_t INVALID_LANE_ID = -1;
using namespace testing;
class DisctributedLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DisctributedLedgerTest::SetUpTestCase()
{
}

void DisctributedLedgerTest::TearDownTestCase()
{
}

void DisctributedLedgerTest::SetUp()
{
    LOG_INFO("LocalLedgerTest start.");
    int32_t ret = LnnInitDistributedLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strcpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID);
    (void)strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID);
    (void)strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);
    (void)strcpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC);
    info.authSeq[0] = AUTH_SEQ;
    info.heartbeatTimeStamp = TIME_STAMP;
    EXPECT_TRUE(REPORT_ONLINE == LnnAddOnlineNode(&info));
}

void DisctributedLedgerTest::TearDown()
{
    LOG_INFO("LocalLedgerTest end.");
    LnnDeinitDistributedLedger();
}

/*
* @tc.name: LNN_ADD_ONLINE_NODE_Test_001
* @tc.desc: lnn add online node test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_ADD_ONLINE_NODE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strcpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID);
    (void)strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID);
    (void)strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);
    (void)strcpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC);
    EXPECT_TRUE(REPORT_NONE == LnnAddOnlineNode(&info));
}

/*
* @tc.name: LNN_GET_REMOTE_STRINFO_Test_001
* @tc.desc: lnn get remote strInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_REMOTE_STRINFO_Test_001, TestSize.Level1)
{
    static InfoKey keyStringTable[] = {
        STRING_KEY_HICE_VERSION,
        STRING_KEY_DEV_UDID,
        STRING_KEY_UUID,
        STRING_KEY_DEV_TYPE,
        STRING_KEY_DEV_NAME,
        STRING_KEY_BT_MAC,
        STRING_KEY_WLAN_IP,
        STRING_KEY_MASTER_NODE_UDID,
        STRING_KEY_P2P_MAC,
        STRING_KEY_P2P_GO_MAC,
        STRING_KEY_NODE_ADDR,
        STRING_KEY_OFFLINE_CODE
    };
    char buf[UDID_BUF_LEN] = {0};
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
        EXPECT_TRUE(ret == SOFTBUS_ERR);
    }
}

/*
* @tc.name: LNN_GET_REMOTE_NUMNFO_Test_002
* @tc.desc: lnn get remote num info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_REMOTE_NUMNFO_Test_002, TestSize.Level1)
{
    static InfoKey keyNumTable[] = {
        NUM_KEY_META_NODE,
        NUM_KEY_SESSION_PORT,
        NUM_KEY_AUTH_PORT,
        NUM_KEY_PROXY_PORT,
        NUM_KEY_NET_CAP,
        NUM_KEY_DISCOVERY_TYPE,
        NUM_KEY_MASTER_NODE_WEIGHT,
        NUM_KEY_P2P_ROLE
    };
    int32_t ret;
    uint32_t i;
    int32_t len = LNN_COMMON_LEN;
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE1_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE2_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_TRUE(ret == SOFTBUS_ERR);
    }
}

/*
* @tc.name: LNN_GET_CNN_CODE_Test_001
* @tc.desc: lnn get cnn code test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_CNN_CODE_Test_001, TestSize.Level1)
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
HWTEST_F(DisctributedLedgerTest, LNN_UPDATE_NODE_INFO_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID);
    int32_t ret = LnnUpdateNodeInfo(&newInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE2_UDID);
    ret = LnnUpdateNodeInfo(&newInfo);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_SET_NODE_OFFLINE_Test_001
* @tc.desc: lnn set node offline test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_SET_NODE_OFFLINE_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(REPORT_NONE == LnnSetNodeOffline(NODE1_UUID, CONNECTION_ADDR_WLAN, AUTH_ID));
    EXPECT_TRUE(REPORT_NONE == LnnSetNodeOffline(NODE2_UUID, CONNECTION_ADDR_WLAN, AUTH_ID));
}

/*
* @tc.name: LNN_GET_BASIC_INFO_BY_UDID_Test_001
* @tc.desc: lnn get basic info by udid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_BASIC_INFO_BY_UDID_Test_001, TestSize.Level1)
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

HWTEST_F(DisctributedLedgerTest, LNN_CONVERT_DLID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = {0};
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
HWTEST_F(DisctributedLedgerTest, LNN_SET_DLP2P_INFO_Test_001, TestSize.Level1)
{
    P2pInfo info;
    (void)memset_s(&info, sizeof(P2pInfo), 0, sizeof(P2pInfo));
    (void)strcpy_s(info.p2pMac, MAC_LEN, P2P_MAC);
    (void)strcpy_s(info.goMac, MAC_LEN, GO_MAC);
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
HWTEST_F(DisctributedLedgerTest, LNN_GET_NETWORKID_BYBTMAC_Test_001, TestSize.Level1)
{
    char buf[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByBtMac(nullptr, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByBtMac(NODE1_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByBtMac(NODE2_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_NETWORKID_BY_UUID_Test_001
* @tc.desc: lnn get neteorkId by uuid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_NETWORKID_BY_UUID_Test_001, TestSize.Level1)
{
    char buf[UUID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(nullptr, buf, UUID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUuid(NODE1_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByUuid(NODE2_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_NETWORKID_BY_UDID_Test_001
* @tc.desc: lnn get neteorkId by udid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_NETWORKID_BY_UDID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUdid(nullptr, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUdid(NODE1_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetNetworkIdByUdid(NODE2_UDID, buf, UDID_BUF_LEN);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_ALL_AUTH_SEQ_Test_001
* @tc.desc: lnn get all auth seq test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_ALL_AUTH_SEQ_Test_001, TestSize.Level1)
{
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = {0};
    int32_t ret = LnnGetAllAuthSeq(nullptr, authSeq, DISCOVERY_TYPE_COUNT);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnGetAllAuthSeq(NODE1_UDID, authSeq, DISCOVERY_TYPE_COUNT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetAllAuthSeq(NODE2_UDID, authSeq, DISCOVERY_TYPE_COUNT);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001
* @tc.desc: lnn get dl heartbeat time stamp test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp;
    int32_t ret = LnnGetDLHeartbeatTimestamp(NODE1_NETWORK_ID, &timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetDLHeartbeatTimestamp(NODE2_NETWORK_ID, &timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001
* @tc.desc: lnn set dl heartbeat time stamp test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp = NEW_TIME_STAMP;
    int32_t ret = LnnSetDLHeartbeatTimestamp(NODE1_NETWORK_ID, timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDLHeartbeatTimestamp(NODE2_NETWORK_ID, timeStamp);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_SET_DLCONN_CAPABILITY_Test_001
* @tc.desc: lnn set dl conn capability test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_SET_DLCONN_CAPABILITY_Test_001, TestSize.Level1)
{
    uint64_t connCapability = CAPABILITY;
    int32_t ret = LnnSetDLConnCapability(NODE1_NETWORK_ID, connCapability);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDLConnCapability(NODE2_NETWORK_ID, connCapability);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_SET_DLNODE_ADDR_Test_001
* @tc.desc: lnn set dl node addr test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_SET_DLNODE_ADDR_Test_001, TestSize.Level1)
{
    int32_t ret = LnnSetDLNodeAddr(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetDLNodeAddr(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_GET_ONLINE_NODE_BY_UDID_HASH_Test_001
* @tc.desc: lnn get online node by udid hash test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_ONLINE_NODE_BY_UDID_HASH_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnGetOnlineNodeByUdidHash(RECV_UDID_HASH) == nullptr);
}

/*
* @tc.name: LNN_REFRESH_DEVICE_ONLINE_STATE_AND_DEVICE_INFO_Test_001
* @tc.desc: lnn refresh device online state and device info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_REFRESH_DEVICE_ONLINE_STATE_AND_DEVICE_INFO_Test_001, TestSize.Level1)
{
    DeviceInfo device;
    InnerDeviceInfoAddtions addtions;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device.devId, DISC_MAX_DEVICE_ID_LEN, NODE1_UDID);
    addtions.medium = COAP;
    LnnRefreshDeviceOnlineStateAndDevIdInfo(nullptr, &device, &addtions);
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    (void)strcpy_s(device.devId, DISC_MAX_DEVICE_ID_LEN, RECV_UDID_HASH);
    addtions.medium = BLE;
    LnnRefreshDeviceOnlineStateAndDevIdInfo(nullptr, &device, &addtions);
}

/*
* @tc.name: LNN_GET_DATA_CHANGE_FLAG_Test_001
* @tc.desc: lnn get data change flag test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
{
    int16_t info = 0;
    int32_t ret = LnnGetRemoteNum16Info(NODE1_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetRemoteNum16Info(NODE2_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_CONVERT_DLID_TO_UDID_Test_001
* @tc.desc: lnn convert dlid to udid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_CONVERT_DLID_TO_UDID_Test_001, TestSize.Level1)
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
HWTEST_F(DisctributedLedgerTest, LNN_GET_LNN_RELATION_Test_001, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX] = {0};
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
HWTEST_F(DisctributedLedgerTest, LNN_SET_DL_DEVICE_INFO_NAME_Test_001, TestSize.Level1)
{
    bool ret = LnnSetDLDeviceInfoName(nullptr, nullptr);
    EXPECT_TRUE(ret == false);
    ret = LnnSetDLDeviceInfoName(NODE1_UDID, NODE1_DEVICE_NAME);
    EXPECT_TRUE(ret == true);
    ret = LnnSetDLDeviceInfoName(NODE2_UDID, NODE2_DEVICE_NAME);
    EXPECT_TRUE(ret == false);
}

/*
* @tc.name: LNN_GET_AND_SET_LANE_COUNT_Test_001
* @tc.desc: lnn get and set lane count test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DisctributedLedgerTest, LNN_GET_AND_SET_LANE_COUNT_Test_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnGetLaneCount(INVALID_LANE_ID) == SOFTBUS_ERR);
    EXPECT_TRUE(LnnSetLaneCount(INVALID_LANE_ID, AUTH_ID) == SOFTBUS_ERR);
}
} // namespace OHOS
