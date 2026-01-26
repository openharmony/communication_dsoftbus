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
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "dsoftbus_enhance_interface.h"
#include "g_enhance_auth_func_pack.h"
#include "g_enhance_lnn_func.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_disctributed_net_ledger_mock.h"
#include "lnn_distributed_net_ledger.c"
#include "lnn_distributed_net_ledger.h"
#include "lnn_distributed_net_ledger_manager.c"
#include "lnn_log.h"
#include "lnn_map.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing;
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
constexpr char NODE3_UDID[] = "3456789udidtest";
constexpr char ACCOUNT_HASH[] = "5FFFFEC";
constexpr char SOFTBUS_VERSION[] = "00";
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
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfo = LnnRetrieveDeviceInfo;
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

    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(REPORT_ONLINE, LnnAddOnlineNode(&info));
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_ADD_ONLINE_NODE_Test_001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfo = LnnRetrieveDeviceInfo;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID, strlen(NODE1_UUID));
    (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID, strlen(NODE1_NETWORK_ID));
    (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC, strlen(NODE1_BT_MAC));
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(REPORT_NONE, LnnAddOnlineNode(&info));
}

/*
 * @tc.name: LNN_GET_REMOTE_STRINFO_Test_001
 * @tc.desc: lnn get remote strInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_STRINFO_Test_001, TestSize.Level1)
{
    static InfoKey keyStringTable[] = { STRING_KEY_HICE_VERSION, STRING_KEY_UUID,
        STRING_KEY_DEV_TYPE, STRING_KEY_DEV_NAME, STRING_KEY_BT_MAC, STRING_KEY_MASTER_NODE_UDID, STRING_KEY_P2P_MAC,
        STRING_KEY_P2P_GO_MAC, STRING_KEY_NODE_ADDR, STRING_KEY_OFFLINE_CODE, STRING_KEY_WIFIDIRECT_ADDR };
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(nullptr, STRING_KEY_HICE_VERSION, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_HICE_VERSION, nullptr, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, NUM_KEY_BEGIN, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t i;
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetRemoteStrInfo(NODE1_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    EXPECT_EQ(LnnGetRemoteStrInfo(NODE1_NETWORK_ID, STRING_KEY_DEV_UDID, buf, UDID_BUF_LEN), SOFTBUS_OK);
    EXPECT_EQ(LnnGetRemoteStrInfo(NODE2_NETWORK_ID, STRING_KEY_DEV_UDID, buf, UDID_BUF_LEN),
        SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteStrInfo(NODE2_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN);
        EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_STRINFO_BY_IFNAME_Test_001
 * @tc.desc: lnn get remote strInfo by ifname test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_STRINFO_BY_IFNAME_Test_001, TestSize.Level1)
{
    static InfoKey keyStringTable[] = { STRING_KEY_IP };
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfoByIfnameIdx(nullptr, STRING_KEY_HICE_VERSION, buf, UDID_BUF_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfoByIfnameIdx(NODE1_NETWORK_ID, STRING_KEY_HICE_VERSION, nullptr, UDID_BUF_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteStrInfoByIfnameIdx(NODE1_NETWORK_ID, NUM_KEY_BEGIN, buf, UDID_BUF_LEN, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t i;
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetRemoteStrInfoByIfnameIdx(NODE1_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN, WLAN_IF);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyStringTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteStrInfoByIfnameIdx(NODE2_NETWORK_ID, keyStringTable[i], buf, UDID_BUF_LEN, WLAN_IF);
        EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMNFO_Test_002
 * @tc.desc: lnn get remote num info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_NUMNFO_Test_002, TestSize.Level1)
{
    static InfoKey keyNumTable[] = { NUM_KEY_META_NODE, NUM_KEY_NET_CAP, NUM_KEY_DISCOVERY_TYPE,
        NUM_KEY_MASTER_NODE_WEIGHT, NUM_KEY_P2P_ROLE, NUM_KEY_SLE_RANGE_CAP, NUM_KEY_USERID };
    int32_t ret;
    uint32_t i;
    int32_t len = LNN_COMMON_LEN;
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE1_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfo(NODE2_NETWORK_ID, keyNumTable[i], &len);
        EXPECT_NE(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_NUMNFO_BY_IFNAME_Test_002
 * @tc.desc: lnn get remote num info by ifname test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_NUMNFO_BY_IFNAME_Test_002, TestSize.Level1)
{
    static InfoKey keyNumTable[] = { NUM_KEY_SESSION_PORT, NUM_KEY_AUTH_PORT, NUM_KEY_PROXY_PORT };
    int32_t ret;
    uint32_t i;
    int32_t len = LNN_COMMON_LEN;
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfoByIfnameIdx(NODE1_NETWORK_ID, keyNumTable[i], &len, WLAN_IF);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(keyNumTable) / sizeof(InfoKey); i++) {
        ret = LnnGetRemoteNumInfoByIfnameIdx(NODE2_NETWORK_ID, keyNumTable[i], &len, WLAN_IF);
        EXPECT_NE(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTEINFO_Test_003
 * @tc.desc: lnn get remote byte info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_BYTEINFO_Test_003, TestSize.Level1)
{
    unsigned char irk[LFINDER_IRK_LEN] = { 0 };
    int32_t ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_IRK, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_IRK, nullptr, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_IRK, irk, LFINDER_IRK_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char pubMac[LFINDER_MAC_ADDR_LEN] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_PUB_MAC, pubMac, LFINDER_MAC_ADDR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_PUB_MAC, nullptr, LFINDER_MAC_ADDR_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_PUB_MAC, pubMac, LFINDER_MAC_ADDR_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char cipherKey[SESSION_KEY_LENGTH] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_KEY, nullptr, SESSION_KEY_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_KEY, cipherKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned char cipherIv[BROADCAST_IV_LEN] = { 0 };
    ret = LnnGetRemoteByteInfo(nullptr, BYTE_KEY_BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_IV, nullptr, BROADCAST_IV_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(NODE1_NETWORK_ID, BYTE_KEY_BROADCAST_CIPHER_IV, cipherIv, BROADCAST_IV_LEN);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: LNN_GET_CNN_CODE_Test_001
 * @tc.desc: lnn get cnn code test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_CNN_CODE_Test_001, TestSize.Level1)
{
    DiscoveryType type = DISCOVERY_TYPE_WIFI;
    short ret = LnnGetCnnCode(nullptr, type);
    EXPECT_EQ(ret, INVALID_CONNECTION_CODE_VALUE);
    ret = LnnGetCnnCode(NODE1_UUID, type);
    EXPECT_EQ(ret, INVALID_CONNECTION_CODE_VALUE);
    ret = LnnGetCnnCode(NODE2_UUID, type);
    EXPECT_EQ(ret, INVALID_CONNECTION_CODE_VALUE);
}

/*
 * @tc.name: LNN_UPDATE_NODE_INFO_Test_001
 * @tc.desc: lnn update node info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_NODE_INFO_Test_001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfo = LnnRetrieveDeviceInfo;
    pfnLnnEnhanceFuncList->lnnSaveRemoteDeviceInfo = LnnSaveRemoteDeviceInfo;

    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));

    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strncpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID, strlen(NODE1_UDID));
    int32_t ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "newpeerIrk", strlen("newpeerIrk"));
    ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)strcpy_s(newInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, "newDeviceName");
    ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strncpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE2_UDID, strlen(NODE2_UDID));
    ret = LnnUpdateNodeInfo(&newInfo, CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MAP_GET_FAILED);
}

/*
 * @tc.name: LNN_UPDATE_META_INFO_Test_001
 * @tc.desc: lnn update meta info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_META_INFO_Test_001, TestSize.Level1)
{
    int32_t ret = LnnAddMetaInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_NODE_OFFLINE_Test_001
 * @tc.desc: lnn set node offline test
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_BASIC_INFO_BY_UDID_Test_001, TestSize.Level1)
{
    NodeBasicInfo basicInfo;
    (void)memset_s(&basicInfo, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    int32_t ret = LnnGetBasicInfoByUdid(NODE1_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetBasicInfoByUdid(NODE1_UDID, &basicInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_CONVERT_DLID_Test_001
 * @tc.desc: lnn convert dl id test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */

HWTEST_F(LNNDisctributedLedgerTest, LNN_CONVERT_DLID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnConvertDlId(nullptr, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnConvertDlId(NODE1_UDID, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnConvertDlId(NODE2_UDID, CATEGORY_UDID, CATEGORY_UDID, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnConvertDlId(NODE2_UUID, CATEGORY_UUID, CATEGORY_UUID, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnConvertDlId(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, CATEGORY_NETWORK_ID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DLP2P_INFO_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.level: Level1
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
    EXPECT_FALSE(ret);
    ret = LnnSetDLP2pInfo(NODE1_NETWORK_ID, &info);
    EXPECT_TRUE(ret);
    ret = LnnSetDLP2pInfo(NODE2_NETWORK_ID, &info);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BYBTMAC_Test_001
 * @tc.desc: lnn get neteorkId by bt mac test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BYBTMAC_Test_001, TestSize.Level1)
{
    char buf[NETWORK_ID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByBtMac(nullptr, buf, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByBtMac(NODE1_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetNetworkIdByBtMac(NODE2_BT_MAC, buf, NETWORK_ID_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BY_UUID_Test_001
 * @tc.desc: lnn get neteorkId by uuid test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BY_UUID_Test_001, TestSize.Level1)
{
    char buf[UUID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByUuid(nullptr, buf, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUuid(NODE1_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetNetworkIdByUuid(NODE2_UUID, buf, NETWORK_ID_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_NETWORKID_BY_UDID_Test_001
 * @tc.desc: lnn get neteorkId by udid test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NETWORKID_BY_UDID_Test_001, TestSize.Level1)
{
    char buf[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByUdid(nullptr, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUdid(NODE1_UDID, buf, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetNetworkIdByUdid(NODE2_UDID, buf, UDID_BUF_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001
 * @tc.desc: lnn get dl heartbeat time stamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp;
    int32_t ret = LnnGetDLHeartbeatTimestamp(NODE1_NETWORK_ID, &timeStamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetDLHeartbeatTimestamp(NODE2_NETWORK_ID, &timeStamp);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001
 * @tc.desc: lnn set dl heartbeat time stamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLHEARTBEAT_TIMER_STAMP_Test_001, TestSize.Level1)
{
    uint64_t timeStamp = NEW_TIME_STAMP;
    int32_t ret = LnnSetDLHeartbeatTimestamp(NODE1_NETWORK_ID, timeStamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetDLHeartbeatTimestamp(NODE2_NETWORK_ID, timeStamp);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLCONN_CAPABILITY_Test_001
 * @tc.desc: lnn set dl conn capability test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLCONN_CAPABILITY_Test_001, TestSize.Level1)
{
    uint64_t connCapability = CAPABILITY;
    int32_t ret = LnnSetDLConnCapability(NODE2_NETWORK_ID, connCapability);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_DLNODE_ADDR_Test_001
 * @tc.desc: lnn set dl node addr test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLNODE_ADDR_Test_001, TestSize.Level1)
{
    int32_t ret = LnnSetDLNodeAddr(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSetDLNodeAddr(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, NODE_ADDRESS);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_ONLINE_NODE_BY_UDID_HASH_Test_001
 * @tc.desc: lnn get online node by udid hash test
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
{
    int16_t info = 0;
    int32_t ret = LnnGetRemoteNum16Info(NODE1_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetRemoteNum16Info(NODE2_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, &info);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    ret = LnnGetRemoteNum16Info(NODE2_NETWORK_ID, NUM_KEY_DATA_CHANGE_FLAG, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_CONVERT_DLID_TO_UDID_Test_001
 * @tc.desc: lnn convert dlid to udid test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_CONVERT_DLID_TO_UDID_Test_001, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = { 0 };
    EXPECT_TRUE(LnnConvertDLidToUdid(nullptr, CATEGORY_NETWORK_ID, udid, UDID_BUF_LEN) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnConvertDLidToUdid(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID, udid, UDID_BUF_LEN - 1) ==
        SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LNN_RELATION_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_LNN_RELATION_Test_001, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX] = { 0 };
    int32_t ret = LnnGetLnnRelation(nullptr, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLnnRelation(NODE1_UDID, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetLnnRelation(NODE2_UDID, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: LNN_SET_DL_DEVICE_INFO_NAME_Test_001
 * @tc.desc: lnn set dl device info name test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DL_DEVICE_INFO_NAME_Test_001, TestSize.Level1)
{
    bool ret = LnnSetDLDeviceInfoName(nullptr, nullptr);
    EXPECT_FALSE(ret);
    ret = LnnSetDLDeviceInfoName(NODE1_UDID, NODE1_DEVICE_NAME);
    EXPECT_TRUE(ret);
    ret = LnnSetDLDeviceInfoName(NODE2_UDID, NODE2_DEVICE_NAME);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GET_NODEINFO_FORMMAP_Test_001
 * @tc.desc: get node info from map test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, GET_NODEINFO_FORMMAP_Test_001, TestSize.Level1)
{
    (void)GetCurrentTime();
    NodeInfo *res = GetNodeInfoFromMap(nullptr, nullptr);
    EXPECT_TRUE(res == nullptr);
}

/*
 * @tc.name: INIT_DISTRIBUTED_INFO_Test_001
 * @tc.desc: init distributed info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, INIT_DISTRIBUTED_INFO_Test_001, TestSize.Level1)
{
    int32_t ret = InitDistributedInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitConnectionCode(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)DeinitConnectionCode(nullptr);
}

/*
 * @tc.name: NEW_BRBLE_DISCOVERED_Test_001
 * @tc.desc: new br ble discovered test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, NEW_BRBLE_DISCOVERED_Test_001, TestSize.Level1)
{
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)NewWifiDiscovered(nullptr, nullptr);
    (void)NewWifiDiscovered(&oldInfo, &newInfo);
    (void)RetainOfflineCode(nullptr, nullptr);
    (void)ConvertNodeInfoToBasicInfo(nullptr, nullptr);
    bool ret = IsNetworkIdChanged(nullptr, nullptr);
    EXPECT_FALSE(ret);
    ret = IsNetworkIdChanged(&newInfo, &oldInfo);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_META_NODE_Test_001
 * @tc.desc: is meta node test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, IS_META_NODE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.metaInfo.isMetaNode = true;
    bool ret = IsMetaNode(nullptr);
    EXPECT_FALSE(ret);
    ret = IsMetaNode(&info);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: LNN_GET_NODEINFO_BYID_Test_001
 * @tc.desc: lnn get node info by id test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_NODEINFO_BYID_Test_001, TestSize.Level1)
{
    INodeStateCb callBack;
    IdCategory type = CATEGORY_UDID;
    NodeInfo *ret = LnnGetNodeInfoById(nullptr, type);
    EXPECT_EQ(ret, nullptr);
    callBack.onNodeOnline = nullptr;
    (void)PostOnlineNodesToCb(&callBack);
    callBack.onNodeOnline = TestFunc;
    (void)PostOnlineNodesToCb(&callBack);
}

/*
 * @tc.name: LNN_GET_REMOTE_NODE_Test_001
 * @tc.desc: lnn get remote node info by key test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_NODE_Test_001, TestSize.Level1)
{
    int32_t ret = LnnGetRemoteNodeInfoByKey(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *key = "dsoftBus";
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ret = LnnGetRemoteNodeInfoByKey(key, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DLGET_DEVICE_TYPEID_Test_001
 * @tc.desc: dl get node ble mac test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_DEVICE_TYPEID_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    char bleMac = '0';
    uint32_t len = 0;
    int32_t ret = DlGetDeviceTypeId(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetNodeBleMac(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)LnnUpdateNodeBleMac(nullptr, nullptr, len);
    (void)LnnUpdateNodeBleMac(networkId, &bleMac, len);
}

/*
 * @tc.name: DL_GET_WIFICFG_Test_001
 * @tc.desc: dl get node ble mac test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DL_GET_WIFICFG_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetWifiCfg(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetChanList5g(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetP2pRole(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetStateVersion(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetStaFrequency(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = LNN_COMMON_LEN;
    ret = DlGetStateVersion(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetStaFrequency(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetNodeDataChangeFlag(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = DATA_CHANGE_FLAG_BUF_LEN;
    ret = DlGetNodeDataChangeFlag(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetMasterWeight(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetNetType(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetProxyPort(nullptr, true, nullptr, len, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetSessionPort(nullptr, true, nullptr, len, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetAuthPort(nullptr, true, nullptr, len, WLAN_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DLGET_NODETTLV_NEGOFLAG_Test_001
 * @tc.desc: dl get node tlv nego flag test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_NODETTLV_NEGOFLAG_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetNodeTlvNegoFlag(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetAccountHash(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = sizeof(bool);
    ret = DlGetNodeTlvNegoFlag(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = SHA_256_HASH_LEN;
    ret = DlGetAccountHash(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)DestroyCnnCodeKey(nullptr);
    (void)DeinitDistributedInfo(nullptr);
}

/*
 * @tc.name: ADD_CNN_CODE_Test_001
 * @tc.desc: add cnn code test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, ADD_CNN_CODE_Test_001, TestSize.Level1)
{
    Map cnnCode;
    const char *uuid = "softBus";
    DiscoveryType type = DISCOVERY_TYPE_WIFI;
    int64_t authSeqNum = 0;
    int32_t ret = AddCnnCode(&cnnCode, nullptr, type, authSeqNum);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ret = AddCnnCode(&cnnCode, uuid, type, authSeqNum);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char *key = CreateCnnCodeKey(uuid, type);
    EXPECT_NE(key, nullptr);
    short *code = (short *)LnnMapGet(&cnnCode, key);
    EXPECT_NE(code, nullptr);

    (void)RemoveCnnCode(&cnnCode, nullptr, type);
    (void)RemoveCnnCode(&cnnCode, uuid, type);

    code = (short *)LnnMapGet(&cnnCode, key);
    EXPECT_EQ(code, nullptr);
}

/*
 * @tc.name: NOTIFY_MIGRATE_UPGRADE_Test_001
 * @tc.desc: notify migrate upgrade test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, NOTIFY_MIGRATE_UPGRADE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    memset_s(info.deviceInfo.deviceUdid, sizeof(info.deviceInfo.deviceUdid), '\0', sizeof(info.deviceInfo.deviceUdid));
    (void)NotifyMigrateUpgrade(&info);
    int32_t ret = LnnUpdateAccountInfo(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_UPDATE_GROUPTYPE_Test_001
 * @tc.desc: lnn update group type test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_GROUPTYPE_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnUpdateGroupType(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    char str[] = "softBus";
    strcpy_s(info.deviceInfo.deviceUdid, sizeof(str), str);
    ret = LnnUpdateGroupType(&info);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MAP_GET_FAILED);

    const char *udid = "softBus";
    (void)NotifyMigrateDegrade(udid);
}

/*
 * @tc.name: LNN_GET_REMOTE_BYTEINFO_Test_001
 * @tc.desc: lnn get remote byte info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GET_REMOTE_BYTEINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BYTE_KEY_END;
    uint8_t info;
    uint32_t len = 0;
    int32_t ret = LnnGetRemoteByteInfo(nullptr, key, &info, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(networkId, key, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteByteInfo(networkId, key, &info, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    key = BYTE_KEY_BEGIN;
    ret = LnnGetRemoteByteInfo(networkId, key, &info, len);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_ISLSA_NODE_Test_001
 * @tc.desc: lnn is LSA node test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_ISLSA_NODE_Test_001, TestSize.Level1)
{
    NodeBasicInfo info;
    memset_s(info.networkId, sizeof(info.networkId), '\0', sizeof(info.networkId));
    bool ret = LnnIsLSANode(&info);
    EXPECT_FALSE(ret);

    int32_t nodeNum = 0;
    int32_t res = LnnGetAllOnlineNodeNum(nullptr);
    EXPECT_TRUE(res == SOFTBUS_INVALID_PARAM);
    res = LnnGetAllOnlineNodeNum(&nodeNum);
    EXPECT_TRUE(res == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GETNETWORKID_BYUDIDHASH_Test_001
 * @tc.desc: lnn get network id by udid hash test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GETNETWORKID_BYUDIDHASH_Test_001, TestSize.Level1)
{
    uint8_t udidHash[UDID_HASH_LEN] = { 0 };
    char buf = '0';
    uint32_t len = 0;
    int32_t ret = LnnGetNetworkIdByUdidHash(nullptr, len, nullptr, len, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetNetworkIdByUdidHash(udidHash, UDID_HASH_LEN, &buf, len, true);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GETDL_ONLINETIMESTAMP_Test_001
 * @tc.desc: lnn get DL online timestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GETDL_ONLINETIMESTAMP_Test_001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = LnnGetDLOnlineTimestamp(nullptr, &timestamp);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SETDL_BATTERYINFO_Test_001
 * @tc.desc: lnn set DL battery info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_BATTERYINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    BatteryInfo info;
    (void)memset_s(&info, sizeof(BatteryInfo), 0, sizeof(BatteryInfo));
    int32_t ret = LnnSetDLBatteryInfo(nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBatteryInfo(networkId, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SETDL_BSSTRANSINFO_Test_001
 * @tc.desc: lnn set DL bss trans info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_BSSTRANSINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    BssTransInfo info;
    (void)memset_s(&info, sizeof(BssTransInfo), 0, sizeof(BssTransInfo));
    int32_t ret = LnnSetDLBssTransInfo(nullptr, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetDLBssTransInfo(networkId, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SETDL_PROXYPORT_Test_001
 * @tc.desc: lnn set DL proxy port test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_PROXYPORT_Test_001, TestSize.Level1)
{
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t proxyPort = 0;
    int32_t ret = LnnSetDLProxyPort(nullptr, type, proxyPort);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SETDL_SESSIONPORT_Test_001
 * @tc.desc: lnn set DL session port test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_SESSIONPORT_Test_001, TestSize.Level1)
{
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t sessionPort = 0;
    int32_t ret = LnnSetDLSessionPort(nullptr, type, sessionPort);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SETDL_AUTHPORT_Test_001
 * @tc.desc: lnn set DL auth port test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SETDL_AUTHPORT_Test_001, TestSize.Level1)
{
    const char *id = "softBus";
    IdCategory type = CATEGORY_NETWORK_ID;
    int32_t authPort = 0;
    int32_t ret = LnnSetDLAuthPort(nullptr, type, authPort);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = LnnSetDLAuthPort(id, type, authPort);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOFTBUS_DUMPBUSCENTER_Test_001
 * @tc.desc: softbus dump buscenter remote device info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, SOFTBUS_DUMPBUSCENTER_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    int32_t ret = SoftBusDumpBusCenterRemoteDeviceInfo(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GETREMOTE_BOOLINFO_Test_001
 * @tc.desc: lnn get remote bool info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_BOOLINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BOOL_KEY_END;
    bool info = false;
    int32_t ret = LnnGetRemoteBoolInfo(nullptr, key, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfo(networkId, key, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteBoolInfo(networkId, key, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    key = BOOL_KEY_BEGIN;
    ret = LnnGetRemoteBoolInfo(networkId, key, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GETREMOTE_NUMU64INFO_Test_001
 * @tc.desc: lnn get remote bool info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_NUMU64INFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    InfoKey key = BOOL_KEY_END;
    uint64_t info = 0;
    int32_t ret = LnnGetRemoteNumU64Info(nullptr, key, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(networkId, key, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRemoteNumU64Info(networkId, key, &info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    key = BOOL_KEY_BEGIN;
    ret = LnnGetRemoteNumU64Info(networkId, key, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GETREMOTE_NODEINFO_Test_001
 * @tc.desc: lnn get remote node info by id test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_GETREMOTE_NODEINFO_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    IdCategory type = CATEGORY_NETWORK_ID;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(networkId, type, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REFRESH_DEVICEONLINE_ANDINFO_Test_001
 * @tc.desc: lnn refresh device online state and devid info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_REFRESH_DEVICEONLINE_ANDINFO_Test_001, TestSize.Level1)
{
    DeviceInfo device;
    (void)memset_s(&device, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    InnerDeviceInfoAddtions additions;
    (void)memset_s(&additions, sizeof(InnerDeviceInfoAddtions), 0, sizeof(InnerDeviceInfoAddtions));
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

/*
 * @tc.name: DLGET_FEATURE_CAP_Test_001
 * @tc.desc: dl get feature cap test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_FEATURE_CAP_Test_001, TestSize.Level1)
{
    const char *networkId = "softBus";
    uint32_t len = 0;
    int32_t ret = DlGetFeatureCap(networkId, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = LNN_COMMON_LEN_64;
    ret = DlGetFeatureCap(networkId, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_DLWIFIDIRECT_ADDR_Test_001
 * @tc.desc: lnn get lnn relation test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_SET_DLWIFIDIRECT_ADDR_Test_001, TestSize.Level1)
{
    bool ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, nullptr);
    EXPECT_FALSE(ret);
    char wifiDirectAddr1[MAC_LEN] = "11223344556677889";
    ret = LnnSetDLWifiDirectAddr(nullptr, wifiDirectAddr1);
    EXPECT_FALSE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, wifiDirectAddr1);
    EXPECT_TRUE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE2_NETWORK_ID, wifiDirectAddr1);
    EXPECT_FALSE(ret);

    char wifiDirectAddr2[MAC_LEN] = "11223344";
    ret = LnnSetDLWifiDirectAddr(nullptr, wifiDirectAddr2);
    EXPECT_FALSE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE1_NETWORK_ID, wifiDirectAddr2);
    EXPECT_TRUE(ret);
    ret = LnnSetDLWifiDirectAddr(NODE2_NETWORK_ID, wifiDirectAddr2);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: DLGET_STATIC_CAP_Test_001
 * @tc.desc: dl get static cap test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_STATIC_CAP_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetStaticCap(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetStaticCap(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetStaticCap(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DLGET_STATIC_CAP_LEN_Test_001
 * @tc.desc: dl get static cap len test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_STATIC_CAP_LEN_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetStaticCapLen(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetStaticCapLen(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetStaticCapLen(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DLGET_REMOTE_PTK_Test_001
 * @tc.desc: dl get remote ptk test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, DLGET_REMOTE_PTK_Test_001, TestSize.Level1)
{
    uint32_t len = 0;
    int32_t ret = DlGetRemotePtk(nullptr, true, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    len = STATIC_CAP_LEN + 1;
    ret = DlGetRemotePtk(nullptr, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *networkId = "softbus";
    ret = DlGetRemotePtk(networkId, true, nullptr, STATIC_CAP_LEN + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LnnSetDLUnifiedDeviceName_Test_001
 * @tc.desc: LnnSetDLUnifiedDeviceName
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.key, SESSION_KEY_LENGTH, "newkey", strlen("newkey")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.cipherInfo.key, SESSION_KEY_LENGTH, "oldkey", strlen("oldkey")));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.key, SESSION_KEY_LENGTH, "samekey", strlen("samekey")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.cipherInfo.key, SESSION_KEY_LENGTH, "samekey", strlen("samekey")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "newiv", strlen("newiv")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "oldiv", strlen("oldiv")));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "sameiv", strlen("sameiv")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.cipherInfo.iv, SESSION_KEY_LENGTH, "sameiv", strlen("sameiv")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "newpeerIrk", strlen("newpeerIrk")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "oldIrk", strlen("oldIrk")));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(EOK, memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "sameIrk", strlen("sameIrk")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "sameIrk", strlen("sameIrk")));
    ret = UpdateFileInfo(&newInfo, &oldInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(EOK, memcpy_s(newInfo.sparkCheck, SPARK_CHECK_LENGTH, "newSparkCheck", strlen("newSparkCheck")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.sparkCheck, SPARK_CHECK_LENGTH, "oldSparkCheck", strlen("oldSparkCheck")));
    EXPECT_EQ(UpdateFileInfo(&newInfo, &oldInfo), SOFTBUS_OK);
    EXPECT_EQ(EOK, memcpy_s(newInfo.sparkCheck, SPARK_CHECK_LENGTH, "sameSparkCheck", strlen("sameSparkCheck")));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.sparkCheck, SPARK_CHECK_LENGTH, "sameSparkCheck", strlen("sameSparkCheck")));
    EXPECT_EQ(UpdateFileInfo(&newInfo, &oldInfo), SOFTBUS_OK);
}

/*
 * @tc.name: Lnn_IsAvailableMeta_Test_001
 * @tc.desc: IsAvailableMeta
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsAvailableMeta_Test_001, TestSize.Level1)
{
    bool ret = IsAvailableMeta(nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: Lnn_IsAvailableMeta_Test_002
 * @tc.desc: IsAvailableMeta
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsAvailableMeta_Test_002, TestSize.Level1)
{
    const char *peerNetworkId = "testNetworkId";
    bool ret = IsAvailableMeta(peerNetworkId);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: Lnn_IsAvailableMeta_Test_003
 * @tc.desc: IsAvailableMeta
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsAvailableMeta_Test_003, TestSize.Level1)
{
    bool ret = IsAvailableMeta(NODE1_NETWORK_ID);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: Lnn_IsAvailableMeta_Test_004
 * @tc.desc: IsAvailableMeta
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsAvailableMeta_Test_004, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceInfo = LnnRetrieveDeviceInfo;

    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));

    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = DISCOVERY_TYPE;
    (void)strncpy_s(info.uuid, UUID_BUF_LEN, NODE2_UUID, strlen(NODE2_UUID));
    (void)strncpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE2_UDID, strlen(NODE2_UDID));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID, strlen(NODE2_NETWORK_ID));
    (void)strncpy_s(info.connectInfo.macAddr, MAC_LEN, NODE2_BT_MAC, strlen(NODE2_BT_MAC));
    info.authSeq[0] = AUTH_SEQ;
    info.heartbeatTimestamp = TIME_STAMP;
    info.AuthTypeValue = 1 << ONLINE_METANODE;
    EXPECT_EQ(REPORT_ONLINE, LnnAddOnlineNode(&info));
    bool ret = IsAvailableMeta(NODE2_NETWORK_ID);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: Lnn_IsRemoteDeviceSupportBleGuide_Test_001
 * @tc.desc: IsRemoteDeviceSupportBleGuide
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsRemoteDeviceSupportBleGuide_Test_001, TestSize.Level1)
{
    bool ret = IsRemoteDeviceSupportBleGuide(nullptr, CATEGORY_UDID);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: Lnn_IsRemoteDeviceSupportBleGuide_Test_002
 * @tc.desc: IsRemoteDeviceSupportBleGuide
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsRemoteDeviceSupportBleGuide_Test_002, TestSize.Level1)
{
    bool ret = IsRemoteDeviceSupportBleGuide("test_id", CATEGORY_UDID);
    EXPECT_FALSE(ret);
    ret = IsRemoteDeviceSupportBleGuide("test_id", CATEGORY_UUID);
    EXPECT_FALSE(ret);
    ret = IsRemoteDeviceSupportBleGuide("test_id", CATEGORY_NETWORK_ID);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: Lnn_IsRemoteDeviceSupportBleGuide_Test_003
 * @tc.desc: IsRemoteDeviceSupportBleGuide
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_IsRemoteDeviceSupportBleGuide_Test_003, TestSize.Level1)
{
    bool ret = IsRemoteDeviceSupportBleGuide(NODE1_UDID, CATEGORY_UDID);
    EXPECT_TRUE(ret);
    ret = IsRemoteDeviceSupportBleGuide(NODE1_UUID, CATEGORY_UUID);
    EXPECT_TRUE(ret);
    ret = IsRemoteDeviceSupportBleGuide(NODE1_NETWORK_ID, CATEGORY_NETWORK_ID);
    EXPECT_TRUE(ret);
    ret = IsRemoteDeviceSupportBleGuide(NODE2_UDID, CATEGORY_UDID);
    EXPECT_FALSE(ret);
    ret = IsRemoteDeviceSupportBleGuide(NODE2_UUID, CATEGORY_UUID);
    EXPECT_FALSE(ret);
    ret = IsRemoteDeviceSupportBleGuide(NODE2_NETWORK_ID, CATEGORY_NETWORK_ID);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GET_AND_SAVE_REMOTE_DEVICE_INFO_ID_Test_001
 * @tc.desc: GetAndSaveRemoteDeviceInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, GET_AND_SAVE_REMOTE_DEVICE_INFO_ID_Test_001, TestSize.Level1)
{
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    EXPECT_EQ(EOK, strcpy_s(info.uuid, UUID_BUF_LEN, NODE1_UUID));
    EXPECT_EQ(EOK, memcpy_s(info.rpaInfo.peerIrk, LFINDER_IRK_LEN, "newpeerIrk", strlen("newpeerIrk")));
    EXPECT_EQ(EOK, memcpy_s(info.cipherInfo.key, SESSION_KEY_LENGTH, "key", strlen("key")));
    EXPECT_EQ(EOK, memcpy_s(info.cipherInfo.iv, BROADCAST_IV_LEN, "iv", strlen("iv")));
    EXPECT_EQ(EOK, strcpy_s(info.remotePtk, PTK_DEFAULT_LEN, "newPtk"));
    EXPECT_EQ(EOK, strcpy_s(deviceInfo.remotePtk, PTK_DEFAULT_LEN, "oldPtk"));
    info.netCapacity = 15;
    info.accountId = 100;
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(GetAndSaveRemoteDeviceInfo(&deviceInfo, &info));
}

/*
 * @tc.name: LNN_UPDATE_NETWORK_ID_Test_001
 * @tc.desc: LnnUpdateNetworkId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_NETWORK_ID_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID));
    EXPECT_EQ(LnnUpdateNetworkId(&info), SOFTBUS_OK);
}

/*
 * @tc.name: CHECK_USER_ID_CHECK_SUM_CHANGE_Test_001
 * @tc.desc: CheckUserIdCheckSumChange test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, CHECK_USER_ID_CHECK_SUM_CHANGE_Test_001, TestSize.Level1)
{
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.userIdCheckSum, USERID_CHECKSUM_LEN, "100", strlen("100")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.userIdCheckSum, USERID_CHECKSUM_LEN, "100", strlen("100")));
    EXPECT_EQ(EOK, strcpy_s(newInfo.networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID));
    newInfo.discoveryType = DISCOVERY_TYPE;
    EXPECT_NO_FATAL_FAILURE(CheckUserIdCheckSumChange(nullptr, &newInfo));
    EXPECT_NO_FATAL_FAILURE(CheckUserIdCheckSumChange(&oldInfo, nullptr));
    EXPECT_NO_FATAL_FAILURE(CheckUserIdCheckSumChange(&oldInfo, &newInfo));
}

/*
 * @tc.name: UPDATE_REMOTE_NODE_INFO_Test_001
 * @tc.desc: UpdateRemoteNodeInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, UPDATE_REMOTE_NODE_INFO_Test_001, TestSize.Level1)
{
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, memcpy_s(oldInfo.userIdCheckSum, USERID_CHECKSUM_LEN, "100", strlen("100")));
    oldInfo.discoveryType = DISCOVERY_TYPE;
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, memcpy_s(newInfo.userIdCheckSum, USERID_CHECKSUM_LEN, "101", strlen("101")));
    EXPECT_EQ(EOK, strcpy_s(newInfo.networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID));
    newInfo.discoveryType = DISCOVERY_TYPE;
    newInfo.connectInfo.ifInfo[WLAN_IF].authPort = 0;
    newInfo.connectInfo.ifInfo[WLAN_IF].proxyPort = 1;
    newInfo.connectInfo.ifInfo[WLAN_IF].sessionPort = 3;
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.nickName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.accountHash, SHA_256_HASH_LEN, ACCOUNT_HASH));
    newInfo.accountId = 100;
    newInfo.userId = 100;
    newInfo.localStateVersion = 1;
    newInfo.stateVersion = 123;
    int32_t connectionType = CONNECTION_ADDR_BLE;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateRemoteNodeInfo(nullptr, &newInfo, connectionType, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateRemoteNodeInfo(&oldInfo, nullptr, connectionType, nullptr));
    EXPECT_EQ(SOFTBUS_OK, UpdateRemoteNodeInfo(&oldInfo, &newInfo, connectionType, nullptr));
}

/*
 * @tc.name: ONLINE_PREVENT_BR_CONNECTION_Test_001
 * @tc.desc: OnlinePreventBrConnection test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, ONLINE_PREVENT_BR_CONNECTION_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    EXPECT_EQ(EOK, strcpy_s(info.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC));
    EXPECT_EQ(EOK, strcpy_s(info.softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION));
    info.bleStartTimestamp = TIME_STAMP;
    EXPECT_NO_FATAL_FAILURE(OnlinePreventBrConnection(&info));
}

/*
 * @tc.name: LNN_UPDATE_ACCOUNT_INFO_Test_001
 * @tc.desc: LnnUpdateAccountInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_ACCOUNT_INFO_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID));
    info.accountId = 100;
    info.userId = 100;
    EXPECT_EQ(SOFTBUS_OK, LnnUpdateAccountInfo(&info));
}

/*
 * @tc.name: LNN_UPDATE_REMOTE_DEVICE_NAME_Test_001
 * @tc.desc: LnnUpdateRemoteDeviceName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_UPDATE_REMOTE_DEVICE_NAME_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, LnnUpdateRemoteDeviceName(nullptr));
    EXPECT_EQ(SOFTBUS_OK, LnnUpdateRemoteDeviceName(&info));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, NODE1_DEVICE_NAME));
    EXPECT_EQ(SOFTBUS_OK, LnnUpdateRemoteDeviceName(&info));
    EXPECT_EQ(EOK, strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE3_UDID));
    EXPECT_EQ(SOFTBUS_OK, LnnUpdateRemoteDeviceName(&info));
}

/*
 * @tc.name: CLEAR_AUTH_CHANNEL_ID_Test_001
 * @tc.desc: ClearAuthChannelId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, CLEAR_AUTH_CHANNEL_ID_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.discoveryType = 4;
    info.authChannelId[CONNECTION_ADDR_BLE][AUTH_AS_CLIENT_SIDE] = AUTH_ID;
    info.authChannelId[CONNECTION_ADDR_BLE][AUTH_AS_CLIENT_SIDE] = AUTH_ID;
    EXPECT_EQ(REPORT_OFFLINE, ClearAuthChannelId(&info, CONNECTION_ADDR_BLE, AUTH_ID));
    EXPECT_EQ(REPORT_OFFLINE, ClearAuthChannelId(&info, CONNECTION_ADDR_BLE, 0));
    info.discoveryType = 8;
    EXPECT_EQ(REPORT_OFFLINE, ClearAuthChannelId(&info, CONNECTION_ADDR_BLE, 0));
}

/*
 * @tc.name: LNN_CONVERT_DL_ID_Test_001
 * @tc.desc: LnnConvertDlId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LNN_CONVERT_DL_ID_Test_001, TestSize.Level1)
{
    const char *srcId = "123456ABCDEF";
    char dstIdBuf[UDID_BUF_LEN] = { 0 };
    EXPECT_EQ(
        SOFTBUS_OK, LnnConvertDlId(const_cast<char *>(srcId), CATEGORY_UDID, CATEGORY_UDID, dstIdBuf, UDID_BUF_LEN));
    const char *srcId1 = "123456ABCDEFGHI";
    char dstIdBuf1[UUID_BUF_LEN] = { 0 };
    EXPECT_EQ(SOFTBUS_NOT_FIND,
        LnnConvertDlId(const_cast<char *>(srcId1), CATEGORY_UUID, CATEGORY_UUID, dstIdBuf1, UUID_BUF_LEN));
    const char *srcId2 = "235689BNHFCF";
    char dstIdBuf2[NETWORK_ID_BUF_LEN] = { 0 };
    EXPECT_EQ(SOFTBUS_OK,
        LnnConvertDlId(
            const_cast<char *>(srcId2), CATEGORY_NETWORK_ID, CATEGORY_NETWORK_ID, dstIdBuf2, NETWORK_ID_BUF_LEN));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, LnnConvertDlId(nullptr, CATEGORY_UDID, CATEGORY_UDID, dstIdBuf, UDID_BUF_LEN));
    EXPECT_EQ(SOFTBUS_NOT_FIND,
        LnnConvertDlId(const_cast<char *>(srcId2), CATEGORY_UDID, CATEGORY_UDID, dstIdBuf, UDID_BUF_LEN));
}

/*
 * @tc.name: UPDATE_DEVICE_NAME_TO_DLEDGER_Test_001
 * @tc.desc: UpdateDeviceNameToDLedger test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, UPDATE_DEVICE_NAME_TO_DLEDGER_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceNameToDLedger(&newInfo, &oldInfo));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.nickName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.unifiedDefaultName, DEVICE_NAME_BUF_LEN, NODE2_DEVICE_NAME));
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceNameToDLedger(&newInfo, &oldInfo));
}

/*
 * @tc.name: UPDATE_DEV_BASIC_INFO_TO_DLEDGER_Test_001
 * @tc.desc: UpdateDevBasicInfoToDLedger test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, UPDATE_DEV_BASIC_INFO_TO_DLEDGER_Test_001, TestSize.Level1)
{
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(newInfo.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, NODE1_UDID));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, SOFTBUS_VERSION));
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(oldInfo.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    oldInfo.status = STATUS_OFFLINE;
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
    EXPECT_EQ(EOK, strcpy_s(oldInfo.networkId, NETWORK_ID_BUF_LEN, NODE2_NETWORK_ID));
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
    oldInfo.status = STATUS_ONLINE;
    oldInfo.discoveryType = 2;
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
    oldInfo.discoveryType = 4;
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnFindDeviceUdidTrustedInfoFromDb)
        .WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnFindDeviceUdidTrustedInfoFromDb).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(UpdateDevBasicInfoToDLedger(&newInfo, &oldInfo));
}

/*
 * @tc.name: UPDATE_DISTRIBUTED_LEDGER_Test_001
 * @tc.desc: UpdateDistributedLedger test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, UPDATE_DISTRIBUTED_LEDGER_Test_001, TestSize.Level1)
{
    NodeInfo newInfo;
    (void)memset_s(&newInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnFindDeviceUdidTrustedInfoFromDb).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(UpdateDistributedLedger(nullptr, &oldInfo));
    EXPECT_NO_FATAL_FAILURE(UpdateDistributedLedger(&newInfo, nullptr));
    EXPECT_EQ(EOK, strcpy_s(newInfo.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    EXPECT_EQ(EOK, strcpy_s(newInfo.softBusVersion, VERSION_MAX_LEN, SOFTBUS_VERSION));
    EXPECT_EQ(EOK, strcpy_s(newInfo.connectInfo.macAddr, MAC_LEN, NODE1_BT_MAC));
    EXPECT_EQ(EOK, strcpy_s(newInfo.deviceInfo.osVersion, OS_VERSION_BUF_LEN, SOFTBUS_VERSION));
    EXPECT_EQ(EOK, strcpy_s(newInfo.p2pInfo.p2pMac, MAC_LEN, P2P_MAC));
    EXPECT_EQ(EOK, memcpy_s(newInfo.rpaInfo.peerIrk, LFINDER_IRK_LEN, "newpeerIrk", strlen("newpeerIrk")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.rpaInfo.publicAddress, LFINDER_MAC_ADDR_LEN, "12345", strlen("12345")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.key, SESSION_KEY_LENGTH, "samekey", strlen("samekey")));
    EXPECT_EQ(EOK, memcpy_s(newInfo.cipherInfo.iv, BROADCAST_IV_LEN, "samekeyIv", strlen("samekeyIv")));
    EXPECT_EQ(EOK, strcpy_s(oldInfo.networkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID));
    EXPECT_NO_FATAL_FAILURE(UpdateDistributedLedger(&newInfo, &oldInfo));
}

/*
 * @tc.name: IS_IGNORE_UPDATE_TO_LEDGER_Test_001
 * @tc.desc: IsIgnoreUpdateToLedger test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, IS_IGNORE_UPDATE_TO_LEDGER_Test_001, TestSize.Level1)
{
    int32_t oldStateVersion = 0;
    uint64_t oldTimestamp = 1;
    int32_t newStateVersion = 0;
    uint64_t newTimestamp = 0;
    EXPECT_EQ(true, IsIgnoreUpdateToLedger(oldStateVersion, oldTimestamp, newStateVersion, newTimestamp));
    newTimestamp = 1;
    EXPECT_EQ(false, IsIgnoreUpdateToLedger(oldStateVersion, oldTimestamp, newStateVersion, newTimestamp));
}

/*
 * @tc.name: Dl_Get_Device_Security_Level_Test_001
 * @tc.desc: DlGetDeviceSecurityLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Dl_Get_Device_Security_Level_Test_001, TestSize.Level1)
{
    const char *networkId = NODE1_NETWORK_ID;
    int32_t level = 0;
    int32_t ret = DlGetDeviceSecurityLevel(networkId, false, reinterpret_cast<void *>(&level), LNN_COMMON_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetDeviceSecurityLevel(networkId, false, reinterpret_cast<void *>(&level), LNN_COMMON_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: Is_Node_Info_Screen_Status_Support_Test_001
 * @tc.desc: IsNodeInfoScreenStatusSupport test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Is_Node_Info_Screen_Status_Support_Test_001, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    info.heartbeatCapacity |= 1 << (uint32_t)BIT_SUPPORT_SCREEN_STATUS;
    EXPECT_EQ(IsNodeInfoScreenStatusSupport(&info), SOFTBUS_OK);
    info.heartbeatCapacity &= ~(1 << (uint32_t)BIT_SUPPORT_SCREEN_STATUS);
    EXPECT_EQ(IsNodeInfoScreenStatusSupport(&info), SOFTBUS_NETWORK_NOT_SUPPORT);
}

/*
 * @tc.name: Lnn_Set_Remote_Screen_Status_Info_Test_001
 * @tc.desc: LnnSetRemoteScreenStatusInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Lnn_Set_Remote_Screen_Status_Info_Test_001, TestSize.Level1)
{
    EXPECT_EQ(LnnSetRemoteScreenStatusInfo(nullptr, false), false);
    const char *networkId = NODE1_NETWORK_ID;
    EXPECT_EQ(LnnSetRemoteScreenStatusInfo(networkId, false), false);
}

/*
 * @tc.name: Dl_Get_Conn_Sub_Feature_Cap_Test_001
 * @tc.desc: DlGetConnSubFeatureCap test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Dl_Get_Conn_Sub_Feature_Cap_Test_001, TestSize.Level1)
{
    EXPECT_EQ(DlGetConnSubFeatureCap(nullptr, false, nullptr, LNN_COMMON_LEN_64 - 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DlGetConnSubFeatureCap(nullptr, false, nullptr, LNN_COMMON_LEN_64), SOFTBUS_INVALID_PARAM);
    const char *networkId = NODE1_NETWORK_ID;
    uint64_t capability = 0;
    int32_t ret = DlGetConnSubFeatureCap(networkId, false, reinterpret_cast<void *>(&capability), LNN_COMMON_LEN_64);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: Dl_Get_Wifi_Cfg_Test_001
 * @tc.desc: DlGetWifiCfg test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Dl_Get_Wifi_Cfg_Test_001, TestSize.Level1)
{
    EXPECT_EQ(DlGetWifiCfg(nullptr, false, nullptr, LNN_COMMON_LEN_64), SOFTBUS_INVALID_PARAM);
    const char *networkId = NODE1_NETWORK_ID;
    char buf[WIFI_CFG_INFO_MAX_LEN] = { 0 };
    EXPECT_EQ(DlGetWifiCfg(networkId, false, reinterpret_cast<void *>(buf), WIFI_CFG_INFO_MAX_LEN), SOFTBUS_OK);
    EXPECT_EQ(DlGetChanList5g(nullptr, false, nullptr, CHANNEL_LIST_STR_LEN), SOFTBUS_INVALID_PARAM);
    char buff[CHANNEL_LIST_STR_LEN] = { 0 };
    EXPECT_EQ(DlGetChanList5g(networkId, false, reinterpret_cast<void *>(buff), CHANNEL_LIST_STR_LEN), SOFTBUS_OK);
}

/*
 * @tc.name: Dl_Get_P2p_Role_Test_001
 * @tc.desc: DlGetP2pRole test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Dl_Get_P2p_Role_Test_001, TestSize.Level1)
{
    EXPECT_EQ(DlGetP2pRole(nullptr, false, nullptr, LNN_COMMON_LEN - 1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DlGetP2pRole(nullptr, false, nullptr, LNN_COMMON_LEN), SOFTBUS_INVALID_PARAM);
    const char *networkId = NODE1_NETWORK_ID;
    int32_t p2pRole = 0;
    EXPECT_EQ(DlGetP2pRole(networkId, false, reinterpret_cast<void *>(&p2pRole), LNN_COMMON_LEN), SOFTBUS_OK);
}

/*
 * @tc.name: Dl_Get_State_Version_Test_001
 * @tc.desc: DlGetStateVersion test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, Dl_Get_State_Version_Test_001, TestSize.Level1)
{
    EXPECT_EQ(DlGetStateVersion(nullptr, false, nullptr, LNN_COMMON_LEN - 1), SOFTBUS_INVALID_PARAM);
    const char *networkId = NODE1_NETWORK_ID;
    int32_t version = 0;
    EXPECT_EQ(DlGetStateVersion(networkId, false, reinterpret_cast<void *>(&version), LNN_COMMON_LEN), SOFTBUS_OK);
}

/*
 * @tc.name: DlGetStaFrequency_Test_001
 * @tc.desc: DlGetStaFrequency test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, DlGetStaFrequency_Test_001, TestSize.Level1)
{
    const char *networkId = NODE1_NETWORK_ID;
    int32_t frequency = 0;
    EXPECT_EQ(DlGetStaFrequency(networkId, false, reinterpret_cast<void *>(&frequency), LNN_COMMON_LEN), SOFTBUS_OK);
    bool flag = false;
    EXPECT_EQ(DlGetNodeTlvNegoFlag(networkId, true, reinterpret_cast<void *>(&flag), sizeof(bool)), SOFTBUS_OK);
    int32_t ret = DlGetNodeScreenOnFlag(networkId, true, reinterpret_cast<void *>(&flag), sizeof(bool) - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DlGetNodeScreenOnFlag(networkId, true, reinterpret_cast<void *>(&flag), sizeof(bool));
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_SUPPORT);
}

/*
 * @tc.name: LnnSetDLDeviceNickName_Test_001
 * @tc.desc: LnnSetDLDeviceNickName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDLDeviceNickName_Test_001, TestSize.Level1)
{
    EXPECT_EQ(LnnSetDLDeviceNickName(nullptr, nullptr), false);
    const char *networkId = NODE1_NETWORK_ID;
    EXPECT_EQ(LnnSetDLDeviceNickName(networkId, nullptr), false);
    const char *name = "testNickName";
    EXPECT_EQ(LnnSetDLDeviceNickName(networkId, name), true);
}

/*
 * @tc.name: LnnSetDlPtk_Test_001
 * @tc.desc: LnnSetDlPtk test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDlPtk_Test_001, TestSize.Level1)
{
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnRetrieveDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    const char *remotePtk = "remotePtkTest";
    const char *networkId = NODE1_NETWORK_ID;
    EXPECT_EQ(LnnSetDlPtk(nullptr, remotePtk), false);
    EXPECT_EQ(LnnSetDlPtk(networkId, nullptr), false);
    EXPECT_EQ(LnnSetDlPtk(networkId, remotePtk), true);
    uint64_t timestamp;
    EXPECT_EQ(LnnGetDLBleDirectTimestamp(nullptr, &timestamp), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDLBleDirectTimestamp(networkId, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDLBleDirectTimestamp(networkId, &timestamp), SOFTBUS_OK);
}

/*
 * @tc.name: LnnGetDLUpdateTimestamp_Test_001
 * @tc.desc: LnnGetDLUpdateTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnGetDLUpdateTimestamp_Test_001, TestSize.Level1)
{
    const char *udid = NODE1_UDID;
    uint64_t timestamp;
    EXPECT_EQ(LnnGetDLUpdateTimestamp(nullptr, &timestamp), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDLUpdateTimestamp(udid, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnGetDLUpdateTimestamp(udid, &timestamp), SOFTBUS_OK);
    const char *networkId = NODE1_NETWORK_ID;
    uint32_t authCapacity;
    EXPECT_EQ(LnnGetDLAuthCapacity(networkId, &authCapacity), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSetDLBleDirectTimestamp_Test_001
 * @tc.desc: LnnSetDLBleDirectTimestamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDLBleDirectTimestamp_Test_001, TestSize.Level1)
{
    const char *networkId = NODE1_NETWORK_ID;
    uint64_t timestamp = 22222;
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDLBleDirectTimestamp(networkId, timestamp), SOFTBUS_OK);
    uint32_t connCapability = 33;
    int32_t ret = LnnSetDLConnCapability(networkId, connCapability);
    EXPECT_TRUE(ret == SOFTBUS_OK || ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LnnSetDLConnUserIdCheckSum_Test_001
 * @tc.desc: LnnSetDLConnUserIdCheckSum test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDLConnUserIdCheckSum_Test_001, TestSize.Level1)
{
    const char *networkId = NODE1_NETWORK_ID;
    int32_t userIdCheckSum = 100;
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDLConnUserIdCheckSum(nullptr, userIdCheckSum), SOFTBUS_INVALID_PARAM);
    int32_t ret = LnnSetDLConnUserIdCheckSum(networkId, userIdCheckSum);
    EXPECT_TRUE(ret == SOFTBUS_OK || ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: LnnSetDLConnUserId_Test_001
 * @tc.desc: LnnSetDLConnUserId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDLConnUserId_Test_001, TestSize.Level1)
{
    const char *networkId = NODE1_NETWORK_ID;
    int32_t userId = 1;
    NiceMock<LnnDisctributedNetLedgerInterfaceMock> lnnDisctributedNetLedgerMock;
    EXPECT_CALL(lnnDisctributedNetLedgerMock, LnnSaveRemoteDeviceInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetDLConnUserId(nullptr, userId), SOFTBUS_INVALID_PARAM);
    int32_t ret = LnnSetDLConnUserId(networkId, userId);
    EXPECT_TRUE(ret == SOFTBUS_OK || ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: GetNodeInfoDiscovery_Test_001
 * @tc.desc: GetNodeInfoDiscovery BLE online update heartbeatTimestamp
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, GetNodeInfoDiscovery_Test_001, TestSize.Level1)
{
    NodeInfo info;
    NodeInfoAbility infoAbility;
    (void)memset_s(&infoAbility, sizeof(NodeInfoAbility), 0, sizeof(infoAbility));
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(info));
    info.discoveryType = 1 << DISCOVERY_TYPE_BLE;
    EXPECT_NO_FATAL_FAILURE(GetNodeInfoDiscovery(NULL, &info, &infoAbility));
    info.discoveryType = 1 << DISCOVERY_TYPE_WIFI;
    EXPECT_NO_FATAL_FAILURE(GetNodeInfoDiscovery(NULL, &info, &infoAbility));
}

/*
 * @tc.name: DlGetDeviceSparkCheck_Test_001
 * @tc.desc: DlGetDeviceSparkCheck
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require: IBH09C
 */
HWTEST_F(LNNDisctributedLedgerTest, DlGetDeviceSparkCheck_Test_001, TestSize.Level1)
{
    unsigned char sparkCheck[SPARK_CHECK_LENGTH] = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, DlGetDeviceSparkCheck(NODE1_NETWORK_ID, true, sparkCheck, 0));
    EXPECT_EQ(SOFTBUS_OK, DlGetDeviceSparkCheck(NODE1_NETWORK_ID, true, sparkCheck, SPARK_CHECK_LENGTH));
}

/*
 * @tc.name: LnnSetDLDeviceSparkCheck_Test_001
 * @tc.desc: LnnSetDLDeviceSparkCheck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDisctributedLedgerTest, LnnSetDLDeviceSparkCheck_Test_001, TestSize.Level1)
{
    const char *sparkCheck = "qqqqqqqqqqqq";
    const char *devUdid = "123456789";
    EXPECT_EQ(LnnSetDLDeviceSparkCheck(nullptr, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnSetDLDeviceSparkCheck(devUdid, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnSetDLDeviceSparkCheck(devUdid, sparkCheck), SOFTBUS_NOT_FIND);
    EXPECT_EQ(LnnSetDLDeviceSparkCheck(NODE1_UDID, sparkCheck), SOFTBUS_OK);
}
} // namespace OHOS
