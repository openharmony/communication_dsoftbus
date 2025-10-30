
  Copyright (c) 2025 Huawei Device Co., Ltd.
  Licensed under the Apache License, Version 2.0 (the License);
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
      httpwww.apache.orglicensesLICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an AS IS BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 

#include gtestgtest.h
#include gmockgmock.h
#include lnn_distributed_net_ledger.h
#include lnn_distributed_net_ledger.c


#include lnn_distributed_net_ledger_new_mock.h

namespace OHOS {
using namespace testingext;
using namespace testing;

constexpr char VALID_UDID[] = 123456789012345678901234567890123456789012345678901234567890ABCD;
constexpr char VALID_NETWORK_ID[] = 1234567890ABCDEF;
constexpr char VALID_UUID[] = 12345678-1234-5678-1234-567812345678;
constexpr char VALID_MAC[] = 112233445566;
constexpr char VALID_IP[] = 192.168.1.1;

class LnnDistributedNetLedgerNewTest  public testingTest {
public
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void LnnDistributedNetLedgerNewTestSetUpTestCase()
{
}

void LnnDistributedNetLedgerNewTestTearDownTestCase()
{
}

void LnnDistributedNetLedgerNewTestSetUp()
{
    g_distributedNetLedger.status = DL_INIT_UNKNOWN;
    (void)memset_s(&g_distributedNetLedger, sizeof(DistributedNetLedger), 0, sizeof(DistributedNetLedger));
    (void)SoftBusMutexInit(&g_distributedNetLedger.lock, NULL);
    LnnMapInit(&g_distributedNetLedger.distributedInfo.udidMap);
    LnnMapInit(&g_distributedNetLedger.distributedInfo.ipMap);
    LnnMapInit(&g_distributedNetLedger.distributedInfo.macMap);
    LnnMapInit(&g_distributedNetLedger.cnnCode.connectionCode);
}

void LnnDistributedNetLedgerNewTestTearDown()
{
    LnnDeinitDistributedLedger();
}


 @tc.name LnnSetAuthTypeValueTest_Invalid
 @tc.desc test LnnSetAuthTypeValue
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnSetAuthTypeValueTest_Invalid, TestSize.Level1)
{
    uint32_t authTypeValue = 0;
    EXPECT_EQ(LnnSetAuthTypeValue(&authTypeValue, AUTH_TYPE_BUTT), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnClearAuthTypeValueTest_Invalid
 @tc.desc test LnnClearAuthTypeValue
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnClearAuthTypeValueTest_Invalid, TestSize.Level1)
{
    uint32_t authTypeValue = 0;
    EXPECT_EQ(LnnClearAuthTypeValue(&authTypeValue, AUTH_TYPE_BUTT), SOFTBUS_INVALID_PARAM);
}


 @tc.name GetNodeInfoFromMapTest_NullMap
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_NullMap, TestSize.Level1)
{
    EXPECT_EQ(GetNodeInfoFromMap(nullptr, test), nullptr);
}


 @tc.name GetNodeInfoFromMapTest_NullId
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_NullId, TestSize.Level1)
{
    DoubleHashMap map;
    LnnMapInit(&map.udidMap);
    EXPECT_EQ(GetNodeInfoFromMap(&map, nullptr), nullptr);
    LnnMapDelete(&map.udidMap);
}


 @tc.name GetNodeInfoFromMapTest_UdidFound
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_UdidFound, TestSize.Level1)
{
    DoubleHashMap map;
    LnnMapInit(&map.udidMap);
    NodeInfo node;
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    LnnMapSet(&map.udidMap, VALID_UDID, &node, sizeof(NodeInfo));
    EXPECT_EQ(GetNodeInfoFromMap(&map, VALID_UDID), &node);
    LnnMapDelete(&map.udidMap);
}


 @tc.name GetNodeInfoFromMapTest_MacFound
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_MacFound, TestSize.Level1)
{
    DoubleHashMap map;
    LnnMapInit(&map.macMap);
    NodeInfo node;
    (void)strcpy_s(node.connectInfo.macAddr, MAC_LEN, VALID_MAC);
    LnnMapSet(&map.macMap, VALID_MAC, &node, sizeof(NodeInfo));
    EXPECT_EQ(GetNodeInfoFromMap(&map, VALID_MAC), &node);
    LnnMapDelete(&map.macMap);
}


 @tc.name GetNodeInfoFromMapTest_IpFound
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_IpFound, TestSize.Level1)
{
    DoubleHashMap map;
    LnnMapInit(&map.ipMap);
    NodeInfo node;
    (void)strcpy_s(node.connectInfo.ifInfo[WLAN_IF].deviceIp, IP_LEN, VALID_IP);
    LnnMapSet(&map.ipMap, VALID_IP, &node, sizeof(NodeInfo));
    EXPECT_EQ(GetNodeInfoFromMap(&map, VALID_IP), &node);
    LnnMapDelete(&map.ipMap);
}


 @tc.name GetNodeInfoFromMapTest_NotFound
 @tc.desc test GetNodeInfoFromMap
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetNodeInfoFromMapTest_NotFound, TestSize.Level1)
{
    DoubleHashMap map;
    LnnMapInit(&map.udidMap);
    LnnMapInit(&map.macMap);
    LnnMapInit(&map.ipMap);
    EXPECT_EQ(GetNodeInfoFromMap(&map, nonexistent), nullptr);
    LnnMapDelete(&map.udidMap);
    LnnMapDelete(&map.macMap);
    LnnMapDelete(&map.ipMap);
}


 @tc.name LnnGetRemoteNodeInfoByIdTest_NullId
 @tc.desc test LnnGetRemoteNodeInfoById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByIdTest_NullId, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(LnnGetRemoteNodeInfoById(nullptr, CATEGORY_UDID, &info), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetRemoteNodeInfoByIdTest_NullInfo
 @tc.desc test LnnGetRemoteNodeInfoById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByIdTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnGetRemoteNodeInfoById(VALID_UDID, CATEGORY_UDID, nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetRemoteNodeInfoByIdTest_NotFound
 @tc.desc test LnnGetRemoteNodeInfoById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByIdTest_NotFound, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(LnnGetRemoteNodeInfoById(nonexistent, CATEGORY_UDID, &info), SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}


 @tc.name LnnGetRemoteNodeInfoByIdTest_Success
 @tc.desc test LnnGetRemoteNodeInfoById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByIdTest_Success, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeInfo result;
    EXPECT_EQ(LnnGetRemoteNodeInfoById(VALID_UDID, CATEGORY_UDID, &result), SOFTBUS_OK);
    EXPECT_STREQ(result.deviceInfo.deviceUdid, VALID_UDID);
}


 @tc.name LnnGetRemoteNodeInfoByKeyTest_NullKey
 @tc.desc test LnnGetRemoteNodeInfoByKey
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByKeyTest_NullKey, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(LnnGetRemoteNodeInfoByKey(nullptr, &info), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetRemoteNodeInfoByKeyTest_NullInfo
 @tc.desc test LnnGetRemoteNodeInfoByKey
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByKeyTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnGetRemoteNodeInfoByKey(some_key, nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetRemoteNodeInfoByKeyTest_NotFound
 @tc.desc test LnnGetRemoteNodeInfoByKey
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByKeyTest_NotFound, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(LnnGetRemoteNodeInfoByKey(nonexistent, &info), SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
}


 @tc.name LnnGetRemoteNodeInfoByKeyTest_Success
 @tc.desc test LnnGetRemoteNodeInfoByKey
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetRemoteNodeInfoByKeyTest_Success, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeInfo result;
    EXPECT_EQ(LnnGetRemoteNodeInfoByKey(VALID_UDID, &result), SOFTBUS_OK);
    EXPECT_STREQ(result.deviceInfo.deviceUdid, VALID_UDID);
}


 @tc.name LnnGetOnlineStateByIdTest_NullId
 @tc.desc test LnnGetOnlineStateById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetOnlineStateByIdTest_NullId, TestSize.Level1)
{
    EXPECT_FALSE(LnnGetOnlineStateById(nullptr, CATEGORY_UDID));
}


 @tc.name LnnGetOnlineStateByIdTest_InvalidId
 @tc.desc test LnnGetOnlineStateById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetOnlineStateByIdTest_InvalidId, TestSize.Level1)
{
    char longId[ID_MAX_LEN + 2];
    (void)memset_s(longId, sizeof(longId), 'a', sizeof(longId));
    longId[sizeof(longId) - 1] = '0';
    EXPECT_FALSE(LnnGetOnlineStateById(longId, CATEGORY_UDID));
}


 @tc.name LnnGetOnlineStateByIdTest_NotFound
 @tc.desc test LnnGetOnlineStateById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetOnlineStateByIdTest_NotFound, TestSize.Level1)
{
    EXPECT_FALSE(LnnGetOnlineStateById(nonexistent, CATEGORY_UDID));
}


 @tc.name LnnGetOnlineStateByIdTest_Online
 @tc.desc test LnnGetOnlineStateById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetOnlineStateByIdTest_Online, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.status = STATUS_ONLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));
    EXPECT_TRUE(LnnGetOnlineStateById(VALID_UDID, CATEGORY_UDID));
}


 @tc.name LnnGetOnlineStateByIdTest_Offline
 @tc.desc test LnnGetOnlineStateById
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetOnlineStateByIdTest_Offline, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.status = STATUS_OFFLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));
    EXPECT_FALSE(LnnGetOnlineStateById(VALID_UDID, CATEGORY_UDID));
}


 @tc.name LnnGetCnnCodeTest_NullUuid
 @tc.desc test LnnGetCnnCode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetCnnCodeTest_NullUuid, TestSize.Level1)
{
    EXPECT_EQ(LnnGetCnnCode(nullptr, DISCOVERY_TYPE_BLE), INVALID_CONNECTION_CODE_VALUE);
}


 @tc.name LnnGetCnnCodeTest_InvalidUuid
 @tc.desc test LnnGetCnnCode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetCnnCodeTest_InvalidUuid, TestSize.Level1)
{
    char longUuid[UUID_BUF_LEN + 2];
    (void)memset_s(longUuid, sizeof(longUuid), 'a', sizeof(longUuid));
    longUuid[sizeof(longUuid) - 1] = '0';
    EXPECT_EQ(LnnGetCnnCode(longUuid, DISCOVERY_TYPE_BLE), INVALID_CONNECTION_CODE_VALUE);
}


 @tc.name LnnGetCnnCodeTest_NotFound
 @tc.desc test LnnGetCnnCode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetCnnCodeTest_NotFound, TestSize.Level1)
{
    EXPECT_EQ(LnnGetCnnCode(VALID_UUID, DISCOVERY_TYPE_BLE), INVALID_CONNECTION_CODE_VALUE);
}


 @tc.name LnnUpdateNodeInfoTest_NullInfo
 @tc.desc test LnnUpdateNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateNodeInfoTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnUpdateNodeInfo(nullptr, CONNECTION_ADDR_BLE), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnUpdateNodeInfoTest_NodeNotFound
 @tc.desc test LnnUpdateNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateNodeInfoTest_NodeNotFound, TestSize.Level1)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, nonexistent);
    EXPECT_EQ(LnnUpdateNodeInfo(&info, CONNECTION_ADDR_BLE), SOFTBUS_NETWORK_MAP_GET_FAILED);
}


 @tc.name LnnAddMetaInfoTest_NullInfo
 @tc.desc test LnnAddMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddMetaInfoTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnAddMetaInfo(nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnDeleteMetaInfoTest_NullUdid
 @tc.desc test LnnDeleteMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnDeleteMetaInfoTest_NullUdid, TestSize.Level1)
{
    EXPECT_EQ(LnnDeleteMetaInfo(nullptr, AUTH_LINK_TYPE_WIFI), SOFTBUS_NETWORK_DELETE_INFO_ERR);
}


 @tc.name LnnDeleteMetaInfoTest_NodeNotFound
 @tc.desc test LnnDeleteMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnDeleteMetaInfoTest_NodeNotFound, TestSize.Level1)
{
    EXPECT_EQ(LnnDeleteMetaInfo(nonexistent, AUTH_LINK_TYPE_WIFI), SOFTBUS_NETWORK_DELETE_INFO_ERR);
}


 @tc.name LnnAddOnlineNodeTest_NullInfo
 @tc.desc test LnnAddOnlineNode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddOnlineNodeTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnAddOnlineNode(nullptr), REPORT_NONE);
}


 @tc.name LnnUpdateAccountInfoTest_NullInfo
 @tc.desc test LnnUpdateAccountInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateAccountInfoTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnUpdateAccountInfo(nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnUpdateRemoteDeviceNameTest_NullInfo
 @tc.desc test LnnUpdateRemoteDeviceName
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateRemoteDeviceNameTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnUpdateRemoteDeviceName(nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnUpdateGroupTypeTest_NullInfo
 @tc.desc test LnnUpdateGroupType
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateGroupTypeTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnUpdateGroupType(nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnSetNodeOfflineTest_NullUdid
 @tc.desc test LnnSetNodeOffline
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnSetNodeOfflineTest_NullUdid, TestSize.Level1)
{
    EXPECT_EQ(LnnSetNodeOffline(nullptr, CONNECTION_ADDR_WLAN, 0), REPORT_NONE);
}


 @tc.name LnnSetNodeOfflineTest_NodeNotFound
 @tc.desc test LnnSetNodeOffline
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnSetNodeOfflineTest_NodeNotFound, TestSize.Level1)
{
    EXPECT_EQ(LnnSetNodeOffline(nonexistent, CONNECTION_ADDR_WLAN, 0), REPORT_NONE);
}


 @tc.name LnnGetBasicInfoByUdidTest_NullUdid
 @tc.desc test LnnGetBasicInfoByUdid
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetBasicInfoByUdidTest_NullUdid, TestSize.Level1)
{
    NodeBasicInfo basicInfo;
    EXPECT_EQ(LnnGetBasicInfoByUdid(nullptr, &basicInfo), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetBasicInfoByUdidTest_NullInfo
 @tc.desc test LnnGetBasicInfoByUdid
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetBasicInfoByUdidTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnGetBasicInfoByUdid(VALID_UDID, nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetBasicInfoByUdidTest_NotFound
 @tc.desc test LnnGetBasicInfoByUdid
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetBasicInfoByUdidTest_NotFound, TestSize.Level1)
{
    NodeBasicInfo basicInfo;
    EXPECT_NE(LnnGetBasicInfoByUdid(nonexistent, &basicInfo), SOFTBUS_OK);
}


 @tc.name LnnRemoveNodeTest_NullUdid
 @tc.desc test LnnRemoveNode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnRemoveNodeTest_NullUdid, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnRemoveNode(nullptr));
}


 @tc.name LnnConvertDLidToUdidTest_NullId
 @tc.desc test LnnConvertDLidToUdid
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnConvertDLidToUdidTest_NullId, TestSize.Level1)
{
    EXPECT_EQ(LnnConvertDLidToUdid(nullptr, CATEGORY_NETWORK_ID), nullptr);
}


 @tc.name LnnConvertDlIdTest_NullSrcId
 @tc.desc test LnnConvertDlId
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnConvertDlIdTest_NullSrcId, TestSize.Level1)
{
    char dstId[UDID_BUF_LEN];
    EXPECT_EQ(LnnConvertDlId(nullptr, CATEGORY_NETWORK_ID, CATEGORY_UDID, dstId, UDID_BUF_LEN), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnConvertDlIdTest_NullDstId
 @tc.desc test LnnConvertDlId
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnConvertDlIdTest_NullDstId, TestSize.Level1)
{
    EXPECT_EQ(LnnConvertDlId(VALID_NETWORK_ID, CATEGORY_NETWORK_ID, CATEGORY_UDID, nullptr, UDID_BUF_LEN),
        SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetLnnRelationTest_NullId
 @tc.desc test LnnGetLnnRelation
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetLnnRelationTest_NullId, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX];
    EXPECT_EQ(LnnGetLnnRelation(nullptr, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetLnnRelationTest_NullRelation
 @tc.desc test LnnGetLnnRelation
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetLnnRelationTest_NullRelation, TestSize.Level1)
{
    EXPECT_EQ(LnnGetLnnRelation(VALID_UDID, CATEGORY_UDID, nullptr, CONNECTION_ADDR_MAX), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnUpdateDistributedNodeInfoTest_NullInfo
 @tc.desc test LnnUpdateDistributedNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateDistributedNodeInfoTest_NullInfo, TestSize.Level1)
{
    EXPECT_EQ(LnnUpdateDistributedNodeInfo(nullptr, VALID_UDID), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnUpdateDistributedNodeInfoTest_NullUdid
 @tc.desc test LnnUpdateDistributedNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateDistributedNodeInfoTest_NullUdid, TestSize.Level1)
{
    NodeInfo info;
    EXPECT_EQ(LnnUpdateDistributedNodeInfo(&info, nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnIsLSANodeTest_NullInfo
 @tc.desc test LnnIsLSANode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnIsLSANodeTest_NullInfo, TestSize.Level1)
{
    EXPECT_FALSE(LnnIsLSANode(nullptr));
}


 @tc.name LnnGetAllOnlineNodeNumTest_Null
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_Null, TestSize.Level1)
{
    EXPECT_EQ(LnnGetAllOnlineNodeNum(nullptr), SOFTBUS_INVALID_PARAM);
}


 @tc.name LnnGetAllOnlineNodeNumTest_Empty
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_Empty, TestSize.Level1)
{
    int32_t num = 0;
    EXPECT_EQ(LnnGetAllOnlineNodeNum(&num), SOFTBUS_OK);
    EXPECT_EQ(num, 0);
}


 @tc.name LnnGetAllOnlineNodeNumTest_OneOnline
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_OneOnline, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.status = STATUS_ONLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    int32_t num = 0;
    EXPECT_EQ(LnnGetAllOnlineNodeNum(&num), SOFTBUS_OK);
    EXPECT_EQ(num, 1);
}


 @tc.name LnnGetAllOnlineNodeNumTest_OneMeta
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_OneMeta, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.metaInfo.isMetaNode = true;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    int32_t num = 0;
    EXPECT_EQ(LnnGetAllOnlineNodeNum(&num), SOFTBUS_OK);
    EXPECT_EQ(num, 1);
}


 @tc.name LnnGetAllOnlineNodeNumTest_OneOnlineOneMeta
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_OneOnlineOneMeta, TestSize.Level1)
{
    NodeInfo node1;
    (void)memset_s(&node1, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node1.deviceInfo.deviceUdid, UDID_BUF_LEN, udid1);
    node1.status = STATUS_ONLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, udid1, &node1, sizeof(NodeInfo));

    NodeInfo node2;
    (void)memset_s(&node2, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node2.deviceInfo.deviceUdid, UDID_BUF_LEN, udid2);
    node2.metaInfo.isMetaNode = true;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, udid2, &node2, sizeof(NodeInfo));

    int32_t num = 0;
    EXPECT_EQ(LnnGetAllOnlineNodeNum(&num), SOFTBUS_OK);
    EXPECT_EQ(num, 2);
}


 @tc.name LnnGetAllOnlineNodeNumTest_OneOffline
 @tc.desc test LnnGetAllOnlineNodeNum
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnGetAllOnlineNodeNumTest_OneOffline, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.status = STATUS_OFFLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    int32_t num = 0;
    EXPECT_EQ(LnnGetAllOnlineNodeNum(&num), SOFTBUS_OK);
    EXPECT_EQ(num, 0);
}


 @tc.name LnnAddOnlineNode_NewNode_Ble
 @tc.desc test LnnAddOnlineNode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddOnlineNode_NewNode_Ble, TestSize.Level1)
{
    NiceMockLnnDistributedNetLedgerInterfaceMock mock;

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    (void)strcpy_s(nodeInfo.uuid, UUID_BUF_LEN, VALID_UUID);
    nodeInfo.discoveryType = DISCOVERY_TYPE_BLE;

    EXPECT_CALL(mock, LnnUpTimeMs()).WillRepeatedly(Return(1000));
    EXPECT_CALL(mock, SoftBusGenerateStrHash(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnSaveRemoteDeviceInfoPacked(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InsertToProfile(_)).Times(1);

    ReportCategory ret = LnnAddOnlineNode(&nodeInfo);
    EXPECT_EQ(ret, REPORT_ONLINE);
}


 @tc.name LnnAddOnlineNode_NewNode_Wifi
 @tc.desc test LnnAddOnlineNode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddOnlineNode_NewNode_Wifi, TestSize.Level1)
{
    NiceMockLnnDistributedNetLedgerInterfaceMock mock;

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    (void)strcpy_s(nodeInfo.uuid, UUID_BUF_LEN, VALID_UUID);
    nodeInfo.discoveryType = DISCOVERY_TYPE_WIFI;

    EXPECT_CALL(mock, LnnUpTimeMs()).WillRepeatedly(Return(1000));
    EXPECT_CALL(mock, SoftBusGenerateStrHash(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnSaveRemoteDeviceInfoPacked(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, InsertToProfile(_)).Times(1);

    ReportCategory ret = LnnAddOnlineNode(&nodeInfo);
    EXPECT_EQ(ret, REPORT_ONLINE);
}


 @tc.name LnnAddOnlineNode_ExistingOfflineNode
 @tc.desc test LnnAddOnlineNode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddOnlineNode_ExistingOfflineNode, TestSize.Level1)
{
    NiceMockLnnDistributedNetLedgerInterfaceMock mock;

    NodeInfo oldNodeInfo;
    (void)memset_s(&oldNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(oldNodeInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    (void)strcpy_s(oldNodeInfo.uuid, UUID_BUF_LEN, VALID_UUID);
    oldNodeInfo.status = STATUS_OFFLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNodeInfo, sizeof(NodeInfo));

    NodeInfo newNodeInfo;
    (void)memset_s(&newNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(newNodeInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    (void)strcpy_s(newNodeInfo.uuid, UUID_BUF_LEN, VALID_UUID);
    newNodeInfo.discoveryType = DISCOVERY_TYPE_BLE;

    EXPECT_CALL(mock, LnnUpTimeMs()).WillRepeatedly(Return(2000));
    EXPECT_CALL(mock, SoftBusGenerateStrHash(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, UpdateProfile(_)).Times(1);

    ReportCategory ret = LnnAddOnlineNode(&newNodeInfo);
    EXPECT_EQ(ret, REPORT_ONLINE);
}


 @tc.name LnnUpdateNodeInfo_Success
 @tc.desc test LnnUpdateNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateNodeInfo_Success, TestSize.Level1)
{
    NiceMockLnnDistributedNetLedgerInterfaceMock mock;

    NodeInfo oldNodeInfo;
    (void)memset_s(&oldNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(oldNodeInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, old_name);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNodeInfo, sizeof(NodeInfo));

    NodeInfo newNodeInfo;
    (void)memset_s(&newNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newNodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(newNodeInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, new_name);

    EXPECT_CALL(mock, SoftBusGenerateStrHash(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnSaveRemoteDeviceInfoPacked(_)).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = LnnUpdateNodeInfo(&newNodeInfo, CONNECTION_ADDR_WLAN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo updatedNode = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_STREQ(updatedNode-deviceInfo.deviceName, new_name);
}


 @tc.name LnnAddMetaInfo_NewNode
 @tc.desc test LnnAddMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddMetaInfo_NewNode, TestSize.Level1)
{
    NodeInfo metaNode;
    (void)memset_s(&metaNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(metaNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    metaNode.metaInfo.isMetaNode = true;

    int32_t ret = LnnAddMetaInfo(&metaNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_TRUE(result-metaInfo.isMetaNode);
}


 @tc.name LnnAddMetaInfo_ExistingNode
 @tc.desc test LnnAddMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnAddMetaInfo_ExistingNode, TestSize.Level1)
{
    NodeInfo oldNode;
    (void)memset_s(&oldNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(oldNode.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNode, sizeof(NodeInfo));

    NodeInfo metaNode;
    (void)memset_s(&metaNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(metaNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(metaNode.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    metaNode.metaInfo.isMetaNode = true;
    metaNode.metaInfo.metaDiscType = (1  DISCOVERY_TYPE_BLE);

    int32_t ret = LnnAddMetaInfo(&metaNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_TRUE(result-metaInfo.isMetaNode);
    EXPECT_TRUE(result-metaInfo.metaDiscType & (1  DISCOVERY_TYPE_BLE));
}


 @tc.name LnnDeleteMetaInfo_Success
 @tc.desc test LnnDeleteMetaInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnDeleteMetaInfo_Success, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    node.metaInfo.isMetaNode = true;
    node.metaInfo.metaDiscType = (1  DISCOVERY_TYPE_BLE);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NiceMockLnnDistributedNetLedgerInterfaceMock mock;
    EXPECT_CALL(mock, ConvertToDiscoveryType(_)).WillRepeatedly(Return(DISCOVERY_TYPE_BLE));

    int32_t ret = LnnDeleteMetaInfo(VALID_UDID, AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_FALSE(result-metaInfo.isMetaNode);
}


 @tc.name LnnConvertDlId_UdidToNetId
 @tc.desc test LnnConvertDlId
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnConvertDlId_UdidToNetId, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnConvertDlId(VALID_UDID, CATEGORY_UDID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(networkId, VALID_NETWORK_ID);
}


 @tc.name LnnConvertDlId_NetIdToUuid
 @tc.desc test LnnConvertDlId
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnConvertDlId_NetIdToUuid, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    (void)strcpy_s(node.uuid, UUID_BUF_LEN, VALID_UUID);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    char uuid[UUID_BUF_LEN] = {0};
    int32_t ret = LnnConvertDlId(VALID_NETWORK_ID, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(uuid, VALID_UUID);
}


 @tc.name LnnUpdateAccountInfo_Success
 @tc.desc test LnnUpdateAccountInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateAccountInfo_Success, TestSize.Level1)
{
    NodeInfo oldNode;
    (void)memset_s(&oldNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    oldNode.accountId = 100;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNode, sizeof(NodeInfo));

    NodeInfo newNode;
    (void)memset_s(&newNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    newNode.accountId = 200;

    NiceMockLnnDistributedNetLedgerInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGenerateStrHash(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = LnnUpdateAccountInfo(&newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result-accountId, 200);
}


 @tc.name LnnUpdateRemoteDeviceName_Success
 @tc.desc test LnnUpdateRemoteDeviceName
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateRemoteDeviceName_Success, TestSize.Level1)
{
    NodeInfo oldNode;
    (void)memset_s(&oldNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(oldNode.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, old_name);
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNode, sizeof(NodeInfo));

    NodeInfo newNode;
    (void)memset_s(&newNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(newNode.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, new_name);

    NiceMockLnnDistributedNetLedgerInterfaceMock mock;
    EXPECT_CALL(mock, LnnNotifyBasicInfoChanged(_, _)).Times(1);
    EXPECT_CALL(mock, AnonymizeWrapper(_)).WillRepeatedly(Return(new_name));

    int32_t ret = LnnUpdateRemoteDeviceName(&newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_STREQ(result-deviceInfo.deviceName, new_name);
}


 @tc.name LnnUpdateGroupType_Success
 @tc.desc test LnnUpdateGroupType
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnUpdateGroupType_Success, TestSize.Level1)
{
    NodeInfo oldNode;
    (void)memset_s(&oldNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(oldNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    oldNode.groupType = 1;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &oldNode, sizeof(NodeInfo));

    NodeInfo newNode;
    (void)memset_s(&newNode, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(newNode.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);

    NiceMockLnnDistributedNetLedgerInterfaceMock mock;
    EXPECT_CALL(mock, AuthGetGroupType(_, _)).WillRepeatedly(Return(2));

    int32_t ret = LnnUpdateGroupType(&newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NodeInfo result = (NodeInfo)LnnMapGet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result-groupType, 2);
}


 @tc.name LnnIsLSANode_True
 @tc.desc test LnnIsLSANode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnIsLSANode_True, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    node.discoveryType = DISCOVERY_TYPE_LSA;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeBasicInfo basicInfo;
    (void)strcpy_s(basicInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);

    EXPECT_TRUE(LnnIsLSANode(&basicInfo));
}


 @tc.name LnnIsLSANode_False
 @tc.desc test LnnIsLSANode
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, LnnIsLSANode_False, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    node.discoveryType = DISCOVERY_TYPE_BLE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeBasicInfo basicInfo;
    (void)strcpy_s(basicInfo.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);

    EXPECT_FALSE(LnnIsLSANode(&basicInfo));
}


 @tc.name GetAllOnlineAndMetaNodeInfo_Empty
 @tc.desc test GetAllOnlineAndMetaNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetAllOnlineAndMetaNodeInfo_Empty, TestSize.Level1)
{
    NodeBasicInfo info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = GetAllOnlineAndMetaNodeInfo(&info, &infoNum, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(infoNum, 0);
    EXPECT_EQ(info, nullptr);
}


 @tc.name GetAllOnlineAndMetaNodeInfo_OneOnline
 @tc.desc test GetAllOnlineAndMetaNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetAllOnlineAndMetaNodeInfo_OneOnline, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    node.status = STATUS_ONLINE;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeBasicInfo info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = GetAllOnlineAndMetaNodeInfo(&info, &infoNum, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(infoNum, 1);
    EXPECT_NE(info, nullptr);
    EXPECT_STREQ(info[0].networkId, VALID_NETWORK_ID);
    SoftBusFree(info);
}


 @tc.name GetAllOnlineAndMetaNodeInfo_OneMeta
 @tc.desc test GetAllOnlineAndMetaNodeInfo
 @tc.type FUNC
 @tc.require

HWTEST_F(LnnDistributedNetLedgerNewTest, GetAllOnlineAndMetaNodeInfo_OneMeta, TestSize.Level1)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strcpy_s(node.deviceInfo.deviceUdid, UDID_BUF_LEN, VALID_UDID);
    (void)strcpy_s(node.networkId, NETWORK_ID_BUF_LEN, VALID_NETWORK_ID);
    node.metaInfo.isMetaNode = true;
    LnnMapSet(&g_distributedNetLedger.distributedInfo.udidMap, VALID_UDID, &node, sizeof(NodeInfo));

    NodeBasicInfo info = nullptr;
    int32_t infoNum = 0;
    int32_t ret = GetAllOnlineAndMetaNodeInfo(&info, &infoNum, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(infoNum, 1);
    EXPECT_NE(info, nullptr);
    EXPECT_STREQ(info[0].networkId, VALID_NETWORK_ID);
    SoftBusFree(info);
}
}  namespace OHOS