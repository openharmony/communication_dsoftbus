/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_mock.h"
#include "lnn_topo_manager.c"
#include "lnn_topo_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"

#define LNN_RELATION_JOIN_THREAD 1
#define LNN_RELATION_ERROR       0
namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char UDID[] = "83b37d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a8651";
constexpr char UDID_1[] = "d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a865183b37";
constexpr char INVALID_UUID[] = "91a0183f4b68272902e7411f8e122fafd59969cd088e22d296be16400dcc9736123";
constexpr char PEER_UDID[] = "dac6f8016d28d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564";
constexpr char PEER_UDID_1[] = "8d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564dac6f8016d2";
constexpr char NETWORK_ID[] = "abc";
constexpr char NETWORK_ID_1[] = "abcd";
constexpr uint8_t OLD_RELATION[] = "1";
constexpr uint8_t NEW_RELATION_1[] = "0";
constexpr uint8_t NEW_RELATION_2[] = "1";
constexpr uint8_t MSG[] = "tempMsg";
constexpr uint32_t MSG_LEN = 7;
constexpr uint32_t RELATION_LEN = 1;
constexpr uint32_t INVALID_RELATION_LEN = 7;
constexpr char MSG_1[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": \"infoTest\"}";
constexpr char MSG_2[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": [{\"udid\": \
    \"83b37d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a8651\", \"peerUdid\": \
    \"dac6f8016d28d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564\", \"wlanRelation\": 1, \
    \"brRelation\": 0, \"bleRelation\": 0, \"ethRelation\": 0}]}";
constexpr char MSG_3[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": [{\"peerUdid\": \
    \"dac6f8016d28d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564\", \"wlanRelation\": 1, \
    \"brRelation\": 0, \"bleRelation\": 0, \"ethRelation\": 0}]}";
constexpr char MSG_4[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": [{\"udid\": \
    \"83b37d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a8651\", \"wlanRelation\": 1, \
    \"brRelation\": 0, \"bleRelation\": 0, \"ethRelation\": 0}]}";
constexpr char MSG_5[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": [{\"udid\": \"\", \"peerUdid\": \
    \"dac6f8016d28d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564\", \"wlanRelation\": 1, \
    \"brRelation\": 0, \"bleRelation\": 0, \"ethRelation\": 0}]}";
constexpr char MSG_6[] = "{\"type\": 0, \"seq\": 20, \"complete\": 1, \"info\": [{\"udid\": \
    \"83b37d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a8651\", \"peerUdid\": \"\", \"wlanRelation\": 1, \
    \"brRelation\": 0, \"bleRelation\": 0, \"ethRelation\": 0}]}";
constexpr char MSG_7[] = "{\"seq\": 20, \"complete\": 1}";
constexpr char MSG_8[] = "{\"type\": 0, \"complete\": 1}";
constexpr char MSG_9[] = "{\"type\": 0, \"seq\": 20}";
constexpr char MSG_10[] = "{\"type\": 1, \"seq\": 20, \"complete\": 1}";
constexpr char MSG_11[] = "{\"type\": 0, \"seq\": 20, \"complete\": 0}";
constexpr char RAND_STR1[] = "-20";
constexpr char RAND_STR2[] = "20";

class LNNTopoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTopoManagerTest::SetUpTestCase() { }

void LNNTopoManagerTest::TearDownTestCase() { }

void LNNTopoManagerTest::SetUp() { }

void LNNTopoManagerTest::TearDown() { }

/*
 * @tc.name: LNN_INIT_TOPO_MANAGER_TEST_001
 * @tc.desc: LnnInitTopoManager test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_001, TestSize.Level1)
{
    unsigned char *isNoSupportTopo = reinterpret_cast<unsigned char *>(const_cast<char *>("0"));
    unsigned char *isSupportTopo = reinterpret_cast<unsigned char *>(const_cast<char *>("1"));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftbusGetConfig)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(*isNoSupportTopo), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*isSupportTopo), Return(SOFTBUS_OK)));
    EXPECT_CALL(serviceMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnUnregisterEventHandler).WillRepeatedly(Return());
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnRegSyncInfoHandler)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMock, LnnUnregSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitTopoManager();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnInitTopoManager();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LnnDeinitTopoManager();
    ret = LnnInitTopoManager();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GET_RELATION_TEST_001
 * @tc.desc: LnnGetRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, LNN_GET_RELATION_TEST_001, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX + 1] = { 0 };
    int32_t ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRelation(nullptr, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRelation(UDID, nullptr, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRelation(UDID, PEER_UDID, nullptr, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: ADD_TOPO_INFO_TEST_001
 * @tc.desc: AddTopoInfo test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, ADD_TOPO_INFO_TEST_001, TestSize.Level1)
{
    int32_t ret = AddTopoInfo(UDID, PEER_UDID, OLD_RELATION, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTopoInfo(UDID, PEER_UDID, OLD_RELATION, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddTopoInfo(UDID, PEER_UDID, OLD_RELATION, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint8_t relation[CONNECTION_ADDR_MAX + 1] = { 0 };
    ret = LnnGetRelation(UDID_1, PEER_UDID_1, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetRelation(UDID, PEER_UDID_1, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetRelation(UDID_1, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: IS_SAME_RELATION_TEST_001
 * @tc.desc: IsSameRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, IS_SAME_RELATION_TEST_001, TestSize.Level1)
{
    bool ret = IsSameRelation(NEW_RELATION_2, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, true);
    ret = IsSameRelation(NEW_RELATION_1, NEW_RELATION_2, RELATION_LEN);
    EXPECT_EQ(ret, true);
    ret = IsSameRelation(NEW_RELATION_2, NEW_RELATION_2, RELATION_LEN);
    EXPECT_EQ(ret, true);
    ret = IsSameRelation(NEW_RELATION_1, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: HAS_RELATION_TEST_001
 * @tc.desc: HasRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, HAS_RELATION_TEST_001, TestSize.Level1)
{
    bool ret = HasRelation(NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, true);
    ret = HasRelation(NEW_RELATION_2, RELATION_LEN);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: CREATE_TOPO_ITEM_TEST_001
 * @tc.desc: CreateTopoItem test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, CREATE_TOPO_ITEM_TEST_001, TestSize.Level1)
{
    TopoTableItem *item = CreateTopoItem(INVALID_UUID);
    EXPECT_EQ(item, nullptr);
    TopoInfo *topo = CreateTopoInfo(INVALID_UUID, OLD_RELATION, RELATION_LEN);
    EXPECT_EQ(topo, nullptr);
    topo = CreateTopoInfo(UDID, OLD_RELATION, INVALID_RELATION_LEN);
    EXPECT_EQ(topo, nullptr);
    item = FindTopoItem(UDID);
    EXPECT_EQ(topo, nullptr);
    item = FindTopoItem(UDID_1);
    EXPECT_EQ(topo, nullptr);
    TopoTableItem *topoItem = nullptr;
    TopoInfo *topoInfo = nullptr;
    int32_t ret = FindTopoInfo(UDID_1, UDID_1, &topoItem, &topoInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = FindTopoInfo(UDID, UDID_1, &topoItem, &topoInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = FindTopoInfo(UDID_1, PEER_UDID, &topoItem, &topoInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = FindTopoInfo(UDID, PEER_UDID, &topoItem, &topoInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_COMMON_TOPO_MSG_TEST_001
 * @tc.desc: PackCommonTopoMsg test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, PACK_COMMON_TOPO_MSG_TEST_001, TestSize.Level1)
{
    cJSON *json = NULL;
    cJSON *info = NULL;
    unsigned char *randStr1 = reinterpret_cast<unsigned char *>(const_cast<char *>(RAND_STR1));
    unsigned char *randStr2 = reinterpret_cast<unsigned char *>(const_cast<char *>(RAND_STR2));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray)
        .WillOnce(Return(SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL))
        .WillOnce(DoAll(SetArgPointee<0>(*randStr1), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<0>(*randStr2), Return(SOFTBUS_OK)));
    int32_t ret = PackCommonTopoMsg(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL);
    ret = PackCommonTopoMsg(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCommonTopoMsg(&json, &info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PACK_TOPO_INFO_TEST_001
 * @tc.desc: PackTopoInfo test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, PACK_TOPO_INFO_TEST_001, TestSize.Level1)
{
    cJSON info;
    (void)memset_s(&info, sizeof(cJSON), 0, sizeof(cJSON));
    int32_t ret = PackTopoInfo(&info, UDID, PEER_UDID, OLD_RELATION, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackTopoInfo(&info, UDID, PEER_UDID, OLD_RELATION, INVALID_RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = PackTopoInfo(&info, nullptr, PEER_UDID, OLD_RELATION, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_ADD_INFO_TO_JSON_FAIL);
    ret = PackTopoInfo(&info, UDID, nullptr, OLD_RELATION, CONNECTION_ADDR_MAX);
    EXPECT_EQ(ret, SOFTBUS_ADD_INFO_TO_JSON_FAIL);
}

/*
 * @tc.name: PACK_ONE_LNN_RELATION_TEST_001
 * @tc.desc: PackOneLnnRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, PACK_ONE_LNN_RELATION_TEST_001, TestSize.Level1)
{
    unsigned char *randStr1 = reinterpret_cast<unsigned char *>(const_cast<char *>(RAND_STR1));
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<0>(*randStr1), Return(SOFTBUS_OK)));
    const char *msg = PackOneLnnRelation(UDID, PEER_UDID, OLD_RELATION, CONNECTION_ADDR_MAX);
    EXPECT_EQ(msg, nullptr);
    msg = PackOneLnnRelation(nullptr, PEER_UDID, OLD_RELATION, INVALID_RELATION_LEN);
    EXPECT_EQ(msg, nullptr);
    msg = PackOneLnnRelation(UDID, PEER_UDID, OLD_RELATION, CONNECTION_ADDR_MAX);
    EXPECT_NE(msg, nullptr);
}

/*
 * @tc.name: UPDATE_LOCAL_TOPO_TEST_001
 * @tc.desc: UpdateLocalTopo test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, UPDATE_LOCAL_TOPO_TEST_001, TestSize.Level1)
{
    int32_t ret = UpdateLocalTopo(UDID_1, UDID_1, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLocalTopo(UDID_1, UDID_1, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SAME_RELATION);
    ret = UpdateLocalTopo(UDID_1, UDID_1, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SAME_RELATION);
    ret = UpdateLocalTopo(UDID_1, UDID_1, NEW_RELATION_2, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SAME_RELATION);
    ret = UpdateLocalTopo(UDID, PEER_UDID, NEW_RELATION_1, RELATION_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SAME_RELATION);
}

/*
 * @tc.name: FORWARD_TOPO_MSG_TO_ALL_TEST_001
 * @tc.desc: ForwardTopoMsgToAll test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, FORWARD_TOPO_MSG_TO_ALL_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillOnce(Return(true)).WillRepeatedly(Return(false));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnSendSyncInfoMsg)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ForwardTopoMsgToAll(NETWORK_ID, MSG, MSG_LEN);
    ForwardTopoMsgToAll(NETWORK_ID, MSG, MSG_LEN);
    ForwardTopoMsgToAll(NETWORK_ID, MSG, MSG_LEN);
    ForwardTopoMsgToAll(NETWORK_ID_1, MSG, MSG_LEN);
    ForwardTopoMsgToAll(NETWORK_ID_1, MSG, MSG_LEN);
}

/*
 * @tc.name: TRY_CORRECT_RELATION_TEST_001
 * @tc.desc: TryCorrectRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, TRY_CORRECT_RELATION_TEST_001, TestSize.Level1)
{
    char *localUdid1 = const_cast<char *>(UDID);
    char *localUdid2 = const_cast<char *>(UDID_1);
    uint8_t *relation = const_cast<uint8_t *>(NEW_RELATION_2);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(*localUdid1), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localUdid2), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(DoAll(SetArgPointee<2>(*relation), Return(SOFTBUS_OK)));
    TryCorrectRelation(NETWORK_ID, UDID, PEER_UDID, NEW_RELATION_2, RELATION_LEN);
    TryCorrectRelation(NETWORK_ID, UDID, PEER_UDID, NEW_RELATION_2, RELATION_LEN);
    TryCorrectRelation(NETWORK_ID, UDID, PEER_UDID, NEW_RELATION_1, RELATION_LEN);
    TryCorrectRelation(NETWORK_ID, UDID, nullptr, NEW_RELATION_1, RELATION_LEN);
    TryCorrectRelation(NETWORK_ID, UDID, PEER_UDID, NEW_RELATION_1, RELATION_LEN);
    TryCorrectRelation(NETWORK_ID, UDID, PEER_UDID, NEW_RELATION_1, RELATION_LEN);
}

/*
 * @tc.name: PROCESS_TOPO_UPDATEINFO_TEST_001
 * @tc.desc: ProcessTopoUpdateInfo test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, PROCESS_TOPO_UPDATEINFO_TEST_001, TestSize.Level1)
{
    char *localUdid1 = const_cast<char *>(UDID);
    char *localUdid2 = const_cast<char *>(PEER_UDID);
    char *localUdid3 = const_cast<char *>(UDID_1);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(*localUdid1), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(*localUdid2), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(*localUdid3), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR));
    char *msg1 = const_cast<char *>(MSG_1);
    char *msg2 = const_cast<char *>(MSG_2);
    cJSON *json = cJSON_ParseWithLength(msg1, strlen(msg1));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    json = cJSON_ParseWithLength(msg2, strlen(msg2));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    char *msg3 = const_cast<char *>(MSG_3);
    char *msg4 = const_cast<char *>(MSG_4);
    json = cJSON_ParseWithLength(msg3, strlen(msg3));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    json = cJSON_ParseWithLength(msg4, strlen(msg4));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    char *msg5 = const_cast<char *>(MSG_5);
    char *msg6 = const_cast<char *>(MSG_6);
    json = cJSON_ParseWithLength(msg5, strlen(msg5));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
    json = cJSON_ParseWithLength(msg6, strlen(msg6));
    EXPECT_NE(json, nullptr);
    ProcessTopoUpdateInfo(json, NETWORK_ID, MSG, MSG_LEN);
}

/*
 * @tc.name: ON_RECEIVE_TOPO_UPDATE_MSG_TEST_001
 * @tc.desc: OnReceiveTopoUpdateMsg test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, ON_RECEIVE_TOPO_UPDATE_MSG_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    uint8_t *msg1 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_2));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_CONNECTION_INFO, NETWORK_ID, msg1, strlen(MSG_2));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg1, 0);
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg1, strlen(MSG_2));
    uint8_t *msg2 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_7));
    uint8_t *msg3 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_8));
    uint8_t *msg4 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_9));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg2, strlen(MSG_7));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg3, strlen(MSG_8));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg4, strlen(MSG_9));
    uint8_t *msg5 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_10));
    uint8_t *msg6 = reinterpret_cast<uint8_t *>(const_cast<char *>(MSG_11));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg5, strlen(MSG_10));
    OnReceiveTopoUpdateMsg(LNN_INFO_TYPE_TOPO_UPDATE, NETWORK_ID, msg6, strlen(MSG_11));
    OnLnnRelationChangedDelay(nullptr);
    LnnRelationChangedMsg *msg =
        reinterpret_cast<LnnRelationChangedMsg *>(SoftBusCalloc(sizeof(LnnRelationChangedMsg)));
    EXPECT_NE(msg, nullptr);
    void *para = reinterpret_cast<void *>(msg);
    OnLnnRelationChangedDelay(para);
}

/*
 * @tc.name: FILL_ALL_RELATION_TEST_001
 * @tc.desc: FillAllRelation test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNTopoManagerTest, FILL_ALL_RELATION_TEST_001, TestSize.Level1)
{
    LnnRelationChanedEventInfo eventInfo = {
        .basic.event = LNN_EVENT_NODE_MIGRATE,
        .udid = nullptr,
        .type = CONNECTION_ADDR_MAX,
    };
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LnnEventBasicInfo *info =
        reinterpret_cast<LnnEventBasicInfo *>(const_cast<LnnRelationChanedEventInfo *>(&eventInfo));
    OnLnnRelationChanged(nullptr);
    OnLnnRelationChanged(info);
    eventInfo.basic.event = LNN_EVENT_RELATION_CHANGED;
    info = reinterpret_cast<LnnEventBasicInfo *>(const_cast<LnnRelationChanedEventInfo *>(&eventInfo));
    OnLnnRelationChanged(info);
    eventInfo.udid = "udidTest";
    info = reinterpret_cast<LnnEventBasicInfo *>(const_cast<LnnRelationChanedEventInfo *>(&eventInfo));
    OnLnnRelationChanged(info);
    eventInfo.type = CONNECTION_ADDR_WLAN;
    info = reinterpret_cast<LnnEventBasicInfo *>(const_cast<LnnRelationChanedEventInfo *>(&eventInfo));
    OnLnnRelationChanged(info);
    OnLnnRelationChanged(info);
    LnnRelation *relation = nullptr;
    uint32_t relationNum = 0;
    int32_t ret = LnnGetAllRelation(&relation, &relationNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetAllRelation(nullptr, &relationNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetAllRelation(&relation, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(serviceMock, LnnUnregisterEventHandler).WillRepeatedly(Return());
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnUnregSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_OK));
    LnnDeinitTopoManager();
}
} // namespace OHOS