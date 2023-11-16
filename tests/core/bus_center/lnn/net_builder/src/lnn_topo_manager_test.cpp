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

#include "bus_center_event.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_sync_info_manager.h"
#include "lnn_service_mock.h"
#include "lnn_topo_manager.c"
#include "lnn_topo_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

#define LNN_RELATION_JOIN_THREAD 1
#define LNN_RELATION_ERROR 0
namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char UDID[] = "83b37d243c8aac5a660d0cb231a7dbf9643b330245d560f4193956b0749a8651";
constexpr char UUID[] = "91a0183f4b68272902e7411f8e122fafd59969cd088e22d296be16400dcc9736";
constexpr char PEER_UDID[] = "dac6f8016d28d6cefa0671a1cdaba4928a53fa4e3b3a6b749c3887deda620564";
constexpr int32_t CHANNELID = 0;

class LNNTopoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTopoManagerTest::SetUpTestCase()
{
    LooperInit();
}

void LNNTopoManagerTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNTopoManagerTest::SetUp()
{
}

void LNNTopoManagerTest::TearDown()
{
}

static bool GetEventHandler(LnnEventType event, LnnEventHandler &handler)
{
    if (LnnServicetInterfaceMock::g_lnnEventHandlers.find(event) !=
        LnnServicetInterfaceMock::g_lnnEventHandlers.end()) {
        handler = LnnServicetInterfaceMock::g_lnnEventHandlers[event];
        return true;
    }
    return false;
}

void InitMock(LnnTransInterfaceMock &transMock, LnnServicetInterfaceMock &serviceMock)
{
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener).WillRepeatedly(
        LnnTransInterfaceMock::ActionOfTransRegister);
    LnnInitSyncInfoManager();
    ON_CALL(serviceMock, LnnRegisterEventHandler).WillByDefault(
        LnnServicetInterfaceMock::ActionOfLnnRegisterEventHandler);
    int ret = LnnInitTopoManager();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void DeinitMock(LnnTransInterfaceMock &transMock, LnnServicetInterfaceMock &serviceMock)
{
    ON_CALL(serviceMock, LnnUnregisterEventHandler).WillByDefault(Return());
    LnnDeinitTopoManager();
    LnnDeinitSyncInfoManager();
}

/*
* @tc.name: LNN_GET_RELATION_TEST_001
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_GET_RELATION_TEST_001, TestSize.Level1)
{
    uint8_t relation[CONNECTION_ADDR_MAX + 1];
    (void)memset_s(relation, sizeof(relation), 0, sizeof(relation));
    int ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX + 1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_RELATION_TEST_002
* @tc.desc: Udid and PeerUdid not find return SOFTBUS_NOT_FIND
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_GET_RELATION_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    uint8_t relation[CONNECTION_ADDR_MAX];
    (void)memset_s(relation, sizeof(relation), 0, sizeof(relation));
    int ret = LnnGetRelation(UDID, PEER_UDID, relation, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_GET_ALL_RELATION_TEST_001
* @tc.desc: relationNum is nullptr return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_GET_ALL_RELATION_TEST_001, TestSize.Level1)
{
    uint32_t *relationNum = nullptr;
    LnnRelation *relation = nullptr;
    int ret = LnnGetAllRelation(&relation, relationNum);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_RELATION_TEST_002
* @tc.desc: *invalid parameter
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_GET_ALL_RELATION_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    uint32_t num = 0;
    LnnRelation *relation = nullptr;
    int ret = LnnGetAllRelation(&relation, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(relation);
    relation = nullptr;
    num = 1;
    ret = LnnGetAllRelation(&relation, &num);
    SoftBusFree(relation);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_001
* @tc.desc: test notify topo info changed
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnRegisterEventHandler(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    int ret = LnnInitTopoManager();
    EXPECT_TRUE(ret = SOFTBUS_ERR);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_002
* @tc.desc: test LnnInitTopoManage
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);

    LnnEventHandler handler;
    bool isGet = GetEventHandler(LNN_EVENT_RELATION_CHANGED, handler);
    ASSERT_TRUE(isGet == true);

    LnnRelationChanedEventInfo eventInfo = {
        .basic.event = LNN_EVENT_RELATION_CHANGED,
        .type = CONNECTION_ADDR_BR,
        .relation = LNN_RELATION_JOIN_THREAD,
        .isJoin = true,
        .udid = nullptr,
    };
    handler(nullptr);
    handler((const LnnEventBasicInfo *)&eventInfo);
    eventInfo.udid = UDID;

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation);
    eventInfo.relation = LNN_RELATION_ERROR;
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId1);
    eventInfo.relation = LNN_RELATION_ERROR;
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    eventInfo.relation = LNN_RELATION_ERROR;
    eventInfo.isJoin = false;
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(Return(SOFTBUS_OK));
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_003
* @tc.desc: test notify topo info changed
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_003, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    LnnEventHandler handler;
    bool isGet = GetEventHandler(LNN_EVENT_RELATION_CHANGED, handler);
    ASSERT_TRUE(isGet == true);
    LnnRelationChanedEventInfo eventInfo = {
        .basic.event = LNN_EVENT_RELATION_CHANGED,
        .type = CONNECTION_ADDR_BR,
        .relation = LNN_RELATION_JOIN_THREAD,
        .isJoin = true,
        .udid = LnnNetLedgertInterfaceMock::peerId.c_str(),
    };
    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation);
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo1);
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId);
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId1);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    uint32_t num = 0;
    LnnRelation *relation = nullptr;
    EXPECT_EQ(LnnGetAllRelation(&relation, &num), SOFTBUS_OK);
    EXPECT_EQ(num, 0);
    SoftBusSleepMs(1000);

    uint8_t getRelation[CONNECTION_ADDR_MAX];
    (void)memset_s(getRelation, sizeof(getRelation), 0, sizeof(getRelation));
    EXPECT_EQ(LnnGetRelation(LnnNetLedgertInterfaceMock::localId.c_str(), LnnNetLedgertInterfaceMock::peerId.c_str(),
        getRelation, CONNECTION_ADDR_MAX), SOFTBUS_NOT_FIND);
    EXPECT_EQ(getRelation[CONNECTION_ADDR_BR], 0);

    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation1);
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);
    DeinitMock(transMock, serviceMock);
}

static void AssambleSyncMsg(const char *localUdid, const char *peerUdid, uint8_t *relation,
    char **msg, uint32_t *msgLen)
{
    if (*msg != nullptr) {
        SoftBusFree(*msg);
        *msg = nullptr;
    }
    const char *msgRelation = PackOneLnnRelation(localUdid, peerUdid, relation, CONNECTION_ADDR_MAX);
    uint32_t msgRelationLen = strlen(msgRelation) + 1;
    *msgLen = msgRelationLen + sizeof(int32_t);
    *msg = (char *)SoftBusCalloc(*msgLen);
    ASSERT_NE(*msg, nullptr);
    *(int32_t *)(*msg) = LNN_INFO_TYPE_TOPO_UPDATE;
    ASSERT_EQ(strcpy_s(*msg + sizeof(int32_t), msgRelationLen, msgRelation), EOK);
    cJSON_free(const_cast<char *>(msgRelation));
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_004
* @tc.desc: test sync online node topo info
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_004, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);

    uint8_t relation[CONNECTION_ADDR_MAX];
    (void)memset_s(relation, sizeof(relation), 0, sizeof(relation));
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    char *msg = nullptr;
    uint32_t msgLen = 0;
    AssambleSyncMsg(LnnNetLedgertInterfaceMock::localId.c_str(),
        LnnNetLedgertInterfaceMock::peerId.c_str(), relation, &msg, &msgLen);
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo1);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_OK)).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusSleepMs(50);

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillOnce(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation1);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusSleepMs(50);

    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusFree(msg);
    SoftBusSleepMs(50);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_005
* @tc.desc: test sync other node topo info
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_005, TestSize.Level1)
{
    EXPECT_STRNE(UDID, LnnNetLedgertInterfaceMock::localId.c_str());
    EXPECT_STRNE(PEER_UDID, LnnNetLedgertInterfaceMock::peerId.c_str());

    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);

    uint8_t relation[CONNECTION_ADDR_MAX];
    (void)memset_s(relation, sizeof(relation), 0, sizeof(relation));
    relation[CONNECTION_ADDR_BR] = LNN_RELATION_JOIN_THREAD;
    char *msg = nullptr;
    uint32_t msgLen = 0;
    AssambleSyncMsg(UUID, PEER_UDID, relation, &msg, &msgLen);
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo1);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo1);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusSleepMs(50);

    /* test recv same topo msg */
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusSleepMs(50);

    /* test recv diff topo msg */
    relation[CONNECTION_ADDR_BLE] = LNN_RELATION_JOIN_THREAD;
    AssambleSyncMsg(UUID, PEER_UDID, relation, &msg, &msgLen);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusSleepMs(50);

    /* test recv clear diff topo msg */
    (void)memset_s(relation, sizeof(relation), 0, sizeof(relation));
    AssambleSyncMsg(UUID, PEER_UDID, relation, &msg, &msgLen);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, msgLen);
    SoftBusFree(msg);
    SoftBusSleepMs(50);
    DeinitMock(transMock, serviceMock);
}
} // namespace OHOS