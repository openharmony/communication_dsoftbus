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

#include "bus_center_event.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_sync_info_manager.h"
#include "lnn_service_mock.h"
#include "lnn_topo_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define LNN_RELATION_JOIN_THREAD 1
#define LNN_RELATION_ERROR 0
namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char UDID[] = "123456789";
constexpr char PEER1_UDID[] = "123456789";
constexpr uint32_t LEN = CONNECTION_ADDR_MAX + 1;
constexpr uint32_t LEN2 = CONNECTION_ADDR_MAX;
constexpr uint32_t LEN3 = 8;
constexpr int32_t CHANNELID = 0;

class LnnTopoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnTopoManagerTest::SetUpTestCase()
{
    LooperInit();
}

void LnnTopoManagerTest::TearDownTestCase()
{
    LooperDeinit();
}

void LnnTopoManagerTest::SetUp()
{
}

void LnnTopoManagerTest::TearDown()
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
HWTEST_F(LnnTopoManagerTest, LNN_GET_RELATION_TEST_001, TestSize.Level1)
{
    uint8_t num = 0;
    int ret = LnnGetRelation(UDID, PEER1_UDID, &num, LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_RELATION_TEST_002
* @tc.desc: Udid and PeerUdid not find return SOFTBUS_NOT_FIND
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_RELATION_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    uint8_t num = 0;
    int ret = LnnGetRelation(UDID, PEER1_UDID, &num, LEN2);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_GET_ALL_RELATION_TEST_001
* @tc.desc: relationNum is NULL return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_ALL_RELATION_TEST_001, TestSize.Level1)
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
HWTEST_F(LnnTopoManagerTest, LNN_GET_ALL_RELATION_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    uint32_t num = 0;
    LnnRelation *relation = nullptr;
    int ret = LnnGetAllRelation(&relation, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    num = 1;
    ret = LnnGetAllRelation(&relation, &num);
    SoftBusFree(relation);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DeinitMock(transMock, serviceMock);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_001
* @tc.desc: test LnnInitTopoManage
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_001, TestSize.Level1)
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
HWTEST_F(LnnTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_002, TestSize.Level1)
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

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation);
    eventInfo.relation = LNN_RELATION_ERROR;
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_003
* @tc.desc: test LnnInitTopoManage
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_003, TestSize.Level1)
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
        .udid = UDID,
    };
    EXPECT_CALL(ledgerMock, LnnGetLnnRelation).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLnnRelation);
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(
        LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo);
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);

    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillOnce(LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnConvertDlId1);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_OK));
    handler((const LnnEventBasicInfo *)&eventInfo);
    SoftBusSleepMs(5500);
}

/*
* @tc.name: LNN_INIT_TOPO_MANAGER_TEST_004
* @tc.desc: test LnnInitTopoManage
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_INIT_TOPO_MANAGER_TEST_004, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    InitMock(transMock, serviceMock);
    char msg[LEN3] = {0};
    *(int32_t *)msg = LNN_INFO_TYPE_TOPO_UPDATE;
    if (memcpy_s(msg + sizeof(int32_t), LEN3 - sizeof(int32_t), "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy sync info msg fail");
    }
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UDID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, LEN3);
    DeinitMock(transMock, serviceMock);
    SoftBusSleepMs(20);
}
} // namespace OHOS
