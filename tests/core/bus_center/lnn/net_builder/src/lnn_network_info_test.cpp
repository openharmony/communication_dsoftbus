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
#include "lnn_devicename_info.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_network_info.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_common.h"

static NodeInfo info;
namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr int32_t CHANNELID = 2;
constexpr uint32_t LEN = 10;
constexpr char UUID[SHA_256_HEX_HASH_LEN] = "abc";

class LnnNetworkInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetworkInfoTest::SetUpTestCase()
{
    LooperInit();
    NiceMock<LnnTransInterfaceMock> transMock;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ActionOfTransRegister enter1");
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener(NotNull())).WillRepeatedly(
        LnnTransInterfaceMock::ActionOfTransRegister);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ActionOfTransRegister enter2");
    EXPECT_EQ(LnnInitSyncInfoManager(), SOFTBUS_OK);
}

void LnnNetworkInfoTest::TearDownTestCase()
{
    LnnDeinitSyncInfoManager();
    LooperDeinit();
}

void LnnNetworkInfoTest::SetUp()
{
}

void LnnNetworkInfoTest::TearDown()
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

void InitMock(LnnNetLedgertInterfaceMock &netLedgerMock, LnnServicetInterfaceMock &serviceMock)
{
    ON_CALL(serviceMock, LnnRegisterEventHandler(_, _)).WillByDefault(
        LnnServicetInterfaceMock::ActionOfLnnRegisterEventHandler);
    ON_CALL(netLedgerMock, LnnGetLocalNumInfo).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(netLedgerMock, LnnSetLocalNumInfo).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(netLedgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(
        LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo);
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    ON_CALL(netLedgerMock, LnnGetNodeInfoById).WillByDefault(Return(&info));
}

/*
* @tc.name: LNN_BT_STATE_EVENT_HANDLER_TEST_001
* @tc.desc: test LnnInitNetworkInfo
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetworkInfoTest, LNN_BT_STATE_EVENT_HANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock>  netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    InitMock(netLedgerMock, serviceMock);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_OK);
    LnnEventHandler handler;
    bool ret = GetEventHandler(LNN_EVENT_BT_STATE_CHANGED, handler);
    ASSERT_TRUE(ret == true);
    LnnMonitorBtStateChangedEvent btEvent1 = {
        .basic.event = LNN_EVENT_BT_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_BR_TURN_ON,
    };
    handler((LnnEventBasicInfo *)&btEvent1);
    LnnMonitorBtStateChangedEvent btEvent2 = {
        .basic.event = LNN_EVENT_BT_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_BR_TURN_OFF,
    };
    handler((LnnEventBasicInfo *)&btEvent2);
    EXPECT_CALL(serviceMock, LnnRegisterEventHandler(_, _)).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_ERR);

    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_ERR);
    handler((LnnEventBasicInfo *)&btEvent1);

    char msg[LEN] = {0};
    *(int32_t *)msg = LNN_INFO_TYPE_CAPABILITY;
    if (memcpy_s(msg + sizeof(int32_t), LEN - sizeof(int32_t), "abc", strlen("abc") + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy sync info msg fail");
    }
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID, msg, LEN);
    SoftBusSleepMs(200);
}

/*
* @tc.name: LNN_WIFI_STATE_EVENT_HANDLER_TEST_001
* @tc.desc: test LnnInitNetworkInfo
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetworkInfoTest, WIFI_STATE_EVENT_HANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock>  netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    InitMock(netLedgerMock, serviceMock);
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_ERR);
    LnnEventHandler handler;
    bool ret = GetEventHandler(LNN_EVENT_WIFI_STATE_CHANGED, handler);
    EXPECT_TRUE(ret == true);

    LnnMonitorWlanStateChangedEvent wifiEvent1 = {
        .basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_WIFI_CONNECTED,
    };
    handler((LnnEventBasicInfo *)&wifiEvent1);

    LnnMonitorWlanStateChangedEvent wifiEvent2 = {
        .basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_WIFI_DISCONNECTED,
    };
    handler((LnnEventBasicInfo *)&wifiEvent2);

    LnnMonitorWlanStateChangedEvent wifiEvent3 = {
        .basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_WIFI_DISABLED,
    };
    handler((LnnEventBasicInfo *)&wifiEvent3);

    LnnMonitorWlanStateChangedEvent wifiEvent4 = {
        .basic.event = LNN_EVENT_WIFI_STATE_CHANGED,
        .status = (uint8_t)SOFTBUS_WIFI_ENABLED,
    };
    handler((LnnEventBasicInfo *)&wifiEvent4);

    EXPECT_CALL(netLedgerMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_ERR);
    handler((LnnEventBasicInfo *)&wifiEvent1);
    SoftBusSleepMs(200);
}
}
