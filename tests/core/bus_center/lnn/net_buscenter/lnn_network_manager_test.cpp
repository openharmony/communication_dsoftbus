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

#include "lnn_auth_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_network_manager.c"
#include "lnn_network_manager.h"
#include "lnn_network_manager_mock.h"
#include "lnn_oobe_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_protocol_def.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

LnnNetIfMgr g_netIfMgr1 = {
    .type = LNN_NETIF_TYPE_ETH,
    .ifName = "ETH",
};
LnnNetIfMgr g_netIfMgr2 = {
    .type = LNN_NETIF_TYPE_WLAN,
    .ifName = "WLAN",
};
LnnNetIfMgr g_netIfMgr3 = {
    .type = LNN_NETIF_TYPE_BR,
    .ifName = "BR",
};
LnnNetIfMgr g_netIfMgr4 = {
    .type = LNN_NETIF_TYPE_BLE,
    .ifName = "BLE",
};
class LNNNetworkManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetworkManagerMockTest::SetUpTestCase()
{
    ListTailInsert(&g_netIfNameList, &g_netIfMgr1.node);
    ListTailInsert(&g_netIfNameList, &g_netIfMgr2.node);
    ListTailInsert(&g_netIfNameList, &g_netIfMgr3.node);
    ListTailInsert(&g_netIfNameList, &g_netIfMgr4.node);
}

void LNNNetworkManagerMockTest::TearDownTestCase() { }

void LNNNetworkManagerMockTest::SetUp() { }

void LNNNetworkManagerMockTest::TearDown() { }

int32_t LnnInitBtProtocolOk(LnnProtocolManager *self)
{
    (void)self;
    return SOFTBUS_OK;
}

int32_t LnnInitBtProtocolErr(LnnProtocolManager *self)
{
    (void)self;
    return SOFTBUS_INVALID_PARAM;
}

int32_t LnnEnableBtProtocol(LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;
    (void)netifMgr;
    return SOFTBUS_OK;
}

static ListenerModule LnnGetBtListenerModule(ListenerMode mode)
{
    (void)mode;
    return UNUSE_BUTT;
}

/*
 * @tc.name: LNN_NETWORK_MANAGER_TEST_001
 * @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNNetworkManagerMockTest, LNN_NETWORK_MANAGER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnAuthtInterfaceMock> authMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(managerMock, RegistIPProtocolManager)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, RegGroupChangeListener)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, LnnInitPhysicalSubnetManager)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetLocalNum64Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, LnnRegisterEventHandler).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetworkManager();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NETWORK_MANAGER_TEST_002
 * @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNNetworkManagerMockTest, LNN_NETWORK_MANAGER_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGetAddrTypeByIfName(nullptr, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ConnectionAddrType type1 = CONNECTION_ADDR_ETH;
    ret = LnnGetAddrTypeByIfName("ETH", &type1);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ConnectionAddrType type2 = CONNECTION_ADDR_WLAN;
    ret = LnnGetAddrTypeByIfName("WLAN", &type2);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ConnectionAddrType type3 = CONNECTION_ADDR_BR;
    ret = LnnGetAddrTypeByIfName("BR", &type3);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ConnectionAddrType type4 = CONNECTION_ADDR_BLE;
    ret = LnnGetAddrTypeByIfName("BLE", &type4);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnGetNetIfTypeByName(nullptr, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NETWORK_MANAGER_TEST_003
 * @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNNetworkManagerMockTest, LNN_NETWORK_MANAGER_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRegistProtocol(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LnnProtocolManager protocolMgr;
    memset_s(&protocolMgr, sizeof(protocolMgr), 0, sizeof(protocolMgr));
    protocolMgr.init = LnnInitBtProtocolErr;
    protocolMgr.enable = LnnEnableBtProtocol;
    protocolMgr.getListenerModule = LnnGetBtListenerModule;

    ret = LnnRegistProtocol(&protocolMgr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    protocolMgr.init = LnnInitBtProtocolOk;
    ret = LnnRegistProtocol(&protocolMgr);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = UnregistProtocol(nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = UnregistProtocol(&protocolMgr);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ProtocolType protocol = LNN_PROTOCOL_BR;

    ListenerModule listenerModule = LnnGetProtocolListenerModule(protocol, LNN_LISTENER_MODE_DIRECT);
    EXPECT_TRUE(listenerModule == UNUSE_BUTT);

    FindProtocolByTypeRequest data = {
        .protocol = LNN_PROTOCOL_BR,
    };
    LnnProtocolManager manager = {
        .id = LNN_PROTOCOL_BR,
    };
    VisitNextChoice visitNextChoice = FindProtocolByType(&manager, (void *)&data);
    EXPECT_TRUE(visitNextChoice == CHOICE_FINISH_VISITING);
    manager.id = LNN_PROTOCOL_BLE;
    visitNextChoice = FindProtocolByType(&manager, (void *)&data);
    EXPECT_TRUE(visitNextChoice == CHOICE_VISIT_NEXT);

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    ON_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillByDefault(Return(true));
    ret = LnnInitNetworkManagerDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NETWORK_MANAGER_TEST_004
 * @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNNetworkManagerMockTest, LNN_NETWORK_MANAGER_TEST_004, TestSize.Level1)
{
    int32_t len = 0;
    char buf[] = "nullptr";
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret = LnnIsAutoNetWorkingEnabled();
    EXPECT_TRUE(ret == true);
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnIsAutoNetWorkingEnabled();
    EXPECT_TRUE(ret == false);

    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t res = LnnInitManagerByConfig();
    EXPECT_TRUE(res != SOFTBUS_OK);

    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    res = LnnInitManagerByConfig();
    EXPECT_TRUE(res == SOFTBUS_OK);

    res = ParseIfNameConfig(nullptr, len);
    EXPECT_TRUE(res != SOFTBUS_OK);
    res = ParseIfNameConfig(buf, sizeof("nullptr"));
    EXPECT_TRUE(res == SOFTBUS_OK);

    res = SetIfNameDefaultVal();
    EXPECT_TRUE(res == SOFTBUS_OK);
}

HWTEST_F(LNNNetworkManagerMockTest, NET_USER_STATE_EVENTHANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    (void)NetUserStateEventHandler(nullptr);
    LnnMonitorHbStateChangedEvent *info1 = new LnnMonitorHbStateChangedEvent();
    EXPECT_TRUE(info1 != nullptr);
    info1->basic.event = LNN_EVENT_USER_STATE_CHANGED;
    info1->status = SOFTBUS_USER_FOREGROUND;
    LnnEventBasicInfo *info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetUserStateEventHandler(info2);

    info1->status = SOFTBUS_USER_BACKGROUND;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetUserStateEventHandler(info2);

    info1->status = SOFTBUS_USER_FOREGROUND;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetUserStateEventHandler(info2);

    info1->status = SOFTBUS_USER_UNKNOWN;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetUserStateEventHandler(info2);

    delete info1;
    info1 = nullptr;
}

HWTEST_F(LNNNetworkManagerMockTest, NET_LOCK_STATE_EVENTHANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    ;
    LnnEventBasicInfo info;
    (void)NetLockStateEventHandler(nullptr);

    info.event = LNN_EVENT_SCREEN_LOCK_CHANGED;
    (void)NetLockStateEventHandler(&info);
}

HWTEST_F(LNNNetworkManagerMockTest, NET_OOB_STATE_EVENTHANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    (void)NetOOBEStateEventHandler(nullptr);
    LnnMonitorHbStateChangedEvent *info1 = new LnnMonitorHbStateChangedEvent();
    EXPECT_TRUE(info1 != nullptr);
    info1->basic.event = LNN_EVENT_OOBE_STATE_CHANGED;
    info1->status = SOFTBUS_OOBE_RUNNING;
    LnnEventBasicInfo *info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetOOBEStateEventHandler(info2);

    info1->status = SOFTBUS_OOBE_END;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetOOBEStateEventHandler(info2);

    info1->status = SOFTBUS_OOBE_UNKNOWN;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetOOBEStateEventHandler(info2);

    delete info1;
    info1 = nullptr;
}

HWTEST_F(LNNNetworkManagerMockTest, ON_DEVICE_BOUND_TEST_001, TestSize.Level1)
{
    const char *udid = nullptr;
    const char *groupInfo = nullptr;
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    (void)OnDeviceBound(udid, groupInfo);
    EXPECT_CALL(managerMock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    (void)OnDeviceBound(udid, groupInfo);
}

HWTEST_F(LNNNetworkManagerMockTest, CREAT_NETIFMGR_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    const char *netIfName = "Softbus";
    LnnNetIfMgr *ret = CreateNetifMgr(netIfName);
    EXPECT_NE(ret, nullptr);
    if (ret != nullptr) {
        SoftBusFree(ret);
    }
    ret = CreateNetifMgr(nullptr);
    EXPECT_EQ(ret, nullptr);
    if (ret != nullptr) {
        SoftBusFree(ret);
    }
}

HWTEST_F(LNNNetworkManagerMockTest, CREAT_NETIFMGR_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    LnnMonitorHbStateChangedEvent *info1 = new LnnMonitorHbStateChangedEvent();
    info1->basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED;
    info1->status = SOFTBUS_USER_UNLOCK;
    const LnnEventBasicInfo *info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetLockStateEventHandler(info2);
    info1->basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED;
    info1->status = SOFTBUS_SCREEN_UNLOCK;
    const LnnEventBasicInfo *info3 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetLockStateEventHandler(info3);
    info1->basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED;
    info1->status = SOFTBUS_SCREEN_LOCK;
    const LnnEventBasicInfo *info4 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetLockStateEventHandler(info4);
    info1->basic.event = LNN_EVENT_SCREEN_LOCK_CHANGED;
    info1->status = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    const LnnEventBasicInfo *info5 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetLockStateEventHandler(info5);
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    LnnNetIfMgr *ret = CreateNetifMgr(nullptr);
    EXPECT_EQ(ret, nullptr);

    delete info1;
    info1 = nullptr;
}

HWTEST_F(LNNNetworkManagerMockTest, SAVE_BRNETWORK_DEVICE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    (void)SaveBrNetworkDevices();
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    (void)SaveBrNetworkDevices();
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    (void)SaveBrNetworkDevices();
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    (void)SaveBrNetworkDevices();
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    (void)SaveBrNetworkDevices();
}

HWTEST_F(LNNNetworkManagerMockTest, NET_ACCOUNT_STATECHANGE_EVENTHANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    (void)NetAccountStateChangeEventHandler(nullptr);
    LnnMonitorHbStateChangedEvent *info1 = new LnnMonitorHbStateChangedEvent();
    EXPECT_TRUE(info1 != nullptr);
    info1->basic.event = LNN_EVENT_ACCOUNT_CHANGED;
    info1->status = SOFTBUS_ACCOUNT_LOG_IN;
    LnnEventBasicInfo *info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetAccountStateChangeEventHandler(info2);

    info1->status = SOFTBUS_ACCOUNT_LOG_OUT;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetAccountStateChangeEventHandler(info2);

    info1->status = SOFTBUS_ACCOUNT_UNKNOWN;
    info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NetAccountStateChangeEventHandler(info2);

    delete info1;
    info1 = nullptr;
}

HWTEST_F(LNNNetworkManagerMockTest, GET_ALL_PROTOCOLS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    const char *groupId = "groupId";
    int32_t groupType = AUTH_IDENTICAL_ACCOUNT_GROUP;
    EXPECT_CALL(managerMock, LnnUpdateOhosAccount).WillRepeatedly(Return());
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(true));
    EXPECT_CALL(managerMock, LnnNotifyAccountStateChangeEvent).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    (void)OnGroupCreated(groupId, groupType);
    groupType = AUTH_PEER_TO_PEER_GROUP;
    EXPECT_CALL(managerMock, LnnUpdateOhosAccount).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnNotifyAccountStateChangeEvent).WillRepeatedly(Return());
    (void)OnGroupCreated(groupId, groupType);
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    void *data = nullptr;
    VisitNextChoice ret = GetAllProtocols(nullptr, data);
    EXPECT_TRUE(ret == CHOICE_FINISH_VISITING);
    LnnProtocolManager manager;
    data = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnProtocolManager)));
    EXPECT_TRUE(data != nullptr);
    ret = GetAllProtocols(&manager, data);
    EXPECT_TRUE(ret == CHOICE_VISIT_NEXT);
    SoftBusFree(data);
}

HWTEST_F(LNNNetworkManagerMockTest, NIGHT_MODE_CHANGE_EVENTHANDLER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DfxRecordTriggerTime(_, _)).WillRepeatedly(Return());
    (void)NightModeChangeEventHandler(nullptr);
    LnnEventBasicInfo info;
    info.event = LNN_EVENT_NIGHT_MODE_CHANGED;
    (void)NightModeChangeEventHandler(&info);

    EXPECT_CALL(managerMock, LnnRequestLeaveByAddrType).WillRepeatedly(Return(SOFTBUS_OK));
    LnnMonitorHbStateChangedEvent *info1 = new LnnMonitorHbStateChangedEvent();
    EXPECT_NE(info1, nullptr);
    info1->basic.event = LNN_EVENT_NIGHT_MODE_CHANGED;
    info1->status = SOFTBUS_NIGHT_MODE_ON;
    LnnEventBasicInfo *info2 = reinterpret_cast<LnnEventBasicInfo *>(info1);
    (void)NightModeChangeEventHandler(info2);

    delete info1;
    info1 = nullptr;
}

HWTEST_F(LNNNetworkManagerMockTest, REGIST_NETIFMGR_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;

    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStopPublish).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartPublish).WillRepeatedly(Return(SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL));
    (void)RestartCoapDiscovery();

    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStopPublish).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartPublish).WillRepeatedly(Return(SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL));
    EXPECT_CALL(managerMock, LnnStopDiscovery).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    (void)RestartCoapDiscovery();

    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStopPublish).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartPublish).WillRepeatedly(Return(SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL));
    EXPECT_CALL(managerMock, LnnStopDiscovery).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartDiscovery).WillRepeatedly(Return(SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL));
    (void)RestartCoapDiscovery();

    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    LnnNetIfNameType type = LNN_MAX_NUM_TYPE;
    LnnNetIfManagerBuilder builder = nullptr;
    int32_t ret = RegistNetIfMgr(type, builder);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    type = LNN_MAX_NUM_TYPE;
    const char *ifName = "Softbus";
    LnnNetIfMgr *res = NetifMgrFactory(type, ifName);
    EXPECT_TRUE(res == nullptr);
}

HWTEST_F(LNNNetworkManagerMockTest, CONVERT_TO_NET_IF_TYPE_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    (void)RestartCoapDiscovery();
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    (void)RestartCoapDiscovery();
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    (void)RestartCoapDiscovery();
    EXPECT_CALL(ledgerMock, IsActiveOsAccountUnlocked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, DiscLinkStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStopPublish).WillRepeatedly(Return());
    EXPECT_CALL(managerMock, LnnStartPublish).WillRepeatedly(Return(SOFTBUS_OK));
    (void)RestartCoapDiscovery();
    LnnNetIfNameType type = LNN_MAX_NUM_TYPE;
    LnnNetIfType lnnNetIfType = ConvertToNetIfType(type);
    EXPECT_EQ(lnnNetIfType, 0);
    type = LNN_ETH_TYPE;
    lnnNetIfType = ConvertToNetIfType(type);
    EXPECT_NE(lnnNetIfType, 0);
    type = LNN_WLAN_TYPE;
    lnnNetIfType = ConvertToNetIfType(type);
    EXPECT_NE(lnnNetIfType, 0);
}

HWTEST_F(LNNNetworkManagerMockTest, LNN_REGISTER_EVENT_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    const char *groupId = "groupId";
    int32_t groupType = AUTH_IDENTICAL_ACCOUNT_GROUP;
    EXPECT_CALL(managerMock, LnnOnOhosAccountLogout).WillRepeatedly(Return());
    (void)OnGroupDeleted(groupId, groupType);
    groupType = AUTH_PEER_TO_PEER_GROUP;
    EXPECT_CALL(managerMock, LnnOnOhosAccountLogout).WillRepeatedly(Return());
    (void)OnGroupDeleted(groupId, groupType);
    int32_t ret = SOFTBUS_OK;
    EXPECT_CALL(managerMock, LnnRegisterEventHandler).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    EXPECT_CALL(managerMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    EXPECT_CALL(managerMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    EXPECT_CALL(managerMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    EXPECT_CALL(managerMock, LnnRegisterEventHandler)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR);
    EXPECT_CALL(managerMock, LnnRegisterEventHandler).WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnRegisterEvent();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

} // namespace OHOS
