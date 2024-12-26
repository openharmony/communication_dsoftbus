/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <gtest/gtest.h>
#include <securec.h>
#include <cstdbool>
#include <cstdint>

#include "anonymizer.h"
#include "bus_center_event.h"
#include "bus_center_event_deps_mock.h"
#include "bus_center_decision_center.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_id.h"
#include "lnn_p2p_info.h"
#include "lnn_connection_addr_utils.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_qos.h"
#include "softbus_bus_center.h"

using namespace testing;
using namespace testing::ext;
constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";

typedef enum {
    NOTIFY_ONLINE_STATE_CHANGED = 0,
    NOTIFY_NODE_BASIC_INFO_CHANGED,
    NOTIFY_NODE_STATUS_CHANGED,
    NOTIFY_NETWORKID_UPDATE,
    NOTIFY_LOCAL_NETWORKID_UPDATE,
} NotifyType;

namespace OHOS {

class BusCenterEventTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BusCenterEventTest::SetUpTestCase(void)
{
}

void BusCenterEventTest::TearDownTestCase(void)
{
}

void BusCenterEventTest::SetUp(void)
{
}

void BusCenterEventTest::TearDown(void)
{
}

static void OnNetworkStateChange(const LnnEventBasicInfo *info)
{
    if (info != nullptr) {
        GTEST_LOG_(INFO) << "Network state changed, event is " << info->event;
    } else {
        GTEST_LOG_(INFO) << "Network state changed, but info is null.";
    }
}

/*
* @tc.name: BusCenterEventTest001
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest001, TestSize.Level1)
{
    bool isOnline = false;
    NodeBasicInfo *info = nullptr;
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, SetDefaultQdisc()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterEventMock, LnnGetAllOnlineNodeNum(_)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LnnNotifyOnlineState(isOnline, info);
    LnnNotifyMigrate(isOnline, info);
    NodeBasicInfo info2 = {
        .networkId = "testNetworkId",
        .deviceName = "testDeviceName",
        .deviceTypeId = 1,
    };
    EXPECT_NE(&info2, nullptr);
    EXPECT_CALL(BusCenterEventMock, LnnGetAllOnlineNodeNum(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LnnNotifyOnlineState(isOnline, &info2);
    isOnline = true;
    LnnNotifyOnlineState(isOnline, &info2);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest002
* @tc.desc: Verify the LnnNotifyBasicInfoChanged function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest002, TestSize.Level1)
{
    NodeBasicInfo *info = nullptr;
    NodeBasicInfoType type = TYPE_DEVICE_NAME;
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    LnnNotifyBasicInfoChanged(info, type);
    NodeBasicInfo info2 = {
        .networkId = "testNetworkId",
        .deviceName = "testDeviceName",
        .deviceTypeId = 1,
    };
    EXPECT_NE(&info2, nullptr);
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, Anonymize(_, _)).WillOnce(Return());
    EXPECT_CALL(BusCenterEventMock, AnonymizeFree(_)).WillOnce(Return());
    LnnNotifyBasicInfoChanged(&info2, type);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest003
* @tc.desc: Verify the LnnNotifyLeaveResult function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest003, TestSize.Level1)
{
    const char *networkId = nullptr;
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    ConnectionAddr *addr = NULL;
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;

    LnnNotifyJoinResult(addr, networkId, retCode);
    LnnNotifyLeaveResult(networkId, retCode);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest004
* @tc.desc: Verify the LnnNotifyTimeSyncResult function return value equal SOFTBUS_LOCK_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest004, TestSize.Level1)
{
    const char *pkgNameTest = "testPkgName";
    const char *pkgName = nullptr;
    int32_t pid = 1000;
    const TimeSyncResultInfo *info = nullptr;
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    LnnEventType event = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler = OnNetworkStateChange;

    LnnNotifyTimeSyncResult(pkgName, pid, info, retCode);
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, LnnIpcNotifyTimeSyncResult(_, _, _, _, _)).WillOnce(Return(SOFTBUS_OK));
    TimeSyncResultInfo info2;
    (void)memset_s(&info2, sizeof(TimeSyncResultInfo), 0, sizeof(TimeSyncResultInfo));
    (void)strcpy_s(info2.target.targetNetworkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);
    LnnNotifyTimeSyncResult(pkgNameTest, pid, &info2, retCode);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: BusCenterEventTest006
* @tc.desc: Verify the LnnNotifyScreenStateChangeEvent function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest006, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusScreenState mockState = (SoftBusScreenState)(SOFTBUS_SCREEN_UNKNOWN + 1);

    LnnNotifyScreenStateChangeEvent(mockState);
    mockState = SOFTBUS_SCREEN_ON;
    LnnNotifyScreenStateChangeEvent(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest008
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_LOCK_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest008, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler = OnNetworkStateChange;
    SoftBusScreenLockState mockState = (SoftBusScreenLockState)(SOFTBUS_SCREEN_LOCK_UNKNOWN + 1);

    LnnNotifyScreenLockStateChangeEvent(mockState);
    mockState = SOFTBUS_USER_UNLOCK;
    LnnNotifyScreenLockStateChangeEvent(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: BusCenterEventTest009
* @tc.desc: Verify the LnnInitBusCenterEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest009, TestSize.Level1)
{
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    SoftBusAccountState mockState = (SoftBusAccountState)(SOFTBUS_ACCOUNT_UNKNOWN + 1);

    LnnNotifyAccountStateChangeEvent(mockState);
    mockState = SOFTBUS_ACCOUNT_LOG_IN;
    LnnNotifyAccountStateChangeEvent(mockState);
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterEventTest010
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest010, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusUserSwitchState mockState = (SoftBusUserSwitchState)(SOFTBUS_USER_SWITCH_UNKNOWN + 1);

    LnnNotifyUserSwitchEvent(mockState);
    mockState = SOFTBUS_USER_SWITCHED;
    LnnNotifyUserSwitchEvent(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest012
* @tc.desc: Verify the LnnNotifyUserStateChangeEvent function return value equal SOFTBUS_LOCK_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest012, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler = OnNetworkStateChange;
    SoftBusUserState mockState = (SoftBusUserState)(SOFTBUS_USER_UNKNOWN + 1);

    LnnNotifyUserStateChangeEvent(mockState);
    mockState = SOFTBUS_USER_BACKGROUND;
    LnnNotifyUserStateChangeEvent(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: BusCenterEventTest014
* @tc.desc: Verify the LnnNotifyOOBEStateChangeEvent function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest014, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusOOBEState mockState = (SoftBusOOBEState)(SOFTBUS_OOBE_UNKNOWN + 1);

    LnnNotifyOOBEStateChangeEvent(mockState);
    mockState = SOFTBUS_OOBE_END;
    LnnNotifyOOBEStateChangeEvent(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest015
* @tc.desc: Verify the LnnNotifyBtAclStateChangeEvent function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest015, TestSize.Level1)
{
    const char *btMac = nullptr;
    const char *btMacTest = "testBtMac";
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusBtAclState state = SOFTBUS_BR_ACL_CONNECTED;

    LnnNotifyBtAclStateChangeEvent(btMac, state);
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, Anonymize(_, _)).WillOnce(Return());
    EXPECT_CALL(BusCenterEventMock, AnonymizeFree(_)).WillOnce(Return());
    LnnNotifyBtAclStateChangeEvent(btMacTest, state);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest016
* @tc.desc: Verify the LnnNotifyAddressChangedEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest016, TestSize.Level1)
{
    const char *ifNameTest = "testIfName";
    const char *ifName = nullptr;

    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    LnnNotifyAddressChangedEvent(ifName);
    LnnNotifyAddressChangedEvent(ifNameTest);
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterEventTest017
* @tc.desc: Verify the LnnNotifyNodeAddressChanged function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest017, TestSize.Level1)
{
    const char *addr = nullptr;
    const char *networkId = "testNetworkId";
    bool isLocal = false;
    const char *addrTest = "testAddr";
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;

    LnnNotifyNodeAddressChanged(addr, networkId, isLocal);
    LnnNotifyNodeAddressChanged(addrTest, networkId, isLocal);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest018
* @tc.desc: Verify the LnnNotifyNetworkStateChanged function return value equal SOFTBUS_LOCK_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest018, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler = OnNetworkStateChange;
    SoftBusNetworkState mockState = (SoftBusNetworkState)(SOFTBUS_NETWORKD_UNKNOWN + 1);

    LnnNotifyNetworkStateChanged(mockState);
    mockState = SOFTBUS_WIFI_NETWORKD_ENABLE;
    LnnNotifyNetworkStateChanged(mockState);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: BusCenterEventTest019
* @tc.desc: Verify the LnnNotifySingleOffLineEvent function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest019, TestSize.Level1)
{
    const ConnectionAddr *addr = nullptr;
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    NodeBasicInfo info = {
        .networkId = "testNetworkId",
        .deviceName = "testDeviceName",
        .deviceTypeId = 1,
    };

    LnnNotifySingleOffLineEvent(addr, &info);
    ConnectionAddr addr2;
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, LnnGetRemoteNodeInfoById(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(BusCenterEventMock, LnnHasDiscoveryType(_, _)).WillOnce(Return(true));
    EXPECT_CALL(BusCenterEventMock, LnnConvAddrTypeToDiscType(_)).WillOnce(Return(DISCOVERY_TYPE_WIFI));
    LnnNotifySingleOffLineEvent(&addr2, &info);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest020
* @tc.desc: Verify the LnnNotifyLpReportEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest020, TestSize.Level1)
{
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    SoftBusLpEventType type = (SoftBusLpEventType)(SOFTBUS_LP_EVENT_UNKNOWN + 1);
    LnnNotifyLpReportEvent(type);
    type = SOFTBUS_MSDP_MOVEMENT_AND_STATIONARY;
    LnnNotifyLpReportEvent(type);
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterEventTest021
* @tc.desc: Verify the LnnNotifyNetworkIdChangeEvent function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest021, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    const char *networkId = nullptr;
    const char *networkIdTest = "testNetworkId";
    LnnNotifyNetworkIdChangeEvent(networkId);
    LnnNotifyNetworkIdChangeEvent(networkIdTest);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest022
* @tc.desc: Verify the LnnInitBusCenterEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest022, TestSize.Level1)
{
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterEventTest023
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_LOCK_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest023, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;

    int32_t ret = LnnRegisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LnnEventType event2 = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler2 = OnNetworkStateChange;
    ret = LnnRegisterEventHandler(event2, handler2);
    LnnUnregisterEventHandler(event2, handler2);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: BusCenterEventTest024
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest024, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;

    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: BusCenterEventTest005
* @tc.desc: Verify the LnnInitBusCenterEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest005, TestSize.Level1)
{
    SoftBusWifiState *mockState = nullptr;
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    LnnNotifyWlanStateChangeEvent(nullptr);
    mockState = (SoftBusWifiState *)SoftBusCalloc(sizeof(SoftBusWifiState));
    ASSERT_TRUE(mockState != nullptr);
    *mockState = (SoftBusWifiState)(SOFTBUS_WIFI_UNKNOWN + 1);
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(mockState);
}

/*
* @tc.name: BusCenterEventTest007
* @tc.desc: Verify the LnnRegisterEventHandler function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest007, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusBtState *mockState = (SoftBusBtState *)SoftBusCalloc(sizeof(SoftBusWifiState));
    ASSERT_TRUE(mockState != nullptr);
    *mockState = (SoftBusBtState)(SOFTBUS_BT_UNKNOWN + 1);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(mockState);
}

/*
* @tc.name: BusCenterEventTest013
* @tc.desc: Verify the LnnInitBusCenterEvent function return value equal SOFTBUS_LOOPER_ERR.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest013, TestSize.Level1)
{
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillOnce(Return(NULL));
    SoftBusNightModeState *mockState = (SoftBusNightModeState *)SoftBusCalloc(sizeof(SoftBusNightModeState));
    ASSERT_TRUE(mockState != nullptr);
    *mockState = (SoftBusNightModeState)(SOFTBUS_NIGHT_MODE_UNKNOWN + 1);
    int32_t ret = LnnInitBusCenterEvent();
    LnnDeinitBusCenterEvent();
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(mockState);
}

/*
* @tc.name: BusCenterEventTest011
* @tc.desc: Authenticate the LnnRegisterEventHandler function return value equal SOFTBUS_INVALID_PARAM.
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterEventTest, BusCenterEventTest011, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_TYPE_MAX;
    LnnEventHandler handler = NULL;
    SoftBusDifferentAccountState *mockState  =
        (SoftBusDifferentAccountState *)SoftBusCalloc(sizeof(SoftBusDifferentAccountState));
    ASSERT_TRUE(mockState != nullptr);
    *mockState = (SoftBusDifferentAccountState)(SOFTBUS_DIF_ACCOUNT_UNKNOWN + 1);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    LnnUnregisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(mockState);
}

/*
 * @tc.name: BusCenterEventTest25
 * @tc.desc: Handle Notify Message Test.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest25, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnNotifyNodeStatusChanged(nullptr, TYPE_AUTH_STATUS));
}

/*
 * @tc.name: BusCenterEventTest26
 * @tc.desc: Test the LnnRegisterEventHandler function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest26, TestSize.Level1)
{
    NodeStatus info = {};
    EXPECT_NO_FATAL_FAILURE(LnnNotifyNodeStatusChanged(&info, TYPE_AUTH_STATUS));
}

/*
 * @tc.name: BusCenterEventTest27
 * @tc.desc: Test the LnnNotifyDeviceTrustedChange function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest027, TestSize.Level1)
{
    char *msg = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDeviceTrustedChange(DEVICE_NOT_TRUSTED, msg, 1));
}

/*
 * @tc.name:BusCenterEventTest28
 * @tc.desc: Test the LnnNotifyDeviceTrustedChange function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest028, TestSize.Level1)
{
    const char *msg = "msg";
    uint32_t msgLen = 0;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDeviceTrustedChange(DEVICE_NOT_TRUSTED, msg, msgLen));
}

/*
 * @tc.name: BusCenterEventTest29
 * @tc.desc: Test the LnnNotifyDeviceTrustedChange function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest029, TestSize.Level1)
{
    char *msg = nullptr;
    uint32_t msgLen = 0;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDeviceTrustedChange(DEVICE_NOT_TRUSTED, msg, msgLen));
}

/*
 * @tc.name: BusCenterEventTest30
 * @tc.desc: Test the LnnNotifyDataShareStateChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest030, TestSize.Level1)
{
    SoftBusDataShareState state = SOFTBUS_DATA_SHARE_UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDataShareStateChangeEvent(state));
}

/*
 * @tc.name: BusCenterEventTest31
 * @tc.desc: Test the LnnNotifyDifferentAccountChangeEvent function.
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest031, TestSize.Level1)
{
    SoftBusDifferentAccountState *difAccountState =
        (SoftBusDifferentAccountState *)SoftBusMalloc(sizeof(SoftBusDifferentAccountState));
    ASSERT_TRUE(difAccountState != nullptr);
    *difAccountState = SOFTBUS_DIF_ACCOUNT_DEV_CHANGE;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDifferentAccountChangeEvent((void *)difAccountState));
}

/* @tc.name: BusCenterEventTest032
 * @tc.desc:  Test the LnnNotifyDifferentAccountChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest032, TestSize.Level1)
{
    SoftBusDifferentAccountState *difAccountState =
        (SoftBusDifferentAccountState *)SoftBusMalloc(sizeof(SoftBusDifferentAccountState));
    ASSERT_TRUE(difAccountState != nullptr);
    *difAccountState = SOFTBUS_DIF_ACCOUNT_UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyDifferentAccountChangeEvent((void *)difAccountState));
}

/*
 * @tc.name: BusCenterEventTest33
 * @tc.desc: Test the LnnNotifyNightModeStateChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest033, TestSize.Level1)
{
    SoftBusNightModeState *nightModeState = (SoftBusNightModeState *)SoftBusMalloc(sizeof(SoftBusNightModeState));
    ASSERT_TRUE(nightModeState != nullptr);
    *nightModeState = SOFTBUS_NIGHT_MODE_ON;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyNightModeStateChangeEvent((void *)nightModeState));
}
/*
 * @tc.name: BusCenterEventTest34
 * @tc.desc: Test the LnnNotifyNightModeStateChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest034, TestSize.Level1)
{
    SoftBusNightModeState *nightModeState = (SoftBusNightModeState *)SoftBusMalloc(sizeof(SoftBusNightModeState));
    ASSERT_TRUE(nightModeState != nullptr);
    *nightModeState = SOFTBUS_NIGHT_MODE_UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(LnnNotifyNightModeStateChangeEvent((void *)nightModeState));
}

/*
 * @tc.name: BusCenterEventTest35
 * @tc.desc: Test the LnnRegisterEventHandler function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest035, TestSize.Level1)
{
    LnnEventType event = LNN_EVENT_NETWORK_STATE_CHANGED;
    LnnEventHandler handler = OnNetworkStateChange;
    SoftBusLooper loop = {};
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    EXPECT_CALL(BusCenterEventMock, CreateNewLooper(_)).WillRepeatedly(Return(&loop));
    int32_t rdt = LnnInitBusCenterEvent();
    EXPECT_EQ(rdt, SOFTBUS_OK);
    int32_t ret = LnnRegisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnRegisterEventHandler(event, handler);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(LnnUnregisterEventHandler(event, handler));
    EXPECT_EQ(rdt, SOFTBUS_OK);
}

/*
 * @tc.name: BusCenterEventTest36
 * @tc.desc: Test the LnnNotifyOnlineState function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest036, TestSize.Level1)
{
    bool isOnline = false;
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    NodeBasicInfo info = {
        .networkId = "testNetworkId",
        .deviceName = "testDeviceName",
        .deviceTypeId = 1,
    };
    EXPECT_CALL(BusCenterEventMock, LnnGetAllOnlineNodeNum(_)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(LnnNotifyOnlineState(isOnline, &info));
}

/*
 * @tc.name: BusCenterEventTest37
 * @tc.desc: Test the LnnNotifyOnlineState function.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(BusCenterEventTest, BusCenterEventTest037, TestSize.Level1)
{
    bool isOnline = false;
    NiceMock<BusCenterEventDepsInterfaceMock> BusCenterEventMock;
    NodeBasicInfo info = {
        .networkId = "testNetworkId",
        .deviceName = "testDeviceName",
        .deviceTypeId = 1,
    };
    EXPECT_CALL(BusCenterEventMock, LnnGetAllOnlineNodeNum(_))
        .WillRepeatedly(DoAll(SetArgPointee<0>(0), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(LnnNotifyOnlineState(isOnline, &info));
}

}
