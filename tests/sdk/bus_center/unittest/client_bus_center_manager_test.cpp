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

#include "client_bus_center_manager.h"
#include "client_bus_center_manager_mock.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_config_type.h"
#include "softbus_error_code.h"

#include "client_bus_center_manager.c"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
constexpr char NODE1_BR_MAC[] = "12345TTU";
constexpr char NODE1_BLE_MAC[] = "23456TTU";
constexpr char NODE1_IP[] = "10.146.181.134";
constexpr uint16_t NODE1_PORT = 10;
constexpr char NODE1_NETWORK_ID[] = "235689BNHFCF";
constexpr int32_t NODE1_SESSION_ID = 100;
constexpr int32_t NODE1_CHANNEL_ID = 100;
constexpr int32_t NODE1_SESSION_TYPE = 100;
constexpr int32_t LNN_PUBLISH_ID = 0;
constexpr int32_t LNN_SUBSCRIBE_ID = 0;
constexpr char CAPABILITY[] = "ddmpCapabilityTest";
constexpr unsigned char CAPABILITY_DATA[] = "ddmpCapabilityTest";
constexpr uint32_t EVENT = 15;
constexpr int32_t INVALID_TYPE = -1;
constexpr int32_t TYPE = 1;
constexpr int32_t LNN_REFRESH_ID = 0;
constexpr int32_t RESULT_REASON = -1;
constexpr char PKGNAME[] = "softbustest";
class ClientBusCentManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientBusCentManagerTest::SetUpTestCase() { }

void ClientBusCentManagerTest::TearDownTestCase() { }

void ClientBusCentManagerTest::SetUp() { }

void ClientBusCentManagerTest::TearDown() { }

/*
 * @tc.name: BUS_CENTER_CLIENT_INIT_Test_001
 * @tc.desc: bus center client init test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, BUS_CENTER_CLIENT_INIT_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit())
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_NE(BusCenterClientInit(), SOFTBUS_OK);
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: JOIN_LNN_INNER_Test_001
 * @tc.desc: join lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, JOIN_LNN_INNER_Test_001, TestSize.Level1)
{
    OnJoinLNNResult cb = nullptr;
    ConnectionAddr target1;
    (void)memset_s(&target1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    target1.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(target1.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    (void)strcpy_s(target1.info.ble.bleMac, BT_MAC_LEN, NODE1_BLE_MAC);
    (void)strcpy_s(target1.info.ip.ip, IP_STR_MAX_LEN, NODE1_IP);
    target1.info.ip.port = NODE1_PORT;
    target1.info.session.sessionId = NODE1_SESSION_ID;
    target1.info.session.channelId = NODE1_CHANNEL_ID;
    target1.info.session.type = NODE1_SESSION_TYPE;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcJoinLNN(_, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(JoinLNNInner(nullptr, &target1, cb), SOFTBUS_OK);
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, cb) == SOFTBUS_OK);
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_ALREADY_EXISTED);
    target1.type = CONNECTION_ADDR_BLE;
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_OK);
    target1.type = CONNECTION_ADDR_WLAN;
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_OK);
    target1.type = CONNECTION_ADDR_ETH;
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_OK);
    target1.type = CONNECTION_ADDR_SESSION;
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_OK);
    target1.type = CONNECTION_ADDR_MAX;
    EXPECT_TRUE(JoinLNNInner(nullptr, &target1, nullptr) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: LEAVE_LNN_INNER_Test_001
 * @tc.desc: leave lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LEAVE_LNN_INNER_Test_001, TestSize.Level1)
{
    OnLeaveLNNResult cb = nullptr;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcLeaveLNN(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(LeaveLNNInner(nullptr, NODE1_NETWORK_ID, cb), SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNNInner(nullptr, NODE1_NETWORK_ID, cb) == SOFTBUS_OK);
    EXPECT_NE(LeaveLNNInner(nullptr, NODE1_NETWORK_ID, nullptr), SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: REG_NODE_DEVICE_STATE_CB_INNER_Test_001
 * @tc.desc: reg node device state cb inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, REG_NODE_DEVICE_STATE_CB_INNER_Test_001, TestSize.Level1)
{
    INodeStateCb callback;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(nullptr, &callback) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(PKGNAME, &callback) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: UNREG_NODE_DEVICE_STATE_CB_INNER_Test_001
 * @tc.desc: unreg node device state cb inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, UNREG_NODE_DEVICE_STATE_CB_INNER_Test_001, TestSize.Level1)
{
    INodeStateCb callback;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(UnregNodeDeviceStateCbInner(&callback) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: GET_ALL_NODE_DEVICE_INFO_INNER_Test_001
 * @tc.desc: get all node device info inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, GET_ALL_NODE_DEVICE_INFO_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcGetAllOnlineNodeInfo(_, _, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(GetAllNodeDeviceInfoInner(nullptr, nullptr, nullptr), SOFTBUS_OK);
    EXPECT_TRUE(GetAllNodeDeviceInfoInner(nullptr, nullptr, nullptr) == SOFTBUS_OK);
}

/*
 * @tc.name: GET_LOCAL_NODE_DEVICE_INFO_INNER_Test_001
 * @tc.desc: get local node device info inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, GET_LOCAL_NODE_DEVICE_INFO_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcGetLocalDeviceInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(GetLocalNodeDeviceInfoInner(nullptr, nullptr), SOFTBUS_OK);
    EXPECT_TRUE(GetLocalNodeDeviceInfoInner(nullptr, nullptr) == SOFTBUS_OK);
}

/*
 * @tc.name: GET_NODE_KEY_INFO_INNER_Test_001
 * @tc.desc: get node key info inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, GET_NODE_KEY_INFO_INNER_Test_001, TestSize.Level1)
{
    int32_t infoLen = 0;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcGetNodeKeyInfo(_, _, _, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(GetNodeKeyInfoInner(nullptr, nullptr, NODE_KEY_UDID, nullptr, infoLen), SOFTBUS_OK);
    EXPECT_TRUE(GetNodeKeyInfoInner(nullptr, nullptr, NODE_KEY_UDID, nullptr, infoLen) == SOFTBUS_OK);
}

/*
 * @tc.name: SET_NODE_DATA_CHANGE_FLAG_INNER_Test_001
 * @tc.desc: set node data change flag inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, SET_NODE_DATA_CHANGE_FLAG_INNER_Test_001, TestSize.Level1)
{
    uint16_t dataChangeFlag = 0;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcSetNodeDataChangeFlag(_, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(SetNodeDataChangeFlagInner(nullptr, nullptr, dataChangeFlag), SOFTBUS_OK);
    EXPECT_TRUE(SetNodeDataChangeFlagInner(nullptr, nullptr, dataChangeFlag) == SOFTBUS_OK);
}

/*
 * @tc.name: START_TIME_SYNC_INNER_Test_001
 * @tc.desc: start time sync inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, START_TIME_SYNC_INNER_Test_001, TestSize.Level1)
{
    ITimeSyncCb cb;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcStartTimeSync(_, _, _, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(StartTimeSyncInner(nullptr, nullptr, LOW_ACCURACY, SHORT_PERIOD, &cb), SOFTBUS_OK);
    EXPECT_TRUE(StartTimeSyncInner(nullptr, NODE1_NETWORK_ID, LOW_ACCURACY, SHORT_PERIOD, &cb) == SOFTBUS_OK);
    EXPECT_NE(StartTimeSyncInner(nullptr, NODE1_NETWORK_ID, LOW_ACCURACY, SHORT_PERIOD, &cb), SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: STOP_TIME_SYNC_INNER_Test_001
 * @tc.desc: stop time sync inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, STOP_TIME_SYNC_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcStopTimeSync(_, _)).WillRepeatedly(Return(SOFTBUS_SERVER_NOT_INIT));
    EXPECT_NE(StopTimeSyncInner(nullptr, NODE1_NETWORK_ID), SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: STOP_TIME_SYNC_INNER_Test_002
 * @tc.desc: stop time sync inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, STOP_TIME_SYNC_INNER_Test_002, TestSize.Level1)
{
    ITimeSyncCb cb;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcStartTimeSync(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(StartTimeSyncInner(nullptr, NODE1_NETWORK_ID, LOW_ACCURACY, SHORT_PERIOD, &cb) == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcStopTimeSync(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(StopTimeSyncInner(nullptr, NODE1_NETWORK_ID) == SOFTBUS_OK);
    EXPECT_NE(StopTimeSyncInner(nullptr, NODE1_NETWORK_ID), SOFTBUS_OK);
    BusCenterClientDeinit();
}

static void OnPublishResultCb(int32_t publishId, PublishResult reason)
{
    (void)publishId;
    (void)reason;
    printf("on call publish result cb\n");
}

/*
 * @tc.name: PUBLISH_LNN_INNER_Test_001
 * @tc.desc: publish lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, PUBLISH_LNN_INNER_Test_001, TestSize.Level1)
{
    IPublishCb cb;
    cb.OnPublishResult = OnPublishResultCb;
    PublishInfo info;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    info.publishId = LNN_PUBLISH_ID;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = COAP;
    info.freq = HIGH;
    info.capability = CAPABILITY;
    info.capabilityData = const_cast<unsigned char *>(CAPABILITY_DATA);
    info.dataLen = strlen(reinterpret_cast<const char *>(const_cast<unsigned char *>(CAPABILITY_DATA)));
    info.ranging = false;
    LnnOnPublishLNNResult(LNN_PUBLISH_ID, RESULT_REASON);
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcPublishLNN(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(PublishLNNInner(nullptr, &info, &cb), SOFTBUS_OK);
    EXPECT_TRUE(PublishLNNInner(nullptr, &info, &cb) == SOFTBUS_OK);
    LnnOnPublishLNNResult(LNN_PUBLISH_ID, RESULT_REASON);
}

/*
 * @tc.name: STOP_PUBLISH_LNN_INNER_Test_001
 * @tc.desc: stop publish lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, STOP_PUBLISH_LNN_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcStopPublishLNN(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(StopPublishLNNInner(nullptr, LNN_PUBLISH_ID), SOFTBUS_OK);
    EXPECT_TRUE(StopPublishLNNInner(nullptr, LNN_PUBLISH_ID) == SOFTBUS_OK);
}

static void OnDeviceFoundCb(const DeviceInfo *device)
{
    (void)device;
    printf("on call device found cb\n");
}

static void OnDiscoverResultCb(int32_t refreshId, RefreshResult reason)
{
    (void)refreshId;
    (void)reason;
    printf("on call discover result cb\n");
}

/*
 * @tc.name: REFRESH_LNN_INNER_Test_001
 * @tc.desc: refresh lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, REFRESH_LNN_INNER_Test_001, TestSize.Level1)
{
    SubscribeInfo info;
    IRefreshCallback cb;
    cb.OnDeviceFound = OnDeviceFoundCb;
    cb.OnDiscoverResult = OnDiscoverResultCb;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    info.subscribeId = LNN_SUBSCRIBE_ID;
    info.mode = DISCOVER_MODE_PASSIVE;
    info.medium = COAP;
    info.freq = HIGH;
    info.isSameAccount = false;
    info.isWakeRemote = false;
    info.capability = CAPABILITY;
    info.capabilityData = const_cast<unsigned char *>(CAPABILITY_DATA);
    info.dataLen = strlen(reinterpret_cast<const char *>(const_cast<unsigned char *>(CAPABILITY_DATA)));
    LnnOnRefreshLNNResult(LNN_REFRESH_ID, RESULT_REASON);
    LnnOnRefreshDeviceFound(nullptr);
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcRefreshLNN(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(RefreshLNNInner(nullptr, &info, &cb), SOFTBUS_OK);
    EXPECT_TRUE(RefreshLNNInner(nullptr, &info, &cb) == SOFTBUS_OK);
    LnnOnRefreshLNNResult(LNN_REFRESH_ID, RESULT_REASON);
    LnnOnRefreshDeviceFound(nullptr);
}

/*
 * @tc.name: STOP_REFRESH_LNN_INNER_Test_001
 * @tc.desc: stop refresh lnn inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, STOP_REFRESH_LNN_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcStopRefreshLNN(_, _))
        .WillOnce(Return(SOFTBUS_SERVER_NOT_INIT))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NE(StopRefreshLNNInner(nullptr, LNN_SUBSCRIBE_ID), SOFTBUS_OK);
    EXPECT_TRUE(StopRefreshLNNInner(nullptr, LNN_SUBSCRIBE_ID) == SOFTBUS_OK);
}

static void OnJoinLNNResultCb(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    (void)addr;
    (void)networkId;
    (void)retCode;
    printf("on call join LNN result cb\n");
}

/*
 * @tc.name: LNN_ONJOIN_RESULT_Test_001
 * @tc.desc: lnn on join result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ONJOIN_RESULT_Test_001, TestSize.Level1)
{
    int32_t retCode = 0;
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = CONNECTION_ADDR_BR;
    (void)strcpy_s(addr.info.br.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    EXPECT_TRUE(LnnOnJoinResult(nullptr, nullptr, retCode) == SOFTBUS_INVALID_PARAM);
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnJoinResult(reinterpret_cast<void *>(&addr), NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcJoinLNN(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(JoinLNNInner(nullptr, &addr, OnJoinLNNResultCb) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnJoinResult(reinterpret_cast<void *>(&addr), NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    EXPECT_TRUE(JoinLNNInner(nullptr, &addr, nullptr) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnJoinResult(reinterpret_cast<void *>(&addr), NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

static void OnLeaveResultCb(const char *networkId, int32_t retCode)
{
    (void)networkId;
    (void)retCode;
    printf("on call leave result cb\n");
}

/*
 * @tc.name: LNN_ON_LEAVE_RESULT_Test_001
 * @tc.desc: lnn on leave result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ON_LEAVE_RESULT_Test_001, TestSize.Level1)
{
    int32_t retCode = 0;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnOnLeaveResult(nullptr, retCode) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnLeaveResult(NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcLeaveLNN(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LeaveLNNInner(nullptr, NODE1_NETWORK_ID, OnLeaveResultCb) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnLeaveResult(NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    EXPECT_TRUE(LeaveLNNInner(nullptr, NODE1_NETWORK_ID, nullptr) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnLeaveResult(NODE1_NETWORK_ID, retCode) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

static void OnNodeOnlineCb(NodeBasicInfo *info)
{
    (void)info;
    printf("on call node online cb\n");
}

static void OnNodeOfflineCb(NodeBasicInfo *info)
{
    (void)info;
    printf("on call node offline cb\n");
}

static void OnNodeBasicInfoChangedCb(NodeBasicInfoType type, NodeBasicInfo *info)
{
    (void)type;
    (void)info;
    printf("on call node basic info changed cb\n");
}

static void OnNodeStatusChangedCb(NodeStatusType type, NodeStatus *status)
{
    (void)type;
    (void)status;
    printf("on call node status changed cb\n");
}

/*
 * @tc.name: LNN_ON_NODE_ONLINE_STATE_CHANGED_Test_001
 * @tc.desc: lnn on node online state changed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ON_NODE_ONLINE_STATE_CHANGED_Test_001, TestSize.Level1)
{
    INodeStateCb callBcak;
    (void)memset_s(&callBcak, sizeof(INodeStateCb), 0, sizeof(INodeStateCb));
    callBcak.events = EVENT;
    callBcak.onNodeOnline = OnNodeOnlineCb;
    callBcak.onNodeOffline = OnNodeOfflineCb;
    callBcak.onNodeBasicInfoChanged = OnNodeBasicInfoChangedCb;
    callBcak.onNodeStatusChanged = OnNodeStatusChangedCb;
    NodeBasicInfo info;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnOnNodeOnlineStateChanged("", false, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(nullptr, &callBcak) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(PKGNAME, &callBcak) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnNodeOnlineStateChanged("", true, reinterpret_cast<void *>(&info)) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnNodeOnlineStateChanged("", false, reinterpret_cast<void *>(&info)) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: LNN_ON_NODE_BASICINFO_CHANGED_Test_001
 * @tc.desc: lnn on node basic info changed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ON_NODE_BASICINFO_CHANGED_Test_001, TestSize.Level1)
{
    INodeStateCb callBcak;
    (void)memset_s(&callBcak, sizeof(INodeStateCb), 0, sizeof(INodeStateCb));
    callBcak.events = EVENT;
    callBcak.onNodeOnline = OnNodeOnlineCb;
    callBcak.onNodeOffline = OnNodeOfflineCb;
    callBcak.onNodeBasicInfoChanged = OnNodeBasicInfoChangedCb;
    callBcak.onNodeStatusChanged = OnNodeStatusChangedCb;
    NodeBasicInfo info;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnOnNodeBasicInfoChanged("", nullptr, INVALID_TYPE) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnOnNodeBasicInfoChanged("", reinterpret_cast<void *>(&info), INVALID_TYPE) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(nullptr, &callBcak) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(PKGNAME, &callBcak) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnNodeBasicInfoChanged("", reinterpret_cast<void *>(&info), INVALID_TYPE) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnOnNodeBasicInfoChanged("", reinterpret_cast<void *>(&info), TYPE) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
 * @tc.name: LNN_ON_NODE_STATUS_CHANGED_Test_001
 * @tc.desc: lnn on node status changed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ON_NODE_STATUS_CHANGED_Test_001, TestSize.Level1)
{
    INodeStateCb callBcak;
    (void)memset_s(&callBcak, sizeof(INodeStateCb), 0, sizeof(INodeStateCb));
    callBcak.events = EVENT_NODE_STATUS_CHANGED;
    callBcak.onNodeStatusChanged = OnNodeStatusChangedCb;
    NodeStatus info;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(
        LnnOnNodeStatusChanged(nullptr, reinterpret_cast<void *>(&info), TYPE_SCREEN_STATUS) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnOnNodeStatusChanged("", nullptr, TYPE_STATUS_MAX + 1) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(nullptr, &callBcak) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(RegNodeDeviceStateCbInner(PKGNAME, &callBcak) == SOFTBUS_OK);
    EXPECT_TRUE(
        LnnOnNodeStatusChanged("", reinterpret_cast<void *>(&info), TYPE_STATUS_MAX + 1) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(LnnOnNodeStatusChanged("", reinterpret_cast<void *>(&info), TYPE_SCREEN_STATUS) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

static void OnTimeSyncResultCb(const TimeSyncResultInfo *info, int32_t retCode)
{
    (void)info;
    (void)retCode;
    printf("on call time sync result cb\n");
}

/*
 * @tc.name: LNN_ON_TIME_SYNC_RESULT_Test_001
 * @tc.desc: lnn on time sync result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientBusCentManagerTest, LNN_ON_TIME_SYNC_RESULT_Test_001, TestSize.Level1)
{
    int32_t retCode = 0;
    ITimeSyncCb cb;
    cb.onTimeSyncResult = OnTimeSyncResultCb;
    TimeSyncResultInfo info;
    (void)memset_s(&info, sizeof(TimeSyncResultInfo), 0, sizeof(TimeSyncResultInfo));
    (void)strcpy_s(info.target.targetNetworkId, NETWORK_ID_BUF_LEN, NODE1_NETWORK_ID);
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftbusGetConfig(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnOnTimeSyncResult(nullptr, retCode) == SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyInit()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, BusCenterServerProxyDeInit()).WillRepeatedly(Return());
    EXPECT_TRUE(BusCenterClientInit() == SOFTBUS_OK);
    EXPECT_CALL(busCentManagerMock, ServerIpcStartTimeSync(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(StartTimeSyncInner(nullptr, NODE1_NETWORK_ID, LOW_ACCURACY, SHORT_PERIOD, &cb) == SOFTBUS_OK);
    EXPECT_TRUE(LnnOnTimeSyncResult(reinterpret_cast<const void *>(&info), retCode) == SOFTBUS_OK);
    BusCenterClientDeinit();
}

/*
* @tc.name: REG_DATA_LEVEL_CHANGE_CB_INNER_Test_001
* @tc.desc: reg data level change cb inner test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, REG_DATA_LEVEL_CHANGE_CB_INNER_Test_001, TestSize.Level1)
{
    IDataLevelCb cb;
    (void)memset_s(&cb, sizeof(IDataLevelCb), 0, sizeof(IDataLevelCb));
    EXPECT_EQ(RegDataLevelChangeCbInner(nullptr, &cb), SOFTBUS_STRCPY_ERR);

    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcRegDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_SERVER_NOT_INIT));
    EXPECT_EQ(RegDataLevelChangeCbInner("pkgName", &cb), SOFTBUS_SERVER_NOT_INIT);

    EXPECT_CALL(busCentManagerMock, ServerIpcRegDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(RegDataLevelChangeCbInner("pkgName", &cb), SOFTBUS_OK);
}

/*
* @tc.name: RESTART_REG_DATA_LEVEL_CHANGE_Test_001
* @tc.desc: restart reg data level change test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, RESTART_REG_DATA_LEVEL_CHANGE_Test_001, TestSize.Level1)
{
    g_regDataLevelChangePkgName[0] = '\0';
    EXPECT_NO_FATAL_FAILURE(RestartRegDataLevelChange());

    g_regDataLevelChangePkgName[0] = '1';
    g_regDataLevelChangePkgName[1] = '\0';
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcRegDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_SERVER_NOT_INIT));
    EXPECT_NO_FATAL_FAILURE(RestartRegDataLevelChange());

    EXPECT_CALL(busCentManagerMock, ServerIpcRegDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(RestartRegDataLevelChange());
}

/*
* @tc.name: UNREG_DATA_LEVEL_CHANGE_CB_INNER_Test_001
* @tc.desc: unreg data level change cb inner test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, UNREG_DATA_LEVEL_CHANGE_CB_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcUnregDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_SERVER_NOT_INIT));
    EXPECT_EQ(UnregDataLevelChangeCbInner(nullptr), SOFTBUS_SERVER_NOT_INIT);

    EXPECT_CALL(busCentManagerMock, ServerIpcUnregDataLevelChangeCb(_)).WillOnce(Return(SOFTBUS_OK));
    auto ret = UnregDataLevelChangeCbInner(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: SET_DATA_LEVEL_INNER_Test_001
* @tc.desc: set data level inner test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, SET_DATA_LEVEL_INNER_Test_001, TestSize.Level1)
{
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, ServerIpcSetDataLevel(_)).WillOnce(Return(SOFTBUS_SERVER_NOT_INIT));
    EXPECT_EQ(SetDataLevelInner(nullptr), SOFTBUS_SERVER_NOT_INIT);

    EXPECT_CALL(busCentManagerMock, ServerIpcSetDataLevel(_)).WillOnce(Return(SOFTBUS_OK));
    auto ret = SetDataLevelInner(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ON_LOCAL_NETWORK_ID_CHANGED_Test_001
* @tc.desc: lnn on local network id changed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, LNN_ON_LOCAL_NETWORK_ID_CHANGED_Test_001, TestSize.Level1)
{
    SoftBusMutexInit(&g_busCenterClient.lock, NULL);
    EXPECT_EQ(LnnOnLocalNetworkIdChanged(nullptr), SOFTBUS_INVALID_PARAM);

    g_busCenterClient.isInit = false;
    EXPECT_EQ(LnnOnLocalNetworkIdChanged("pkgName"), SOFTBUS_NO_INIT);

    g_busCenterClient.isInit = true;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnLocalNetworkIdChanged("pkgName"), SOFTBUS_LOCK_ERR);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    auto ret = LnnOnLocalNetworkIdChanged("pkgName");
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_OK));
    ret = LnnOnLocalNetworkIdChanged("pkgName");
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ON_NODE_DEVICE_TRUSTED_CHANGE_Test_001
* @tc.desc: lnn on node device trusted change test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, LNN_ON_NODE_DEVICE_TRUSTED_CHANGE_Test_001, TestSize.Level1)
{
    SoftBusMutexInit(&g_busCenterClient.lock, NULL);
    EXPECT_EQ(LnnOnNodeDeviceTrustedChange(nullptr, 0, nullptr, 0), SOFTBUS_INVALID_PARAM);

    g_busCenterClient.isInit = false;
    EXPECT_EQ(LnnOnNodeDeviceTrustedChange("pkgName", 0, nullptr, 0), SOFTBUS_NO_INIT);

    g_busCenterClient.isInit = true;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnNodeDeviceTrustedChange("pkgName", 0, nullptr, 0), SOFTBUS_LOCK_ERR);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnNodeDeviceTrustedChange("pkgName", 0, nullptr, 0), SOFTBUS_OK);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnNodeDeviceTrustedChange("pkgName", 0, nullptr, 0), SOFTBUS_OK);
}

/*
* @tc.name: LNN_ON_HICHAIN_PROOF_EXCEPTION_Test_001
* @tc.desc: lnn on hichain proof exception test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, LNN_ON_HICHAIN_PROOF_EXCEPTION_Test_001, TestSize.Level1)
{
    SoftBusMutexInit(&g_busCenterClient.lock, NULL);
    EXPECT_EQ(LnnOnHichainProofException(nullptr, nullptr, 0, 0, 0), SOFTBUS_INVALID_PARAM);

    g_busCenterClient.isInit = false;
    EXPECT_EQ(LnnOnHichainProofException("pkgName", nullptr, 0, 0, 0), SOFTBUS_NO_INIT);

    g_busCenterClient.isInit = true;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnHichainProofException("pkgName", nullptr, 0, 0, 0), SOFTBUS_LOCK_ERR);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnHichainProofException("pkgName", nullptr, 0, 0, 0), SOFTBUS_OK);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnHichainProofException("pkgName", nullptr, 0, 0, 0), SOFTBUS_OK);
}

/*
* @tc.name: LNN_ON_TIME_SYNC_RESULT_Test_002
* @tc.desc: lnn on time sync result test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, LNN_ON_TIME_SYNC_RESULT_Test_002, TestSize.Level1)
{
    SoftBusMutexInit(&g_busCenterClient.lock, NULL);
    EXPECT_EQ(LnnOnTimeSyncResult(nullptr, 0), SOFTBUS_INVALID_PARAM);

    g_busCenterClient.isInit = false;
    EXPECT_EQ(LnnOnTimeSyncResult("info", 0), SOFTBUS_NETWORK_CLIENT_NOT_INIT);

    g_busCenterClient.isInit = true;
    ClientBusCenterManagerInterfaceMock busCentManagerMock;
    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnTimeSyncResult("info", 0), SOFTBUS_LOCK_ERR);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnTimeSyncResult("info", 0), SOFTBUS_OK);

    EXPECT_CALL(busCentManagerMock, SoftBusMutexLockInner(_)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(busCentManagerMock, SoftBusMutexUnlockInner(_)).WillOnce(Return(SOFTBUS_LOCK_ERR));
    EXPECT_EQ(LnnOnTimeSyncResult("info", 0), SOFTBUS_OK);
}

/*
* @tc.name: LNN_ON_DATA_LEVEL_CHANGED_Test_001
* @tc.desc: lnn on data level changed test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, LNN_ON_DATA_LEVEL_CHANGED_Test_001, TestSize.Level1)
{
    auto ptr = g_busCenterClient.dataLevelCb.onDataLevelChanged;
    g_busCenterClient.dataLevelCb.onDataLevelChanged = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnOnDataLevelChanged(nullptr, nullptr));

    g_busCenterClient.dataLevelCb.onDataLevelChanged = ptr;
    EXPECT_NO_FATAL_FAILURE(LnnOnDataLevelChanged(nullptr, nullptr));
}

/*
* @tc.name: DISC_RECOVERY_PUBLISH_Test_001
* @tc.desc: disc recovery publish test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, DISC_RECOVERY_PUBLISH_Test_001, TestSize.Level1)
{
    g_isInited = false;
    EXPECT_EQ(DiscRecoveryPublish(), SOFTBUS_OK);

    g_isInited = true;
    auto ret = DiscRecoveryPublish();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: DISC_RECOVERY_SUBSCRIBE_Test_001
* @tc.desc: disc recovery subscribe test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, DISC_RECOVERY_SUBSCRIBE_Test_001, TestSize.Level1)
{
    g_isInited = false;
    EXPECT_EQ(DiscRecoverySubscribe(), SOFTBUS_OK);

    g_isInited = true;
    auto ret = DiscRecoverySubscribe();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: IS_SAME_CONNECTION_ADDR_Test_001
* @tc.desc: is same connection addr test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, IS_SAME_CONNECTION_ADDR_Test_001, TestSize.Level1)
{
    ConnectionAddr addr1;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ConnectionAddr addr2;
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_BR;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr1.type = CONNECTION_ADDR_BR;
    addr2.type = CONNECTION_ADDR_BR;
    memset_s(addr1.info.br.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    memset_s(addr2.info.br.brMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    addr1.type = CONNECTION_ADDR_BLE;
    addr2.type = CONNECTION_ADDR_BLE;
    memset_s(addr2.info.ble.udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    memset_s(addr1.info.ble.bleMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    memset_s(addr2.info.ble.bleMac, BT_MAC_LEN, 0, BT_MAC_LEN);
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    memset_s(addr1.info.ble.udidHash, UDID_HASH_LEN, 0, UDID_HASH_LEN);
    memset_s(addr2.info.ble.udidHash, UDID_HASH_LEN, 1, UDID_HASH_LEN);
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    memset_s(addr1.info.ble.udidHash, UDID_HASH_LEN, 1, UDID_HASH_LEN);
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_WLAN;
    memset_s(addr1.info.ip.ip, IP_STR_MAX_LEN, 0, IP_STR_MAX_LEN);
    memset_s(addr2.info.ip.ip, IP_STR_MAX_LEN, 0, IP_STR_MAX_LEN);
    addr1.info.ip.port = 0;
    addr2.info.ip.port = 0;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    addr2.info.ip.port = 1;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);
}

/*
* @tc.name: IS_SAME_CONNECTION_ADDR_Test_002
* @tc.desc: is same connection addr test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, IS_SAME_CONNECTION_ADDR_Test_002, TestSize.Level1)
{
    ConnectionAddr addr1;
    (void)memset_s(&addr1, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ConnectionAddr addr2;
    (void)memset_s(&addr2, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr1.type = CONNECTION_ADDR_WLAN;
    addr2.type = CONNECTION_ADDR_WLAN;
    memset_s(addr1.info.ip.ip, IP_STR_MAX_LEN, 0, IP_STR_MAX_LEN);
    memset_s(addr1.info.ip.ip, IP_STR_MAX_LEN, 1, IP_STR_MAX_LEN);
    addr1.info.ip.port = 0;
    addr2.info.ip.port = 0;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr1.type = CONNECTION_ADDR_ETH;
    addr2.type = CONNECTION_ADDR_ETH;
    memset_s(addr1.info.ip.ip, IP_STR_MAX_LEN, 0, IP_STR_MAX_LEN);
    memset_s(addr2.info.ip.ip, IP_STR_MAX_LEN, 0, IP_STR_MAX_LEN);
    addr1.info.ip.port = 0;
    addr2.info.ip.port = 0;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    addr2.info.ip.port = 1;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    memset_s(addr1.info.ip.ip, IP_STR_MAX_LEN, 1, IP_STR_MAX_LEN);
    addr1.info.ip.port = 0;
    addr2.info.ip.port = 0;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr1.type = CONNECTION_ADDR_SESSION;
    addr2.type = CONNECTION_ADDR_SESSION;
    addr1.info.session.sessionId = 0;
    addr2.info.session.sessionId = 0;
    addr1.info.session.channelId = 0;
    addr2.info.session.channelId = 0;
    addr1.info.session.type = 0;
    addr2.info.session.type = 0;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), true);

    addr2.info.session.type = 1;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr2.info.session.channelId = 1;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr2.info.session.sessionId = 1;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);

    addr1.type = CONNECTION_ADDR_MAX;
    addr2.type = CONNECTION_ADDR_MAX;
    EXPECT_EQ(IsSameConnectionAddr(&addr1, &addr2), false);
}

/*
* @tc.name: ADD_LEAVE_LNNCB_ITEM_Test_001
* @tc.desc: add leave lnncb item test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, ADD_LEAVE_LNNCB_ITEM_Test_001, TestSize.Level1)
{
    OnLeaveLNNResult cb = [](const char *, int32_t) -> void {};
    ListInit(&g_busCenterClient.leaveLNNCbList);
    EXPECT_EQ(AddLeaveLNNCbItem("1.2.3.4", cb), SOFTBUS_OK);
}

/*
* @tc.name: ADD_TIME_SYNC_CB_ITEM_Test_001
* @tc.desc: add time sync cb item test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, ADD_TIME_SYNC_CB_ITEM_Test_001, TestSize.Level1)
{
    ITimeSyncCb cb;
    (void)memset_s(&cb, sizeof(ITimeSyncCb), 0, sizeof(ITimeSyncCb));
    cb.onTimeSyncResult = [](const TimeSyncResultInfo *, int32_t) ->void {};
    ListInit(&g_busCenterClient.timeSyncCbList);
    EXPECT_EQ(AddTimeSyncCbItem("1.2.3.4", &cb), SOFTBUS_OK);
}

/*
* @tc.name: FREE_DISC_PUBLISH_MSG_Test_001
* @tc.desc: free disc publish msg test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, FREE_DISC_PUBLISH_MSG_Test_001, TestSize.Level1)
{
    DiscPublishMsg *msg = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscPublishMsg(&msg));

    msg = (DiscPublishMsg *)SoftBusCalloc(sizeof(DiscPublishMsg));
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "msg calloc fail");
        return;
    }
    msg->info = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscPublishMsg(&msg));

    msg = (DiscPublishMsg *)SoftBusCalloc(sizeof(DiscPublishMsg));
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "msg calloc fail");
        return;
    }
    msg->info = (PublishInfo *)SoftBusCalloc(sizeof(PublishInfo));
    if (msg->info == nullptr) {
        COMM_LOGE(COMM_TEST, "msgInfo calloc fail");
        SoftBusFree(msg);
        return;
    }
    msg->info->capability = nullptr;
    msg->info->capabilityData = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscPublishMsg(&msg));
}

/*
* @tc.name: FREE_DISC_SUBSCRIBE_MSG_Test_001
* @tc.desc: free disc subscribe msg test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ClientBusCentManagerTest, FREE_DISC_SUBSCRIBE_MSG_Test_001, TestSize.Level1)
{
    DiscSubscribeMsg *msg = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscSubscribeMsg(&msg));

    msg = (DiscSubscribeMsg *)SoftBusCalloc(sizeof(DiscSubscribeMsg));
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "msg calloc fail");
        return;
    }
    msg->info = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscSubscribeMsg(&msg));

    msg = (DiscSubscribeMsg *)SoftBusCalloc(sizeof(DiscSubscribeMsg));
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "msg calloc fail");
        return;
    }
    msg->info = (SubscribeInfo *)SoftBusCalloc(sizeof(SubscribeInfo));
    if (msg->info == nullptr) {
        COMM_LOGE(COMM_TEST, "msgInfo calloc fail");
        SoftBusFree(msg);
        return;
    }
    msg->info->capability = nullptr;
    msg->info->capabilityData = nullptr;
    EXPECT_NO_FATAL_FAILURE(FreeDiscSubscribeMsg(&msg));
}
} // namespace OHOS