/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "lnn_connection_fsm.c"
#include "lnn_connection_fsm.h"
#include "lnn_connection_fsm_process.c"
#include "lnn_connection_fsm_process.h"
#include "lnn_devicename_info.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

constexpr char DEVICE_IP1[MAX_ADDR_LEN] = "127.0.0.1";
constexpr char DEVICE_IP2[MAX_ADDR_LEN] = "127.0.0.2";
constexpr uint16_t PORT1 = 1000;
constexpr uint16_t PORT2 = 1001;
constexpr int64_t AUTH_ID = 10;
constexpr char NODE_UDID[UUID_BUF_LEN] = "123456ABCDEF";
constexpr char NETWORKID1[NETWORK_ID_BUF_LEN] = "123456ABD";
constexpr uint32_t REQUEST_ID = 1;
constexpr uint32_t CONN_FLAG = 0;

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class LNNConnectionFsmMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNConnectionFsmMockTest::SetUpTestCase()
{
    LooperInit();
}

void LNNConnectionFsmMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNConnectionFsmMockTest::SetUp() { }

void LNNConnectionFsmMockTest::TearDown() { }

static void LnnConnectionFsmStopCallback(struct tagLnnConnectionFsm *connFsm)
{
    (void)connFsm;
    return;
}

/*
 * @tc.name: LNN_IS_NODE_INFO_CHANGED_TEST_001
 * @tc.desc: Verify IsNodeInfoChanged detects node info changes when sessionPort,
 *           proxyPort, authPort or deviceIp are modified
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, LNN_IS_NODE_INFO_CHANGED_TEST_001, TestSize.Level1)
{
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT1,
    };
    (void)strcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, DEVICE_IP1);
    LnnConnectionFsm *connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo oldNodeInfo;
    NodeInfo newNodeInfo;
    ConnectionAddrType type;
    (void)strcpy_s(oldNodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID1);
    (void)strcpy_s(newNodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID1);
    (void)strcpy_s(oldNodeInfo.connectInfo.ifInfo[WLAN_IF].deviceIp, MAX_ADDR_LEN, DEVICE_IP1);
    (void)strcpy_s(newNodeInfo.connectInfo.ifInfo[WLAN_IF].deviceIp, MAX_ADDR_LEN, DEVICE_IP1);
    oldNodeInfo.connectInfo.ifInfo[WLAN_IF].authPort = PORT1;
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].authPort = PORT1;
    oldNodeInfo.connectInfo.ifInfo[WLAN_IF].proxyPort = PORT1;
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].proxyPort = PORT1;
    oldNodeInfo.connectInfo.ifInfo[WLAN_IF].sessionPort = PORT1;
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].sessionPort = PORT1;

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    bool ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].sessionPort = PORT2;
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == true);
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].proxyPort = PORT2;
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == true);
    newNodeInfo.connectInfo.ifInfo[WLAN_IF].authPort = PORT2;
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == true);
    (void)strcpy_s(newNodeInfo.connectInfo.ifInfo[WLAN_IF].deviceIp, MAX_ADDR_LEN, DEVICE_IP2);
    ret1 = IsNodeInfoChanged(connFsm, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == true);
    LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: AUTH_STATE_PROCESS_TEST_001
 * @tc.desc: Verify AuthStateProcess handles FSM_MSG_TYPE_JOIN_LNN, FSM_MSG_TYPE_AUTH_DONE,
 *           FSM_MSG_TYPE_DISCONNECT and FSM_MSG_TYPE_JOIN_LNN_TIMEOUT messages correctly
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, AUTH_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = reinterpret_cast<LnnConnectionFsm *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(connFsm != nullptr);
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(para != nullptr);
    void *para1 = nullptr;
    para1 = reinterpret_cast<void *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(para1 != nullptr);
    connFsm->connInfo.authHandle.authId = AUTH_ID;
    connFsm->isSession = false;
    EXPECT_CALL(serviceMock, LnnNotifyJoinResult).WillRepeatedly(Return());
    bool ret = AuthStateProcess(nullptr, FSM_MSG_TYPE_JOIN_LNN, para);
    EXPECT_TRUE(ret == false);
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, para);
    EXPECT_TRUE(ret == true);
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, nullptr);
    EXPECT_TRUE(ret == true);
    connFsm->isDead = true;
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, nullptr);
    EXPECT_TRUE(ret == true);
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, para1);
    EXPECT_TRUE(ret == true);
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_DISCONNECT, nullptr);
    EXPECT_TRUE(ret == true);
    ret = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, nullptr);
    EXPECT_TRUE(ret == true);
    SoftBusFree(connFsm);
}

/*
 * @tc.name: AUTH_STATE_PROCESS_TEST_002
 * @tc.desc: Verify AuthStateProcess with FSM_MSG_TYPE_JOIN_LNN message and
 *           AuthStartVerify returning SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, AUTH_STATE_PROCESS_TEST_002, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connFsm->isDead = false;
    connFsm->isNeedConnect = false;
    int32_t *retCode = nullptr;
    retCode = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(retCode != nullptr);
    *retCode = SOFTBUS_OK;

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnAuthtInterfaceMock> authtMock;
    EXPECT_CALL(serviceMock, AuthGenRequestId).WillRepeatedly(Return(REQUEST_ID));
    EXPECT_CALL(authtMock, AuthStartVerify).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    bool ret1 = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: AUTH_STATE_PROCESS_TEST_003
 * @tc.desc: Verify AuthStateProcess with FSM_MSG_TYPE_AUTH_DONE message and
 *           various mock return values
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, AUTH_STATE_PROCESS_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    NiceMock<LnnAuthtInterfaceMock> authtMock;
    EXPECT_CALL(authtMock, AuthGetVersion).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, AuthGetDeviceUuid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t *retCode = nullptr;
    retCode = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(retCode != nullptr);
    *retCode = SOFTBUS_OK;
    int32_t *retCode1 = nullptr;
    retCode1 = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(retCode1 != nullptr);
    *retCode1 = SOFTBUS_OK;
    int32_t *retCode2 = nullptr;
    retCode2 = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(retCode2 != nullptr);
    *retCode2 = SOFTBUS_OK;
    int32_t *retCode3 = nullptr;
    retCode3 = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    EXPECT_TRUE(retCode3 != nullptr);
    *retCode3 = SOFTBUS_OK;
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT1,
    };
    (void)strcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, DEVICE_IP1);
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connFsm->connInfo.nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    EXPECT_TRUE(connFsm->connInfo.nodeInfo != nullptr);
    connFsm->isDead = false;
    connFsm->fsm.flag = 0;
    connFsm->fsm.looper = nullptr;

    bool ret1 = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, reinterpret_cast<void *>(retCode1));
    EXPECT_TRUE(ret1 == true);
    ret1 = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, reinterpret_cast<void *>(retCode2));
    EXPECT_TRUE(ret1 == true);
    (void)strcpy_s(connFsm->connInfo.nodeInfo->uuid, UUID_BUF_LEN, NODE_UDID);
    ret1 = AuthStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, reinterpret_cast<void *>(retCode3));
    EXPECT_TRUE(ret1 == true);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: ONLINE_STATE_ENTER_TEST_001
 * @tc.desc: Verify OnlineStateEnter handles nullptr and valid fsm correctly
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, ONLINE_STATE_ENTER_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connFsm->connInfo.nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    EXPECT_TRUE(connFsm->connInfo.nodeInfo != nullptr);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(netLedgerMock, LnnAddOnlineNode).WillOnce(Return(REPORT_CHANGE)).WillRepeatedly(Return(REPORT_ONLINE));

    OnlineStateEnter(nullptr);
    OnlineStateEnter(&connFsm->fsm);
    connFsm->connInfo.nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    EXPECT_TRUE(connFsm->connInfo.nodeInfo != nullptr);
    OnlineStateEnter(&connFsm->fsm);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: CLEAN_INVALID_CONNSTATE_PROCESS_TEST_001
 * @tc.desc: Verify CleanInvalidConnStateProcess handles various FSM message types
 *           including LEAVE_INVALID_CONN, NOT_TRUSTED, DISCONNECT and INITIATE_ONLINE
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, CLEAN_INVALID_CONNSTATE_PROCESS_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    int32_t *retCode = nullptr;
    retCode = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    *retCode = SOFTBUS_OK;
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connFsm->connInfo.nodeInfo = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    EXPECT_TRUE(connFsm->connInfo.nodeInfo != nullptr);
    connFsm->fsm.flag = CONN_FLAG;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(netLedgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(netLedgerMock, LnnIsNodeOnline).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret1 =
        CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 =
        CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 =
        CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_NOT_TRUSTED, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_DISCONNECT, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_INITIATE_ONLINE, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 =
        CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = CleanInvalidConnStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == false);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: ONLINE_STATE_PROCESS_TEST_001
 * @tc.desc: Verify OnlineStateProcess handles FSM_MSG_TYPE_JOIN_LNN and
 *           FSM_MSG_TYPE_LEAVE_LNN messages correctly
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, ONLINE_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    int32_t *retCode = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    *retCode = SOFTBUS_OK;
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    bool ret1 = OnlineStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = OnlineStateProcess(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: LEAVING_STATE_ENTER_TEST_001
 * @tc.desc: Verify LeavingStateEnter handles nullptr and valid fsm correctly
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, LEAVING_STATE_ENTER_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    LeavingStateEnter(nullptr);
    LeavingStateEnter(&connFsm->fsm);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: LEAVING_STATE_PROCESS_TEST_001
 * @tc.desc: Verify LeavingStateProcess handles FSM_MSG_TYPE_JOIN_LNN and
 *           FSM_MSG_TYPE_AUTH_DONE messages correctly
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, LEAVING_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    int32_t *retCode = reinterpret_cast<int32_t *>(SoftBusMalloc(sizeof(int32_t)));
    *retCode = SOFTBUS_OK;
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    bool ret1 = LeavingStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = LeavingStateProcess(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == true);
    ret1 = LeavingStateProcess(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, reinterpret_cast<void *>(retCode));
    EXPECT_TRUE(ret1 == false);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: LNN_STOP_CONNECTION_FSM_TEST_001
 * @tc.desc: Verify LnnStopConnectionFsm with nullptr connFsm or nullptr callback
 *           returns SOFTBUS_INVALID_PARAM; with valid parameters returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, LNN_STOP_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_BLE,
    };
    int32_t ret = LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connFsm = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm != nullptr);
    ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnStopConnectionFsm(connFsm, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: DFX_RECORD_TRIGGER_TIME_TEST_001
 * @tc.desc: test DfxRecordTriggerTime with valid parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, DFX_RECORD_TRIGGER_TIME_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DfxRecordTriggerTime(WIFI_STATE_CHANGED, EVENT_STAGE_LNN_USER_SWITCHED));
}

/*
 * @tc.name: DEVICE_STATE_CHANGE_PROCESS_TEST_001
 * @tc.desc: test DeviceStateChangeProcess with null udid
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, DEVICE_STATE_CHANGE_PROCESS_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DeviceStateChangeProcess(nullptr, CONNECTION_ADDR_BLE, true));
}

/*
 * @tc.name: DEVICE_STATE_CHANGE_PROCESS_TEST_002
 * @tc.desc: test DeviceStateChangeProcess with non-BLE type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, DEVICE_STATE_CHANGE_PROCESS_TEST_002, TestSize.Level1)
{
    char udid[UDID_BUF_LEN] = "testUdid";
    EXPECT_NO_FATAL_FAILURE(DeviceStateChangeProcess(udid, CONNECTION_ADDR_WLAN, true));
}

/*
 * @tc.name: DEVICE_STATE_CHANGE_PROCESS_TEST_003
 * @tc.desc: test DeviceStateChangeProcess with BLE type
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, DEVICE_STATE_CHANGE_PROCESS_TEST_003, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnIsLocalSupportMcuFeature).WillRepeatedly(Return(false));

    char udid[UDID_BUF_LEN] = "testUdid";
    EXPECT_NO_FATAL_FAILURE(DeviceStateChangeProcess(udid, CONNECTION_ADDR_BLE, true));
}

/*
 * @tc.name: SET_ASSET_SESSION_KEY_BY_AUTH_INFO_TEST_001
 * @tc.desc: test SetAssetSessionKeyByAuthInfo with null info
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, SET_ASSET_SESSION_KEY_BY_AUTH_INFO_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = {};
    EXPECT_NO_FATAL_FAILURE(SetAssetSessionKeyByAuthInfo(nullptr, authHandle));
}

/*
 * @tc.name: UPDATE_DEVICE_INFO_TO_MCU_TEST_001
 * @tc.desc: test UpdateDeviceInfoToMcu with valid udid
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, UPDATE_DEVICE_INFO_TO_MCU_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_MEM_ERR));

    const char *udid = "testUdid";
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceInfoToMcu(udid));
}

/*
 * @tc.name: UPDATE_DEVICE_INFO_TO_MLPS_TEST_001
 * @tc.desc: test UpdateDeviceInfoToMlps with valid udid
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, UPDATE_DEVICE_INFO_TO_MLPS_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_MEM_ERR));

    const char *udid = "testUdid";
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceInfoToMlps(udid));
}

/*
 * @tc.name: IS_REPEAT_DEVICE_ID_TEST_003
 * @tc.desc: test IsRepeatDeviceId with device not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, IS_REPEAT_DEVICE_ID_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    NodeInfo info = {};
    (void)memset_s(info.deviceInfo.deviceUdid, UDID_BUF_LEN, 'A', UDID_BUF_LEN - 1);
    info.deviceInfo.deviceUdid[UDID_BUF_LEN - 1] = '\0';
    (void)memset_s(info.networkId, NETWORK_ID_BUF_LEN, 'B', NETWORK_ID_BUF_LEN - 1);
    info.networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    EXPECT_FALSE(IsRepeatDeviceId(&info));
}

/*
 * @tc.name: CHECK_REMOTE_BASIC_INFO_CHANGED_TEST_001
 * @tc.desc: test CheckRemoteBasicInfoChanged with null info
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, CHECK_REMOTE_BASIC_INFO_CHANGED_TEST_001, TestSize.Level1)
{
    EXPECT_FALSE(CheckRemoteBasicInfoChanged(nullptr));
}

/*
 * @tc.name: CHECK_REMOTE_BASIC_INFO_CHANGED_TEST_002
 * @tc.desc: test CheckRemoteBasicInfoChanged with device not found
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, CHECK_REMOTE_BASIC_INFO_CHANGED_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    NodeInfo nodeInfo = {};
    EXPECT_FALSE(CheckRemoteBasicInfoChanged(&nodeInfo));
}

/*
 * @tc.name: FILL_BLE_ADDR_TEST_001
 * @tc.desc: test FillBleAddr with valid parameters
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, FILL_BLE_ADDR_TEST_001, TestSize.Level1)
{
    ConnectionAddr addr = {};
    ConnectionAddr connAddr = {};
    NodeInfo nodeInfo = {};
    (void)memset_s(nodeInfo.connectInfo.macAddr, BT_MAC_LEN, 'A', BT_MAC_LEN - 1);
    nodeInfo.connectInfo.macAddr[BT_MAC_LEN - 1] = '\0';
    (void)memset_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, 'B', UDID_BUF_LEN - 1);
    nodeInfo.deviceInfo.deviceUdid[UDID_BUF_LEN - 1] = '\0';
    int32_t ret = FillBleAddr(&addr, &connAddr, &nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(addr.type, CONNECTION_ADDR_BLE);
}

/*
 * @tc.name: UPDATE_DEVICE_DEVICE_NAME_TEST_001
 * @tc.desc: test UpdateDeviceDeviceName with same name
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, UPDATE_DEVICE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnSetDLDeviceInfoName).WillRepeatedly(Return(true));

    NodeInfo nodeInfo = {};
    NodeInfo remoteInfo = {};
    (void)strcpy_s(nodeInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, "TestDevice");
    (void)strcpy_s(remoteInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, "TestDevice");
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceDeviceName(&nodeInfo, &remoteInfo));
}

/*
 * @tc.name: UPDATE_DEVICE_DEVICE_NAME_TEST_002
 * @tc.desc: test UpdateDeviceDeviceName with different name
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LNNConnectionFsmMockTest, UPDATE_DEVICE_DEVICE_NAME_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnSetDLDeviceInfoName).WillRepeatedly(Return(true));

    NodeInfo nodeInfo = {};
    NodeInfo remoteInfo = {};
    (void)strcpy_s(nodeInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, "NewDevice");
    (void)strcpy_s(remoteInfo.deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, "OldDevice");
    EXPECT_NO_FATAL_FAILURE(UpdateDeviceDeviceName(&nodeInfo, &remoteInfo));
}

} // namespace OHOS
