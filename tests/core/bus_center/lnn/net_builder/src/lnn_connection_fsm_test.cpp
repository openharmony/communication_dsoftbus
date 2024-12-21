/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "distribute_net_ledger_mock.h"
#include "lnn_auth_mock.h"
#include "lnn_connection_fsm.c"
#include "lnn_connection_fsm.h"
#include "lnn_connection_fsm_mock.h"
#include "lnn_devicename_info.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

#define FUNC_SLEEP_MS 10
constexpr char IP[IP_STR_MAX_LEN] = "127.0.0.1";
constexpr uint16_t PORT = 1000;
constexpr char MACTEST[BT_MAC_LEN] = "00:11:22:33:44";
constexpr char PEERUID[MAX_ACCOUNT_HASH_LEN] = "021315ASD";
constexpr char PEERUID1[MAX_ACCOUNT_HASH_LEN] = "021315ASE";
constexpr char PEERUID2[MAX_ACCOUNT_HASH_LEN] = "021315ASC";
constexpr char PEERUID3[MAX_ACCOUNT_HASH_LEN] = "021315ACE";
constexpr char NETWORKID1[NETWORK_ID_BUF_LEN] = "123456ABD";
constexpr char NETWORKID2[NETWORK_ID_BUF_LEN] = "123456ABC";
constexpr char NETWORKID3[LNN_CONNECTION_FSM_NAME_LEN] = "123456ABD";
constexpr char PEERUDID[UDID_BUF_LEN] = "021315ASD";
constexpr char SOFTBUSVERSION[VERSION_MAX_LEN] = "softBusVersion";

namespace OHOS {
using namespace testing;
using namespace testing::ext;

static LnnConnectionFsm *connFsm = nullptr;
static ConnectionAddr target = {
    .type = CONNECTION_ADDR_WLAN,
    .info.ip.port = PORT,
};
static LnnConnectionFsm *connFsm2 = nullptr;
static ConnectionAddr target3 = {
    .type = CONNECTION_ADDR_WLAN,
    .info.ip.port = PORT,
};
static LnnConnectionFsm *connFsm3 = nullptr;
static ConnectionAddr target4 = {
    .type = CONNECTION_ADDR_WLAN,
    .info.ip.port = PORT,
};
static LnnConnectionFsm *connFsm4 = nullptr;
class LNNConnectionFsmTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNConnectionFsmTest::SetUpTestCase()
{
    LooperInit();
    const char *ip = IP;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnPrintConnectionAddr).WillRepeatedly(Return(ip));
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    connFsm2 = LnnCreateConnectionFsm(&target, "pkgName", true);
    EXPECT_TRUE(connFsm2 != nullptr);

    (void)memcpy_s(target3.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID1, strlen(PEERUID1));
    (void)memcpy_s(target3.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    connFsm3 = LnnCreateConnectionFsm(&target3, "pkgName1", true);
    EXPECT_TRUE(connFsm3 != nullptr);

    (void)memcpy_s(target4.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID2, strlen(PEERUID2));
    (void)memcpy_s(target4.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    connFsm4 = LnnCreateConnectionFsm(&target4, "pkgName2", true);
    EXPECT_TRUE(connFsm4 != nullptr);
}

void LNNConnectionFsmTest::TearDownTestCase()
{
    LooperDeinit();
    LnnDestroyConnectionFsm(connFsm2);
    LnnDestroyConnectionFsm(connFsm3);
    LnnDestroyConnectionFsm(connFsm4);
}

void LNNConnectionFsmTest::SetUp() { }

void LNNConnectionFsmTest::TearDown() { }

void FsmStopCallback(struct tagLnnConnectionFsm *connFsm) { }

/*
 * @tc.name: LNN_CREATE_CONNECTION_FSM_TEST_001
 * @tc.desc: para is null
 * @tc.type: FUNC
 * @tc.require:I5PRUD
 */
HWTEST_F(LNNConnectionFsmTest, LNN_CREATE_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    ConnectionAddr *target1 = nullptr;
    LnnConnectionFsm *fsm = LnnCreateConnectionFsm(target1, "pkgName", true);
    EXPECT_TRUE(fsm == nullptr);
    LnnDestroyConnectionFsm(fsm);
    DfxRecordConnAuthStart(nullptr, fsm, 0);
}

/*
 * @tc.name: LNN_START_CONNECTION_FSM_TEST_001
 * @tc.desc: test LnnStartConnectionFsm
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNConnectionFsmTest, LNN_START_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnStartConnectionFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(200);
}

/*
 * @tc.name: LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendJoinRequestToConnFsm
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NiceMock<LnnAuthtInterfaceMock> authMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    const char *ip = IP;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnPrintConnectionAddr).WillRepeatedly(Return(ip));
    ON_CALL(serviceMock, AuthGenRequestId).WillByDefault(Return(1));
    EXPECT_CALL(authMock, AuthStartVerify).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(serviceMock, LnnNotifyJoinResult).WillByDefault(Return());
    ret = LnnSendJoinRequestToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: LNN_SEND_AUTH_RESULT_MSG_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendAuthResultMsgToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_AUTH_RESULT_MSG_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t retCode = 0;
    int32_t ret = LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connFsm3->isDead = true;
    ret = LnnSendAuthResultMsgToConnFsm(connFsm3, retCode);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connFsm3->isDead = false;
    ret = LnnSendAuthResultMsgToConnFsm(connFsm3, retCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnConnectionFsm connFsm = {};
    connFsm.fsm.looper = nullptr;
    connFsm.isDead = false;
    ret = LnnSendAuthResultMsgToConnFsm(&connFsm, retCode);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_SEND_FAIL);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendNotTrustedToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnSendNotTrustedToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSendNotTrustedToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendDisconnectMsgToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnSendDisconnectMsgToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendLeaveRequestToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm2);
    ret = LnnSendLeaveRequestToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSendLeaveRequestToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendSyncOfflineFinishToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSendSyncOfflineFinishToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSendSyncOfflineFinishToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001
 * @tc.desc: test LnnSendNewNetworkOnlineToConnFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnSendNewNetworkOnlineToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnSendNewNetworkOnlineToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_CHECK_STATE_MSG_COMMON_ARGS_TEST_001
 * @tc.desc: test CheckStateMsgCommonArgs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_CHECK_STATE_MSG_COMMON_ARGS_TEST_001, TestSize.Level1)
{
    bool ret = CheckStateMsgCommonArgs(nullptr);
    EXPECT_TRUE(ret == false);
    ConnectionFsmDinitCallback(nullptr);
    FsmStateMachine fsm;
    ret = CheckStateMsgCommonArgs(&fsm);
    EXPECT_TRUE(ret == true);
    SoftBusSleepMs(FUNC_SLEEP_MS);
}

/*
 * @tc.name: LNN_REPORT_LNN_RESULT_EVT_TEST_001
 * @tc.desc: test OnlineTrustGroupProc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_REPORT_LNN_RESULT_EVT_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connFsm4->connInfo.addr.type = CONNECTION_ADDR_MAX;
    ReportLnnResultEvt(connFsm4, SOFTBUS_HISYSEVT_LINK_TYPE_BR);
    connFsm4->connInfo.addr.type = CONNECTION_ADDR_SESSION;
    ReportLnnResultEvt(connFsm4, SOFTBUS_HISYSEVT_LINK_TYPE_BR);
    ReportLnnResultEvt(connFsm4, SOFTBUS_HISYSEVT_LINK_TYPE_BLE);
}

/*
 * @tc.name: LNN_POST_PC_ONLINE_UNIQUELY_TEST_001
 * @tc.desc: test PostPcOnlineUniquely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_POST_PC_ONLINE_UNIQUELY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnGenerateBtMacHash)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    PostPcOnlineUniquely(nullptr);
    NodeInfo *info = nullptr;
    info = reinterpret_cast<NodeInfo *>(SoftBusMalloc(sizeof(NodeInfo)));
    EXPECT_TRUE(info != nullptr);
    info->deviceInfo.deviceTypeId = TYPE_PC_ID;
    (void)memcpy_s(info->networkId, NETWORK_ID_BUF_LEN, NETWORKID1, NETWORK_ID_BUF_LEN);
    (void)memcpy_s(info->deviceInfo.deviceUdid, NETWORK_ID_BUF_LEN, NETWORKID1, NETWORK_ID_BUF_LEN);
    PostPcOnlineUniquely(info);
    (void)memcpy_s(info->deviceInfo.deviceUdid, NETWORK_ID_BUF_LEN, NETWORKID2, NETWORK_ID_BUF_LEN);
    PostPcOnlineUniquely(info);
    PostPcOnlineUniquely(info);
    info->deviceInfo.deviceTypeId = TYPE_IPCAMERA_ID;
    PostPcOnlineUniquely(info);
    SoftBusFree(info);
}

/*
 * @tc.name: LNN_IS_NODE_INFO_CHANGED_TEST_001
 * @tc.desc: test IsNodeInfoChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_IS_NODE_INFO_CHANGED_TEST_001, TestSize.Level1)
{
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(lnnConnMock, LnnUpdateNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));

    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo oldNodeInfo;
    NodeInfo newNodeInfo;
    (void)strcpy_s(oldNodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID1);
    (void)strcpy_s(newNodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID2);
    ConnectionAddrType type;
    bool ret1 = IsNodeInfoChanged(connFsm4, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == true);
    (void)strcpy_s(newNodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID1);
    connFsm4->connInfo.addr.type = CONNECTION_ADDR_BLE;
    ret1 = IsNodeInfoChanged(connFsm4, &oldNodeInfo, &newNodeInfo, &type);
    EXPECT_TRUE(ret1 == false);
}

/*
 * @tc.name: LNN_CLEAN_INVALID_CONN_STATE_PROCESS_TEST_001
 * @tc.desc: test CleanInvalidConnStateProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_CLEAN_INVALID_CONN_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(para != nullptr);
    bool ret1 = CleanInvalidConnStateProcess(nullptr, FSM_MSG_TYPE_LEAVE_LNN, para);
    EXPECT_TRUE(ret1 == false);
    ret1 = CleanInvalidConnStateProcess(&(connFsm4->fsm), FSM_MSG_TYPE_LEAVE_LNN, nullptr);
    EXPECT_TRUE(ret1 == true);
}

/*
 * @tc.name: LNN_CLEAN_INVALID_CONN_STATE_PROCESS_TEST_002
 * @tc.desc: test CleanInvalidConnStateProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_CLEAN_INVALID_CONN_STATE_PROCESS_TEST_002, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(para != nullptr);
    bool ret1 = CleanInvalidConnStateProcess(nullptr, FSM_MSG_TYPE_LEAVE_LNN, para);
    EXPECT_TRUE(ret1 == false);
    ret1 = CleanInvalidConnStateProcess(&(connFsm4->fsm), FSM_MSG_TYPE_LEAVE_INVALID_CONN, nullptr);
    EXPECT_TRUE(ret1 == true);
}

/*
 * @tc.name: LNN_LEAVE_LNN_IN_ONLINE_TEST_001
 * @tc.desc: test LeaveLNNInOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_LEAVE_LNN_IN_ONLINE_TEST_001, TestSize.Level1)
{
    const char *ip = IP;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnPrintConnectionAddr).WillRepeatedly(Return(ip));
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr targetObj = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT,
    };

    (void)memcpy_s(targetObj.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID3, strlen(PEERUID3));
    (void)memcpy_s(targetObj.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    connFsm = LnnCreateConnectionFsm(&targetObj, "pkgNameTest", true);
    EXPECT_TRUE(connFsm != nullptr);
    LeaveLNNInOnline(connFsm);
}

/*
 * @tc.name: LNN_ONLINE_STATE_PROCESS_TEST_001
 * @tc.desc: test OnlineStateProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_ONLINE_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(para != nullptr);
    ret = OnlineStateProcess(nullptr, FSM_MSG_TYPE_JOIN_LNN, para);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: LNN_ONLINE_STATE_PROCESS_TEST_002
 * @tc.desc: test OnlineStateProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_ONLINE_STATE_PROCESS_TEST_002, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(para != nullptr);
    ret = OnlineStateProcess(&(connFsm4->fsm), FSM_MSG_TYPE_AUTH_DONE, para);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: LNN_LEAVING_STATE_PROCESS_TEST_001
 * @tc.desc: test LeavingStateProcess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_LEAVING_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    void *para = nullptr;
    para = reinterpret_cast<void *>(SoftBusMalloc(sizeof(LnnConnectionFsm)));
    EXPECT_TRUE(para != nullptr);
    int32_t ret = LeavingStateProcess(nullptr, FSM_MSG_TYPE_JOIN_LNN, para);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: LNN_INIT_CONNECTION_STATE_MACHINE_TEST_001
 * @tc.desc: test InitConnectionStateMachine
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_INIT_CONNECTION_STATE_MACHINE_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    (void)strcpy_s(connFsm4->fsmName, LNN_CONNECTION_FSM_NAME_LEN, NETWORKID3);
    ret = InitConnectionStateMachine(connFsm4);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: DFX_RECORD_LNN_ONLINE_TYPE_TEST_001
 * @tc.desc: test DfxRecordLnnOnlineType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, DFX_RECORD_LNN_ONLINE_TYPE_TEST_001, TestSize.Level1)
{
    NodeInfo info = {
        .netCapacity = 15,
    };
    uint32_t local1 = 1;
    uint32_t local2 = 15;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    int32_t ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_WIFI);
    ret = DfxRecordLnnOnlineType(nullptr);
    EXPECT_EQ(ret, ONLINE_TYPE_INVALID);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_BR);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_INVALID);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_NETWORK_NOT_FOUND));
    ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_INVALID);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info).WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_BLE_THREE_STATE);
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    ret = DfxRecordLnnOnlineType(&info);
    EXPECT_EQ(ret, ONLINE_TYPE_BLE);
}

/*
 * @tc.name: IS_EMPTY_SHORT_HASH_STR_TEST_001
 * @tc.desc: test IsEmptyShortHashStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, IS_EMPTY_SHORT_HASH_STR_TEST_001, TestSize.Level1)
{
    const char *udid = "testuuid";
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ReportResult(udid, REPORT_CHANGE);
    ReportResult(udid, REPORT_OFFLINE);
    ReportResult(udid, REPORT_NONE);
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    OnlineTrustGroupProc(udid);
    const char *udidHash = "testuuid";
    bool ret = IsEmptyShortHashStr(const_cast<char *>(udidHash));
    EXPECT_EQ(ret, false);
    const char *udidHash1 = "";
    ret = IsEmptyShortHashStr(const_cast<char *>(udidHash1));
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GET_UDID_HASH_FOR_DFX_TEST_001
 * @tc.desc: test GetUdidHashForDfx
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, GET_UDID_HASH_FOR_DFX_TEST_001, TestSize.Level1)
{
    NodeInfo localInfo;
    (void)memset_s(&localInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, memcpy_s(localInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    LnnConntionInfo connInfo = {
        .addr.type = CONNECTION_ADDR_WLAN,
    };
    EXPECT_EQ(EOK, memcpy_s(connInfo.addr.info.ip.udidHash, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(&localInfo));
    char localUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t ret = GetUdidHashForDfx(localUdidHash, peerUdidHash, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    ret = GetUdidHashForDfx(localUdidHash, peerUdidHash, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    connInfo.addr.type = CONNECTION_ADDR_BLE;
    EXPECT_EQ(EOK, memcpy_s(connInfo.addr.info.ble.udidHash, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    ret = GetUdidHashForDfx(localUdidHash, peerUdidHash, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_PEER_UDID_HASH_TEST_001
 * @tc.desc: test GetPeerUdidHash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, GET_PEER_UDID_HASH_TEST_001, TestSize.Level1)
{
    NodeBasicInfo peerDevInfo = {
        .deviceTypeId = 1,
    };
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<DistributeLedgerInterfaceMock> mock;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    ON_CALL(serviceMock, LnnAsyncCallbackDelayHelper).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    ON_CALL(mock, LnnGetRemoteStrInfo).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillByDefault(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(lnnConnMock, SendDeviceStateToMlps).WillByDefault(Return());
    const char *udid = "testuuid";
    char udidData[UDID_BUF_LEN] = { 0 };
    ReportDeviceOnlineEvt(udid, &peerDevInfo);
    DeviceStateChangeProcess(udidData, CONNECTION_ADDR_BLE, false);
    DeviceStateChangeProcess(nullptr, CONNECTION_ADDR_BLE, false);
    DeviceStateChangeProcess(nullptr, CONNECTION_ADDR_WLAN, false);
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, memcpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t ret = GetPeerUdidHash(&nodeInfo, peerUdidHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetPeerUdidHash(nullptr, peerUdidHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerUdidHash(&nodeInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_DEV_TYPE_FOR_DFX_TEST_001
 * @tc.desc: test GetDevTypeForDfx
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, GET_DEV_TYPE_FOR_DFX_TEST_001, TestSize.Level1)
{
    NodeInfo localInfo;
    localInfo.deviceInfo.deviceTypeId = 1;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnGetLocalNodeInfoSafe)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<0>(localInfo), Return(SOFTBUS_OK)));
    LnnConntionInfo connInfo = {
        .nodeInfo = nullptr,
        .infoReport.type = DESKTOP_PC,
    };
    char localDeviceType[DEVICE_TYPE_SIZE_LEN + 1] = { 0 };
    char peerDeviceType[DEVICE_TYPE_SIZE_LEN + 1] = { 0 };
    int32_t ret = GetDevTypeForDfx(localDeviceType, peerDeviceType, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    ret = GetDevTypeForDfx(localDeviceType, peerDeviceType, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_PEER_UDID_INFO_TEST_001
 * @tc.desc: test GetPeerUdidInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, GET_PEER_UDID_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    ON_CALL(ledgerMock, LnnHasDiscoveryType).WillByDefault(Return(true));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(EOK, strcpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEERUDID));
    LnnEventExtra extra;
    SetOnlineType(SOFTBUS_OK, &nodeInfo, extra);
    SetOnlineType(SOFTBUS_INVALID_PARAM, &nodeInfo, extra);
    char udidData[UDID_BUF_LEN] = { 0 };
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    int32_t ret = GetPeerUdidInfo(&nodeInfo, udidData, peerUdidHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: FILL_DEVICE_BLE_REPORT_EXTRA_TEST_001
 * @tc.desc: test FillDeviceBleReportExtra
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, FILL_DEVICE_BLE_REPORT_EXTRA_TEST_001, TestSize.Level1)
{
    LnnEventExtra extra = {
        .onlineType = 0,
        .errcode = SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP,
    };
    extra.peerNetworkId = NETWORKID1;
    extra.peerUdid = PEERUDID;
    extra.peerUdidHash = PEERUDID;
    extra.peerBleMac = MACTEST;
    LnnBleReportExtra bleExtra;
    (void)memset_s(&bleExtra, sizeof(LnnBleReportExtra), 0, sizeof(LnnBleReportExtra));
    int32_t ret = FillDeviceBleReportExtra(&extra, &bleExtra);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnConntionInfo connInfo = {
        .nodeInfo = nullptr,
        .infoReport.type = DESKTOP_PC,
    };
    extra.localUdidHash = PEERUDID;
    extra.localDeviceType = PC_DEV_TYPE;
    extra.peerDeviceType = PC_DEV_TYPE;
    DfxAddBleReportExtra(&connInfo, &extra, &bleExtra);
    DfxAddBleReportExtra(&connInfo, &extra, &bleExtra);
    DfxAddBleReportExtra(nullptr, &extra, &bleExtra);
    DfxAddBleReportExtra(&connInfo, nullptr, &bleExtra);
    DfxAddBleReportExtra(&connInfo, &extra, nullptr);
    connInfo.addr.type = CONNECTION_ADDR_BLE;
    DfxReportOnlineEvent(nullptr, SOFTBUS_OK, extra);
    DfxReportOnlineEvent(&connInfo, SOFTBUS_OK, extra);
    connInfo.addr.type = CONNECTION_ADDR_WLAN;
    DfxReportOnlineEvent(&connInfo, SOFTBUS_OK, extra);
    ret = FillDeviceBleReportExtra(nullptr, &bleExtra);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = FillDeviceBleReportExtra(&extra, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_LEAVE_TO_LEDGER_TEST_001
 * @tc.desc: test UpdateLeaveToLedger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, UPDATE_LEAVE_TO_LEDGER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    ON_CALL(serviceMock, LnnNotifyLnnRelationChanged).WillByDefault(Return());
    EXPECT_CALL(lnnConnMock, LnnGetLocalNodeInfoSafe).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LnnConntionInfo connInfo = {
        .infoReport.bleConnectReason = FIND_REMOTE_CIPHERKEY_FAILED,
        .nodeInfo = nullptr,
    };
    uint32_t connOnlineReason = 0;
    GetConnectOnlineReason(&connInfo, &connOnlineReason, SOFTBUS_OK);
    EXPECT_CALL(lnnConnMock, LnnGetLocalNodeInfoSafe).WillRepeatedly(Return(SOFTBUS_OK));
    GetConnectOnlineReason(&connInfo, &connOnlineReason, SOFTBUS_OK);
    GetConnectOnlineReason(&connInfo, &connOnlineReason, SOFTBUS_INVALID_PARAM);
    NodeInfo nodeInfo;
    connInfo.nodeInfo = &nodeInfo;
    EXPECT_CALL(lnnConnMock, LnnGetLocalNodeInfoSafe).WillRepeatedly(Return(SOFTBUS_OK));
    GetConnectOnlineReason(&connInfo, &connOnlineReason, SOFTBUS_OK);
    GetConnectOnlineReason(&connInfo, &connOnlineReason, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetDeviceUdid).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(ledgerMock, LnnSetNodeOffline).WillRepeatedly(Return(REPORT_OFFLINE));
    EXPECT_CALL(lnnConnMock, DeleteFromProfile).WillRepeatedly(Return());
    LnnConnectionFsm connFsm = {
        .connInfo.cleanInfo = nullptr,
    };
    const char *networkId = "networkIdTest";
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    bool ret = UpdateLeaveToLedger(&connFsm, networkId, &basic);
    EXPECT_EQ(ret, false);
    ret = UpdateLeaveToLedger(&connFsm, networkId, &basic);
    EXPECT_EQ(ret, true);
    ret = UpdateLeaveToLedger(&connFsm, networkId, &basic);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: LNN_RECOVERY_BROADCAST_KEY_TEST_001
 * @tc.desc: test LnnRecoveryBroadcastKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_RECOVERY_BROADCAST_KEY_TEST_001, TestSize.Level1)
{
    NiceMock<LnnConnFsmInterfaceMock> lnnConnMock;
    EXPECT_CALL(lnnConnMock, LnnLoadLocalBroadcastCipherKey)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnConnMock, LnnGetLocalBroadcastCipherKey)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnRecoveryBroadcastKey();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnRecoveryBroadcastKey();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnRecoveryBroadcastKey();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnRecoveryBroadcastKey();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IS_WIFI_CONNECT_INFO_CHANGED_TEST_001
 * @tc.desc: test IsWifiConnectInfoChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, IS_WIFI_CONNECT_INFO_CHANGED_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillOnce(Return(false)).WillRepeatedly(Return(true));
    NodeInfo oldNodeInfo = {
        .connectInfo.authPort = PORT,
        .connectInfo.proxyPort = PORT,
        .connectInfo.sessionPort = PORT,
    };
    NodeInfo newNodeInfo = {
        .connectInfo.authPort = PORT,
        .connectInfo.proxyPort = PORT,
        .connectInfo.sessionPort = PORT,
    };
    EXPECT_EQ(EOK, memcpy_s(oldNodeInfo.connectInfo.deviceIp, IP_STR_MAX_LEN, IP, strlen(IP)));
    EXPECT_EQ(EOK, memcpy_s(newNodeInfo.connectInfo.deviceIp, IP_STR_MAX_LEN, IP, strlen(IP)));
    bool ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, false);
    ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, false);
    oldNodeInfo.connectInfo.sessionPort = PORT + 1;
    ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, true);
    oldNodeInfo.connectInfo.proxyPort = PORT + 1;
    ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, true);
    oldNodeInfo.connectInfo.authPort = PORT + 1;
    ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(EOK, memcpy_s(oldNodeInfo.connectInfo.deviceIp, IP_STR_MAX_LEN, PEERUDID, strlen(PEERUDID)));
    ret = IsWifiConnectInfoChanged(&oldNodeInfo, &newNodeInfo);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: LNN_IS_NEED_CLEAN_CONNECTION_FSM_TEST_001
 * @tc.desc: test LnnIsNeedCleanConnectionFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, LNN_IS_NEED_CLEAN_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    NodeInfo node;
    EXPECT_EQ(EOK, memcpy_s(node.networkId, NETWORK_ID_BUF_LEN, NETWORKID1, strlen(NETWORKID1)));
    EXPECT_EQ(EOK, memcpy_s(node.uuid, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    EXPECT_EQ(EOK, memcpy_s(node.softBusVersion, VERSION_MAX_LEN, SOFTBUSVERSION, strlen(SOFTBUSVERSION)));
    NodeInfo nodeInfo;
    EXPECT_EQ(EOK, memcpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID1, strlen(NETWORKID1)));
    EXPECT_EQ(EOK, memcpy_s(nodeInfo.uuid, UDID_BUF_LEN, PEERUDID, strlen(PEERUDID)));
    EXPECT_EQ(EOK, memcpy_s(nodeInfo.softBusVersion, VERSION_MAX_LEN, SOFTBUSVERSION, strlen(SOFTBUSVERSION)));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<2>(node), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnIsNodeOnline).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType).WillRepeatedly(Return(false));
    bool ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_ETH);
    EXPECT_EQ(ret, false);
    ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_ETH);
    EXPECT_EQ(ret, false);
    ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_ETH);
    EXPECT_EQ(ret, false);
    ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_WLAN);
    EXPECT_EQ(ret, false);
    ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_BR);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(EOK, strcpy_s(nodeInfo.networkId, NETWORK_ID_BUF_LEN, NETWORKID2));
    ret = LnnIsNeedCleanConnectionFsm(&nodeInfo, CONNECTION_ADDR_BR);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: SYNC_BR_OFFLINE_TEST_001
 * @tc.desc: test SyncBrOffline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNConnectionFsmTest, SYNC_BR_OFFLINE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetCnnCode).WillRepeatedly(Return(INVALID_CONNECTION_CODE_VALUE));
    LnnConnectionFsm connFsm = {
        .connInfo.addr.type = CONNECTION_ADDR_WLAN,
        .connInfo.flag = 1,
    };
    int32_t ret = SyncBrOffline(&connFsm);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_LEAVE_OFFLINE);
    connFsm.connInfo.addr.type = CONNECTION_ADDR_BR;
    ret = SyncBrOffline(&connFsm);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_LEAVE_OFFLINE);
    connFsm.connInfo.flag = LNN_CONN_INFO_FLAG_LEAVE_REQUEST;
    ret = SyncBrOffline(&connFsm);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SyncBrOffline(&connFsm);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS