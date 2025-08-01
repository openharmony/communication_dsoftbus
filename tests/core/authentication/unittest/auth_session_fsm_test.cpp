/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_request.h"
#include "auth_session_fsm.c"
#include "auth_session_fsm.h"
#include "auth_session_fsm_mock.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
constexpr int64_t AUTH_SEQ = 1;
constexpr int64_t AUTH_SEQ_1 = 2;
constexpr uint64_t CONN_ID = 10;
constexpr uint64_t CONN_ID_1 = 11;
constexpr int32_t DEVICE_ID_HASH_LEN = 9;
constexpr uint32_t REQUEST_ID = 1000;
constexpr uint32_t REQUEST_ID_1 = 1001;
constexpr int32_t TMP_DATA_LEN = 10;
constexpr int32_t TEST_REQUEST_ID = 123;
constexpr char UDID_HASH[UDID_HASH_LEN] = "9ada389cd0898797";
constexpr char UDID_TEST[UDID_BUF_LEN] = "123456789udidtest";
constexpr char INVALID_UDID_TEST[UDID_BUF_LEN] = "nullptr";
constexpr char BR_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr char BLE_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr char SLE_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr uint8_t DEVICE_ID_HASH[UDID_HASH_LEN] = "123456789";
constexpr uint8_t TMP_IN_DATA[TMP_DATA_LEN] = "tmpInData";

class AuthSessionFsmTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthSessionFsmTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "AuthSessionFsmTest start";
    AuthCommonInit();
}

void AuthSessionFsmTest::TearDownTestCase()
{
    AuthCommonDeinit();
    GTEST_LOG_(INFO) << "AuthSessionFsmTest end";
}

void AuthSessionFsmTest::SetUp() { }

void AuthSessionFsmTest::TearDown() { }

/*
 * @tc.name: TRANSLATE_TO_AUTH_FSM_TEST_001
 * @tc.desc: TranslateToAuthFsm test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, TRANSLATE_TO_AUTH_FSM_TEST_001, TestSize.Level1)
{
    EXPECT_TRUE(strcmp(FsmMsgTypeToStr(-1), "UNKNOWN MSG!!") == EOK);
    EXPECT_TRUE(strcmp(FsmMsgTypeToStr(FSM_MSG_UNKNOWN), "UNKNOWN MSG!!") == EOK);
    EXPECT_TRUE(strcmp(FsmMsgTypeToStr(FSM_MSG_AUTH_FINISH), "AUTH_FINISH") == EOK);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    ASSERT_TRUE(memcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    AuthFsmParam authFsmParam;
    (void)memset_s(&authFsmParam, sizeof(authFsmParam), 0, sizeof(authFsmParam));
    authFsmParam.authSeq = AUTH_SEQ;
    authFsmParam.requestId = REQUEST_ID;
    authFsmParam.connId = CONN_ID;
    authFsmParam.isServer = true;
    authFsmParam.deviceKeyId.hasDeviceKeyId = false;
    authFsmParam.deviceKeyId.localDeviceKeyId = AUTH_INVALID_DEVICEKEY_ID;
    authFsmParam.deviceKeyId.remoteDeviceKeyId = AUTH_INVALID_DEVICEKEY_ID;
    AuthFsm *authFsm = CreateAuthFsm(&authFsmParam, &connInfo);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(nullptr, FSM_MSG_AUTH_TIMEOUT, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(&authFsm->fsm, FSM_MSG_RECV_DEVICE_ID, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(&authFsm->fsm, FSM_MSG_UNKNOWN, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    AuthFsmDeinitCallback(nullptr);
}

/*
 * @tc.name: PROC_AUTH_FSM_TEST_001
 * @tc.desc: ProcAuthFsm test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, PROC_AUTH_FSM_TEST_001, TestSize.Level1)
{
    ClearAuthRequest();
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.authId = REQUEST_ID;
    request.type = REQUEST_TYPE_RECONNECT;
    EXPECT_TRUE(SoftBusGenerateStrHash(
                    DEVICE_ID_HASH, DEVICE_ID_HASH_LEN, request.connInfo.info.bleInfo.deviceIdHash) == SOFTBUS_OK);
    EXPECT_TRUE(AddAuthRequest(&request) == 0);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    AddUdidInfo(REQUEST_ID, true, &connInfo);
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_USB;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_MAX;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_NE(ProcAuthFsm(REQUEST_ID_1, true, &authFsm), SOFTBUS_OK);
    EXPECT_NE(ProcAuthFsm(REQUEST_ID, true, &authFsm), SOFTBUS_OK);
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(ProcAuthFsm(REQUEST_ID, true, &authFsm) == SOFTBUS_OK);
    authFsm.authSeq = AUTH_SEQ_1;
    authFsm.info.isServer = false;
    authFsm.info.isSupportFastAuth = false;
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_BLE;
    CompleteAuthSession(&authFsm, SOFTBUS_OK);
    authFsm.info.isSupportFastAuth = true;
    CompleteAuthSession(&authFsm, SOFTBUS_OK);
    authFsm.info.normalizedType = NORMALIZED_KEY_ERROR;
    authFsm.info.isConnectServer = true;
    authFsm.info.peerState = AUTH_STATE_ACK;
    CompleteAuthSession(&authFsm, SOFTBUS_OK);
}

/*
 * @tc.name: RECOVERY_DEVICE_KEY_TEST_001
 * @tc.desc: RecoveryFastAuthKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, RECOVERY_DEVICE_KEY_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.isNodeInfoReceived = true;
    authFsm.info.isCloseAckReceived = true;
    HandleCommonMsg(&authFsm, FSM_MSG_DEVICE_NOT_TRUSTED, nullptr);
    HandleCommonMsg(&authFsm, FSM_MSG_DEVICE_DISCONNECTED, nullptr);
    authFsm.info.isCloseAckReceived = false;
    HandleCommonMsg(&authFsm, FSM_MSG_DEVICE_DISCONNECTED, nullptr);
    authFsm.info.isNodeInfoReceived = false;
    HandleCommonMsg(&authFsm, FSM_MSG_DEVICE_DISCONNECTED, nullptr);
    HandleCommonMsg(&authFsm, SOFTBUS_AUTH_INNER_ERR, nullptr);
    ASSERT_TRUE(memcpy_s(authFsm.info.udid, UDID_BUF_LEN, UDID_TEST, strlen(UDID_TEST)) == EOK);
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    EXPECT_NE(RecoveryFastAuthKey(&authFsm), SOFTBUS_OK);
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_NE(RecoveryFastAuthKey(&authFsm), SOFTBUS_OK);
    SyncDevIdStateEnter(nullptr);
}

/*
 * @tc.name: CLIENT_SET_EXCHANGE_ID_TYPE_TEST_001
 * @tc.desc: ClientSetExchangeIdType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, CLIENT_SET_EXCHANGE_ID_TYPE_TEST_001, TestSize.Level1)
{
    LnnAuditExtra *auditData = reinterpret_cast<LnnAuditExtra *>(SoftBusMalloc(sizeof(LnnAuditExtra)));
    EXPECT_TRUE(auditData != nullptr);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(auditData, sizeof(LnnAuditExtra), 0, sizeof(LnnAuditExtra));
    AuditReportSetPeerDevInfo(nullptr, &info);
    AuditReportSetPeerDevInfo(auditData, nullptr);
    info.connInfo.type = AUTH_LINK_TYPE_BR;
    EXPECT_TRUE(memcpy_s(info.connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    AuditReportSetPeerDevInfo(auditData, &info);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(memcpy_s(info.connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
    AuditReportSetPeerDevInfo(auditData, &info);
    info.connInfo.type = AUTH_LINK_TYPE_SLE;
    EXPECT_TRUE(memcpy_s(info.connInfo.info.sleInfo.sleMac, BT_MAC_LEN, SLE_MAC, strlen(SLE_MAC)) == EOK);
    AuditReportSetPeerDevInfo(auditData, &info);
    info.connInfo.type = AUTH_LINK_TYPE_MAX;
    AuditReportSetPeerDevInfo(auditData, &info);
    AuditReportSetLocalDevInfo(nullptr);
    BuildLnnAuditEvent(nullptr, &info, SOFTBUS_OK, SOFTBUS_OK, AUDIT_EVENT_PACKETS_ERROR);
    BuildLnnAuditEvent(auditData, nullptr, SOFTBUS_OK, SOFTBUS_OK, AUDIT_EVENT_PACKETS_ERROR);
    SoftBusFree(auditData);
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.idType = EXCHANGE_FAIL;
    EXPECT_NE(ClientSetExchangeIdType(&authFsm), SOFTBUS_OK);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = true;
    EXPECT_TRUE(TrySyncDeviceInfo(AUTH_SEQ_1, &info) == SOFTBUS_OK);
    info.isServer = false;
    EXPECT_TRUE(TrySyncDeviceInfo(AUTH_SEQ_1, &info) == SOFTBUS_ENCRYPT_ERR);
    info.connInfo.type = AUTH_LINK_TYPE_MAX;
    EXPECT_NE(TrySyncDeviceInfo(AUTH_SEQ_1, &info), SOFTBUS_OK);
}

/*
 * @tc.name: GET_AUTH_FSM_TEST_001
 * @tc.desc: GetAuthFsmByConnId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, GET_AUTH_FSM_TEST_001, TestSize.Level1)
{
    AuthFsm *authFsm = (AuthFsm *)SoftBusCalloc(sizeof(AuthFsm));
    ASSERT_TRUE(authFsm != nullptr);
    (void)memset_s(authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    ASSERT_TRUE(memcpy_s(authFsm->info.udid, UDID_BUF_LEN, UDID_TEST, strlen(UDID_TEST)) == EOK);
    authFsm->authSeq = AUTH_SEQ;
    authFsm->info.connId = CONN_ID;
    authFsm->info.isServer = true;
    authFsm->isDead = true;
    ListNodeInsert(&g_authFsmList, &authFsm->node);
    EXPECT_TRUE(GetAuthFsmByAuthSeq(AUTH_SEQ) == nullptr);
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID_1, false, false) == nullptr);
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID, false, false) == nullptr);
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID, true, false) == nullptr);
}

/*
 * @tc.name: AUTH_SESSION_HANDLE_TEST_001
 * @tc.desc: AuthSessionHandle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, AUTH_SESSION_HANDLE_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.deviceInfoData = nullptr;
    MessagePara para;
    (void)memset_s(&para, sizeof(MessagePara), 0, sizeof(MessagePara));
    ASSERT_TRUE(memcpy_s(para.data, TMP_DATA_LEN, TMP_IN_DATA, TMP_DATA_LEN) == EOK);
    para.len = TMP_DATA_LEN;
    HandleMsgRecvDevInfoEarly(&authFsm, &para);
    authFsm.info.deviceInfoData = reinterpret_cast<uint8_t *>(SoftBusMalloc(TMP_DATA_LEN));
    EXPECT_TRUE(authFsm.info.deviceInfoData != nullptr);
    para.len = 0;
    HandleMsgRecvDevInfoEarly(&authFsm, &para);
    TryFinishAuthSession(&authFsm);
    authFsm.info.isNodeInfoReceived = true;
    TryFinishAuthSession(&authFsm);
    authFsm.info.isCloseAckReceived = true;
    TryFinishAuthSession(&authFsm);
    authFsm.info.isAuthFinished = true;
    TryFinishAuthSession(&authFsm);
    EXPECT_TRUE(AuthSessionHandleDeviceNotTrusted(INVALID_UDID_TEST) == SOFTBUS_OK);
    EXPECT_TRUE(AuthSessionHandleDeviceNotTrusted(UDID_TEST) == SOFTBUS_OK);
    EXPECT_TRUE(AuthSessionHandleDeviceDisconnected(CONN_ID_1, true) == SOFTBUS_OK);
    EXPECT_TRUE(AuthSessionHandleDeviceDisconnected(CONN_ID, true) == SOFTBUS_OK);
    AuthSessionFsmExit();
}

/*
 * @tc.name: HANDLE_CLOSE_ACK_TEST_001
 * @tc.desc: handle close ack base remote info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, HANDLE_CLOSE_ACK_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info = { 0 };
    info.nodeInfo.feature = 0xF7CA;
    AuthSessionFsmInterfaceMock mock;
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));

    EXPECT_CALL(mock, SoftBusGetBrState()).WillRepeatedly(Return(BR_ENABLE));
    int32_t ret = HandleCloseAckMessage(&authFsm, &info);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, SoftBusGetBrState()).WillRepeatedly(Return(BR_DISABLE));
    ret = HandleCloseAckMessage(&authFsm, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    UpdateUdidHashIfEmpty(&authFsm, &info);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.nodeInfo.feature = 0;
    ret = HandleCloseAckMessage(&authFsm, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_EQ(memcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST, strlen(UDID_TEST)), 0);
    UpdateUdidHashIfEmpty(&authFsm, &info);
    info.nodeInfo.feature = 0x1F7CA;
    ret = HandleCloseAckMessage(&authFsm, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IS_NEED_EXCHANGE_NETWORKID_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, IS_NEED_EXCHANGE_NETWORKID_TEST_001, TestSize.Level1)
{
    uint32_t feature = 0;
    AuthFsm authFsm;
    AuthSessionInfo info;
    MessagePara para;
    int32_t result = 0;
    (void)memset_s(&authFsm, sizeof(authFsm), 0, sizeof(authFsm));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    (void)memset_s(&para, sizeof(para), 0, sizeof(para));
    info.localState = AUTH_STATE_START;
    LocalAuthStateProc(&authFsm, &info, &result);
    info.localState = AUTH_STATE_ACK;
    LocalAuthStateProc(&authFsm, &info, &result);
    info.localState = AUTH_STATE_WAIT;
    LocalAuthStateProc(&authFsm, &info, &result);
    info.localState = AUTH_STATE_COMPATIBLE;
    LocalAuthStateProc(&authFsm, &info, &result);
    info.localState = AUTH_STATE_UNKNOW;
    LocalAuthStateProc(&authFsm, &info, &result);
    HandleMsgRecvDeviceIdNego(&authFsm, &para);
    bool ret = IsNeedExchangeNetworkId(feature, BIT_SUPPORT_EXCHANGE_NETWORKID);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: ADD_CONCURRENT_AUTH_REQUEST_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, ADD_CONCURRENT_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    uint32_t ret = AddConcurrentAuthRequest(&authFsm);
    EXPECT_TRUE(ret == 0);

    EXPECT_TRUE(strcpy_s(authFsm.info.udidHash, SHA_256_HEX_HASH_LEN, UDID_HASH) == EOK);
    ret = AddConcurrentAuthRequest(&authFsm);
    EXPECT_TRUE(ret != 0);
    StopAuthFsm(&authFsm);
    SyncNegotiationEnter(nullptr);
}

/*
 * @tc.name: RECOVERY_NORMALIZED_DEVICE_KEY_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, RECOVERY_NORMALIZED_DEVICE_KEY_TEST_001, TestSize.Level1)
{
    AuthFsm *authFsm = (AuthFsm *)SoftBusCalloc(sizeof(AuthFsm));
    ASSERT_TRUE(authFsm != nullptr);
    (void)memset_s(authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm->info.normalizedKey = nullptr;
    int32_t ret = RecoveryNormalizedDeviceKey(authFsm);
    EXPECT_NE(ret, SOFTBUS_OK);

    authFsm->info.normalizedKey = (SessionKey *)SoftBusCalloc(sizeof(SessionKey));
    if (authFsm->info.normalizedKey == nullptr) {
        SoftBusFree(authFsm);
        return;
    }
    ret = RecoveryNormalizedDeviceKey(authFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    EXPECT_TRUE(strcpy_s(authFsm->info.udidHash, SHA_256_HEX_HASH_LEN, UDID_HASH) == EOK);
    ret = RecoveryNormalizedDeviceKey(authFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(authFsm->info.normalizedKey);
    SoftBusFree(authFsm);
}

/*
 * @tc.name: TRY_RECOVERY_KEY_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, TRY_RECOVERY_KEY_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.normalizedType = NORMALIZED_SUPPORT;
    int32_t ret = TryRecoveryKey(&authFsm);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_SYNC_DEVID_FAIL);

    authFsm.info.normalizedType = NORMALIZED_NOT_SUPPORT;
    authFsm.info.isSupportFastAuth = true;
    ret = TryRecoveryKey(&authFsm);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_SYNC_DEVID_FAIL);

    authFsm.info.isSupportFastAuth = false;
    ret = TryRecoveryKey(&authFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_CLIENT_AUTH_STATE_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, PROCESS_CLIENT_AUTH_STATE_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.idType = EXCHANGE_FAIL;
    int32_t ret = ProcessClientAuthState(&authFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    authFsm.info.idType = EXCHANGE_TYPE_MAX;
    ret = ProcessClientAuthState(&authFsm);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    DeviceAuthStateEnter(nullptr);
    FsmStateMachine fsm;
    (void)memset_s(&fsm, sizeof(FsmStateMachine), 0, sizeof(FsmStateMachine));
    DeviceAuthStateEnter(&fsm);
}

/*
 * @tc.name: DEVICE_AUTH_STATE_PROCESS_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, DEVICE_AUTH_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.isDead = false;
    int32_t msgType = FSM_MSG_RECV_DEVICE_ID;
    MessagePara *para1 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para1 != nullptr);
    bool ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para1);
    EXPECT_TRUE(ret == true);

    MessagePara *para2 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para2 != nullptr);
    msgType = FSM_MSG_RECV_AUTH_DATA;
    ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para2);
    EXPECT_TRUE(ret == false);

    MessagePara *para3 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para3 != nullptr);
    msgType = FSM_MSG_SAVE_SESSION_KEY;
    ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para3);
    EXPECT_TRUE(ret == false);

    MessagePara *para4 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para4 != nullptr);
    msgType = FSM_MSG_AUTH_ERROR;
    ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para4);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: DEVICE_AUTH_STATE_PROCESS_TEST_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, DEVICE_AUTH_STATE_PROCESS_TEST_002, TestSize.Level1)
{
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.isDead = false;
    int32_t msgType = FSM_MSG_AUTH_FINISH;
    MessagePara *para1 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para1 != nullptr);
    bool ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para1);
    EXPECT_TRUE(ret == true);

    MessagePara *para2 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para2 != nullptr);
    msgType = FSM_MSG_UNKNOWN;
    ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para2);
    EXPECT_TRUE(ret == true);

    MessagePara *para3 = NewMessagePara(TMP_IN_DATA, TMP_DATA_LEN);
    ASSERT_TRUE(para3 != nullptr);
    msgType = FSM_MSG_RECV_DEVICE_INFO;
    ret = DeviceAuthStateProcess(&authFsm.fsm, msgType, para3);
    EXPECT_TRUE(ret == true);
    authFsm.info.isNodeInfoReceived = true;
    HandleMsgRecvCloseAck(&authFsm, para1);
}

/*
 * @tc.name: SYNC_DEV_ID_STATE_PROCESS_TEST_001
 * @tc.desc: SyncDevIdStateProcess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, SYNC_DEV_ID_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    int32_t ret;
    AuthFsm authFsm;
    AuthSessionFsmInterfaceMock mock;
    MessagePara *para = (MessagePara *)SoftBusCalloc(sizeof(MessagePara));
    ASSERT_NE(para, nullptr);
    authFsm.isDead = false;
    (void)memset_s(&authFsm, sizeof(authFsm), 0, sizeof(authFsm));
    (void)memset_s(para, sizeof(MessagePara), 0, sizeof(MessagePara));
    ret = SyncDevIdStateProcess(&(authFsm.fsm), FSM_MSG_RECV_DEVICE_ID, para);
    EXPECT_TRUE(ret);
    para = (MessagePara *)SoftBusCalloc(sizeof(MessagePara));
    ASSERT_NE(para, nullptr);
    ret = SyncDevIdStateProcess(&(authFsm.fsm), FSM_MSG_DEVICE_POST_DEVICEID, para);
    EXPECT_FALSE(ret);
    para = (MessagePara *)SoftBusCalloc(sizeof(MessagePara));
    ASSERT_NE(para, nullptr);
    ret = SyncDevIdStateProcess(&(authFsm.fsm), FSM_MSG_UNKNOWN, para);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GET_AUTH_FSM_BY_REQUEST_ID_TEST_001
 * @tc.desc: GetAuthFsmByRequestId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, GET_AUTH_FSM_BY_REQUEST_ID_TEST_001, TestSize.Level1)
{
    uint64_t requestId = TEST_REQUEST_ID;
    AuthFsm * fsm = GetAuthFsmByRequestId(requestId);
    EXPECT_EQ(fsm, nullptr);
}

/*
 * @tc.name: IS_PEER_SUPPORT_NEGO_AUTH_TEST_001
 * @tc.desc: IsPeerSupportNegoAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, IS_PEER_SUPPORT_NEGO_AUTH_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    AuthSessionFsmInterfaceMock mock;
    EXPECT_CALL(mock, GetUdidShortHash).WillOnce(Return(false));
    bool ret = IsPeerSupportNegoAuth(&info);
    EXPECT_TRUE(ret);
    EXPECT_CALL(mock, GetUdidShortHash).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillOnce(Return(SOFTBUS_NOT_IMPLEMENT));
    ret = IsPeerSupportNegoAuth(&info);
    EXPECT_TRUE(ret);
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsSupportFeatureByCapaBit).WillOnce(Return(true));
    ret = IsPeerSupportNegoAuth(&info);
    EXPECT_TRUE(ret);
    EXPECT_CALL(mock, IsSupportFeatureByCapaBit).WillOnce(Return(false));
    ret = IsPeerSupportNegoAuth(&info);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GET_FIRST_FSM_TEST_001
 * @tc.desc: GetFirstFsmState test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, GET_FIRST_FSM_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    int64_t authSeq = AUTH_SEQ;
    AuthFsmStateIndex state;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.isConnectServer = true;
    AuthSessionFsmInterfaceMock mock;
    EXPECT_CALL(mock, GetUdidShortHash).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsSupportFeatureByCapaBit).WillRepeatedly(Return(true));
    int32_t ret = GetFirstFsmState(&info, authSeq, &state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.isConnectServer = false;
    ret = GetFirstFsmState(&info, authSeq, &state);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_SESSION_GET_CRED_ID_TEST_001
 * @tc.desc: AuthSessionGetCredId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, AUTH_SESSION_GET_CRED_ID_TEST_001, TestSize.Level1)
{
    int64_t authSeq = AUTH_SEQ;
    char *credId = AuthSessionGetCredId(authSeq);
    EXPECT_EQ(credId, nullptr);
}

/*
 * @tc.name: AUTH_SESSION_GET_AUTH_VERSION_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, AUTH_SESSION_GET_AUTH_VERSION_TEST_001, TestSize.Level1)
{
    int64_t authSeq = AUTH_SEQ;
    int32_t version = 0;
    int32_t ret = AuthSessionGetAuthVersion(authSeq, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthSessionGetAuthVersion(authSeq, &version);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_SESSION_INFO_FAIL);
}


/*
 * @tc.name: AUTH_SESSION_GET_IS_SAME_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, AUTH_SESSION_GET_IS_SAME_TEST_001, TestSize.Level1)
{
    int64_t authSeq = AUTH_SEQ;
    bool ret = AuthSessionGetIsSameAccount(authSeq);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: AUTH_SESSION_HANDLE_AUTH_ERROR_TEST_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, AUTH_SESSION_HANDLE_AUTH_ERROR_TEST_001, TestSize.Level1)
{
    int64_t authSeq = AUTH_SEQ;
    int32_t reason = 0;
    int32_t ret = AuthSessionHandleAuthError(authSeq, reason);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_FSM_FAIL);
}

/*
 * @tc.name: POPULATE_DEVICE_TYPE_ID_TEST_001
 * @tc.desc: PopulateDeviceTypeId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, POPULATE_DEVICE_TYPE_ID_TEST_001, TestSize.Level1)
{
    AuthSessionFsmInterfaceMock mock;
    HiChainAuthParam authParam;
    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    uint32_t requestId = REQUEST_ID_1;
    EXPECT_NO_FATAL_FAILURE(PopulateDeviceTypeId(&authParam, requestId));
    ClearAuthRequest();
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.authId = REQUEST_ID;
    request.deviceTypeId = REQUEST_TYPE_RECONNECT;
    EXPECT_TRUE(AddAuthRequest(&request) == SOFTBUS_OK);
    requestId = REQUEST_ID;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(PopulateDeviceTypeId(&authParam, requestId));
}

/*
 * @tc.name: POPULATE_DEVICE_TYPE_ID_TEST_002
 * @tc.desc: PopulateDeviceTypeId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, POPULATE_DEVICE_TYPE_ID_TEST_002, TestSize.Level1)
{
    AuthSessionFsmInterfaceMock mock;
    HiChainAuthParam authParam;
    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    uint32_t requestId = REQUEST_ID_1;
    EXPECT_NO_FATAL_FAILURE(PopulateDeviceTypeId(&authParam, requestId));
    ClearAuthRequest();
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.authId = REQUEST_ID;
    request.deviceTypeId = TYPE_PC_ID;
    EXPECT_TRUE(AddAuthRequest(&request) == SOFTBUS_OK);
    requestId = REQUEST_ID;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).Times(0);
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).Times(0);
    EXPECT_NO_FATAL_FAILURE(PopulateDeviceTypeId(&authParam, requestId));
}

/*
 * @tc.name: POPULATE_DEVICE_TYPE_ID_TEST_003
 * @tc.desc: PopulateDeviceTypeId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthSessionFsmTest, POPULATE_DEVICE_TYPE_ID_TEST_003, TestSize.Level1)
{
    HiChainAuthParam authParam;
    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    uint32_t requestId = 123;
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.deviceTypeId = 0;
    NodeInfo infoPc;
    infoPc.deviceInfo.deviceTypeId = TYPE_PC_ID;
    NodeInfo infoOther;
    infoOther.deviceInfo.deviceTypeId = 0;
    AuthSessionFsmInterfaceMock mock;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillOnce(DoAll(SetArgPointee<1>(infoPc), Return(SOFTBUS_OK)));
    PopulateDeviceTypeId(&authParam, requestId);
    EXPECT_EQ(authParam.deviceTypeId, TYPE_PC_ID);
    authParam.deviceTypeId = 0;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(DoAll(SetArgPointee<2>(infoPc), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).Times(0);
    PopulateDeviceTypeId(&authParam, requestId);
    EXPECT_EQ(authParam.deviceTypeId, TYPE_PC_ID);
    authParam.deviceTypeId = 0;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_NOT_FIND)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(DoAll(SetArgPointee<2>(infoOther), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillOnce(DoAll(SetArgPointee<1>(infoPc), Return(SOFTBUS_OK)));
    PopulateDeviceTypeId(&authParam, requestId);
    EXPECT_EQ(authParam.deviceTypeId, TYPE_PC_ID);
    authParam.deviceTypeId = 0;
    EXPECT_CALL(mock, GetAuthRequest).WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_NOT_FIND)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillOnce(DoAll(SetArgPointee<2>(infoOther), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnRetrieveDeviceInfoPacked).WillOnce(DoAll(SetArgPointee<1>(infoOther), Return(SOFTBUS_OK)));
    PopulateDeviceTypeId(&authParam, requestId);
    EXPECT_EQ(authParam.deviceTypeId, 0);
}
} // namespace OHOS