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
#include "auth_session_fsm.h"
#include "auth_session_fsm.c"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
constexpr int64_t AUTH_SEQ = 1;
constexpr int64_t AUTH_SEQ_1 = 2;
constexpr uint64_t CONN_ID = 10;
constexpr uint64_t CONN_ID_1 = 11;
constexpr int32_t DEVICE_ID_HASH_LEN = 9;
constexpr uint32_t REQUEST_ID = 1000;
constexpr uint32_t REQUEST_ID_1 = 1001;
constexpr int32_t TMP_DATA_LEN = 10;
constexpr char UDID_TEST[UDID_BUF_LEN] = "123456789udidtest";
constexpr char INVALID_UDID_TEST[UDID_BUF_LEN] = "nullptr";
constexpr char BR_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
constexpr char BLE_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
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

void AuthSessionFsmTest::SetUp() {}

void AuthSessionFsmTest::TearDown() {}

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
    AuthFsm *authFsm = CreateAuthFsm(AUTH_SEQ, REQUEST_ID, CONN_ID, &connInfo, true);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(nullptr, FSM_MSG_AUTH_TIMEOUT, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(&authFsm->fsm, FSM_MSG_AUTH_TIMEOUT, nullptr);
    EXPECT_TRUE(authFsm == nullptr);
    authFsm = TranslateToAuthFsm(&authFsm->fsm, FSM_MSG_RECV_DEVICE_ID, nullptr);
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
    EXPECT_TRUE(SoftBusGenerateStrHash(DEVICE_ID_HASH, DEVICE_ID_HASH_LEN,
        request.connInfo.info.bleInfo.deviceIdHash) == SOFTBUS_OK);
    EXPECT_TRUE(AddAuthRequest(&request) == 0);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BR;
    AddUdidInfo(REQUEST_ID, true, &connInfo);
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    AddUdidInfo(REQUEST_ID, false, &connInfo);
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(ProcAuthFsm(REQUEST_ID_1, true, &authFsm) == SOFTBUS_ERR);
    EXPECT_TRUE(ProcAuthFsm(REQUEST_ID, true, &authFsm) == SOFTBUS_ERR);
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(ProcAuthFsm(REQUEST_ID, true, &authFsm) == SOFTBUS_OK);
    authFsm.authSeq = AUTH_SEQ_1;
    authFsm.info.isServer = false;
    authFsm.info.isSupportFastAuth = false;
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_BLE;
    CompleteAuthSession(&authFsm, SOFTBUS_OK);
    authFsm.info.isSupportFastAuth = true;
    CompleteAuthSession(&authFsm, SOFTBUS_OK);
}

/*
 * @tc.name: RECOVERY_DEVICE_KEY_TEST_001
 * @tc.desc: RecoveryDeviceKey test
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
    EXPECT_TRUE(RecoveryDeviceKey(&authFsm) == SOFTBUS_ERR);
    authFsm.info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_TRUE(RecoveryDeviceKey(&authFsm) == SOFTBUS_ERR);
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
    ASSERT_TRUE(memcpy_s(info.connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    AuditReportSetPeerDevInfo(auditData, &info);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(info.connInfo.info.bleInfo.bleMac, BT_MAC_LEN, BLE_MAC, strlen(BLE_MAC)) == EOK);
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
    EXPECT_TRUE(ClientSetExchangeIdType(&authFsm) == SOFTBUS_ERR);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.isServer = true;
    EXPECT_TRUE(TrySyncDeviceInfo(AUTH_SEQ_1, &info) == SOFTBUS_OK);
    info.isServer = false;
    EXPECT_TRUE(TrySyncDeviceInfo(AUTH_SEQ_1, &info) == SOFTBUS_ENCRYPT_ERR);
    info.connInfo.type = AUTH_LINK_TYPE_MAX;
    EXPECT_TRUE(TrySyncDeviceInfo(AUTH_SEQ_1, &info) == SOFTBUS_ERR);
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
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID_1, false) == nullptr);
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID, false) == nullptr);
    EXPECT_TRUE(GetAuthFsmByConnId(CONN_ID, true) == nullptr);
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
    EXPECT_TRUE(AuthSessionHandleDeviceDisconnected(CONN_ID_1) == SOFTBUS_OK);
    EXPECT_TRUE(AuthSessionHandleDeviceDisconnected(CONN_ID) == SOFTBUS_OK);
    AuthSessionFsmExit();
}
} // namespace OHOS
