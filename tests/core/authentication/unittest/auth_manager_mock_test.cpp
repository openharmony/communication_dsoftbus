/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "auth_manager.c"
#include "auth_manager.h"
#include "auth_manager_deps_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char UDID_TEST[UDID_BUF_LEN] = "testId123";
constexpr char UUID_TEST[UUID_BUF_LEN] = "testId123";
constexpr int64_t AUTH_SEQ = 1;
constexpr uint64_t TIME_TEST = 65535;
constexpr int32_t PORT = 1;
constexpr int32_t PORT_1 = 2;
constexpr int32_t INDEX_TEST = 3;
constexpr int32_t FD_TEST = 3701;
constexpr uint32_t REQ_ID = 100;
const uint64_t CONN_ID = 10 | ((uint64_t)AUTH_LINK_TYPE_WIFI << INT32_BIT_NUM);

class AuthManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthManagerMockTest::SetUpTestCase() { }

void AuthManagerMockTest::TearDownTestCase() { }

void AuthManagerMockTest::SetUp() { }

void AuthManagerMockTest::TearDown() { }

/*
 * @tc.name: RAW_LINK_NEED_UPDATE_AUTH_MANAGER_TEST_001
 * @tc.desc: Invalid uuid or require auth lock fail, do not need update auth manager
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, RAW_LINK_NEED_UPDATE_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    bool ret = RawLinkNeedUpdateAuthManager(nullptr, true);
    EXPECT_FALSE(ret);
    ret = RawLinkNeedUpdateAuthManager(UUID_TEST, true);
    EXPECT_FALSE(ret);
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    AuthManager *auth = NewAuthManager(AUTH_SEQ, &info);
    EXPECT_NE(auth, nullptr);
    ret = RawLinkNeedUpdateAuthManager(UUID_TEST, true);
    EXPECT_FALSE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.isSavedSessionKey = true;
    AuthHandle handle;
    info.isConnectServer = true;
    NotifyAuthResult(handle, &info);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: IS_AUTH_NODE_DISCONNECT_TEST_001
 * @tc.desc: Invalid input param, auth manager not need disconnect device
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, IS_AUTH_NODE_DISCONNECT_TEST_001, TestSize.Level1)
{
    AuthManager auth;
    AuthSessionInfo info;
    (void)memset_s(&auth, sizeof(auth), 0, sizeof(auth));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    bool ret = IsAuthNoNeedDisconnect(nullptr, &info);
    EXPECT_FALSE(ret);
    ret = IsAuthNoNeedDisconnect(&auth, nullptr);
    EXPECT_FALSE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = IsAuthNoNeedDisconnect(&auth, &info);
    EXPECT_FALSE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.connInfo.info.ipInfo.port = PORT;
    auth.connInfo[AUTH_LINK_TYPE_WIFI].info.ipInfo.port = PORT_1;
    ret = IsAuthNoNeedDisconnect(&auth, &info);
    EXPECT_TRUE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_USB;
    ret = IsAuthNoNeedDisconnect(&auth, &info);
    EXPECT_TRUE(ret);
    auth.connInfo[AUTH_LINK_TYPE_WIFI].info.ipInfo.port = PORT;
    ret = IsAuthNoNeedDisconnect(&auth, &info);
    EXPECT_TRUE(ret);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    ret = IsAuthNoNeedDisconnect(&auth, &info);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: PROCESS_SESSION_KEY_TEST_001
 * @tc.desc: Add session key fail and process session key fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, PROCESS_SESSION_KEY_TEST_001, TestSize.Level1)
{
    SessionKeyList list;
    (void)memset_s(&list, sizeof(SessionKeyList), 0, sizeof(SessionKeyList));
    SessionKey key;
    (void)memset_s(&key, sizeof(SessionKey), 0, sizeof(SessionKey));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.normalizedType = NORMALIZED_SUPPORT;
    bool isOldKey = false;
    int64_t peerAuthSeq;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, SetSessionKeyAuthLinkType)
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProcessSessionKey(&list, &key, &info, isOldKey, &peerAuthSeq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(authManagerMock, AddSessionKey)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = ProcessSessionKey(&list, &key, &info, isOldKey, &peerAuthSeq);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SESSION_KEY_PROC_ERR);
    ret = ProcessSessionKey(&list, &key, &info, isOldKey, &peerAuthSeq);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DFX_RECORD_SERVER_RECV_PASSIVE_CONN_TIME_TEST_001
 * @tc.desc: Different connection types dfx record test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, DFX_RECORD_SERVER_RECV_PASSIVE_CONN_TIME_TEST_001, TestSize.Level1)
{
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GetLnnTriggerInfo)
        .WillRepeatedly(Return());
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_NO_FATAL_FAILURE(DfxRecordServerRecvPassiveConnTime(&connInfo, &head));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_NO_FATAL_FAILURE(DfxRecordServerRecvPassiveConnTime(&connInfo, &head));
    connInfo.type = AUTH_LINK_TYPE_SESSION_KEY;
    EXPECT_NO_FATAL_FAILURE(DfxRecordServerRecvPassiveConnTime(&connInfo, &head));
}

/*
 * @tc.name: HANDLE_DEVICE_ID_DATA_TEST_001
 * @tc.desc: Different process anomalies lead to the failure of function execution
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_DEVICE_ID_DATA_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    head.flag = CLIENT_SIDE_FLAG;
    uint64_t connId = CONN_ID;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GetConfigSupportAsServer)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ConnGetNewRequestId)
        .WillRepeatedly(Return(REQ_ID));
    EXPECT_CALL(authManagerMock, HandleRepeatDeviceIdDataDelay)
        .WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    AuthFsm fsm;
    (void)memset_s(&fsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    fsm.info.idType = EXCHANGE_NETWORKID;
    EXPECT_CALL(authManagerMock, GetAuthFsmByConnId)
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&fsm));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthSessionStartAuth)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, AuthSessionProcessDevIdData)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    fsm.info.idType = EXCHANGE_FAIL;
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    fsm.info.localState = AUTH_STATE_ACK;
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    fsm.info.idType = EXCHANGE_UDID;
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
    fsm.info.localState = AUTH_STATE_COMPATIBLE;
    EXPECT_NO_FATAL_FAILURE(HandleDeviceIdData(connId, &connInfo, false, &head, nullptr));
}

/*
 * @tc.name: HANDLE_DEVICE_INFO_DATA_TEST_001
 * @tc.desc: Require auth lock fail and handle device info data fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_DEVICE_INFO_DATA_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    uint64_t connId = CONN_ID;
    DeviceMessageParse messageParse = { 0 };
    messageParse.messageType = CODE_VERIFY_DEVICE;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, IsDeviceMessagePacket)
        .WillRepeatedly(DoAll(SetArgPointee<4>(messageParse), Return(true)));
    EXPECT_CALL(authManagerMock, RequireAuthLock).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(HandleDeviceInfoData(connId, &connInfo, false, &head, nullptr));
}

/*
 * @tc.name: HANDLE_DEVICE_INFO_DATA_TEST_002
 * @tc.desc: Handle device info data sucess
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_DEVICE_INFO_DATA_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    uint64_t connId = CONN_ID;
    DeviceMessageParse messageParse = { 0 };
    messageParse.messageType = CODE_TCP_KEEPALIVE;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, IsDeviceMessagePacket)
        .WillRepeatedly(DoAll(SetArgPointee<4>(messageParse), Return(true)));
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(authManagerMock, AuthSetTcpKeepaliveOption)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(HandleDeviceInfoData(connId, &connInfo, false, &head, nullptr));
    messageParse.messageType = 0;
    EXPECT_NO_FATAL_FAILURE(HandleDeviceInfoData(connId, &connInfo, false, &head, nullptr));
}

/*
 * @tc.name: SET_LOCAL_TCP_KEEPALIVE_TEST_001
 * @tc.desc: Invalid param and set local tcp keepalive fail test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, SET_LOCAL_TCP_KEEPALIVE_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(false));
    ModeCycle cycle = MID_FREQ_CYCLE;
    int32_t ret = AuthSendKeepaliveOption(nullptr, cycle);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthSendKeepaliveOption(UUID_TEST, cycle);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL);
}

/*
 * @tc.name: TRY_GET_BR_CONN_INFO_TEST_001
 * @tc.desc: Different process anomalies lead to get br conn info fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, TRY_GET_BR_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, LnnGetNetworkIdByUuid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TryGetBrConnInfo(UUID_TEST, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
    EXPECT_CALL(authManagerMock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = TryGetBrConnInfo(UUID_TEST, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
    EXPECT_CALL(authManagerMock, LnnGetRemoteNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = TryGetBrConnInfo(UUID_TEST, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
}

/*
 * @tc.name: AUTH_DEVICE_GET_CONN_INFO_BY_TYPE_TEST_001
 * @tc.desc: Different process anomalies lead to get conn info by type fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_DEVICE_GET_CONN_INFO_BY_TYPE_TEST_001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_BR;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = AuthDeviceGetConnInfoByType(nullptr, type, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthDeviceGetConnInfoByType(UUID_TEST, type, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(authManagerMock, LnnGetNetworkIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = AuthDeviceGetConnInfoByType(UUID_TEST, type, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL);
    type = AUTH_LINK_TYPE_BLE;
    ret = AuthDeviceGetConnInfoByType(UUID_TEST, type, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_FAILED_TEST_001
 * @tc.desc: Auth manager set auth failed because get auth request failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_AUTH_FAILED_TEST_001, TestSize.Level1)
{
    int64_t authSeq = AUTH_SEQ;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    int32_t reason = SOFTBUS_AUTH_TIMEOUT;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceDisconnect)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authManagerMock, GetConnType)
        .WillRepeatedly(Return(AUTH_LINK_TYPE_WIFI));
    EXPECT_CALL(authManagerMock, UpdateAuthDevicePriority)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DisconnectAuthDevice)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthAddNodeToLimitMap)
        .WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthFailed(authSeq, &info, reason));
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_PASSED_TEST_001
 * @tc.desc: Auth manager set auth passed sucess test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_AUTH_PASSED_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthPassed(authSeq, &info));
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: GET_EXIST_AUTH_MANAGER_TEST_001
 * @tc.desc: Get auth manager and return not null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, GET_EXIST_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    info.normalizedType = NORMALIZED_NOT_SUPPORT;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = GetExistAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
    info.normalizedType = NORMALIZED_SUPPORT;
    auth = GetExistAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: GET_DEVICE_AUTH_MANAGER_TEST_001
 * @tc.desc: Get device auth manager and return not null
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, GET_DEVICE_AUTH_MANAGER_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    uint64_t time = TIME_TEST;
    EXPECT_CALL(authManagerMock, GetCurrentTimeMs)
        .WillRepeatedly(Return(time));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    bool isNewCreated = false;
    int64_t lastAuthSeq = AUTH_SEQ;
    AuthManager *authNew = GetDeviceAuthManager(authSeq, &info, &isNewCreated, lastAuthSeq);
    EXPECT_NE(authNew, nullptr);
    DelAuthManager(authNew, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: PROCESS_EMPTY_SESSION_KEY_TEST_001
 * @tc.desc: Process empty session key succeed test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, PROCESS_EMPTY_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr).WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk).WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList).WillRepeatedly(Return());
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthPassed(authSeq, &info));
    int32_t index = INDEX_TEST;
    bool isServer = true;
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    EXPECT_CALL(authManagerMock, ClearOldKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, SetSessionKeyAuthLinkType).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProcessEmptySessionKey(&info, index, isServer, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(authManagerMock, AddSessionKey).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = ProcessEmptySessionKey(&info, index, isServer, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SESSION_KEY_INVALID);
    ret = ProcessEmptySessionKey(&info, index, isServer, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SESSION_KEY_INVALID);
    ret = ProcessEmptySessionKey(&info, index, isServer, &sessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: AUTH_PROCESS_EMPTY_SESSION_KEY_TEST_001
 * @tc.desc: Auth process empty session key failed because get session key by index failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_PROCESS_EMPTY_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetSessionKeyByIndex)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authManagerMock, ClearOldKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, SetSessionKeyAuthLinkType)
        .WillRepeatedly(Return(SOFTBUS_OK));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.module = AUTH_MODULE_TRANS;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthPassed(authSeq, &info));
    int32_t index = INDEX_TEST;
    int32_t ret = AuthProcessEmptySessionKey(&info, index);
    EXPECT_EQ(ret, SOFTBUS_AUTH_GET_SESSION_KEY_FAIL);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: AUTH_MANAGER_SET_SESSION_KEY_TEST_001
 * @tc.desc: Auth manager set session key succeed test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey).WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList).WillRepeatedly(Return());
    uint64_t time = TIME_TEST;
    EXPECT_CALL(authManagerMock, GetCurrentTimeMs).WillRepeatedly(Return(time));
    int64_t seq = AUTH_SEQ;
    EXPECT_CALL(authManagerMock, GenSeq).WillRepeatedly(Return(seq));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    bool isConnect = false;
    bool isOldKey = false;
    int32_t ret = AuthManagerSetSessionKey(authSeq, &info, &sessionKey, isConnect, isOldKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: REPORT_AUTH_REQUEST_PASSED_TEST_001
 * @tc.desc: Request conn info type is wifi test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, REPORT_AUTH_REQUEST_PASSED_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, CheckAuthConnCallback)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformAuthConnCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DelAuthRequest)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformVerifyCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, FindAuthRequestByConnInfo)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    uint32_t requestId = REQ_ID;
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NO_FATAL_FAILURE(ReportAuthRequestPassed(requestId, authHandle, &nodeInfo));
}

/*
 * @tc.name: REPORT_AUTH_REQUEST_PASSED_TEST_002
 * @tc.desc: Request conn info type is sle and request module is trans test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, REPORT_AUTH_REQUEST_PASSED_TEST_002, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, CheckAuthConnCallback)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformAuthConnCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DelAuthRequest)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformVerifyCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, FindAuthRequestByConnInfo)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.connInfo.type = AUTH_LINK_TYPE_SLE;
    request.module = AUTH_MODULE_TRANS;
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillOnce(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    uint32_t requestId = REQ_ID;
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NO_FATAL_FAILURE(ReportAuthRequestPassed(requestId, authHandle, &nodeInfo));
}

/*
 * @tc.name: REPORT_AUTH_REQUEST_FAILED_TEST_001
 * @tc.desc: Report auth request info succeed test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, REPORT_AUTH_REQUEST_FAILED_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, CheckAuthConnCallback)
        .WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, DelAuthRequest)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformVerifyCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PerformAuthConnCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, FindAuthRequestByConnInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, ConnectAuthDevice)
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t requestId = REQ_ID;
    int32_t reason = SOFTBUS_AUTH_TIMEOUT;
    EXPECT_NO_FATAL_FAILURE(ReportAuthRequestFailed(requestId, reason));
}

/*
 * @tc.name: AUTH_NOTIFY_AUTH_PASSED_TEST_001
 * @tc.desc: Auth notify auth passed succeed test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_NOTIFY_AUTH_PASSED_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DelAuthNormalizeRequest)
        .WillRepeatedly(Return());
    uint64_t time = TIME_TEST;
    EXPECT_CALL(authManagerMock, GetCurrentTimeMs)
        .WillRepeatedly(Return(time));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthNotifyAuthPassed(authSeq, &info));
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: AUTH_NOTIFY_AUTH_PASSED_TEST_002
 * @tc.desc: Auth notify auth passed failed test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_NOTIFY_AUTH_PASSED_TEST_002, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, DelAuthNormalizeRequest)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, PrintAuthConnInfo)
        .WillRepeatedly(Return());
    int64_t authSeq = AUTH_SEQ;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_NO_FATAL_FAILURE(AuthNotifyAuthPassed(authSeq, &info));
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_FINISHED_TEST_001
 * @tc.desc: Auth manager set auth finished and feature support, protocol is gatt
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_AUTH_FINISHED_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.isConnectServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.connInfo.info.bleInfo.protocol = BLE_GATT;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, IsFeatureSupport)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, DisconnectAuthDevice)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, AuthDeleteLimitMap)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PostAuthEvent)
        .WillRepeatedly(Return(SOFTBUS_OK));
    int64_t authSeq = AUTH_SEQ;
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthFinished(authSeq, &info));
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_FINISHED_TEST_002
 * @tc.desc: Auth manager set auth finished and feature not support, protocol is gatt
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_AUTH_FINISHED_TEST_002, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.isConnectServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.connInfo.info.bleInfo.protocol = BLE_GATT;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, IsFeatureSupport)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(authManagerMock, DisconnectAuthDevice)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, AuthDeleteLimitMap)
        .WillRepeatedly(Return());
    int64_t authSeq = AUTH_SEQ;
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthFinished(authSeq, &info));
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_FINISHED_TEST_003
 * @tc.desc: Auth manager set auth finished and feature not support, protocol is coc
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_MANAGER_SET_AUTH_FINISHED_TEST_003, TestSize.Level1)
{
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.isConnectServer = false;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    info.connInfo.info.bleInfo.protocol = BLE_COC;
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, IsFeatureSupport)
        .WillRepeatedly(Return(false));
    EXPECT_CALL(authManagerMock, DisconnectAuthDevice)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, SoftBusGenerateStrHash)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, AuthDeleteLimitMap)
        .WillRepeatedly(Return());
    int64_t authSeq = AUTH_SEQ;
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthFinished(authSeq, &info));
}

/*
 * @tc.name: ON_CONNECT_RESULT_TEST_001
 * @tc.desc: Result is SOFTBUS_OK test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, ON_CONNECT_RESULT_TEST_001, TestSize.Level1)
{
    uint32_t requestId = REQ_ID;
    uint64_t connId = CONN_ID;
    int32_t result = SOFTBUS_OK;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthManagerInterfaceMock authManagerMock;
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.type = REQUEST_TYPE_VERIFY;
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillRepeatedly(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    EXPECT_CALL(authManagerMock, AuthSessionStartAuth)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(OnConnectResult(requestId, connId, result, &connInfo));
}

/*
 * @tc.name: ON_CONNECT_RESULT_TEST_002
 * @tc.desc: Result is SOFTBUS_INVALID_PARAM test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, ON_CONNECT_RESULT_TEST_002, TestSize.Level1)
{
    uint32_t requestId = REQ_ID;
    uint64_t connId = CONN_ID;
    int32_t result = SOFTBUS_INVALID_PARAM;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthManagerInterfaceMock authManagerMock;
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.type = REQUEST_TYPE_RECONNECT;
    EXPECT_CALL(authManagerMock, GetAuthRequest)
        .WillRepeatedly(DoAll(SetArgPointee<1>(request), Return(SOFTBUS_OK)));
    EXPECT_CALL(authManagerMock, PerformAuthConnCallback)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DelAuthRequest)
        .WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(OnConnectResult(requestId, connId, result, &connInfo));
}

/*
 * @tc.name: HANDLE_UK_CONNECTION_DATA_TEST_001
 * @tc.desc: Auth get uk decrypt size return abnormal test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_UK_CONNECTION_DATA_TEST_001, TestSize.Level1)
{
    uint64_t connId = CONN_ID;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool fromServer = true;
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GenConnId)
        .WillRepeatedly(Return(connId));
    int32_t fd = FD_TEST;
    EXPECT_CALL(authManagerMock, GetFd)
        .WillRepeatedly(Return(fd));
    uint32_t len = UK_ENCRYPT_INDEX_LEN + 1;
    EXPECT_CALL(authManagerMock, AuthGetUkDecryptSize)
        .WillRepeatedly(Return(len));
    EXPECT_CALL(authManagerMock, AuthDecryptByUkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, PrintAuthConnInfo)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetConnType)
        .WillRepeatedly(Return(AUTH_LINK_TYPE_WIFI));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, GetConnTypeStr)
        .WillRepeatedly(Return("wifi/eth"));
    uint32_t connIdTest = REQ_ID;
    EXPECT_CALL(authManagerMock, GetConnId)
        .WillRepeatedly(Return(connIdTest));
    uint32_t data = INDEX_TEST;
    EXPECT_NO_FATAL_FAILURE(HandleUkConnectionData(connId, &connInfo, fromServer,
        &head, reinterpret_cast<const uint8_t *>(&data)));
}

/*
 * @tc.name: HANDLE_UK_CONNECTION_DATA_TEST_002
 * @tc.desc: Auth get uk decrypt size return normal test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_UK_CONNECTION_DATA_TEST_002, TestSize.Level1)
{
    uint64_t connId = CONN_ID;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool fromServer = true;
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GenConnId)
        .WillRepeatedly(Return(connId));
    int32_t fd = FD_TEST;
    EXPECT_CALL(authManagerMock, GetFd)
        .WillRepeatedly(Return(fd));
    uint32_t len = UK_ENCRYPT_INDEX_LEN;
    EXPECT_CALL(authManagerMock, AuthGetUkDecryptSize)
        .WillRepeatedly(Return(len));
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetConnType)
        .WillRepeatedly(Return(AUTH_LINK_TYPE_WIFI));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, GetConnTypeStr)
        .WillRepeatedly(Return("wifi/eth"));
    uint32_t connIdTest = REQ_ID;
    EXPECT_CALL(authManagerMock, GetConnId)
        .WillRepeatedly(Return(connIdTest));
    uint32_t data = INDEX_TEST;
    EXPECT_NO_FATAL_FAILURE(HandleUkConnectionData(connId, &connInfo, fromServer,
        &head, reinterpret_cast<const uint8_t *>(&data)));
}

/*
 * @tc.name: HANDLE_UK_CONNECTION_DATA_TEST_003
 * @tc.desc: Handle uk connection data failed because decrypt data failed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, HANDLE_UK_CONNECTION_DATA_TEST_003, TestSize.Level1)
{
    uint64_t connId = CONN_ID;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool fromServer = true;
    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, GenConnId)
        .WillRepeatedly(Return(connId));
    int32_t fd = FD_TEST;
    EXPECT_CALL(authManagerMock, GetFd)
        .WillRepeatedly(Return(fd));
    uint32_t len = UK_ENCRYPT_INDEX_LEN + 1;
    EXPECT_CALL(authManagerMock, AuthGetUkDecryptSize)
        .WillRepeatedly(Return(len));
    EXPECT_CALL(authManagerMock, AuthDecryptByUkId)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetConnType)
        .WillRepeatedly(Return(AUTH_LINK_TYPE_WIFI));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, GetConnTypeStr)
        .WillRepeatedly(Return("wifi/eth"));
    uint32_t connIdTest = REQ_ID;
    EXPECT_CALL(authManagerMock, GetConnId)
        .WillRepeatedly(Return(connIdTest));
    uint32_t data = INDEX_TEST;
    EXPECT_NO_FATAL_FAILURE(HandleUkConnectionData(connId, &connInfo, fromServer,
        &head, reinterpret_cast<const uint8_t *>(&data)));
}

/*
 * @tc.name: POST_DEVICE_MESSAGE_BY_UUID_TEST_001
 * @tc.desc: Post device message by uuid succeed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, POST_DEVICE_MESSAGE_BY_UUID_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, PostDeviceMessage)
        .WillRepeatedly(Return(SOFTBUS_OK));
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthPassed(authSeq, &info));
    int32_t messageType = 1;
    ModeCycle cycle = HIGH_FREQ_CYCLE;
    int32_t ret = PostDeviceMessageByUuid(UUID_TEST, messageType, cycle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: AUTH_DEVICE_GET_PREFER_CONN_INFO_TEST_001
 * @tc.desc: Auth device get prefer conn info succeed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthManagerMockTest, AUTH_DEVICE_GET_PREFER_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthManagerInterfaceMock authManagerMock;
    EXPECT_CALL(authManagerMock, RequireAuthLock)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, ReleaseAuthLock)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CheckAuthConnInfoType)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, InitSessionKeyList)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, GetAuthSideStr)
        .WillRepeatedly(Return("server"));
    EXPECT_CALL(authManagerMock, CompareConnInfo)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, SetSessionKeyAvailable)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnSetDlPtk)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(authManagerMock, GetIsExchangeUdidByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authManagerMock, LnnClearAuthExchangeUdidPacked)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, AuthNotifyDeviceVerifyPassed)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, CancelUpdateSessionKey)
        .WillRepeatedly(Return());
    EXPECT_CALL(authManagerMock, DestroySessionKeyList)
        .WillRepeatedly(Return());
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(strcpy_s(info.udid, UDID_BUF_LEN, UDID_TEST), EOK);
    EXPECT_EQ(strcpy_s(info.uuid, UUID_BUF_LEN, UUID_TEST), EOK);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    info.module = AUTH_MODULE_LNN;
    info.isConnectServer = true;
    int64_t authSeq = AUTH_SEQ;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_NE(auth, nullptr);
    EXPECT_NO_FATAL_FAILURE(AuthManagerSetAuthPassed(authSeq, &info));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = AuthDeviceGetPreferConnInfo(UUID_TEST, &connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}
} // namespace OHOS