/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_connection.h"
#include "auth_connection.c"
#include "auth_interface.h"
#include "auth_interface.c"
#include "auth_manager.h"
#include "auth_manager.c"
#include "auth_session_fsm.h"
#include "auth_session_fsm.c"
#include "auth_session_key.h"
#include "auth_session_key.c"
#include "auth_session_message.h"
#include "auth_session_message.c"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 30;

class AuthOtherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthOtherTest::SetUpTestCase()
{
    int32_t ret =  AuthCommonInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void AuthOtherTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthOtherTest::SetUp()
{
    LOG_INFO("AuthOtherTest start.");
}

void AuthOtherTest::TearDown() {}

void OnConnectResultTest(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo)
{
    (void)requestId;
    (void)connId;
    (void)result;
    (void)connInfo;
}

void OnDisconnectedTest(uint64_t connId, const AuthConnInfo *connInfo)
{
    (void)connId;
    (void)connInfo;
}

void OnDataReceivedTest(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    (void)connId;
    (void)connInfo;
    (void)fromServer;
    (void)head;
    (void)data;
}

void OnDeviceNotTrustedTest(const char *udid)
{
    (void)udid;
}

void OnDeviceVerifyPassTest(int64_t authId, const NodeInfo *info)
{
    (void)authId;
    (void)info;
}

void OnDeviceDisconnectTest(int64_t authId)
{
    (void)authId;
}

void OnGroupCreatedTest(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
}

void OnGroupDeletedTest(const char *groupId)
{
    (void)groupId;
}

/*
 * @tc.name: ADD_CONN_REQUEST_TEST_001
 * @tc.desc: add conn request test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ADD_CONN_REQUEST_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    uint32_t requestId = 0;
    int32_t fd = 0;

    int32_t ret = AddConnRequest(&connInfo, requestId, fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ConnRequest *item = FindConnRequestByRequestId(requestId);
    EXPECT_TRUE(item != nullptr);
    DelConnRequest(nullptr);
    DelConnRequest(item);
}

/*
 * @tc.name: NOTIFY_CLIENT_CONNECTED_TEST_001
 * @tc.desc: notify client connected test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_CLIENT_CONNECTED_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    uint64_t connId = 0;
    int32_t result = 0;
    AuthConnInfo connInfo;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    g_listener.onConnectResult = nullptr;
    NotifyClientConnected(requestId, connId, result, &connInfo);
    g_listener.onConnectResult = OnConnectResultTest;
    NotifyClientConnected(requestId, connId, result, &connInfo);
}

/*
 * @tc.name: NOTIFY_DISCONNECTED_TEST_001
 * @tc.desc: notify disconnected test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_DISCONNECTED_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    AuthConnInfo connInfo;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    g_listener.onDisconnected = nullptr;
    NotifyDisconnected(connId, &connInfo);
    g_listener.onDisconnected = OnDisconnectedTest;
    NotifyDisconnected(connId, &connInfo);
}

/*
 * @tc.name: NOTIFY_DATA_RECEIVED_TEST_001
 * @tc.desc: notify data received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    AuthConnInfo connInfo;
    bool fromServer = true;
    AuthDataHead head;
    uint8_t *data = nullptr;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    g_listener.onDataReceived = nullptr;
    NotifyDataReceived(connId, &connInfo, fromServer, &head, data);
    g_listener.onDataReceived = OnDataReceivedTest;
    NotifyDataReceived(connId, &connInfo, fromServer, &head, data);
}

/*
 * @tc.name: HANDLE_CONNCONNECT_TIMEOUT_TEST_001
 * @tc.desc: handle connConnect timeout test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_CONNCONNECT_TIMEOUT_TEST_001, TestSize.Level1)
{
    const void *para = "testdata";

    HandleConnConnectTimeout(nullptr);
    HandleConnConnectTimeout(para);
}

/*
 * @tc.name: REMOVE_FUNC_TEST_001
 * @tc.desc: remove func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, REMOVE_FUNC_TEST_001, TestSize.Level1)
{
    uint32_t obj = 1;
    uint32_t param = 1;

    int32_t ret = RemoveFunc(nullptr, static_cast<void *>(&param));
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RemoveFunc(static_cast<void *>(&obj), nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RemoveFunc(static_cast<void *>(&obj), static_cast<void *>(&param));
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: HANDLE_CONN_CONNECT_CMD_TEST_001
 * @tc.desc: handle conn connect cmd test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_CONN_CONNECT_CMD_TEST_001, TestSize.Level1)
{
    ConnCmdInfo info;

    (void)memset_s(&info, sizeof(ConnCmdInfo), 0, sizeof(ConnCmdInfo));
    HandleConnConnectCmd(nullptr);
    HandleConnConnectCmd((void *)&info);
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    HandleConnConnectCmd((void *)&info);
}

/*
 * @tc.name: HANDLE_CONN_CONNECT_RESULT_TEST_001
 * @tc.desc: handle conn connect result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_CONN_CONNECT_RESULT_TEST_001, TestSize.Level1)
{
    int32_t para = 0;

    HandleConnConnectResult(nullptr);
    HandleConnConnectResult((void *)&para);
}

/*
 * @tc.name: ON_WIFI_CONNECTED_TEST_001
 * @tc.desc: on wifi connected test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_WIFI_CONNECTED_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;

    OnWiFiConnected(fd, true);
    OnWiFiConnected(fd, false);
}

/*
 * @tc.name: ON_WIFI_DATA_RECEIVED_TEST_001
 * @tc.desc: on wifi data received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_WIFI_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    AuthDataHead head;
    const uint8_t data[TEST_DATA_LEN] = { 0 };

    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    OnWiFiDataReceived(fd, nullptr, data);
    OnWiFiDataReceived(fd, &head, nullptr);
    OnWiFiDataReceived(fd, &head, data);
}

/*
 * @tc.name: ON_COMM_DISCONNECTED_TEST_001
 * @tc.desc: on comm disconnected test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_COMM_DISCONNECTED_TEST_001, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnectionInfo info;

    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    OnCommDisconnected(connectionId, nullptr);
    OnCommDisconnected(connectionId, &info);
}

/*
 * @tc.name: ON_COMM_CONNECT_SUCC_TEST_001
 * @tc.desc: on comm connect succ test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_COMM_CONNECT_SUCC_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    uint32_t connectionId = 0;
    ConnectionInfo info;

    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    OnCommConnectSucc(requestId, connectionId, nullptr);
    OnCommConnectSucc(requestId, connectionId, &info);
}

/*
 * @tc.name: CHECK_ACTIVE_AUTH_CONNECTION_TEST_001
 * @tc.desc: check active auth connection test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, CHECK_ACTIVE_AUTH_CONNECTION_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool ret = CheckActiveAuthConnection(nullptr);
    EXPECT_TRUE(ret == false);
    ret = CheckActiveAuthConnection(&connInfo);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: AUTH_GET_META_TYPE_TEST_001
 * @tc.desc: auth get meta type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_GET_META_TYPE_TEST_001, TestSize.Level1)
{
    int64_t authId = 0;
    bool isMetaAuth = false;

    int32_t ret = AuthGetMetaType(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetMetaType(authId, &isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: REMOVE_AUTH_MANAGER_BY_AUTH_ID_TEST_001
 * @tc.desc: remove auth manager by auth id test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, REMOVE_AUTH_MANAGER_BY_AUTH_ID_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo info;
    AuthConnInfo connInfo;
    const char *udid = "000";
    uint64_t connId = 0;
    uint64_t errConnId = 1;
    const char *ip = "192.168.12.1";

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)strcpy_s(info.udid, UDID_BUF_LEN, udid);
    (void)strcpy_s(info.uuid, UUID_BUF_LEN, udid);
    info.connId = 0;
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    ListInit(&g_authServerList);
    (void)strcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_TRUE(auth != nullptr);
    int64_t ret = GetAuthIdByConnId(errConnId, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = GetAuthIdByConnId(connId, true);
    EXPECT_TRUE(ret != AUTH_INVALID_ID);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, ip);
    ret = GetActiveAuthIdByConnInfo(&connInfo);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    RemoveAuthManagerByAuthId(authSeq);
    RemoveAuthManagerByConnInfo(&connInfo, true);
    RemoveNotPassedAuthManagerByUdid(udid);
}

/*
 * @tc.name: NOTIFY_DEVICE_VERIFY_PASSED_TEST_001
 * @tc.desc: notify device verify passed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_DEVICE_VERIFY_PASSED_TEST_001, TestSize.Level1)
{
    int64_t authId = 0;
    int64_t errAuthId = 1;
    NodeInfo nodeInfo;
    AuthSessionInfo info;

    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    NotifyDeviceVerifyPassed(errAuthId, &nodeInfo);
    g_verifyListener.onDeviceVerifyPass = nullptr;
    NotifyDeviceVerifyPassed(authId, &nodeInfo);
    g_verifyListener.onDeviceVerifyPass = OnDeviceVerifyPassTest,
    NotifyDeviceVerifyPassed(authId, &nodeInfo);
    DelAuthManager(auth, true);
}

/*
 * @tc.name: NOTIFY_DEVICE_DISCONNECT_TEST_001
 * @tc.desc: notify device disconnect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_DEVICE_DISCONNECT_TEST_001, TestSize.Level1)
{
    int64_t authId = 0;

    g_verifyListener.onDeviceDisconnect = nullptr;
    NotifyDeviceDisconnect(authId);
    g_verifyListener.onDeviceDisconnect = OnDeviceDisconnectTest;
    NotifyDeviceDisconnect(authId);
}

/*
 * @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_001
 * @tc.desc: on device not trusted test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    const char *peerUdid = "000";

    g_verifyListener.onDeviceNotTrusted = nullptr;
    OnDeviceNotTrusted(peerUdid);
    g_verifyListener.onDeviceNotTrusted = OnDeviceNotTrustedTest;
    OnDeviceNotTrusted(peerUdid);
}

/*
 * @tc.name: ON_GROUP_CREATED_TEST_001
 * @tc.desc: on group created test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_GROUP_CREATED_TEST_001, TestSize.Level1)
{
    const char *groupId = "000";
    int32_t groupType = 0;

    g_groupChangeListener.onGroupCreated = nullptr;
    OnGroupCreated(groupId, groupType);
    g_groupChangeListener.onGroupCreated = OnGroupCreatedTest;
    OnGroupCreated(groupId, groupType);
    g_groupChangeListener.onGroupDeleted = nullptr;
    OnGroupDeleted(groupId);
    g_groupChangeListener.onGroupDeleted = OnGroupDeletedTest;
    OnGroupDeleted(groupId);
}

/*
 * @tc.name: AUTH_MANAGER_SET_AUTH_PASSED_TEST_001
 * @tc.desc: auth manager set auth passed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_MANAGER_SET_AUTH_PASSED_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int64_t errAuthId = 1;
    AuthSessionInfo info;
    int32_t reason = 0;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_TRUE(auth != nullptr);
    AuthManagerSetAuthPassed(authSeq, nullptr);
    AuthManagerSetAuthPassed(errAuthId, &info);
    AuthManagerSetAuthPassed(authSeq, &info);
    AuthManagerSetAuthFailed(errAuthId, &info, reason);
    AuthManagerSetAuthFailed(authSeq, &info, reason);
    DelAuthManager(auth, true);
}

/*
 * @tc.name: HANDLE_RECONNECT_RESULT_TEST_001
 * @tc.desc: handle reconnect result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_RECONNECT_RESULT_TEST_001, TestSize.Level1)
{
    AuthRequest request;
    uint64_t connId = 0;
    int32_t result = -1;

    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    HandleReconnectResult(&request, connId, result);
    result = 0;
    HandleReconnectResult(&request, connId, result);
}

/*
 * @tc.name: HANDLE_DEVICE_INFO_DATA_TEST_001
 * @tc.desc: handle device info data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_DEVICE_INFO_DATA_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    AuthConnInfo connInfo;
    bool fromServer = true;
    AuthDataHead head;
    const uint8_t *data = nullptr;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    HandleDeviceInfoData(connId, &connInfo, fromServer, &head, data);
    head.seq = 1;
    HandleDeviceInfoData(connId, &connInfo, fromServer, &head, data);
}

/*
 * @tc.name: HANDLE_CONNECTION_DATA_TEST_001
 * @tc.desc: handle connection data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_CONNECTION_DATA_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    int64_t authId = 0;
    AuthConnInfo connInfo;
    AuthDataHead head;
    AuthSessionInfo info;
    const uint8_t *data = nullptr;
    bool fromServer = true;
    const char *ip = "192.168.12.1";

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    (void)strcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip);
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    HandleConnectionData(connId, &connInfo, fromServer, &head, data);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, ip);
    HandleConnectionData(connId, &connInfo, fromServer, &head, data);
    DelAuthManager(auth, true);
}

/*
 * @tc.name: HANDLE_DISCONNECTED_EVENT_TEST_001
 * @tc.desc: handle disconnected event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_DISCONNECTED_EVENT_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;

    HandleDisconnectedEvent(nullptr);
    HandleDisconnectedEvent((void *)&connId);
}


static void OnConnOpenedTest(uint32_t requestId, int64_t authId)
{
    ALOGI("OnConnOpenedTest: requestId = %d, authId = %" PRId64 ".", requestId, authId);
}

static void OnConnOpenFailedTest(uint32_t requestId, int32_t reason)
{
    ALOGI("OnConnOpenFailedTest: requestId = %d, reason = %d.", requestId, reason);
}

/*
 * @tc.name: AUTH_DEVICE_OPEN_CONN_TEST_001
 * @tc.desc: auth device open conn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_DEVICE_OPEN_CONN_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info;
    AuthConnInfo connInfo;
    uint32_t requestId = 0;
    int64_t authId = 0;
    const char *ip = "192.168.12.1";
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedTest,
        .onConnOpenFailed = OnConnOpenFailedTest,
    };

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    (void)strcpy_s(info.connInfo.info.ipInfo.ip, IP_LEN, ip);
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    int32_t ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);
    (void)strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, ip);
    ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_BR;
    ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_CONN_FAIL);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_CONN_FAIL);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_CONN_FAIL);
}

/*
 * @tc.name: UPDATE_AUTH_REQUEST_CONN_INFO_TEST_001
 * @tc.desc: update auth request conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UPDATE_AUTH_REQUEST_CONN_INFO_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));

    int32_t ret = UpdateAuthRequestConnInfo(requestId, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: UPDATE_AUTH_REQUEST_CONN_INFO_TEST_001
 * @tc.desc: update auth request conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthRequest request;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(&connInfo, &request);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: DEL_AUTH_REQUEST_TEST_001
 * @tc.desc: del auth request test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, DEL_AUTH_REQUEST_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    DelAuthRequest(requestId);
}

/*
 * @tc.name: PERFORM_VERIFY_CALLBACK_TEST_001
 * @tc.desc: perform verify callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, PERFORM_VERIFY_CALLBACK_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int32_t result = 0;
    int64_t authId = 0;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    PerformVerifyCallback(requestId, result, authId, &info);
}

/*
 * @tc.name: PERFORM_AUTH_CONN_CALLBACK_TEST_001
 * @tc.desc: perform auth conn callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, PERFORM_AUTH_CONN_CALLBACK_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int32_t result = 0;
    int64_t authId = 0;
    PerformAuthConnCallback(requestId, result, authId);
}

/*
 * @tc.name: COMPLETE_AUTH_SESSION_TEST_001
 * @tc.desc: complete auth session test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, COMPLETE_AUTH_SESSION_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    int32_t result = SOFTBUS_OK;
    (void)memset_s(&authFsm, sizeof(authFsm), 0, sizeof(authFsm));
    CompleteAuthSession(&authFsm, result);
    result = SOFTBUS_ERR;
    CompleteAuthSession(&authFsm, result);
}

/*
 * @tc.name: HANDLE_COMMON_MSG_TEST_001
 * @tc.desc: handle common msg test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_COMMON_MSG_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    int32_t msgType = FSM_MSG_AUTH_TIMEOUT;
    MessagePara msgPara;
    (void)memset_s(&authFsm, sizeof(authFsm), 0, sizeof(authFsm));
    (void)memset_s(&msgPara, sizeof(MessagePara), 0, sizeof(MessagePara));
    HandleCommonMsg(&authFsm, msgType, &msgPara);
    msgType = FSM_MSG_DEVICE_NOT_TRUSTED;
    HandleCommonMsg(&authFsm, msgType, &msgPara);
    msgType = FSM_MSG_DEVICE_DISCONNECTED;
    HandleCommonMsg(&authFsm, msgType, &msgPara);
    msgType++;
    HandleCommonMsg(&authFsm, msgType, &msgPara);
}

/*
 * @tc.name: HANDLE_MSG_RECV_DEVICE_INFO_TEST_001
 * @tc.desc: handle msg recv device info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_MSG_RECV_DEVICE_INFO_TEST_001, TestSize.Level1)
{
    AuthFsm authFsm;
    MessagePara para;
    (void)memset_s(&authFsm, sizeof(authFsm), 0, sizeof(authFsm));
    (void)memset_s(&para, sizeof(para), 0, sizeof(para));
    HandleMsgRecvDeviceInfo(&authFsm, &para);
}

/*
 * @tc.name: DUMP_SESSION_KEY_LIST_TEST_001
 * @tc.desc: dump session key list test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, DUMP_SESSION_KEY_LIST_TEST_001, TestSize.Level1)
{
    SessionKeyList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    DumpSessionkeyList(nullptr);
    InitSessionKeyList(&list);
    DumpSessionkeyList(&list);
    DestroySessionKeyList(&list);
}

/*
 * @tc.name: HANDLE_UPDATE_SESSION_KEY_EVENT_TEST_001
 * @tc.desc: handle update session key event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, HANDLE_UPDATE_SESSION_KEY_EVENT_TEST_001, TestSize.Level1)
{
    int64_t authId = 1;
    HandleUpdateSessionKeyEvent(nullptr);
    HandleUpdateSessionKeyEvent(&authId);
}

/*
 * @tc.name: RMOVE_UPDATE_SESSION_KEY_FUNC_TEST_001
 * @tc.desc: rmove update session key func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, RMOVE_UPDATE_SESSION_KEY_FUNC_TEST_001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t para = 0;
    int32_t ret = RmoveUpdateSessionKeyFunc(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RmoveUpdateSessionKeyFunc(&authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RmoveUpdateSessionKeyFunc(&authId, &para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RmoveUpdateSessionKeyFunc(&authId, &authId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: UNPACK_COMMON_TEST_001
 * @tc.desc: unpack common test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UNPACK_COMMON_TEST_001, TestSize.Level1)
{
    cJSON json;
    NodeInfo info;
    SoftBusVersion version = SOFTBUS_OLD_V2;
    bool isMetaAuth = true;
    (void)memset_s(&json, sizeof(json), 0, sizeof(json));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    UnpackCommon(&json, &info, version, isMetaAuth);
    version = SOFTBUS_NEW_V1;
    UnpackCommon(&json, &info, version, isMetaAuth);
    isMetaAuth = false;
    UnpackCommon(&json, &info, version, isMetaAuth);
}

/*
 * @tc.name: UNPACK_BT_TEST_001
 * @tc.desc: unpack bt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UNPACK_BT_TEST_001, TestSize.Level1)
{
    cJSON json;
    NodeInfo info;
    SoftBusVersion version = SOFTBUS_OLD_V2;
    bool isMetaAuth = true;
    (void)memset_s(&json, sizeof(json), 0, sizeof(json));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = UnpackBt(&json, &info, version, isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: PACK_WIFI_TEST_001
 * @tc.desc: pack wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, PACK_WIFI_TEST_001, TestSize.Level1)
{
    cJSON json;
    NodeInfo info;
    SoftBusVersion version = SOFTBUS_OLD_V2;
    bool isMetaAuth = true;
    (void)memset_s(&json, sizeof(json), 0, sizeof(json));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = PackWiFi(nullptr, nullptr, version, isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = PackWiFi(&json, &info, version, isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: UNPACK_WIFI_TEST_001
 * @tc.desc: unpack wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UNPACK_WIFI_TEST_001, TestSize.Level1)
{
    cJSON json;
    NodeInfo info;
    SoftBusVersion version = SOFTBUS_OLD_V2;
    bool isMetaAuth = true;
    (void)memset_s(&json, sizeof(json), 0, sizeof(json));
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = UnpackWiFi(&json, &info, version, isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: POST_CLOSE_ACK_MESSAGE_TEST_001
 * @tc.desc: post close ack message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, POST_CLOSE_ACK_MESSAGE_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = PostCloseAckMessage(authSeq, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = PostCloseAckMessage(authSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
} // namespace OHOS
