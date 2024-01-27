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
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_manager.c"
#include "auth_session_fsm.h"
#include "auth_session_fsm.c"
#include "auth_session_key.h"
#include "auth_session_key.c"
#include "auth_session_message.h"
#include "auth_session_message.c"
#include "softbus_errcode.h"
#include "softbus_adapter_json.h"
#include "softbus_socket.h"
#include "lnn_lane_score.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 30;
constexpr uint32_t BLE_CONNID = 196609;
constexpr uint32_t BR_CONNID = 65570;
constexpr uint32_t WIFI_CONNID = 131073;

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
    HandleConnConnectCmd(reinterpret_cast<void *>(&info));
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    HandleConnConnectCmd(reinterpret_cast<void *>(&info));
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
    HandleConnConnectResult(reinterpret_cast<void *>(&para));
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
    OnWiFiDataReceived(AUTH, fd, nullptr, data);
    OnWiFiDataReceived(AUTH, fd, &head, nullptr);
    OnWiFiDataReceived(AUTH, fd, &head, data);
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
    AuthDataHead head;

    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    OnWiFiConnected(AUTH, fd, false);
    OnWiFiConnected(AUTH, fd, true);
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


static void OnConnOpenedTest(uint32_t requestId, int64_t authId)
{
    AUTH_LOGI(AUTH_TEST, "OnConnOpenedTest: requestId=%{public}d, authId=%{public}" PRId64 ".", requestId, authId);
}

static void OnConnOpenFailedTest(uint32_t requestId, int32_t reason)
{
    AUTH_LOGI(AUTH_TEST, "OnConnOpenFailedTest: requestId=%{public}d, reason=%{public}d.", requestId, reason);
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
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);
    connInfo.type = AUTH_LINK_TYPE_BR;
    ret = AuthDeviceOpenConn(&connInfo, requestId, &cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    uint32_t requestId = 1;
    ret = GetAuthRequestNoLock(requestId, &request);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    ret = FindAndDelAuthRequestByConnInfo(requestId, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    int32_t result = 1;
    int64_t authId = 10;
    PerformAuthConnCallback(requestId, result, authId);
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
    int32_t ret = RemoveUpdateSessionKeyFunc(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RemoveUpdateSessionKeyFunc(&authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RemoveUpdateSessionKeyFunc(&authId, &para);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RemoveUpdateSessionKeyFunc(&authId, &authId);
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
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: PACK_AUTH_DATA_TEST_001
 * @tc.desc: pack auth data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, PACK_AUTH_DATA_TEST_001, TestSize.Level1)
{
    AuthDataHead head;
    uint8_t *buf = NULL;
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = 32;

    (void)memset_s(&head, sizeof(AuthDataHead), AUTH_CONN_DATA_HEAD_SIZE, sizeof(AuthDataHead));
    int32_t ret = PackAuthData(&head, data, buf, len);
    EXPECT_TRUE(ret == SOFTBUS_NO_ENOUGH_DATA);
}

/*
 * @tc.name: ON_COMM_DATA_RECEIVED_TEST_001
 * @tc.desc: on commdata received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_COMM_DATA_RECEIVED_TEST_001, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnModule moduleId = MODULE_DEVICE_AUTH;
    int64_t seq = 0;
    char *data = reinterpret_cast<char *>(malloc(1024));
    const int SEND_DATA_SIZE_1KB = 1024;
    ASSERT_NE(data, nullptr);
    const char *testData = "{\"data\":\"open session test!!!\"}";
    int32_t len = 2;
    int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1KB, testData, strlen(testData));
    EXPECT_EQ(ret, SOFTBUS_OK);

    OnCommDataReceived(connectionId, moduleId, seq, NULL, len);
    OnCommDataReceived(connectionId, moduleId, seq, data, len);
    free(data);
}

/*
 * @tc.name: GET_CONN_SIDE_TYPE_TEST_001
 * @tc.desc: get connside type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_CONN_SIDE_TYPE_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    connId = GetConnType(connId);
    ConnSideType ret = GetConnSideType(connId);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
    ret = GetConnSideType(0x1FFFFFFFF);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
    ret = GetConnSideType(0x2FFFFFFFF);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
    ret = GetConnSideType(0x3FFFFFFFF);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
    ret = GetConnSideType(0x4FFFFFFFF);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
}

/*
 * @tc.name: PACK_FAST_AUTH_VALUE_TEST_001
 * @tc.desc: Pack fast auth value test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, PACK_FAST_AUTH_VALUE_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo deviceCommKey = {0};
    JsonObj *obj = JSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    uint32_t keyLen = 0;
    deviceCommKey.keyLen = keyLen;
    uint64_t ret = PackFastAuthValue(obj, &deviceCommKey);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    JSON_Delete(obj);
}

/*
 * @tc.name: NOTIFY_DATE_RECEIVED_TEST_001
 * @tc.desc: notify data received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, NOTIFY_DATE_RECEIVED_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    const AuthConnInfo *connInfo = NULL;
    bool fromServer = false;
    const AuthDataHead *head = NULL;
    const uint8_t *data = NULL;
    NotifyDataReceived(connId, connInfo, fromServer, head, data);
}

/*
 * @tc.name: ON_COMM_DATA_RECEVIED_TEST_001
 * @tc.desc: on comm data received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, ON_COMM_DATA_RECEVIED_TEST_001, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnModule moduleId = MODULE_DEVICE_AUTH;
    int64_t seq = 0;
    int32_t len = 0;
    char *data = reinterpret_cast<char *>(malloc(1024));
    ASSERT_NE(data, nullptr);
    OnCommDataReceived(connectionId, moduleId, seq, data, len);

    const int SEND_DATA_SIZE_1KB = 1024;
    const char *testData = "{\"data\":\"open session test!!!\"}";
    len = 2;
    moduleId = MODULE_CONNECTION;
    int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1KB, testData, strlen(testData));
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnCommDataReceived(connectionId, moduleId, seq, data, len);

    free(data);
}

/*
 * @tc.name: UPDATE_AUTH_DEVICE_PRIORITY_TEST_001
 * @tc.desc: update auth device priority test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UPDATE_AUTH_DEVICE_PRIORITY_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0;
    UpdateAuthDevicePriority(connId);
    connId = 0x3FFFFFFFF;
    UpdateAuthDevicePriority(connId);
}

/*
 * @tc.name: UPDATE_AUTH_DEVICE_PRIORITY_TEST_002
 * @tc.desc: update auth device priority test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, UPDATE_AUTH_DEVICE_PRIORITY_TEST_002, TestSize.Level1)
{
    UpdateAuthDevicePriority(BLE_CONNID);
    UpdateAuthDevicePriority(BR_CONNID);
    UpdateAuthDevicePriority(WIFI_CONNID);
}

/*
 * @tc.name: CHECK_BUS_VERSION_TEST_001
 * @tc.desc: check bus version test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, CHECK_BUS_VERSION_TEST_001, TestSize.Level1)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        return;
    }

    NodeInfo *info = (NodeInfo*)SoftBusCalloc(sizeof(NodeInfo));
    if (info == NULL) {
        JSON_Delete(obj);
        return;
    }
    (void)memset_s(info, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    SoftBusVersion version = SOFTBUS_NEW_V1;
    ASSERT_NE(obj, NULL);
    if (!JSON_AddInt32ToObject(obj, "CODE", (int32_t)1) ||
        !JSON_AddInt32ToObject(obj, "BUS_MAX_VERSION", (int32_t)2) ||
        !JSON_AddInt32ToObject(obj, "BUS_MIN_VERSION", (int32_t)1) ||
        !JSON_AddInt32ToObject(obj, "AUTH_PORT", (int32_t)8710) ||
        !JSON_AddInt32ToObject(obj, "SESSION_PORT", (int32_t)26) ||
        !JSON_AddInt32ToObject(obj, "PROXY_PORT", (int32_t)80) ||
        !JSON_AddStringToObject(obj, "DEV_IP", "127.0.0.1")) {
        JSON_Delete(obj);
        return;
    }
    JSON_AddStringToObject(obj, BLE_OFFLINE_CODE, "10244");

    info->connectInfo.authPort = 8710;
    info->connectInfo.sessionPort = 26;
    info->connectInfo.proxyPort = 80;
    info->supportedProtocols = LNN_PROTOCOL_BR;
    
    int32_t ret = UnpackWiFi(obj, info, version, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    JSON_AddInt32ToObject(obj, "BUS_MAX_VERSION", (int32_t)-1);
    ret = UnpackWiFi(obj, info, version, false);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)JSON_AddStringToObject(obj, "BROADCAST_CIPHER_KEY", "1222222222");
    (void)JSON_AddStringToObject(obj, "BROADCAST_CIPHER_IV", "1222222222");
    (void)JSON_AddStringToObject(obj, "IRK", "1222222222");
    (void)JSON_AddStringToObject(obj, "PUB_MAC", "1222222222");

    JSON_AddStringToObject(obj, "MASTER_UDID", "1122334554444");
    JSON_AddStringToObject(obj, "NODE_ADDR", "1122334554444");
    UnpackCommon(obj, info, version, false);
    version = SOFTBUS_OLD_V1;
    JSON_AddInt32ToObject(obj, "MASTER_WEIGHT", (int32_t)10);
    UnpackCommon(obj, info, version, true);
    UnpackCipherRpaInfo(obj, info);
    JSON_Delete(obj);
    SoftBusFree(info);
}

/*
 * @tc.name: IS_FLUSH_DEVICE_PACKET_TEST_001
 * @tc.desc: is flush device packet test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, IS_FLUSH_DEVICE_PACKET_TEST_001, TestSize.Level1)
{
    const char *sessionKeyStr = "www.test.com";
    AuthConnInfo *connInfo = (AuthConnInfo*)SoftBusCalloc(sizeof(AuthConnInfo));
    if (connInfo == NULL) {
        return;
    }
    (void)memset_s(connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo->type = AUTH_LINK_TYPE_BLE;

    AuthDataHead *head = (AuthDataHead*)SoftBusCalloc(sizeof(AuthDataHead));
    if (head == NULL) {
        return;
    }
    (void)memset_s(head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    head->len = strlen(sessionKeyStr);
    const uint8_t data = {0};
    bool isServer = false;
    bool ret = IsFlushDevicePacket(connInfo, head, &data, isServer);
    EXPECT_TRUE(ret == false);
    connInfo->type = AUTH_LINK_TYPE_WIFI;
    ret = IsFlushDevicePacket(connInfo, head, &data, isServer);
    EXPECT_TRUE(ret == false);
    SoftBusFree(head);
    SoftBusFree(connInfo);
}

/*
 * @tc.name: POST_BT_V1_DEVID_TEST_001
 * @tc.desc: post bt v1 devid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, POST_BT_V1_DEVID_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo *info = (AuthSessionInfo*)SoftBusCalloc(sizeof(AuthSessionInfo));
    if (info == NULL) {
        return;
    }
    info->requestId = 1;
    info->connId = 1;
    info->isServer = false;
    info->version = SOFTBUS_NEW_V1;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    int32_t ret = PostDeviceIdV1(authSeq, info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    FsmStateMachine *fsm = NULL;
    AuthFsmDeinitCallback(fsm);
    SoftBusFree(info);
}

/*
 * @tc.name: FSM_MSG_TYPE_TO_STR_TEST_001
 * @tc.desc: fsm msg type to str test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, FSM_MSG_TYPE_TO_STR_TEST_001, TestSize.Level1)
{
    int32_t type = FSM_MSG_UNKNOWN;
    const char *str = "UNKNOWN MSG!!";
    char *ret = FsmMsgTypeToStr(type);
    EXPECT_EQ(ret, str);
    type = -1;
    ret = FsmMsgTypeToStr(type);
    EXPECT_EQ(ret, str);
    type = FSM_MSG_RECV_DEVICE_ID;
    ret = FsmMsgTypeToStr(type);
    const char *str1= "RECV_DEVICE_ID";
    EXPECT_EQ(ret, str1);
}

/*
 * @tc.name: AUTH_MANAGER_SET_SESSION_KEY_TEST_001
 * @tc.desc: fsm msg type to str test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_MANAGER_SET_SESSION_KEY_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo *info = (AuthSessionInfo*)SoftBusCalloc(sizeof(AuthSessionInfo));
    if (info == NULL) {
        return;
    }
    info->requestId = 1;
    info->isServer = false;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    SessionKey *sessionKey = (SessionKey*)SoftBusCalloc(sizeof(SessionKey));
    if (info == NULL) {
        return;
    }
    sessionKey->len = 0;
    int32_t ret = AuthManagerSetSessionKey(authSeq, info, sessionKey, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthManagerGetSessionKey(authSeq, info, sessionKey);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    AuthManagerSetAuthPassed(authSeq, info);
    AuthManagerSetAuthFinished(authSeq, info);
    info->isServer = true;
    info->connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthManagerSetAuthFinished(authSeq, info);
    SoftBusFree(sessionKey);
    SoftBusFree(info);
}

/*
 * @tc.name: AUTH_DEVICE_CLOSE_CONN_TEST_001
 * @tc.desc: fsm msg type to str test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_DEVICE_CLOSE_CONN_TEST_001, TestSize.Level1)
{
    int64_t authId = 111;
    AuthDeviceCloseConn(authId);
    AuthTransData *dataInfo = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    if (dataInfo == NULL) {
        return;
    }
    int32_t ret = AuthDevicePostTransData(authId, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    dataInfo->module = 1;
    dataInfo->seq = 2;
    dataInfo->flag = 0;
    ret = AuthDevicePostTransData(authId, dataInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);
    SoftBusFree(dataInfo);
}

/*
 * @tc.name: AUTH_DEVICE_GET_PREFER_CONN_INFO_TEST_001
 * @tc.desc: fsm msg type to str test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_DEVICE_GET_PREFER_CONN_INFO_TEST_001, TestSize.Level1)
{
    const char *uuid = "";
    int32_t ret = AuthDeviceGetPreferConnInfo(uuid, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    AuthConnInfo *connInfo =(AuthConnInfo*)SoftBusCalloc(sizeof(AuthConnInfo));
    if (connInfo == NULL) {
        return;
    }
    ret = AuthDeviceGetPreferConnInfo(NULL, connInfo);
    connInfo->type = AUTH_LINK_TYPE_BLE;
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(connInfo); 
}

/*
 * @tc.name: AUTH_DEVICE_CHECK_CONN_INFO_TEST_001
 * @tc.desc: fsm msg type to str test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_DEVICE_CHECK_CONN_INFO_TEST_001, TestSize.Level1)
{
    const char *uuid = "test66";
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    bool checkConnection = false;
    bool ret = AuthDeviceCheckConnInfo(uuid, type, checkConnection);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: CONVERT_AUTH_LINK_TYPE_TO_HISYSEVENT_LINKTYPE_TEST_001
 * @tc.desc: sync deviceInfo state process test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, CONVERT_AUTH_LINK_TYPE_TO_HISYSEVENT_LINKTYPE_TEST_001, TestSize.Level1)
{
    AuthFsm *authFsm = (AuthFsm *)SoftBusCalloc(sizeof(AuthFsm));
    ASSERT_TRUE(authFsm != nullptr);
    authFsm->info.connInfo.type = (AuthLinkType)(AUTH_LINK_TYPE_WIFI - 1);
    ReportAuthResultEvt(authFsm, 0);

    authFsm->info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    SoftBusLinkType ret = ConvertAuthLinkTypeToHisysEvtLinkType(AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(ret == SOFTBUS_HISYSEVT_LINK_TYPE_WLAN);

    authFsm->info.connInfo.type = AUTH_LINK_TYPE_BR;
    ret = ConvertAuthLinkTypeToHisysEvtLinkType(AUTH_LINK_TYPE_BR);
    EXPECT_TRUE(ret == SOFTBUS_HISYSEVT_LINK_TYPE_BR);

    authFsm->info.connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = ConvertAuthLinkTypeToHisysEvtLinkType(AUTH_LINK_TYPE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_HISYSEVT_LINK_TYPE_BLE);

    authFsm->info.connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConvertAuthLinkTypeToHisysEvtLinkType(AUTH_LINK_TYPE_P2P);
    EXPECT_TRUE(ret == SOFTBUS_HISYSEVT_LINK_TYPE_P2P);

    ReportAuthResultEvt(authFsm, SOFTBUS_AUTH_SEND_FAIL);
    ReportAuthResultEvt(authFsm, SOFTBUS_AUTH_DEVICE_DISCONNECTED);
    ReportAuthResultEvt(authFsm, SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL);
    ReportAuthResultEvt(authFsm, 11);
    int32_t  ret1 = RecoveryDeviceKey(authFsm);
    EXPECT_TRUE(ret1 != SOFTBUS_OK);
    AuthSessionInfo authSessionInfo;
    authSessionInfo.requestId = 11;
    authSessionInfo.isServer= false;
    authSessionInfo.connInfo.type = AUTH_LINK_TYPE_WIFI;
    const char *udid = "1111";
    (void)strcpy_s(authSessionInfo.udid, UDID_BUF_LEN, udid);
    authFsm->info = authSessionInfo;
    authFsm->authSeq = 512;
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    MessagePara *para = NewMessagePara(data, 1024);
    HandleMsgRecvDeviceInfo(authFsm, para);
    authSessionInfo.isServer= true;
    HandleMsgRecvDeviceInfo(authFsm, para);
    SoftBusFree(authFsm);
}

/*
 * @tc.name: POST_MESSAGE_TO_AUTH_FSM_TEST_001
 * @tc.desc: post message to auth fsm test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, POST_MESSAGE_TO_AUTH_FSM_TEST_001, TestSize.Level1)
{
    int32_t msgType = 1;
    int64_t authSeq = 0;
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 0;
    int32_t ret = PostMessageToAuthFsm(msgType, authSeq, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    len = 1024;
    ret = PostMessageToAuthFsm(msgType, authSeq, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_FSM_TEST_001
 * @tc.desc: authSession handle device disconnected test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_FSM_TEST_001, TestSize.Level1)
{
    uint64_t connId = 111;
    bool isServer = true;
    AuthFsm* ret = GetAuthFsmByConnId(connId, isServer);
    EXPECT_TRUE(ret == NULL);
    int32_t ret1 = AuthSessionHandleDeviceDisconnected(connId);
    EXPECT_TRUE(ret1 == SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_RESTORE_MANAGER_TEST_001
 * @tc.desc: authRestore authManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_RESTORE_MANAGER_TEST_001, TestSize.Level1)
{
    AuthConnInfo *connInfo =(AuthConnInfo*)SoftBusCalloc(sizeof(AuthConnInfo));
    if (connInfo == NULL) {
        return;
    }
    connInfo->type = AUTH_LINK_TYPE_BLE;
    uint32_t requestId = 1;
    NodeInfo *nodeInfo = (NodeInfo*)SoftBusCalloc(sizeof(NodeInfo));
    ASSERT_TRUE(nodeInfo != nullptr);
    int64_t *authId = (int64_t *)malloc(sizeof(int64_t));
    int32_t ret = AuthRestoreAuthManager(NULL, connInfo, requestId, nodeInfo, authId);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    const char *udidHash = "1234uuid";
    ret = AuthRestoreAuthManager(udidHash, NULL, requestId, nodeInfo, authId);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, NULL, authId);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, NULL);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, authId);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    const char *udidHash1 = "testudidhashpass";
    ret = AuthRestoreAuthManager(udidHash1, connInfo, requestId, nodeInfo, authId);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    SoftBusFree(connInfo);
    SoftBusFree(nodeInfo);
}

/*
 * @tc.name: COMPLEMENT_CONNECTION_INFO_TEST_001
 * @tc.desc: complement connectionInfo ifNeed test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, COMPLEMENT_CONNECTION_INFO_TEST_001, TestSize.Level1)
{
    AuthManager *auth = (AuthManager*)SoftBusCalloc(sizeof(AuthManager));
    ASSERT_TRUE(auth != nullptr);
    auth->connInfo.type = AUTH_LINK_TYPE_P2P;

    int32_t ret = ComplementConnectionInfoIfNeed(auth, "test");
    EXPECT_TRUE(ret == SOFTBUS_OK);

    auth->connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = ComplementConnectionInfoIfNeed(auth, "");
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    
    ret = ComplementConnectionInfoIfNeed(auth, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: COVERT_AUTH_LINKTYPE_TO_CONNECT_TEST_001
 * @tc.desc: Convert authLinkType to connect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, COVERT_AUTH_LINKTYPE_TO_CONNECT_TEST_001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    ConnectionAddrType ret = ConvertAuthLinkTypeToConnect(type);
    EXPECT_TRUE(ret == CONNECTION_ADDR_WLAN);
    type = AUTH_LINK_TYPE_BLE;
    ret = ConvertAuthLinkTypeToConnect(type);
    EXPECT_TRUE(ret == CONNECTION_ADDR_BLE);
    type = AUTH_LINK_TYPE_BR;
    ret = ConvertAuthLinkTypeToConnect(type);
    EXPECT_TRUE(ret == CONNECTION_ADDR_BR);
}

/*
 * @tc.name: GET_PEER_UDID_BY_NETWORK_ID_TEST_001
 * @tc.desc: get peer udid by networkId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_PEER_UDID_BY_NETWORK_ID_TEST_001, TestSize.Level1)
{
    const char *networkId = "testudid";
    int32_t ret = GetPeerUdidByNetworkId(networkId, NULL);
    char udid[UDID_BUF_LEN] = {0};
    ret = GetPeerUdidByNetworkId(NULL, udid);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = GetPeerUdidByNetworkId(networkId, udid);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: GET_LATEST_ID_BY_CONNINFO_TEST_001
 * @tc.desc: get latest id by connInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_LATEST_ID_BY_CONNINFO_TEST_001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    int64_t ret = GetLatestIdByConnInfo(NULL, type);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    connInfo->type = AUTH_LINK_TYPE_WIFI;
    const char *ip = "192.168.12.1";
    (void)strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, ip);
    ret = GetLatestIdByConnInfo(connInfo, type);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    type = AUTH_LINK_TYPE_BLE;
    ret = GetLatestIdByConnInfo(connInfo, type);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    SoftBusFree(connInfo);
}

/*
 * @tc.name: START_RECONNECT_DEVICE_TEST_001
 * @tc.desc: start reconnection device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, START_RECONNECT_DEVICE_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthConnCallback connCb;
    int32_t ret = StartReconnectDevice(1, &connInfo, 1, &connCb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    NodeInfo nodeInfo;
    ReportAuthRequestPassed(11, 1, &nodeInfo);
    AuthRequest request;
    uint64_t connId = 10;
    int32_t result = 1;
    HandleReconnectResult(&request, connId, result);
    request.authId = 10;
    request.requestId = 11;
    HandleReconnectResult(&request, connId, result);
}

/*
 * @tc.name: AUTH_GET_LATEST_AUTHSEQ_LIST_TEST_001
 * @tc.desc: auth get latest authsed list test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_GET_LATEST_AUTHSEQ_LIST_TEST_001, TestSize.Level1)
{
    int64_t seqList = 1024;
    uint32_t num = 1;
    int32_t ret = AuthGetLatestAuthSeqList(NULL, &seqList, num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *udid = "";
    ret = AuthGetLatestAuthSeqList(udid, &seqList, num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    const char *udid1 = "11";
    ret = AuthGetLatestAuthSeqList(udid1, NULL, num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetLatestAuthSeqList(udid1, &seqList, num);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    num = DISCOVERY_TYPE_COUNT;
    ret = AuthGetLatestAuthSeqList(udid1, &seqList, num);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);
    
    AuthConnInfo connInfo;
    AuthDataHead head;
    uint8_t data = 1;
    head.flag = 0;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    uint64_t connId = 11;
    HandleDeviceInfoData(connId, &connInfo, false, &head, &data);
    head.flag = 1;
    HandleDeviceInfoData(connId, &connInfo, false, &head, &data);
}


/*
 * @tc.name: SYNC_DEVINFO_STATE_PROCESS_TEST_001
 * @tc.desc: sync deviceInfo state process test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, SYNC_DEVINFO_STATE_PROCESS_TEST_001, TestSize.Level1)
{
    FsmStateMachine *fsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(fsm != nullptr);
    int32_t msgType = 1;
    bool ret = SyncDevInfoStateProcess(fsm, msgType, NULL);
    EXPECT_TRUE(ret == false);
    SoftBusFree(fsm);
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    testFsm->flag = 1;

    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    EXPECT_TRUE(ret == false);

    msgType = FSM_MSG_AUTH_TIMEOUT;
    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    msgType = FSM_MSG_RECV_DEVICE_INFO;
    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    EXPECT_TRUE(ret == false);

    msgType = FSM_MSG_RECV_CLOSE_ACK;
    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    EXPECT_TRUE(ret == false);

    msgType = FSM_MSG_RECV_AUTH_DATA;
    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    EXPECT_TRUE(ret == false);
    
    msgType = FSM_MSG_AUTH_FINISH;
    ret = SyncDevInfoStateProcess(testFsm, msgType, NULL);
    EXPECT_TRUE(ret == false);
    SoftBusFree(testFsm);
}
} // namespace OHOS
