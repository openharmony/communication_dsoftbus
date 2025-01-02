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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_connection.c"
#include "auth_connection.h"
#include "auth_device.c"
#include "auth_interface.c"
#include "auth_interface.h"
#include "auth_lane.c"
#include "auth_log.h"
#include "auth_manager.c"
#include "auth_manager.h"
#include "auth_session_fsm.c"
#include "auth_session_fsm.h"
#include "auth_session_key.c"
#include "auth_session_key.h"
#include "auth_tcp_connection_mock.h"
#include "lnn_connection_mock.h"
#include "lnn_ctrl_lane.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_score.h"
#include "softbus_adapter_json.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
constexpr uint32_t TEST_DATA_LEN = 30;
constexpr uint32_t MSG_LEN = 50;
constexpr char NETWORK_ID[] = "testnetworkid123";

class AuthOtherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthOtherTest::SetUpTestCase()
{
    int32_t ret = AuthCommonInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void AuthOtherTest::TearDownTestCase()
{
    AuthCommonDeinit();
}

void AuthOtherTest::SetUp() { }

void AuthOtherTest::TearDown() { }

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

void OnDataReceivedTest(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
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

void OnDeviceVerifyPassTest(AuthHandle authHandle, const NodeInfo *info)
{
    (void)authHandle;
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
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RemoveFunc(static_cast<void *>(&obj), nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RemoveFunc(static_cast<void *>(&obj), static_cast<void *>(&param));
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
    ret = GetActiveAuthIdByConnInfo(&connInfo, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    AuthHandle authHandle = { .authId = authSeq, .type = AUTH_LINK_TYPE_WIFI };
    RemoveAuthManagerByAuthId(authHandle);
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
    AuthHandle errHandle = { .authId = errAuthId, .type = AUTH_LINK_TYPE_BLE };
    AuthHandle authHandle = { .authId = authId, .type = AUTH_LINK_TYPE_BLE };
    AuthNotifyDeviceVerifyPassed(errHandle, &nodeInfo);
    g_verifyListener.onDeviceVerifyPass = nullptr;
    AuthNotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    g_verifyListener.onDeviceVerifyPass = OnDeviceVerifyPassTest, AuthNotifyDeviceVerifyPassed(authHandle, &nodeInfo);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    info.connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthManager *auth = NewAuthManager(authSeq, &info);
    EXPECT_TRUE(auth != nullptr);
    AuthManagerSetAuthPassed(authSeq, nullptr);
    AuthManagerSetAuthPassed(errAuthId, &info);
    AuthManagerSetAuthPassed(authSeq, &info);
    AuthManagerSetAuthFailed(errAuthId, &info, reason);
    AuthManagerSetAuthFailed(authSeq, &info, reason);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

static void OnConnOpenedTest(uint32_t requestId, AuthHandle authHandle)
{
    AUTH_LOGI(
        AUTH_TEST, "OnConnOpenedTest: requestId=%{public}d, authId=%{public}" PRId64 ".", requestId, authHandle.authId);
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
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedTest,
        .onConnOpenFailed = OnConnOpenFailedTest,
    };
    request.requestId = 1;
    request.connInfo.type = AUTH_LINK_TYPE_BLE;
    request.connCb = cb;
    ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret != 0);
    ret = FindAndDelAuthRequestByConnInfo(requestId, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authId);
    PerformAuthConnCallback(request.requestId, SOFTBUS_NOT_FIND, authId);
    request.connInfo.type = AUTH_LINK_TYPE_WIFI;
    ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret != 0);
    DelAuthRequest(request.requestId);
}

/*
 * @tc.name: UPDATE_AUTH_REQUEST_CONN_INFO_TEST_002
 * @tc.desc: update auth request conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, FIND_AUTH_REQUEST_BY_CONN_INFO_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;
    AuthRequest request;
    int64_t authId = 10;
    uint32_t requestId = 1;
    AuthConnCallback connCb = {
        .onConnOpened = nullptr,
        .onConnOpenFailed = nullptr,
    };

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.requestId = requestId;
    request.connInfo.type = AUTH_LINK_TYPE_BLE;
    request.connCb = connCb;
    int32_t ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret != 0);
    PerformAuthConnCallback(requestId, SOFTBUS_OK, authId);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    request.requestId = 2;
    ret = FindAndDelAuthRequestByConnInfo(request.requestId, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret != 0);
    DelAuthRequest(requestId);
    DelAuthRequest(request.requestId);
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
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RemoveUpdateSessionKeyFunc(&authId, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = RemoveUpdateSessionKeyFunc(&authId, &para);
    EXPECT_NE(ret, SOFTBUS_OK);
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
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_CONN_SIDE_TYPE_TEST_001
 * @tc.desc: get connside type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_CONN_SIDE_TYPE_TEST_001, TestSize.Level1)
{
    LnnConnectInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillRepeatedly(Return(true));
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

    const int32_t SEND_DATA_SIZE_1KB = 1024;
    const char *testData = "{\"data\":\"open session test!!!\"}";
    len = 2;
    moduleId = MODULE_CONNECTION;
    int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1KB, testData, strlen(testData));
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnCommDataReceived(connectionId, moduleId, seq, NULL, len);
    OnCommDataReceived(connectionId, moduleId, seq, data, len);

    free(data);
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
    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
    if (connInfo == NULL) {
        return;
    }
    (void)memset_s(connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo->type = AUTH_LINK_TYPE_BLE;

    AuthDataHead *head = (AuthDataHead *)SoftBusCalloc(sizeof(AuthDataHead));
    if (head == NULL) {
        return;
    }
    (void)memset_s(head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    head->len = strlen(sessionKeyStr);
    const uint8_t data = { 0 };
    bool isServer = false;
    DeviceMessageParse messageParse = { 0 };
    bool ret = IsDeviceMessagePacket(connInfo, head, &data, isServer, &messageParse);
    EXPECT_TRUE(ret == false);
    connInfo->type = AUTH_LINK_TYPE_WIFI;
    ret = IsDeviceMessagePacket(connInfo, head, &data, isServer, &messageParse);
    EXPECT_TRUE(ret == false);
    SoftBusFree(head);
    SoftBusFree(connInfo);
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
    const char *str1 = "RECV_DEVICE_ID";
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
    AuthSessionInfo *info = (AuthSessionInfo *)SoftBusCalloc(sizeof(AuthSessionInfo));
    if (info == NULL) {
        return;
    }
    info->requestId = 1;
    info->isServer = false;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    SessionKey *sessionKey = (SessionKey *)SoftBusCalloc(sizeof(SessionKey));
    if (sessionKey == NULL) {
        return;
    }
    sessionKey->len = 0;
    int32_t ret = AuthManagerSetSessionKey(authSeq, info, sessionKey, false, false);
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
    AuthHandle authHandle = { .authId = 111, .type = AUTH_LINK_TYPE_WIFI };
    AuthDeviceCloseConn(authHandle);
    AuthTransData *dataInfo = (AuthTransData *)SoftBusCalloc(sizeof(AuthTransData));
    if (dataInfo == NULL) {
        return;
    }
    int32_t ret = AuthDevicePostTransData(authHandle, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    dataInfo->module = 1;
    dataInfo->seq = 2;
    dataInfo->flag = 0;
    ret = AuthDevicePostTransData(authHandle, dataInfo);
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
    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
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
    int32_t ret1 = RecoveryFastAuthKey(authFsm);
    EXPECT_TRUE(ret1 != SOFTBUS_OK);
    AuthSessionInfo authSessionInfo;
    authSessionInfo.requestId = 11;
    authSessionInfo.isServer = false;
    authSessionInfo.connInfo.type = AUTH_LINK_TYPE_WIFI;
    const char *udid = "1111";
    (void)strcpy_s(authSessionInfo.udid, UDID_BUF_LEN, udid);
    authFsm->info = authSessionInfo;
    authFsm->authSeq = 512;
    const uint8_t *data = reinterpret_cast<const uint8_t *>(malloc(sizeof(uint8_t)));
    if (data == NULL) {
        SoftBusFree(authFsm);
        return;
    }
    MessagePara *para = NewMessagePara(data, MSG_LEN);
    HandleMsgRecvDeviceInfo(authFsm, para);
    authSessionInfo.isServer = true;
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
    const uint8_t *data = reinterpret_cast<const uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 0;
    int32_t ret = PostMessageToAuthFsm(msgType, authSeq, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    len = MSG_LEN;
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
    AuthFsm *ret = GetAuthFsmByConnId(connId, isServer, false);
    EXPECT_TRUE(ret == NULL);
    int32_t ret1 = AuthSessionHandleDeviceDisconnected(connId, true);
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
    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
    if (connInfo == NULL) {
        return;
    }
    connInfo->type = AUTH_LINK_TYPE_BLE;
    uint32_t requestId = 1;
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    if (nodeInfo == NULL) {
        SoftBusFree(connInfo);
        return;
    }
    int64_t *authId = reinterpret_cast<int64_t *>(malloc(sizeof(int64_t)));
    int32_t ret = AuthRestoreAuthManager(NULL, connInfo, requestId, nodeInfo, authId);
    EXPECT_NE(ret, SOFTBUS_OK);
    const char *udidHash = "1234uuid";
    ret = AuthRestoreAuthManager(udidHash, NULL, requestId, nodeInfo, authId);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, NULL, authId);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, NULL);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, authId);
    EXPECT_NE(ret, SOFTBUS_OK);
    const char *udidHash1 = "testudidhashpass";
    ret = AuthRestoreAuthManager(udidHash1, connInfo, requestId, nodeInfo, authId);
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(connInfo);
    SoftBusFree(nodeInfo);
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
    int32_t ret = GetPeerUdidByNetworkId(networkId, nullptr, UDID_BUF_LEN);
    char udid[UDID_BUF_LEN] = { 0 };
    ret = GetPeerUdidByNetworkId(nullptr, udid, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerUdidByNetworkId(networkId, udid, UDID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: GET_LATEST_ID_BY_CONNINFO_TEST_001
 * @tc.desc: get latest id by connInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_LATEST_ID_BY_CONNINFO_TEST_001, TestSize.Level1)
{
    int64_t ret = GetLatestIdByConnInfo(NULL);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    connInfo->type = AUTH_LINK_TYPE_WIFI;
    const char *ip = "192.168.12.1";
    (void)strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, ip);
    ret = GetLatestIdByConnInfo(connInfo);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    connInfo->type = AUTH_LINK_TYPE_BLE;
    ret = GetLatestIdByConnInfo(connInfo);
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
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = AuthStartReconnectDevice(authHandle, &connInfo, 1, &connCb);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    NodeInfo nodeInfo;
    ReportAuthRequestPassed(11, authHandle, &nodeInfo);
    AuthRequest request;
    uint64_t connId = 10;
    int32_t result = 1;
    HandleReconnectResult(&request, connId, result, 0);
    request.authId = 10;
    request.requestId = 11;
    HandleReconnectResult(&request, connId, result, 0);
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

/*
 * @tc.name: GET_AUTH_CONN_001
 * @tc.desc: get auth conn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, GET_AUTH_CONN_001, TestSize.Level1)
{
    const char *uuid = "testuuid123";

    AuthConnInfo *connInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo));
    ASSERT_TRUE(connInfo != nullptr);

    int32_t ret = GetAuthConn(uuid, LANE_BR, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = GetAuthConn(nullptr, LANE_BR, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    connInfo->type = AUTH_LINK_TYPE_BR;
    ret = GetAuthConn(uuid, LANE_BR, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    connInfo->type = AUTH_LINK_TYPE_BLE;
    ret = GetAuthConn(uuid, LANE_BLE, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    connInfo->type = AUTH_LINK_TYPE_P2P;
    ret = GetAuthConn(uuid, LANE_P2P, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    ret = GetAuthConn(uuid, LANE_HML, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    ret = GetAuthConn(uuid, LANE_WLAN_2P4G, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_NOT_FOUND);

    SoftBusFree(connInfo);
}

/*
 * @tc.name: AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_001
 * @tc.desc: AuthGetAuthHandleByIndex test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_GET_AUTH_HANDLE_BY_INDEX_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo = {
        .info.ipInfo.ip = "192.168.12.1",
        .type = AUTH_LINK_TYPE_WIFI,
    };
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    EXPECT_TRUE(AuthGetAuthHandleByIndex(nullptr, true, 1, &authHandle) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthGetAuthHandleByIndex(&connInfo, true, 1, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthGetAuthHandleByIndex(&connInfo, true, 1, &authHandle) == SOFTBUS_LOCK_ERR);
    char UDID_TEST[UDID_BUF_LEN] = "123456789udidtest";
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, UDID_TEST, strlen(UDID_TEST)) == EOK);
    EXPECT_TRUE(AuthGetAuthHandleByIndex(&connInfo, true, 1, &authHandle) == SOFTBUS_NOT_FIND);
    char BR_MAC[BT_MAC_LEN] = "00:15:5d:de:d4:23";
    connInfo.type = AUTH_LINK_TYPE_BR;
    ASSERT_TRUE(memcpy_s(connInfo.info.brInfo.brMac, BT_MAC_LEN, BR_MAC, strlen(BR_MAC)) == EOK);
    EXPECT_TRUE(AuthGetAuthHandleByIndex(&connInfo, true, 1, &authHandle) == SOFTBUS_LOCK_ERR);
    connInfo.type = AUTH_LINK_TYPE_MAX;
    EXPECT_TRUE(AuthGetAuthHandleByIndex(&connInfo, true, 1, &authHandle) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_CHECK_SESSION_KEY_VALID_BY_CONN_INFO_TEST_001
 * @tc.desc: AuthCheckSessionKeyValidByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_CHECK_SESSION_KEY_VALID_BY_CONN_INFO_TEST_001, TestSize.Level1)
{
    const char *networkId = "123456456";
    AuthConnInfo connInfo;
    EXPECT_TRUE(AuthCheckSessionKeyValidByConnInfo(nullptr, &connInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthCheckSessionKeyValidByConnInfo(networkId, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo) == SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    EXPECT_TRUE(AuthCheckSessionKeyValidByAuthHandle(nullptr) == SOFTBUS_INVALID_PARAM);
    AuthHandle authHandle = {
        .type = AUTH_LINK_TYPE_WIFI,
        .authId = 0,
    };
    EXPECT_TRUE(AuthCheckSessionKeyValidByAuthHandle(&authHandle) == SOFTBUS_AUTH_SESSION_KEY_INVALID);
    authHandle.type = -1;
    AuthTransData dataInfo;
    AuthCloseConn(authHandle);
    EXPECT_TRUE(AuthPostTransData(authHandle, &dataInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthGetConnInfo(authHandle, &connInfo) == SOFTBUS_INVALID_PARAM);
    authHandle.type = AUTH_LINK_TYPE_MAX;
    AuthCloseConn(authHandle);
    EXPECT_TRUE(AuthPostTransData(authHandle, &dataInfo) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthGetConnInfo(authHandle, &connInfo) == SOFTBUS_INVALID_PARAM);
    AuthFreeConn(nullptr);
    AuthFreeConn(&authHandle);
    AuthConnCallback callback;
    EXPECT_TRUE(AuthAllocConn(nullptr, 1, &callback) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthAllocConn(networkId, 1, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthAllocConn(nullptr, 1, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthGetP2pConnInfo(nullptr, nullptr, true) == AUTH_INVALID_ID);
    EXPECT_TRUE(AuthGetHmlConnInfo(nullptr, nullptr, true) == AUTH_INVALID_ID);
    AuthGetLatestIdByUuid(nullptr, AUTH_LINK_TYPE_WIFI, true, nullptr);
    AuthGetLatestIdByUuid(nullptr, AUTH_LINK_TYPE_WIFI, true, &authHandle);
}

/*
 * @tc.name: AUTH_DIRECT_ONLINE_PROCESS_SESSION_KEY_TEST_001
 * @tc.desc: AuthDirectOnlineProcessSessionKey test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_DIRECT_ONLINE_PROCESS_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthDeviceKeyInfo keyInfo = {
        .keyLen = strlen("testKey"),
        .isOldKey = true,
    };
    ASSERT_TRUE(memcpy_s(keyInfo.deviceKey, SESSION_KEY_LENGTH, "testKey", strlen("testKey")) == EOK);
    AuthSessionInfo info = {
        .connInfo.type = AUTH_LINK_TYPE_BR,
    };
    int64_t authId;
    EXPECT_NE(AuthDirectOnlineProcessSessionKey(&info, &keyInfo, &authId), SOFTBUS_OK);
    EXPECT_NE(AuthDirectOnlineWithoutSessionKey(&info, &keyInfo, &authId), SOFTBUS_OK);
    EXPECT_TRUE(AuthEncrypt(nullptr, nullptr, 0, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AuthDecrypt(nullptr, nullptr, 0, nullptr, nullptr) == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IS_SAME_ACCOUNT_DEVICE_TEST_001
 * @tc.desc: IsSameAccountDevice test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, IS_SAME_ACCOUNT_DEVICE_TEST_001, TestSize.Level1)
{
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    uint8_t accountHash[SHA_256_HASH_LEN] = "accounthashtest";
    EXPECT_TRUE(LnnSetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(AuthIsPotentialTrusted(nullptr) == false);
    DeviceInfo device = {
        .devId = "testId",
        .accountHash = "accounthashtest",
    };
    EXPECT_TRUE(AuthIsPotentialTrusted(&device) == true);
    EXPECT_TRUE(IsSameAccountDevice(nullptr) == false);
    EXPECT_TRUE(IsSameAccountDevice(&device) == true);
    EXPECT_TRUE(AuthHasSameAccountGroup() == false);
}

/*
 * @tc.name: FILL_AUTH_SESSION_INFO_TEST_001
 * @tc.desc: FillAuthSessionInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, FILL_AUTH_SESSION_INFO_TEST_001, TestSize.Level1)
{
    AuthSessionInfo info = {
        .connInfo.info.bleInfo.deviceIdHash = "123456789udidhashtest",
    };
    NodeInfo nodeInfo = {
        .authCapacity = 127,
        .uuid = "123456789uuidhashtest",
        .deviceInfo.deviceUdid = "123456789udidtest",
    };
    AuthDeviceKeyInfo keyInfo;
    EXPECT_TRUE(FillAuthSessionInfo(&info, &nodeInfo, &keyInfo, true) == SOFTBUS_OK);
    EXPECT_TRUE(FillAuthSessionInfo(&info, &nodeInfo, &keyInfo, false) == SOFTBUS_OK);
}

/*
 * @tc.name: DEL_AUTH_REQ_INFO_BY_AUTH_HANDLE_TEST_001
 * @tc.desc: DelAuthReqInfoByAuthHandle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, DEL_AUTH_REQ_INFO_BY_AUTH_HANDLE_TEST_001, TestSize.Level1)
{
    InitAuthReqInfo();
    AuthConnCallback authConnCb = {
        .onConnOpened = OnConnOpenedTest,
        .onConnOpenFailed = OnConnOpenFailedTest,
    };
    EXPECT_EQ(AddAuthReqNode(NETWORK_ID, 1, 1, &authConnCb), SOFTBUS_OK);
    EXPECT_EQ(AddAuthReqNode(NETWORK_ID, 2, 2, &authConnCb), SOFTBUS_OK);
    EXPECT_EQ(AddAuthReqNode(NETWORK_ID, 3, 3, &authConnCb), SOFTBUS_OK);
    OnAuthConnOpenedFail(1, -1);
    OnAuthConnOpenedFail(4, -1);
    AuthHandle authHandle = {
        .authId = 2,
        .type = 1,
    };
    AuthFreeLane(&authHandle);
    EXPECT_EQ(DelAuthReqInfoByAuthHandle(&authHandle), SOFTBUS_OK);
    authHandle.type = 0;
    AuthFreeLane(&authHandle);
    EXPECT_EQ(DelAuthReqInfoByAuthHandle(&authHandle), SOFTBUS_OK);
    authHandle.authId = 1;
    AuthFreeLane(&authHandle);
    EXPECT_EQ(DelAuthReqInfoByAuthHandle(&authHandle), SOFTBUS_OK);
    authHandle.authId = 2;
    AuthFreeLane(&authHandle);
    EXPECT_EQ(DelAuthReqInfoByAuthHandle(&authHandle), SOFTBUS_OK);
    DeInitAuthReqInfo();
}

/*
 * @tc.name: IS_ENHANCE_P2P_MODULE_ID_Test_001
 * @tc.desc: IsEnhanceP2pModuleId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, IS_ENHANCE_P2P_MODULE_ID_Test_001, TestSize.Level1)
{
    EXPECT_EQ(IsEnhanceP2pModuleId(AUTH_ENHANCED_P2P_START), true);
    EXPECT_EQ(IsEnhanceP2pModuleId(DIRECT_CHANNEL_SERVER_P2P), false);
    EXPECT_EQ(IsEnhanceP2pModuleId(AUTH_P2P), false);
}

/*
 * @tc.name: AUTH_START_LISTENING_FOR_WIFI_DIRECT_Test_001
 * @tc.desc: AuthStartListeningForWifiDirect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthOtherTest, AUTH_START_LISTENING_FOR_WIFI_DIRECT_Test_001, TestSize.Level1)
{
    AsyncCallDeviceIdReceived(nullptr);
    LnnConnectInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnStopLocalListening).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnStartLocalListening).WillRepeatedly(Return(0));
    AuthStopListeningForWifiDirect(AUTH_LINK_TYPE_P2P, AUTH_ENHANCED_P2P_START);
    AuthDataHead head;
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    OnWiFiDataReceived(PROXY, 0, &head, data);
    OnWiFiDataReceived(AUTH, 0, &head, data);
    OnWiFiDataReceived(AUTH_P2P, 0, &head, data);
    OnWiFiDataReceived(AUTH_RAW_P2P_SERVER, 0, &head, data);
    OnWiFiDataReceived(AUTH_ENHANCED_P2P_START, 0, &head, data);
    const char *ip = "192.138.33.33";
    ListenerModule moduleId;
    (void)memset_s(&moduleId, sizeof(ListenerModule), 0, sizeof(ListenerModule));
    EXPECT_NE(AuthStartListeningForWifiDirect(AUTH_LINK_TYPE_P2P, ip, 37025, &moduleId), SOFTBUS_INVALID_PORT);
    EXPECT_NE(AuthStartListeningForWifiDirect(AUTH_LINK_TYPE_ENHANCED_P2P, ip, 37025, &moduleId), SOFTBUS_INVALID_PORT);
    EXPECT_EQ(AuthStartListeningForWifiDirect(AUTH_LINK_TYPE_WIFI, ip, 37025, &moduleId), SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
