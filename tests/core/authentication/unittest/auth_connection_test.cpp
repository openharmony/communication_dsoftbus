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

#include <gtest/gtest.h>
#include <securec.h>

#include "auth_connection.c"
#include "auth_connection_mock.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
const uint32_t TEST_REQUEST_ID = 111;
const uint32_t TEST_SIZE = 32;
const uint32_t TEST_HEAD_LEN = 10;
const uint32_t TEST_DATA_LEN = 20;
const int32_t TEST_FD = 888;
const int32_t TEST_PORT = 1234;
const char TEST_IP[] = "192.168.1.134";
uint64_t g_connId = 0;

class AuthConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static void OnConnectResult(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo)
{
    (void)requestId;
    (void)connInfo;
    g_connId = connId;
    AUTH_LOGI(AUTH_TEST, "result = %{public}d", result);
}

static void OnDisconnected(uint64_t connId, const AuthConnInfo *connInfo)
{
    (void)connId;
    (void)connInfo;
    AUTH_LOGI(AUTH_TEST, "Auth Connection Disconnected.");
}

static void OnDataReceived(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head,
    const uint8_t *data)
{
    (void)connId;
    (void)connInfo;
    (void)fromServer;
    (void)head;
    (void)data;
    AUTH_LOGI(AUTH_TEST, "Receive data.");
}

AuthConnListener g_connListener = {
    .onConnectResult = OnConnectResult,
    .onDisconnected = OnDisconnected,
    .onDataReceived = OnDataReceived,
};

void AuthConnectionTest::SetUpTestCase()
{
    int32_t ret = ConnServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthConnInit(&g_connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void AuthConnectionTest::TearDownTestCase()
{
    AuthConnDeinit();
    ConnServerDeinit();
}

void AuthConnectionTest::SetUp() { }

void AuthConnectionTest::TearDown() { }

/*
 * @tc.name: FIND_CONN_REQUEST_BY_FD_TEST_001
 * @tc.desc: Test finding connection request by unused fd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, FIND_CONN_REQUEST_BY_FD_TEST_001, TestSize.Level1)
{
    ConnRequest *connRequest = FindConnRequestByFd(TEST_FD);
    EXPECT_EQ(connRequest, nullptr);
}

/*
 * @tc.name: FIND_CONN_REQUEST_BY_FD_TEST_002
 * @tc.desc: Test findind connection request by added fd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, FIND_CONN_REQUEST_BY_FD_TEST_002, TestSize.Level1)
{
    AuthConnInfo connInfo;

    int32_t ret = AddConnRequest(&connInfo, TEST_REQUEST_ID, TEST_FD);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnRequest *connRequest = FindConnRequestByFd(TEST_FD);
    EXPECT_NE(connRequest, nullptr);
    ClearConnRequest();
}

/*
 * @tc.name: FIND_CONN_REQUEST_BY_REQUEST_ID_TEST_001
 * @tc.desc: Test finding connection request by nonexisted request id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, FIND_CONN_REQUEST_BY_REQUEST_ID_TEST_001, TestSize.Level1)
{
    ConnRequest *connRequest = FindConnRequestByRequestId(TEST_REQUEST_ID);
    EXPECT_EQ(connRequest, nullptr);
}

/*
 * @tc.name: PACK_AUTH_DATA_TEST_002
 * @tc.desc: Test buffer is not enough while packing auth data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, FIND_CONN_REQUEST_BY_REQUEST_ID_TEST_002, TestSize.Level1)
{
    AuthDataHead head;
    (void)memset_s(&head, 0, sizeof(AuthDataHead), 0);
    head.len = TEST_HEAD_LEN;
    uint8_t data[TEST_SIZE] = { 0 };
    uint8_t buf[TEST_SIZE] = { 0 };
    int32_t ret = PackAuthData(&head, data, buf, TEST_SIZE);
    EXPECT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);
}

/*
 * @tc.name: UNPACK_AUTH_DATA_TEST_001
 * @tc.desc: Test the data length is shorter than head length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, UNPACK_AUTH_DATA_TEST_001, TestSize.Level1)
{
    uint8_t data[TEST_DATA_LEN] = { 0 };
    AuthDataHead head;
    const uint8_t *buf = UnpackAuthData(data, TEST_DATA_LEN, &head);
    EXPECT_EQ(buf, nullptr);
}

/*
 * @tc.name: GET_AUTH_TIMEOUT_ERR_CODE_TEST_001
 * @tc.desc: Test GetAuthTimeoutErrCode return the exact error code according to auth link type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, GET_AUTH_TIMEOUT_ERR_CODE_TEST_001, TestSize.Level1)
{
    int32_t ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_AUTH_WIFI_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_BR);
    EXPECT_EQ(ret, SOFTBUS_AUTH_BR_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_BLE);
    EXPECT_EQ(ret, SOFTBUS_AUTH_BLE_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_P2P);
    EXPECT_EQ(ret, SOFTBUS_AUTH_P2P_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_ENHANCED_P2P);
    EXPECT_EQ(ret, SOFTBUS_AUTH_ENHANCEP2P_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_SESSION_KEY);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SESSION_KEY_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_AUTH_CONN_TIMEOUT);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_001
 * @tc.desc: Mock ble is not enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_001, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_BR;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusGetBtState).WillOnce(Return(BLE_DISABLE));
    EXPECT_CALL(mock, PostAuthEvent).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(1, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_AUTH_CONN_FAIL);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_002
 * @tc.desc: ConnectAuthDevice success, auth link type is AUTH_LINK_TYPE_SESSION.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_002, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_SESSION;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DisconnectAuthDevice(nullptr);
    DisconnectAuthDevice(&g_connId);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_003
 * @tc.desc: ConnectAuthDevice success, auth link type is AUTH_LINK_TYPE_SESSION_KEY.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_003, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_SESSION_KEY;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_004
 * @tc.desc: ConnectAuthDevice success, auth link type is AUTH_LINK_TYPE_MAX.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_004, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_MAX;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: POST_BY_TEST_FOR_SESSION_TEST_001
 * @tc.desc: PostBytesForSession test, data is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_BY_TEST_FOR_SESSION_TEST_001, TestSize.Level0)
{
    AuthDataHead head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    int32_t ret = PostBytesForSession(TEST_FD, &head, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: POST_BY_TEST_FOR_SESSION_TEST_002
 * @tc.desc: Mock SocketPostBytes fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_BY_TEST_FOR_SESSION_TEST_002, TestSize.Level0)
{
    AuthDataHead head;
    uint8_t data[TEST_DATA_LEN] = {0};
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    AuthConnectionInterfaceMock mock;
    int32_t ret = PostBytesForSession(TEST_FD, &head, data);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    head.len = TEST_DATA_LEN;
    EXPECT_CALL(mock, SocketPostBytes).WillOnce(Return(SOFTBUS_AUTH_PACK_SOCKET_PKT_FAIL));
    ret = PostBytesForSession(TEST_FD, &head, data);
    EXPECT_EQ(ret, SOFTBUS_AUTH_PACK_SOCKET_PKT_FAIL);
}

/*
 * @tc.name: POST_BY_TEST_FOR_SESSION_TEST_003
 * @tc.desc: PostBytesForSession success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_BY_TEST_FOR_SESSION_TEST_003, TestSize.Level0)
{
    AuthDataHead head;
    uint8_t data[TEST_DATA_LEN] = {0};
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    head.len = TEST_DATA_LEN;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, SocketPostBytes).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = PostBytesForSession(TEST_FD, &head, data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_START_LISTENING_TEST_001
 * @tc.desc: Auth start wifi listening success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, AUTH_START_LISTENING_TEST_001, TestSize.Level0)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, StartSocketListening).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = AuthStartListening(AUTH_LINK_TYPE_WIFI, TEST_IP, TEST_PORT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthStopListening(AUTH_LINK_TYPE_WIFI);
}

/*
 * @tc.name: AUTH_START_LISTENING_TEST_002
 * @tc.desc: Auth start enhanced p2p listening success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, AUTH_START_LISTENING_TEST_002, TestSize.Level0)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, StartSocketListening).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = AuthStartListening(AUTH_LINK_TYPE_RAW_ENHANCED_P2P, TEST_IP, TEST_PORT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthStopListening(AUTH_LINK_TYPE_RAW_ENHANCED_P2P);
}

/*
 * @tc.name: AUTH_START_LISTENING_TEST_003
 * @tc.desc: Unsupported link type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, AUTH_START_LISTENING_TEST_003, TestSize.Level0)
{
    int32_t ret = AuthStartListening(AUTH_LINK_TYPE_ENHANCED_P2P, TEST_IP, TEST_PORT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    AuthStopListening(AUTH_LINK_TYPE_ENHANCED_P2P);
}
}
