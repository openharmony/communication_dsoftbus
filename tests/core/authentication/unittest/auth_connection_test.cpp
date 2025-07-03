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
    static void OnConnectResult(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo);
    static void OnDisconnected(uint64_t connId, const AuthConnInfo *connInfo);
    static void OnDataReceived(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
        const AuthDataHead *head, const uint8_t *data);
    static bool isOnConnectResultSuccess;
    static bool isOnDisconnectedSuccess;
    static bool isOnDataReceivedSuccess;
};

bool AuthConnectionTest::isOnConnectResultSuccess = false;
bool AuthConnectionTest::isOnDisconnectedSuccess = false;
bool AuthConnectionTest::isOnDataReceivedSuccess = false;

void AuthConnectionTest::SetUpTestCase() { }

void AuthConnectionTest::TearDownTestCase() { }

void AuthConnectionTest::SetUp() { }

void AuthConnectionTest::TearDown() { }

void AuthConnectionTest::OnConnectResult(uint32_t requestId, uint64_t connId, int32_t result,
    const AuthConnInfo *connInfo)
{
    (void)requestId;
    (void)connInfo;
    g_connId = connId;
    isOnConnectResultSuccess = true;
    AUTH_LOGI(AUTH_TEST, "result = %{public}d", result);
}

void AuthConnectionTest::OnDisconnected(uint64_t connId, const AuthConnInfo *connInfo)
{
    (void)connId;
    (void)connInfo;
    isOnDisconnectedSuccess = true;
    AUTH_LOGI(AUTH_TEST, "Auth Connection Disconnected.");
}

void AuthConnectionTest::OnDataReceived(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    (void)connId;
    (void)connInfo;
    (void)fromServer;
    (void)head;
    (void)data;
    isOnDataReceivedSuccess = true;
    AUTH_LOGI(AUTH_TEST, "Receive data.");
}

/*
 * @tc.name: IS_ENHANCE_P2P_MODULE_ID_TEST_001
 * @tc.desc: is enhance P2p moduleId test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, IS_ENHANCE_P2P_MODULE_ID_TEST_001, TestSize.Level1)
{
    ListenerModule moduleId = ListenerModule::AUTH_SESSION_KEY;
    bool ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_FALSE(ret);

    moduleId = ListenerModule::AUTH_P2P;
    ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_FALSE(ret);

    moduleId = ListenerModule::AUTH_ENHANCED_P2P_START;
    ret = IsEnhanceP2pModuleId(moduleId);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: CEN_CONN_ID_TEST_001
 * @tc.desc: generate conn ID test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CEN_CONN_ID_TEST_001, TestSize.Level1)
{
    int32_t connType = 1;
    int32_t id = 1;
    uint64_t ret = GenConnId(connType, id);
    EXPECT_EQ(ret, 0x100000001);
}

/*
 * @tc.name: CET_CONN_TYPE_TEST_001
 * @tc.desc: get conn type test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CET_CONN_TYPE_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0x100000001;
    int32_t ret = GetConnType(connId);
    EXPECT_EQ(ret, 1);
}


/*
 * @tc.name: CET_CONN_TYPE_TEST_001
 * @tc.desc: get conn type str test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CET_CONN_TYPE_STR_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0x100000000;
    const char *str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "wifi/eth");

    connId = 0x200000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "br");

    connId = 0x300000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "ble");

    connId = 0x400000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "p2p");

    connId = 0x500000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "enhanced_p2p");

    connId = 0x800000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "session");

    connId = 0x900000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "session");

    connId = 0xA00000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "sle");

    connId = 0xB00000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "usb");

    connId = 0xC00000000;
    str = GetConnTypeStr(connId);
    EXPECT_STREQ(str, "unknown");
}

/*
 * @tc.name: CET_CONN_TYPE_TEST_001
 * @tc.desc: get conn id test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CET_CONN_ID_TEST_001, TestSize.Level1)
{
    uint64_t connId = 13579;
    int32_t ret = GetConnId(connId);
    EXPECT_EQ(ret, 13579);
}

/*
 * @tc.name: CET_CONN_TYPE_TEST_001
 * @tc.desc: get fd test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CET_FD_TEST_001, TestSize.Level1)
{
    uint64_t connId = 13579;
    int32_t ret = GetFd(connId);
    EXPECT_EQ(ret, 13579);
}

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
 * @tc.name: FIND_CONN_REQUEST_BY_REQUEST_ID_TEST_001
 * @tc.desc: Notify client connected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, NOTIFY_CLIENT_CONNECTED_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    uint64_t connId = 2;
    int32_t result = 3;
    AuthConnInfo connInfo;
    isOnConnectResultSuccess = false;
    NotifyClientConnected(requestId, connId, result, &connInfo);
    EXPECT_FALSE(isOnConnectResultSuccess);

    ConnServerInit();
    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    int32_t ret = AuthConnInit(&connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyClientConnected(requestId, connId, result, &connInfo);
    EXPECT_TRUE(isOnConnectResultSuccess);
    AuthConnDeinit();
    ConnServerDeinit();
}

/*
 * @tc.name: NOTIFY_CLIENT_DISCONNECTED_TEST_001
 * @tc.desc: Notify client disconnected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, NOTIFY_CLIENT_DISCONNECTED_TEST_001, TestSize.Level1)
{
    uint64_t connId = 2;
    AuthConnInfo connInfo;
    isOnDisconnectedSuccess = false;
    NotifyDisconnected(connId, &connInfo);
    EXPECT_FALSE(isOnDisconnectedSuccess);

    ConnServerInit();
    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    int32_t ret = AuthConnInit(&connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDisconnected(connId, &connInfo);
    EXPECT_TRUE(isOnDisconnectedSuccess);
    AuthConnDeinit();
    ConnServerDeinit();
}

/*
 * @tc.name: NOTIFY_DATE_RECEIVED_TEST_001
 * @tc.desc: Notify data received.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, NOTIFY_DATE_RECEIVED_TEST_001, TestSize.Level1)
{
    uint64_t connId = 2;
    AuthConnInfo connInfo;
    AuthDataHead head;
    uint8_t data = 3;
    isOnDataReceivedSuccess = false;
    NotifyDataReceived(connId, &connInfo, true, &head, &data);
    EXPECT_FALSE(isOnDataReceivedSuccess);

    ConnServerInit();
    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    int32_t ret = AuthConnInit(&connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyDataReceived(connId, &connInfo, true, &head, &data);
    EXPECT_TRUE(isOnDataReceivedSuccess);
    AuthConnDeinit();
    ConnServerDeinit();
}

/*
 * @tc.name: GET_AUTH_DATA_SIZE_TEST_001
 * @tc.desc: Get auth data size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, GET_AUTH_DATA_SIZE_TEST_001, TestSize.Level1)
{
    uint32_t len = 10;
    uint32_t ret = GetAuthDataSize(len);
    EXPECT_EQ(ret, 34);
}

/*
 * @tc.name: PACK_AUTH_DATA_TEST_001
 * @tc.desc: Test buffer is not enough while packing auth data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, PACK_AUTH_DATA_TEST_001, TestSize.Level1)
{
    AuthDataHead head;
    (void)memset_s(&head, 0, sizeof(AuthDataHead), 0);
    head.len = TEST_HEAD_LEN;
    uint8_t data[TEST_SIZE] = { 0 };
    uint8_t buf[TEST_SIZE] = { 0 };
    int32_t ret = PackAuthData(nullptr, data, buf, TEST_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PackAuthData(&head, nullptr, buf, TEST_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PackAuthData(&head, data, nullptr, TEST_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PackAuthData(&head, data, buf, TEST_SIZE);
    EXPECT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);

    uint32_t size = 36;
    ret = PackAuthData(&head, data, buf, size);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
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

    uint32_t size = 36;
    buf = UnpackAuthData(data, size, &head);
    EXPECT_EQ(buf, nullptr);

    head.len = TEST_HEAD_LEN;
    buf = UnpackAuthData(data, size, &head);
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
    int32_t ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_USB);
    EXPECT_EQ(ret, SOFTBUS_AUTH_USB_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_WIFI);
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
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_SLE);
    EXPECT_EQ(ret, SOFTBUS_AUTH_SLE_CONN_TIMEOUT);
    ret = GetAuthTimeoutErrCode(AUTH_LINK_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_AUTH_CONN_TIMEOUT);
}

/*
 * @tc.name: IS_SESSION_AUTH_TEST_001
 * @tc.desc: Is session auth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, IS_SESSION_AUTH_TEST_001, TestSize.Level1)
{
    int32_t module = MODULE_SESSION_KEY_AUTH;
    bool ret = IsSessionAuth(module);
    EXPECT_FALSE(ret);

    module = MODULE_SESSION_AUTH;
    ret = IsSessionAuth(module);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IS_SESSION_AUTH_TEST_001
 * @tc.desc: Is session key auth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, IS_SESSION_KEY_AUTH_TEST_001, TestSize.Level1)
{
    int32_t module = MODULE_SESSION_KEY_AUTH;
    bool ret = IsSessionKeyAuth(module);
    EXPECT_TRUE(ret);

    module = MODULE_SESSION_AUTH;
    ret = IsSessionKeyAuth(module);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IS_SESSION_AUTH_TEST_001
 * @tc.desc: Init WiFi conn.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, INIT_WIFI_CONN_TEST_001, TestSize.Level1)
{
    int32_t ret = InitWiFiConn();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_COMM_DISCONNECTED_TEST_001
 * @tc.desc: notify comm disconnected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, ON_COMM_DISCONNECTED_TEST_001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnectionInfo info;
    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    isOnDisconnectedSuccess = false;
    ConnServerInit();
    int32_t ret = AuthConnInit(&connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnCommDisconnected(connectionId, nullptr);
    EXPECT_FALSE(isOnDisconnectedSuccess);

    OnCommDisconnected(connectionId, &info);
    EXPECT_TRUE(isOnDisconnectedSuccess);
    AuthConnDeinit();
    ConnServerDeinit();
}

/*
 * @tc.name: GET_CONN_INFO_BY_CONNECTION_ID_TEST_001
 * @tc.desc: get connInfo by connection id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, GET_CONN_INFO_BY_CONNECTION_ID_TEST_001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    AuthConnInfo connInfo;
    int32_t ret = GetConnInfoByConnectionId(connectionId, &connInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: INIT_COMM_CONN_TEST_001
 * @tc.desc: init comm conn.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, INIT_COMM_CONN_TEST_001, TestSize.Level1)
{
    int32_t ret = InitCommConn();
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthConnDeinit();
}

/*
 * @tc.name: SESSION_CONNECT_SUCC_TEST_001
 * @tc.desc: session connect succ.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, SESSION_CONNECT_SUCC_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthConnInfo connInfo;
    isOnConnectResultSuccess = false;
    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    ConnServerInit();
    int32_t ret = AuthConnInit(&connListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConnectSucc(requestId, &connInfo);
    EXPECT_TRUE(isOnConnectResultSuccess);
    AuthConnDeinit();
    ConnServerDeinit();
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
 * @tc.name: CONNECT_AUT_DEVICE_TEST_005
 * @tc.desc: ConnectAuthDevice success, auth link type is AUTH_LINK_TYPE_WIFI or AUTH_LINK_TYPE_USB.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_005, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connInfo.type = AUTH_LINK_TYPE_USB;
    ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_006
 * @tc.desc: ConnectAuthDevice fail, auth link type is AUTH_LINK_TYPE_BLE or AUTH_LINK_TYPE_SLE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_006, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_AUTH_CONN_FAIL);

    connInfo.type = AUTH_LINK_TYPE_SLE;
    ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
}

/*
 * @tc.name: CONNECT_AUT_DEVICE_TEST_007
 * @tc.desc: ConnectAuthDevice fail, auth link type is AUTH_LINK_TYPE_P2P or AUTH_LINK_TYPE_ENHANCED_P2P.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CONNECT_AUT_DEVICE_TEST_007, TestSize.Level0)
{
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_P2P;
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, PostAuthEvent).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);

    connInfo.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ret = ConnectAuthDevice(TEST_REQUEST_ID, &connInfo, CONN_SIDE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
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
 * @tc.name: IS_AUTH_SESSION_KEY_MODULE_TEST_001
 * @tc.desc: is auth session key module.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, IS_AUTH_SESSION_KEY_MODULE_TEST_001, TestSize.Level1)
{
    AuthDataHead head;
    head.dataType = DATA_TYPE_AUTH;
    bool ret = IsAuthSessionKeyModule(&head);
    EXPECT_TRUE(ret);

    head.dataType = DATA_TYPE_DEVICE_INFO;
    ret = IsAuthSessionKeyModule(&head);
    EXPECT_TRUE(ret);

    head.dataType = DATA_TYPE_DEVICE_ID;
    ret = IsAuthSessionKeyModule(&head);
    EXPECT_TRUE(ret);

    head.dataType = DATA_TYPE_CLOSE_ACK;
    ret = IsAuthSessionKeyModule(&head);
    EXPECT_TRUE(ret);

    head.dataType = DATA_TYPE_UK_CONNECTION;
    ret = IsAuthSessionKeyModule(&head);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: POST_BYTES_FOR_SESSION_KEY_TEST_001
 * @tc.desc: post bytes for sessionKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_BYTES_FOR_SESSION_KEY_TEST_001, TestSize.Level1)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, SocketPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    AuthDataHead head;
    head.dataType = DATA_TYPE_AUTH;
    head.len = TEST_HEAD_LEN;
    int32_t fd = 1;
    uint8_t data = 2;
    int32_t ret = PostBytesForSessionKey(fd, &head, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    head.dataType = DATA_TYPE_UK_CONNECTION;
    ret = IsAuthSessionKeyModule(&head);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: POST_AUTH_DATA_TEST_001
 * @tc.desc: Post auth data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_AUTH_DATA_TEST_001, TestSize.Level1)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, SocketPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    uint64_t connId = 0x100000000;
    bool toServer = true;
    AuthDataHead head;
    head.dataType = DATA_TYPE_AUTH;
    head.len = TEST_HEAD_LEN;
    uint8_t data = 2;
    int32_t ret = PostAuthData(connId, toServer, nullptr, &data);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PostAuthData(connId, toServer, &head, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connId = 0xB00000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connId = 0x200000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);

    connId = 0x300000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);

    connId = 0xA00000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: POST_AUTH_DATA_TEST_002
 * @tc.desc: Post auth data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, POST_AUTH_DATA_TEST_002, TestSize.Level1)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, SocketPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    uint64_t connId = 0x900000000;
    bool toServer = true;
    AuthDataHead head;
    head.dataType = DATA_TYPE_AUTH;
    head.len = TEST_HEAD_LEN;
    uint8_t data = 2;
    int32_t ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connId = 0xC00000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);

    connId = 0x400000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);

    connId = 0x500000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_NE(ret, SOFTBUS_OK);

    connId = 0x800000000;
    ret = PostAuthData(connId, toServer, &head, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GET_CONN_SIDE_TYPE_TEST_001
 * @tc.desc: get conn side type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, GET_CONN_SIDE_TYPE_TEST_001, TestSize.Level1)
{
    uint64_t connId = 0x100000000;
    ConnSideType ret = GetConnSideType(connId);
    EXPECT_EQ(ret, CONN_SIDE_ANY);

    connId = 0xB00000000;
    ret = GetConnSideType(connId);
    EXPECT_EQ(ret, CONN_SIDE_ANY);

    connId = 0x200000000;
    ret = GetConnSideType(connId);
    EXPECT_EQ(ret, CONN_SIDE_ANY);
}

/*
 * @tc.name: CHECK_ACTIVE_AUTH_CONNECTION_TEST_001
 * @tc.desc: check active auth connection.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, CHECK_ACTIVE_AUTH_CONNECTION_TEST_001, TestSize.Level1)
{
    bool ret = CheckActiveAuthConnection(nullptr);
    EXPECT_FALSE(ret);
    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = CheckActiveAuthConnection(nullptr);
    EXPECT_FALSE(ret);
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

/*
 * @tc.name: AUTH_START_LISTENING_TEST_004
 * @tc.desc: Auth start usb listening success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, AUTH_START_LISTENING_TEST_004, TestSize.Level0)
{
    AuthConnectionInterfaceMock mock;
    EXPECT_CALL(mock, StartSocketListening).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = AuthStartListening(AUTH_LINK_TYPE_USB, TEST_IP, TEST_PORT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthStopListening(AUTH_LINK_TYPE_USB);
}

/*
 * @tc.name: AUTH_START_LISTENING_FOR_WIFI_DIRECT_TEST_001
 * @tc.desc: Auth start AUTH_LINK_TYPE_P2P listening.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthConnectionTest, AUTH_START_LISTENING_FOR_WIFI_DIRECT_TEST_001, TestSize.Level0)
{
    AuthLinkType type = AUTH_LINK_TYPE_P2P;
    const char *addr = "192.168.11.44";
    int32_t port = 37025;
    ListenerModule moduleId = ListenerModule::AUTH_P2P;

    int32_t ret = AuthStartListeningForWifiDirect(type, nullptr, port, &moduleId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AuthStartListeningForWifiDirect(type, addr, port, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AuthStartListeningForWifiDirect(type, addr, port, &moduleId);
    EXPECT_NE(ret, SOFTBUS_OK);

    type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ret = AuthStartListeningForWifiDirect(type, addr, port, &moduleId);
    EXPECT_NE(ret, SOFTBUS_OK);

    type = AUTH_LINK_TYPE_WIFI;
    ret = AuthStartListeningForWifiDirect(type, addr, port, &moduleId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}
