/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "auth_common.h"
#include "auth_common_mock.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_net_ledger_mock.h"
#include "auth_request.h"
#include "lnn_connection_fsm.h"
#include "lnn_connection_mock.h"
#include "lnn_hichain_mock.h"
#include "lnn_map.h"
#include "lnn_socket_mock.h"
#include "message_handler.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

namespace OHOS {
using namespace testing;
using namespace testing::ext;

const AuthConnInfo g_connInfo = {
    .type = AUTH_LINK_TYPE_BR,
    .info.brInfo.brMac = "11:22:33:44:55:66",
    .peerUid = "002",
};
const AuthConnInfo g_connInfo2 = {
    .type = AUTH_LINK_TYPE_P2P,
    .info.brInfo.brMac = "11:22:33:44:55:66",
    .peerUid = "002",
};
uint32_t g_requestId = 88;
const AuthVerifyCallback g_callback = {
    .onVerifyPassed = LnnConnectInterfaceMock::OnVerifyPassed,
    .onVerifyFailed = LnnConnectInterfaceMock::onVerifyFailed,
};

const AuthConnCallback g_connCallback = {
    .onConnOpened = LnnConnectInterfaceMock::onConnOpened,
    .onConnOpenFailed = LnnConnectInterfaceMock::onConnOpenFailed,
};
static const int32_t MILLIS = 15;
static constexpr int32_t DEFALUT_USERID = 100;

class AuthEnhanceMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthEnhanceMockTest::SetUpTestCase()
{
    SetAccessTokenPermission("AuthEnhanceMockTest");
    AuthCommonInit();
}

void AuthEnhanceMockTest::TearDownTestCase()
{
    SoftBusSleepMs(MILLIS);
    AuthCommonDeinit();
}

void AuthEnhanceMockTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthTest start.");
}

void AuthEnhanceMockTest::TearDown() { }

void AuthInitMock(LnnConnectInterfaceMock &connMock, LnnHichainInterfaceMock &hichainMock,
    GroupAuthManager &authManager, DeviceGroupManager &groupManager)
{
    groupManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    authManager.authDevice = LnnHichainInterfaceMock::InvokeAuthDevice;
    groupManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    ON_CALL(connMock, ConnSetConnectCallback(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hichainMock, InitDeviceAuthService()).WillByDefault(Return(0));
    ON_CALL(hichainMock, GetGaInstance()).WillByDefault(Return(&authManager));
    ON_CALL(hichainMock, GetGmInstance()).WillByDefault(Return(&groupManager));
}

/*
 * @tc.name: AUTH_START_LISTENING_Test_001
 * @tc.desc: auth start listening
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, AUTH_START_LISTENING_Test_001, TestSize.Level0)
{
    int32_t port = 5566;
    int32_t ret = AuthStartListening(AUTH_LINK_TYPE_P2P, nullptr, port);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthStartListening(AUTH_LINK_TYPE_P2P, "192.168.78.1", port);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_HICHAIN_START_AUTH_Test_001
 * @tc.desc: hichain start auth
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, AUTH_HICHAIN_START_AUTH_Test_001, TestSize.Level0)
{
    const char *udid = "1111222233334444";
    const char *uid = "8888";
    int64_t authSeq = 5678;
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(hichainMock, GetLnnTriggerInfo(_)).WillByDefault(Return());
    int32_t ret = HichainStartAuth(authSeq, udid, uid, DEFALUT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_INIT_Test_001
 * @tc.desc: auth init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, AUTH_INIT_Test_001, TestSize.Level0)
{
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NiceMock<AuthCommonInterfaceMock> commMock;
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(commMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_START_VERIFY_Test_001
 * @tc.desc: client auth start verify ble
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CLINET_AUTH_START_VERIFY_Test_001, TestSize.Level1)
{
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<AuthCommonInterfaceMock> commMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(commMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ON_CALL(ledgermock, LnnGetLocalStrInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(connMock, ConnConnectDevice(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(commMock, SoftBusGetBtState).WillByDefault(Return(BLE_ENABLE));
    ret = AuthStartVerify(&g_connInfo, g_requestId, &g_callback, AUTH_MODULE_LNN, true);
    SoftBusSleepMs(MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthStartConnVerify(&g_connInfo, g_requestId, &g_connCallback, AUTH_MODULE_TRANS, true);
    SoftBusSleepMs(MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_START_VERIFY_Test_002
 * @tc.desc: client auth start verify wifi
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CLINET_AUTH_START_VERIFY_Test_002, TestSize.Level1)
{
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<AuthCommonInterfaceMock> commMock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(commMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ON_CALL(ledgermock, LnnGetLocalStrInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(connMock, ConnConnectDevice(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(2));
    ON_CALL(socketMock, ConnSetTcpKeepalive(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(socketMock, ConnShutdownSocket(_));
    ret = AuthStartVerify(&g_connInfo2, g_requestId, &g_callback, AUTH_MODULE_LNN, true);
    SoftBusSleepMs(MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AuthStartConnVerify(&g_connInfo2, g_requestId, &g_connCallback, AUTH_MODULE_LNN, true);
    SoftBusSleepMs(MILLIS);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: POST_DEVICEID_001
 * @tc.desc: client auth start verify failed callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CLINET_CONN_FAILED_001, TestSize.Level1)
{
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    NiceMock<AuthCommonInterfaceMock> commMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(commMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ON_CALL(connMock, ConnSetConnectCallback(_, _))
        .WillByDefault(LnnConnectInterfaceMock::ActionofConnSetConnectCallback);
    ON_CALL(ledgermock, LnnGetLocalStrInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(connMock, ConnConnectDevice(_, _, NotNull()))
        .WillByDefault(LnnConnectInterfaceMock::ActionofOnConnectFailed);
    ON_CALL(connMock, ConnPostBytes(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(commMock, SoftBusGetBtState).WillByDefault(Return(BLE_ENABLE));
    ret = AuthStartVerify(&g_connInfo, g_requestId, &g_callback, AUTH_MODULE_LNN, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(MILLIS);
}

/*
 * @tc.name: AUTH_START_VERIFY_Test_003
 * @tc.desc: client auth start verify success callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CLINET_AUTH_START_VERIFY_Test_003, TestSize.Level1)
{
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    NiceMock<AuthCommonInterfaceMock> commMock;
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NodeInfo *info = { 0 };
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ON_CALL(commMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ON_CALL(connMock, ConnSetConnectCallback(_, _))
        .WillByDefault(LnnConnectInterfaceMock::ActionofConnSetConnectCallback);
    ON_CALL(ledgermock, LnnGetLocalStrInfo(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(ledgermock, LnnGetLocalNodeInfo).WillByDefault(Return(info));
    ON_CALL(connMock, ConnConnectDevice(_, _, NotNull()))
        .WillByDefault(LnnConnectInterfaceMock::ActionofOnConnectSuccessed);
    ON_CALL(connMock, ConnPostBytes(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(commMock, SoftBusGetBtState).WillByDefault(Return(BLE_ENABLE));
    ret = AuthStartVerify(&g_connInfo, g_requestId, &g_callback, AUTH_MODULE_LNN, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(MILLIS);
}

/*
 * @tc.name: CHECK_SESSIONKEY_VALID_Test_001
 * @tc.desc: AuthCheckSessionKeyValidByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CHECK_SESSIONKEY_VALID_Test_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_NE(AuthCheckSessionKeyValidByConnInfo(nullptr, &connInfo), SOFTBUS_OK);
    node.authCapacity = BIT_SUPPORT_NORMALIZED_LINK << 1;
    ON_CALL(ledgermock, LnnGetRemoteNodeInfoById(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(node), Return(SOFTBUS_OK)));
    EXPECT_NE(AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo), SOFTBUS_OK);
}

/*
 * @tc.name: CHECK_SESSIONKEY_VALID_Test_002
 * @tc.desc: AuthCheckSessionKeyValidByConnInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CHECK_SESSIONKEY_VALID_Test_002, TestSize.Level1)
{
    char udidHash[UDID_HASH_LEN] = { 0 };
    int64_t authSeq = 1;
    int32_t keyLen = 32;
    AuthSessionInfo info;
    AuthConnInfo connInfo;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(info.connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) == EOK);
    EXPECT_EQ(AuthDirectOnlineCreateAuthManager(authSeq, &info), SOFTBUS_OK);

    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    node.authCapacity = BIT_SUPPORT_NORMALIZED_LINK << 1;
    ON_CALL(ledgermock, LnnGetRemoteNodeInfoById(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(node), Return(SOFTBUS_OK)));
    EXPECT_EQ(AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo), SOFTBUS_AUTH_SESSION_KEY_INVALID);
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    sessionKey.len = keyLen;
    EXPECT_EQ(AuthManagerSetSessionKey(authSeq, &info, &sessionKey, true, false), SOFTBUS_OK);
    EXPECT_EQ(AuthCheckSessionKeyValidByConnInfo(networkId, &connInfo), SOFTBUS_OK);
}

/*
 * @tc.name: CHECK_SESSION_KEY_VALID_BY_AUTH_HANDLE_Test_001
 * @tc.desc: AuthCheckSessionKeyValidByAuthHandle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthEnhanceMockTest, CHECK_SESSION_KEY_VALID_BY_AUTH_HANDLE_Test_001, TestSize.Level1)
{
    char udidHash[UDID_HASH_LEN] = { 0 };
    int64_t authSeq = 1;
    int32_t keyLen = 32;
    AuthSessionInfo info;
    AuthConnInfo connInfo;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ASSERT_TRUE(memcpy_s(info.connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) == EOK);
    ASSERT_TRUE(memcpy_s(connInfo.info.bleInfo.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) == EOK);
    EXPECT_EQ(AuthDirectOnlineCreateAuthManager(authSeq, &info), SOFTBUS_OK);
    AuthHandle authHandle = { .authId = authSeq, .type = connInfo.type };
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    sessionKey.len = keyLen;
    EXPECT_EQ(AuthManagerSetSessionKey(authSeq, &info, &sessionKey, true, false), SOFTBUS_OK);
    EXPECT_EQ(AuthCheckSessionKeyValidByAuthHandle(&authHandle), SOFTBUS_OK);
}
} // namespace OHOS
