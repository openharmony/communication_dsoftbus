/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "message_handler.h"
#include "softbus_feature_config.h"
#include "trans_auth_negotiation.c"
#include "trans_manager_mock.h"
#include "trans_session_service.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
#define TRANS_TEST_INVALID_AUTH_REQUEST_ID (0)
#define TRANS_TEST_AUTH_REQUEST_ID (1)
#define TRANS_TEST_CHANNEL_ID  2
#define CONNECTION_ID 1
#define SOFTBUS_PORT 50002

class TransAuthNegotiateTest : public testing::Test {
public:
    TransAuthNegotiateTest()
    {}
    ~TransAuthNegotiateTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthNegotiateTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    (void)LooperInit();
    (void)ConnServerInit();
    (void)TransProxyTransInit();
    (void)TransServerInit();
    (void)TransReqAuthPendingInit();
}

void TransAuthNegotiateTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    TransServerDeinit();
    TransReqAuthPendingDeinit();
}

/**
 * @tc.name: TransAuthPendingTest001
 * @tc.desc: Use the wrong parameter and legal parameter to test TransAddAuthReqToPendingList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest001, TestSize.Level1)
{
    int32_t ret = TransAddAuthReqToPendingList(TRANS_TEST_INVALID_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest002
 * @tc.desc: Use the wrong parameter and legal parameter to test TransUpdateAuthInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest002, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t ret = TransUpdateAuthInfo(TRANS_TEST_INVALID_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND, ret);

    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest003
 * @tc.desc: Use the wrong parameter and legal parameter to test TransCheckAuthNegoStatusByReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest003, TestSize.Level1)
{
    bool isFinished = false;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t cnt = 0;
    int32_t ret = TransCheckAuthNegoStatusByReqId(TRANS_TEST_AUTH_REQUEST_ID, &isFinished, &errCode, &cnt);
    EXPECT_EQ(SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND, ret);

    errCode = SOFTBUS_OK;
    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransCheckAuthNegoStatusByReqId(TRANS_TEST_AUTH_REQUEST_ID, &isFinished, &errCode, &cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(true, isFinished);
    EXPECT_EQ(SOFTBUS_OK, errCode);
    EXPECT_EQ(1, cnt);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest004
 * @tc.desc: Use the wrong parameter and legal parameter to test WaitingForAuthNegoToBeDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = WaitingForAuthNegoToBeDone(TRANS_TEST_INVALID_AUTH_REQUEST_ID, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = WaitingForAuthNegoToBeDone(TRANS_TEST_AUTH_REQUEST_ID, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest005
 * @tc.desc: Use the wrong parameter to test TransNegotiateSessionKey and TransReNegotiateSessionKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest005, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t channelId = 1;
    char peerNetworkId[DEVICE_ID_SIZE_MAX] = { 0 };
    int32_t ret = TransNegotiateSessionKey(nullptr, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNegotiateSessionKey(&authConnInfo, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNegotiateSessionKey(nullptr, channelId, peerNetworkId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransReNegotiateSessionKey(nullptr, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransAuthPendingTest006
 * @tc.desc: Use the wrong parameter to test GetAuthConnInfoByConnId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest006, TestSize.Level1)
{
    uint32_t connectionId = 1;
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = GetAuthConnInfoByConnId(connectionId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnAuthSessionKeyGenSucc and OnAuthSessionKeyGenFail Test
 * @tc.desc: OnAuthSessionKeyGenFail OnAuthSessionKeyGenSucc001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, OnAuthSessionKeyGenSucc001, TestSize.Level1)
{
    AuthHandle authHandle;
    authHandle.authId = TRANS_TEST_AUTH_REQUEST_ID;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    OnAuthSessionKeyGenSucc(TRANS_TEST_AUTH_REQUEST_ID, authHandle);
    OnAuthSessionKeyGenFail(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: OnUpdateSessionKeySucc and OnUpdateSessionKeyFail Test
 * @tc.desc: OnUpdateSessionKeySucc OnUpdateSessionKeyFail001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, OnUpdateSessionKeyFail001, TestSize.Level1)
{
    AuthHandle authHandle;
    authHandle.authId = TRANS_TEST_AUTH_REQUEST_ID;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    OnUpdateSessionKeySucc(TRANS_TEST_AUTH_REQUEST_ID, authHandle);
    OnUpdateSessionKeyFail(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransNegotiateSessionKey Test
 * @tc.desc: TransNegotiateSessionKey001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransNegotiateSessionKey001, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    authConnInfo.type = AUTH_LINK_TYPE_BR;
    authConnInfo.info.brInfo.connectionId = TRANS_TEST_CHANNEL_ID;
    const char *peerNetworkId = "";
    int32_t ret = TransNegotiateSessionKey(nullptr, TRANS_TEST_CHANNEL_ID, peerNetworkId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransNegotiateSessionKey(&authConnInfo, TRANS_TEST_CHANNEL_ID, peerNetworkId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    const char *peerNetworkId1 = "123123";
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, AuthCheckSessionKeyValidByConnInfo).WillOnce(Return(SOFTBUS_AUTH_SESSION_KEY_TOO_OLD));
    ret = TransNegotiateSessionKey(&authConnInfo, TRANS_TEST_CHANNEL_ID, peerNetworkId1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransNegotiateSessionKey Test
 * @tc.desc: TransNegotiateSessionKey002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransNegotiateSessionKey002, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    authConnInfo.type = AUTH_LINK_TYPE_BR;
    authConnInfo.info.brInfo.connectionId = TRANS_TEST_CHANNEL_ID;
    const char *peerNetworkId1 = "123123";
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, AuthCheckSessionKeyValidByConnInfo).WillOnce(Return(SOFTBUS_AUTH_SESSION_KEY_INVALID))
        .WillOnce(Return(SOFTBUS_AUTH_NOT_FOUND));
    int32_t ret = TransNegotiateSessionKey(&authConnInfo, TRANS_TEST_CHANNEL_ID, peerNetworkId1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransNegotiateSessionKey(&authConnInfo, TRANS_TEST_CHANNEL_ID, peerNetworkId1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransReNegotiateSessionKey Test
 * @tc.desc: TransReNegotiateSessionKey001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransReNegotiateSessionKey001, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    authConnInfo.type = AUTH_LINK_TYPE_BR;
    authConnInfo.info.brInfo.connectionId = TRANS_TEST_CHANNEL_ID;
    int32_t ret = TransReNegotiateSessionKey(&authConnInfo, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SetWlanAuthConnInfo Test
 * @tc.desc: SetWlanAuthConnInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, SetWlanAuthConnInfo001, TestSize.Level1)
{
    ConnSocketInfo socketInfo;
    socketInfo.protocol = LNN_PROTOCOL_BLE;
    AuthConnInfo authConnInfo;
    int32_t ret = SetWlanAuthConnInfo(&socketInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: SetWlanAuthConnInfo Test
 * @tc.desc: SetWlanAuthConnInfo002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, SetWlanAuthConnInfo002, TestSize.Level1)
{
    ConnSocketInfo socketInfo;
    socketInfo.protocol = LNN_PROTOCOL_IP;
    socketInfo.port = SOFTBUS_PORT;
    socketInfo.moduleId = DIRECT_CHANNEL_SERVER_WIFI;
    (void)strcpy_s(socketInfo.addr, IP_LEN, "");
    AuthConnInfo authConnInfo;
    int32_t ret = SetWlanAuthConnInfo(&socketInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)strcpy_s(socketInfo.addr, IP_LEN, "127.0.0.1");
    ret = SetWlanAuthConnInfo(&socketInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SetBrAuthConnInfo Test
 * @tc.desc: SetBrAuthConnInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, SetBrAuthConnInfo001, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    BrInfo brInfo;
    (void)strcpy_s(brInfo.brMac, BT_MAC_LEN, "");
    int32_t ret = SetBrAuthConnInfo(&brInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)strcpy_s(brInfo.brMac, BT_MAC_LEN, "11:22:33:44:55:66");
    ret = SetBrAuthConnInfo(&brInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SetBleAuthConnInfo Test
 * @tc.desc: SetBleAuthConnInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, SetBleAuthConnInfo001, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    BleInfo bleInfo;
    bleInfo.protocol = BLE_COC;
    (void)strcpy_s(bleInfo.bleMac, BT_MAC_LEN, "");
    bleInfo.psm = 1;
    int32_t ret = SetBleAuthConnInfo(&bleInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)strcpy_s(bleInfo.bleMac, BT_MAC_LEN, "11:22:33:44:55:66");
    (void)strcpy_s(bleInfo.deviceIdHash, UDID_HASH_LEN, "dev/ice%Id()Hash()");
    ret = SetBleAuthConnInfo(&bleInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ConvertConnInfoToAuthConnInfo Test
 * @tc.desc: ConvertConnInfoToAuthConnInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, ConvertConnInfoToAuthConnInfo001, TestSize.Level1)
{
    ConnectionInfo connInfo;
    AuthConnInfo authConnInfo;
    connInfo.type = CONNECT_TCP;
    connInfo.socketInfo.protocol = LNN_PROTOCOL_IP;
    connInfo.socketInfo.port = SOFTBUS_PORT;
    connInfo.socketInfo.moduleId = DIRECT_CHANNEL_SERVER_WIFI;
    (void)strcpy_s(connInfo.socketInfo.addr, IP_LEN, "127.0.0.1");
    int32_t ret = ConvertConnInfoToAuthConnInfo(&connInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ConvertConnInfoToAuthConnInfo Test
 * @tc.desc: ConvertConnInfoToAuthConnInfo002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, ConvertConnInfoToAuthConnInfo002, TestSize.Level1)
{
    ConnectionInfo connInfo;
    connInfo.type = CONNECT_BR;
    AuthConnInfo authConnInfo;
    (void)strcpy_s(connInfo.brInfo.brMac, BT_MAC_LEN, "11:22:33:44:55:66");
    int32_t ret = ConvertConnInfoToAuthConnInfo(&connInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ConvertConnInfoToAuthConnInfo Test
 * @tc.desc: ConvertConnInfoToAuthConnInfo003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, ConvertConnInfoToAuthConnInfo003, TestSize.Level1)
{
    ConnectionInfo connInfo;
    connInfo.type = CONNECT_BLE;
    AuthConnInfo authConnInfo;
    connInfo.bleInfo.protocol = BLE_COC;
    connInfo.bleInfo.psm = 1;
    (void)strcpy_s(connInfo.bleInfo.bleMac, BT_MAC_LEN, "11:22:33:44:55:66");
    (void)strcpy_s(connInfo.bleInfo.deviceIdHash, UDID_HASH_LEN, "dev/ice%Id()Hash()");
    int32_t ret = ConvertConnInfoToAuthConnInfo(&connInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ConvertConnInfoToAuthConnInfo Test
 * @tc.desc: ConvertConnInfoToAuthConnInfo004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, ConvertConnInfoToAuthConnInfo004, TestSize.Level1)
{
    ConnectionInfo connInfo;
    connInfo.type = CONNECT_HML;
    AuthConnInfo authConnInfo;
    int32_t ret = ConvertConnInfoToAuthConnInfo(&connInfo, &authConnInfo);
    EXPECT_EQ(SOFTBUS_FUNC_NOT_SUPPORT, ret);
}

/**
 * @tc.name: GetAuthConnInfoByConnId Test
 * @tc.desc: GetAuthConnInfoByConnId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, GetAuthConnInfoByConnId001, TestSize.Level1)
{
    int32_t ret = GetAuthConnInfoByConnId(CONNECTION_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AuthConnInfo authConnInfo;
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, ConnGetConnectionInfo).WillOnce(Return(SOFTBUS_OK));
    ret = GetAuthConnInfoByConnId(CONNECTION_ID, &authConnInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetAuthConnInfoByConnId and TransAuthNegoTaskManager Test
 * @tc.desc: GetAuthConnInfoByConnId002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, GetAuthConnInfoByConnId002, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, ConnGetConnectionInfo).WillOnce(Return(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT));
    int32_t ret = GetAuthConnInfoByConnId(CONNECTION_ID, &authConnInfo);
    TransAuthNegoTaskManager(0, TRANS_TEST_CHANNEL_ID);
    TransAuthNegoTaskManager(TRANS_TEST_AUTH_REQUEST_ID, TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}
} // OHOS
