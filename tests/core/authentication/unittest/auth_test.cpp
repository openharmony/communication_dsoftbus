/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>
#include <cinttypes>

#include "auth_channel.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "auth_session_message.h"
#include "auth_tcp_connection.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_access_token_test.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 10;
constexpr uint32_t CRYPT_DATA_LEN = 200;
constexpr uint32_t P2P_MAC_LEN = 6;

class AuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTest::SetUpTestCase()
{
    SetAceessTokenPermission("AuthTest");
}

void AuthTest::TearDownTestCase()
{
}

void AuthTest::SetUp()
{
    LOG_INFO("AuthTest start.");
}

void AuthTest::TearDown()
{
}

/*
* @tc.name: AUTH_COMMON_Test_001
* @tc.desc: auth commone test
* @tc.type: FUNC
* @tc.require: I5OAEP
*/
HWTEST_F(AuthTest, AUTH_COMMON_Test_001, TestSize.Level1)
{
    int32_t ret = AuthCommonInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: REG_TRUST_DATA_CHANGE_LISTENER_Test_001
* @tc.desc: trust data change listener test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, REG_TRUST_DATA_CHANGE_LISTENER_Test_001, TestSize.Level1)
{
    int32_t ret;
    const TrustDataChangeListener listener = {0};

    ret = RegTrustDataChangeListener(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = RegTrustDataChangeListener(&listener);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: HICHAIN_START_AUTH_Test_001
* @tc.desc: hichain start auth test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, HICHAIN_START_AUTH_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const char *udid = "testdata";
    const char *uid = "testdata";
    int32_t ret;

    ret = HichainStartAuth(authSeq, nullptr, uid);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = HichainStartAuth(authSeq, udid, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = HichainStartAuth(authSeq, udid, uid);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: HICHAIN_PROCESS_DATA_Test_001
* @tc.desc: hichain process data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, HICHAIN_PROCESS_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const uint8_t data[TEST_DATA_LEN] = {0};
    uint32_t len = TEST_DATA_LEN;
    int32_t ret;

    ret = HichainProcessData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = HichainProcessData(authSeq, data, len);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: ADD_AUTH_REQUEST_Test_001
* @tc.desc: add auth request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, ADD_AUTH_REQUEST_Test_001, TestSize.Level1)
{
    const AuthRequest request = {0};

    int32_t ret = AddAuthRequest(&request);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: GET_AUTH_REQUEST_Test_001
* @tc.desc: get auth request test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, GET_AUTH_REQUEST_Test_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthRequest request = {0};

    int32_t ret = GetAuthRequest(requestId, &request);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
* @tc.name: UPDATE_AUTH_REQUEST_CONN_INFO_Test_001
* @tc.desc: update auth request connInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, UPDATE_AUTH_REQUEST_CONN_INFO_Test_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthConnInfo connInfo;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = UpdateAuthRequestConnInfo(requestId, (const AuthConnInfo *)&connInfo);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
* @tc.name: AUTH_SESSION_PROCESS_DEVID_DATA_Test_001
* @tc.desc: auth session process devId data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_DEVID_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionProcessDevIdData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_SESSION_POST_AUTH_DATA_Test_001
* @tc.desc: auth session post auth data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_POST_AUTH_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = -1;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionPostAuthData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: AUTH_SESSION_PROCESS_AUTH_DATA_Test_001
* @tc.desc: auth session process auth data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_AUTH_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionProcessAuthData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_SESSION_GET_UDID_Test_001
* @tc.desc: auth session get udid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_GET_UDID_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    char udid[UDID_BUF_LEN] = {0};
    uint32_t size = UDID_BUF_LEN;
    int32_t ret;

    ret = AuthSessionGetUdid(authSeq, nullptr, size);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    authSeq = -1;
    ret = AuthSessionGetUdid(authSeq, udid, size);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: AUTH_SESSION_SAVE_SESSIONKEY_Test_001
* @tc.desc: auth session save sessionKey test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_SAVE_SESSIONKEY_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionSaveSessionKey(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_SESSION_PROCESS_DEVINFO_DATA_Test_001
* @tc.desc: auth session process devInfo data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_DEVINFO_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionProcessDevInfoData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_SESSION_PROCESS_CLOSE_ACK_Test_001
* @tc.desc: auth session process close ack test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_CLOSE_ACK_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint32_t len = 1;
    int32_t ret;

    ret = AuthSessionProcessCloseAck(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_SESSION_PROCESS_CLOSE_ACK_BY_CONNID_Test_001
* @tc.desc: auth session process close ack by connId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_CLOSE_ACK_BY_CONNID_Test_001, TestSize.Level1)
{
    uint64_t connId = 0;
    bool isServer = true;
    const uint8_t data[TEST_DATA_LEN] = {0};
    uint32_t len = TEST_DATA_LEN;
    uint32_t errlen = 0;
    int32_t ret;

    ret = AuthSessionProcessCloseAckByConnId(connId, isServer, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthSessionProcessCloseAckByConnId(connId, isServer, data, errlen);
    EXPECT_TRUE(ret == SOFTBUS_MALLOC_ERR);
    ret = AuthSessionProcessCloseAckByConnId(connId, isServer, data, len);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: AUTH_SESSION_HANDLE_DEVICE_NOT_TRUSTED_Test_001
* @tc.desc: auth session handle device not trusted test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SESSION_HANDLE_DEVICE_NOT_TRUSTED_Test_001, TestSize.Level1)
{
    const char *udid = "testdata";
    int32_t ret;

    ret = AuthSessionHandleDeviceNotTrusted(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret =  AuthSessionHandleDeviceNotTrusted(udid);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: ENCRYPT_INNER_Test_001
* @tc.desc: encrypt inner test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, ENCRYPT_INNER_Test_001, TestSize.Level1)
{
    SessionKeyList list = {0};
    SessionKey sessionKey = {{0}, TEST_DATA_LEN};
    int64_t authSeq = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = {0};
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t *outData = nullptr;
    uint32_t outLen = 0;
    int32_t ret;

    ret = EncryptInner(nullptr, inData, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list, nullptr, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = EncryptInner(&list, inData, inLen, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    inLen = 0;
    ret = EncryptInner(&list, inData, inLen, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ListInit(&list);
    ret = AddSessionKey(&list, TO_INT32(authSeq), &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    inLen = CRYPT_DATA_LEN;
    ret = EncryptInner(&list, inData, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: DENCRYPT_INNER_Test_001
* @tc.desc: dencrypt inner test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, DENCRYPT_INNER_Test_001, TestSize.Level1)
{
    SessionKeyList list = {0};
    SessionKey sessionKey = {{0}, TEST_DATA_LEN};
    int64_t authSeq = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = {0};
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t *outData = nullptr;
    uint32_t outLen = 0;
    int32_t ret;

    ret = DecryptInner(nullptr, inData, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DecryptInner(&list, nullptr, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DecryptInner(&list, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = DecryptInner(&list, inData, inLen, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    inLen = 0;
    ret = DecryptInner(&list, inData, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ListInit(&list);
    ret = AddSessionKey(&list, TO_INT32(authSeq), &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    inLen = CRYPT_DATA_LEN;
    ret = DecryptInner(&list, inData, inLen, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_DECRYPT_ERR);
}

/*
* @tc.name: POST_DEVICEID_MESSAGE_Test_001
* @tc.desc: post deviceId message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_DEVICEID_MESSAGE_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int64_t errAuthSeq = -1;
    const AuthSessionInfo info = {0};
    int32_t ret;

    ret = PostDeviceIdMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = PostDeviceIdMessage(authSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: POST_DEVICE_INFO_MESSAGE_Test_001
* @tc.desc: post device info message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_DEVICE_INFO_MESSAGE_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int64_t errAuthSeq = -1;
    const AuthSessionInfo info = {0};
    int32_t ret;

    ret = PostDeviceInfoMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    ret = PostDeviceInfoMessage(authSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: PROCESS_DEVICE_INFO_MESSAGE_Test_001
* @tc.desc: process device info message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, PROCESS_DEVICE_INFO_MESSAGE_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo info = {0};
    const uint8_t data[TEST_DATA_LEN] = {0};
    uint32_t len = TEST_DATA_LEN;

    int32_t ret = ProcessDeviceInfoMessage(authSeq, &info, data, len);
    EXPECT_TRUE(ret == SOFTBUS_DECRYPT_ERR);
}

/*
* @tc.name: POST_CLOSE_ACK_MESSAGE_Test_001
* @tc.desc: post close ack message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_CLOSE_ACK_MESSAGE_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int64_t errAuthSeq = -1;
    const AuthSessionInfo info = {0};
    int32_t ret;

    ret = PostDeviceInfoMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    ret = PostDeviceInfoMessage(authSeq, &info);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: POST_HICHAIN_AUTH_MESSAGE_Test_001
* @tc.desc: post hichain auth message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_HICHAIN_AUTH_MESSAGE_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const AuthSessionInfo info = {0};
    const uint8_t data[TEST_DATA_LEN] = {0};
    uint32_t len = TEST_DATA_LEN;

    int32_t ret = PostHichainAuthMessage(authSeq, &info, data, len);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: POST_VERIFY_DEVICE_MESSAGE_001
* @tc.desc: post verify device message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_VERIFY_DEVICE_MESSAGE_001, TestSize.Level1)
{
    AuthManager auth = {0};

    InitSessionKeyList(&auth.sessionKeyList);
    int32_t ret = PostVerifyDeviceMessage((const AuthManager *)&auth);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: START_SOCKET_LISTENING_Test_001
* @tc.desc: start socket listening test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, START_SOCKET_LISTENING_Test_001, TestSize.Level1)
{
    const char *ip = "192.168.12.1";
    int32_t port = 22;

    int32_t ret = StartSocketListening(ip, port);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: SOCKET_CONNECT_DEVICE_Test_001
* @tc.desc: socket connect device test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, SOCKET_CONNECT_DEVICE_Test_001, TestSize.Level1)
{
    const char *ip = "192.168.12.1";
    int32_t port = 22;
    bool isBlockMode = true;

    int32_t ret = SocketConnectDevice(ip, port, isBlockMode);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
}

/*
* @tc.name: SOCKER_POST_BYTES_Test_001
* @tc.desc: socket post bytes test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, SOCKER_POST_BYTES_Test_001, TestSize.Level1)
{
    int32_t fd = 1;
    const AuthDataHead head = {0};
    const uint8_t data[TEST_DATA_LEN] = {0};

    int32_t ret = SocketPostBytes(fd, &head, data);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: SOCKER_GET_CONN_INFO_Test_001
* @tc.desc: socket get conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, SOCKER_GET_CONN_INFO_Test_001, TestSize.Level1)
{
    int32_t fd = 1;
    AuthConnInfo connInfo;
    bool isServer = true;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = SocketGetConnInfo(fd, &connInfo, &isServer);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: REGAUTH_CHANNEL_LISTENER_Test_001
* @tc.desc: regauth channel listener test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, REGAUTH_CHANNEL_LISTENER_Test_001, TestSize.Level1)
{
    int32_t module = 0;
    AuthChannelListener listener = {0};
    int32_t ret;

    ret = RegAuthChannelListener(module, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    listener.onDataReceived = nullptr;
    ret = RegAuthChannelListener(module, (const AuthChannelListener *)&listener);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_OPRN_CHANNEL_Test_001
* @tc.desc: auth open channel test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_OPRN_CHANNEL_Test_001, TestSize.Level1)
{
    const char *ip = "192.168.12.1";
    int32_t port = 1;
    int32_t ret;

    ret = AuthOpenChannel(nullptr, port);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
    port = 0;
    ret = AuthOpenChannel(ip, port);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
}

/*
* @tc.name: AUTH_POST_CHANNEL_DATA_Test_001
* @tc.desc: auth post channel data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_POST_CHANNEL_DATA_Test_001, TestSize.Level1)
{
    int32_t channelId = -1;
    const uint8_t testData[TEST_DATA_LEN] = {0};
    AuthChannelData data = {
        .module = 0,
        .flag = 0,
        .seq = 0,
        .len = TEST_DATA_LEN,
        .data = nullptr,
    };
    int32_t ret;

    ret = AuthPostChannelData(channelId, (const AuthChannelData *)&data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    channelId = 0;
    ret = AuthPostChannelData(channelId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    data.len = 0;
    ret = AuthPostChannelData(channelId, (const AuthChannelData *)&data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    data.len = 0;
    data.data = testData;
    ret = AuthPostChannelData(channelId, (const AuthChannelData *)&data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_MANAGER_SET_SESSION_KEY_Test_001
* @tc.desc: auth manager set session key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_MANAGER_SET_SESSION_KEY_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const AuthSessionInfo info = {0};
    const SessionKey sessionKey = {{0}, TEST_DATA_LEN};

    int32_t ret = AuthManagerSetSessionKey(authSeq, &info, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_MANAGER_GET_SESSION_KEY_Test_001
* @tc.desc: auth manager get session key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_MANAGER_GET_SESSION_KEY_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const AuthSessionInfo info = {0};
    SessionKey sessionKey = {{0}, TEST_DATA_LEN};

    int32_t ret = AuthManagerGetSessionKey(authSeq, &info, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: REGAUTH_VERIFY_LISTENER_Test_001
* @tc.desc: regAuth verify listener test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, REGAUTH_VERIFY_LISTENER_Test_001, TestSize.Level1)
{
    int32_t ret = RegAuthVerifyListener(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_START_VERIFY_Test_001
* @tc.desc: auth start verify test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_START_VERIFY_Test_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    uint32_t requestId = 0;
    const AuthVerifyCallback callback = {0};
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthStartVerify(nullptr, requestId, &callback);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthStartVerify((const AuthConnInfo *)&connInfo, requestId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_FLUSH_DEVICE_Test_001
* @tc.desc: auth flush device test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_FLUSH_DEVICE_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    int32_t ret;

    ret = AuthFlushDevice(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '\0';
    ret = AuthFlushDevice((const char *)uuid);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthFlushDevice((const char *)uuid);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_DEVICE_GET_PREFER_CONN_INFO_Test_001
* @tc.desc: auth device get prefer conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DEVICE_GET_PREFER_CONN_INFO_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    AuthConnInfo connInfo;
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthDeviceGetPreferConnInfo(nullptr, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '\0';
    ret = AuthDeviceGetPreferConnInfo((const char *)uuid, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthDeviceGetPreferConnInfo((const char *)uuid, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDeviceGetPreferConnInfo((const char *)uuid, &connInfo);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_DEVICE_POST_TRANS_DATA_Test_001
* @tc.desc: auth device post trans data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DEVICE_POST_TRANS_DATA_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    const AuthTransData dataInfo = {0};
    int32_t ret;

    ret = AuthDevicePostTransData(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDevicePostTransData(authId, &dataInfo);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: AUTH_DEVICE_GET_LATEST_ID_BY_UUID_Test_001
* @tc.desc: auth device get latest id by uuid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DEVICE_GET_LATEST_ID_BY_UUID_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    int64_t ret;

    ret = AuthDeviceGetLatestIdByUuid(nullptr, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    uuid[0] = '\0';
    ret = AuthDeviceGetLatestIdByUuid((const char *)uuid, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    uuid[0] = '1';
    ret = AuthDeviceGetLatestIdByUuid((const char *)uuid, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthDeviceGetLatestIdByUuid((const char *)uuid, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: AUTH_DEVICE_GET_ID_BY_CONN_INFO_Test_001
* @tc.desc: auth device get id by conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DEVICE_GET_ID_BY_CONN_INFO_Test_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    int64_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthDeviceGetIdByConnInfo(nullptr, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthDeviceGetIdByConnInfo((const AuthConnInfo *)&connInfo, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: AUTH_DEVICE_GET_ID_BY_P2P_MAC_Test_001
* @tc.desc: auth device get id by p2p mac test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DEVICE_GET_ID_BY_P2P_MAC_Test_001, TestSize.Level1)
{
    char p2pMac[P2P_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    bool isServer = true;
    int64_t ret;

    ret = AuthDeviceGetIdByP2pMac(nullptr, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    p2pMac[0] = '\0';
    ret = AuthDeviceGetIdByP2pMac((const char *)p2pMac, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    p2pMac[0] = '1';
    ret = AuthDeviceGetIdByP2pMac((const char *)p2pMac, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: REGAUTH_TRANS_LISTENER_Test_001
* @tc.desc: regAuth trans listener test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, REGAUTH_TRANS_LISTENER_Test_001, TestSize.Level1)
{
    int32_t module = 0;
    AuthTransListener listener = {0};
    int32_t ret;

    ret = RegAuthTransListener(module, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = RegAuthTransListener(module, (const AuthTransListener *)&listener);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    UnregAuthTransListener(MODULE_P2P_LINK);
}

/*
* @tc.name: AUTH_GET_PREFER_CONNINFO_Test_001
* @tc.desc: auth get prefer connInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_PREFER_CONNINFO_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    AuthConnInfo connInfo;
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthGetPreferConnInfo(nullptr, &connInfo, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetPreferConnInfo((const char *)uuid, nullptr, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '\0';
    ret = AuthGetPreferConnInfo((const char *)uuid, &connInfo, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthGetPreferConnInfo((const char *)uuid, &connInfo, false);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: AUTH_OPEN_CONN_Test_001
* @tc.desc: auth open conn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_OPEN_CONN_Test_001, TestSize.Level1)
{
    AuthConnInfo info;
    uint32_t requestId = 0;
    const AuthConnCallback callback = {0};
    int32_t ret;

    (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthOpenConn(nullptr, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn((const AuthConnInfo *)&info, requestId, nullptr, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn((const AuthConnInfo *)&info, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    info.type = AUTH_LINK_TYPE_WIFI;
    ret = AuthOpenConn((const AuthConnInfo *)&info, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn((const AuthConnInfo *)&info, requestId, &callback, true);
    EXPECT_TRUE(ret == SOFTBUS_NOT_IMPLEMENT);
}

/*
* @tc.name: AUTH_POST_TRANS_DATA_Test_001
* @tc.desc: auth post trans data test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_POST_TRANS_DATA_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    const AuthTransData dataInfo = {0};
    int32_t ret;

    ret = AuthPostTransData(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthPostTransData(authId, &dataInfo);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    AuthCloseConn(authId);
}

/*
* @tc.name: REG_GROUP_CHANGE_LISTENER_Test_001
* @tc.desc: Reg Group Change Listener test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, REG_GROUP_CHANGE_LISTENER_Test_001, TestSize.Level1)
{
    int32_t ret = RegGroupChangeListener(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_GET_LATESTID_BY_UUID_Test_001
* @tc.desc: auth get latestId by uuid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_LATESTID_BY_UUID_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    int64_t ret;

    ret = AuthGetLatestIdByUuid(nullptr, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthGetLatestIdByUuid((const char *)uuid, true, true);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    uuid[0] = '\0';
    ret = AuthGetLatestIdByUuid((const char *)uuid, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: AUTH_GET_ID_BY_CONN_INFO_Test_001
* @tc.desc: auth get id by conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_ID_BY_CONN_INFO_Test_001, TestSize.Level1)
{
    int64_t ret;

    ret = AuthGetIdByConnInfo(nullptr, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: AUTH_GET_ID_BY_P2P_MAC_Test_001
* @tc.desc: auth get id by p2p mac test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_ID_BY_P2P_MAC_Test_001, TestSize.Level1)
{
    char p2pMac[P2P_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    AuthLinkType type;
    int64_t ret;

    type = AUTH_LINK_TYPE_BR;
    ret = AuthGetIdByP2pMac(nullptr, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthGetIdByP2pMac((const char *)p2pMac, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    p2pMac[0] = '\0';
    ret = AuthGetIdByP2pMac((const char *)p2pMac, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

/*
* @tc.name: AUTH_ENCRYPT_Test_001
* @tc.desc: auth encrypt test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_ENCRYPT_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = {0};
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t outData[CRYPT_DATA_LEN] = {0};
    uint32_t outLen = CRYPT_DATA_LEN;
    uint32_t errLen = 0;
    int32_t ret;

    ret = AuthEncrypt(authId, nullptr, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(authId, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(authId, inData, inLen, outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(authId, inData, errLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(authId, inData, inLen, outData, &errLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_DECRYPT_Test_001
* @tc.desc: auth eecrypt test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_DECRYPT_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = {0};
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t outData[CRYPT_DATA_LEN] = {0};
    uint32_t outLen = CRYPT_DATA_LEN;
    uint32_t errLen = 0;
    int32_t ret;

    ret = AuthDecrypt(authId, nullptr, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(authId, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(authId, inData, inLen, outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(authId, inData, errLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(authId, inData, inLen, outData, &errLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(authId, inData, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
* @tc.name: AUTH_SET_P2P_MAC_Test_001
* @tc.desc: auth set p2p mac test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_SET_P2P_MAC_Test_001, TestSize.Level1)
{
    char p2pMac[P2P_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    int64_t authId = 0;
    int32_t ret;

    ret = AuthSetP2pMac(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthSetP2pMac(authId, (const char *)p2pMac);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
    p2pMac[0] = '\0';
    ret = AuthSetP2pMac(authId, (const char *)p2pMac);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_GET_CONN_INFO_Test_001
* @tc.desc: auth get conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_CONN_INFO_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    int32_t ret;

    ret = AuthGetConnInfo(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_GET_SERVER_SIDE_Test_001
* @tc.desc: auth get server side test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_SERVER_SIDE_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    int32_t ret;

    ret = AuthGetServerSide(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_GET_META_TYPE_Test_001
* @tc.desc: auth get meta type test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_META_TYPE_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    bool isMetaAuth = true;
    int32_t ret;

    ret = AuthGetMetaType(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetMetaType(authId, &isMetaAuth);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_GET_DEVICE_UUID_Test_001
* @tc.desc: auth get device uuid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_DEVICE_UUID_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    char uuid[TEST_DATA_LEN] = "testdata";
    uint16_t size = TEST_DATA_LEN;
    int32_t ret;

    ret = AuthGetDeviceUuid(authId, nullptr, size);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetDeviceUuid(authId, uuid, size);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_GET_VERSION_Test_001
* @tc.desc: auth get version test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_GET_VERSION_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    SoftBusVersion version;
    int32_t ret;

    version = SOFTBUS_OLD_V1;
    ret = AuthGetVersion(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetVersion(authId, &version);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_INIT_Test_001
* @tc.desc: auth init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_INIT_Test_001, TestSize.Level1)
{
    int32_t ret;

    ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_AUTH_INIT_FAIL);
    AuthDeinit();
}

/*
* @tc.name: POST_AUTH_EVENT_INIT_Test_001
* @tc.desc: post suth event test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, POST_AUTH_EVENT_INIT_Test_001, TestSize.Level1)
{
    EventHandler handler = {0};
    const void *obj = "testdata";
    uint32_t size = TEST_DATA_LEN;
    uint64_t delayMs = 0;
    int32_t ret;

    ret = PostAuthEvent(EVENT_CONNECT_CMD, handler, obj, size, delayMs);
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
}

/*
* @tc.name: COMPARE_CONN_INFO_Test_001
* @tc.desc: compare conn info test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, COMPARE_CONN_INFO_Test_001, TestSize.Level1)
{
    AuthConnInfo info1;
    AuthConnInfo info2;
    bool ret;

    (void)memset_s(&info1, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&info2, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info1.type = AUTH_LINK_TYPE_WIFI;
    info2.type = AUTH_LINK_TYPE_WIFI;
    ret = CompareConnInfo(&info1, &info2);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_BR;
    info2.type = AUTH_LINK_TYPE_BR;
    ret = CompareConnInfo(&info1, &info2);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_BLE;
    info2.type = AUTH_LINK_TYPE_BLE;
    ret = CompareConnInfo(&info1, &info2);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_P2P;
    info2.type = AUTH_LINK_TYPE_P2P;
    ret = CompareConnInfo(&info1, &info2);
    EXPECT_TRUE(ret == true);
}

/*
* @tc.name: CONVERT_TO_CONNECT_OPTION_Test_001
* @tc.desc: convert to connect option test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, CONVERT_TO_CONNECT_OPTION_Test_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    ConnectOption option;
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connInfo.type = AUTH_LINK_TYPE_BR;
    ret = ConvertToConnectOption((const AuthConnInfo *)&connInfo, &option);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = ConvertToConnectOption((const AuthConnInfo *)&connInfo, &option);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConvertToConnectOption((const AuthConnInfo *)&connInfo, &option);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: CONVERT_TO_AUTH_CONNINFO_Test_001
* @tc.desc: convert to auth connInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, CONVERT_TO_AUTH_CONNINFO_Test_001, TestSize.Level1)
{
    ConnectionInfo info;
    AuthConnInfo connInfo;
    int32_t ret;

    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    info.type = CONNECT_TCP;
    info.socketInfo.protocol = LNN_PROTOCOL_IP;
    ret = ConvertToAuthConnInfo((const ConnectionInfo *)&info, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    info.type = CONNECT_BR;
    ret = ConvertToAuthConnInfo((const ConnectionInfo *)&info, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    info.type = CONNECT_BLE;
    ret = ConvertToAuthConnInfo((const ConnectionInfo *)&info, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_CONN_INIT_Test_001
* @tc.desc: auth conn init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_CONN_INIT_Test_001, TestSize.Level1)
{
    AuthConnListener listener;
    (void)memset_s(&listener, sizeof(AuthConnListener), 0, sizeof(AuthConnListener));
    int32_t ret = AuthConnInit(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthConnInit(&listener);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: CONNECT_AUTH_DEVICE_Test_001
* @tc.desc: connect auth device test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, CONNECT_AUTH_DEVICE_Test_001, TestSize.Level1)
{
    uint32_t requestId = 123;
    AuthConnInfo connInfo;
    ConnSideType sideType = CONN_SIDE_SERVER;
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    ret = ConnectAuthDevice(requestId, &connInfo, sideType);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConnectAuthDevice(requestId, &connInfo, sideType);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: AUTH_START_LISTENING_Test_001
* @tc.desc: auth start listening test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthTest, AUTH_START_LISTENING_Test_001, TestSize.Level1)
{
    const char *ip = "192.168.12.1";
    int32_t port = 22;
    int32_t ret;

    ret = AuthStartListening(AUTH_LINK_TYPE_WIFI, nullptr, port);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthStartListening(AUTH_LINK_TYPE_WIFI, ip, port);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
    ret = AuthStartListening(AUTH_LINK_TYPE_P2P, ip, port);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
