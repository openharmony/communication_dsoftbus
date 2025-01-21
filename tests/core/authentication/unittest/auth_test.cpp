/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_channel.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_interface.c"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "auth_session_message.h"
#include "auth_tcp_connection.c"
#include "auth_tcp_connection.h"
#include "common_list.h"
#include "lnn_net_builder.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 10;
constexpr uint32_t CRYPT_DATA_LEN = 200;
constexpr uint32_t ENCRYPT_OVER_HEAD_LEN_TEST = 32;
constexpr char P2P_MAC[BT_MAC_LEN] = "01:02:03:04:05:06";
constexpr char P2P_MAC2[BT_MAC_LEN] = { 0 };
constexpr char UUID_TEST[UUID_BUF_LEN] = "0123456789ABC";
constexpr char UUID_TEST2[UUID_BUF_LEN] = { 0 };
static constexpr int32_t DEFALUT_USERID = 100;

#define LINK_TYPE      9
#define CLIENT_PORT    6666
#define KEEPALIVE_TIME 601

class AuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTest::SetUpTestCase()
{
    SetAccessTokenPermission("AuthTest");
}

void AuthTest::TearDownTestCase() { }

void AuthTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthTest start");
}

static void OnGroupCreated(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
    return;
}

static void OnGroupDeleted(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
    return;
}

static void OnDeviceNotTrusted(const char *udid, int32_t localUserId)
{
    (void)udid;
    (void)localUserId;
    return;
}

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    (void)udid;
    (void)groupInfo;
    return;
}

void AuthTest::TearDown() { }

/*
 * @tc.name: AUTH_COMMON_Test_001
 * @tc.desc: auth commone test
 * @tc.type: FUNC
 * @tc.require:
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
    const TrustDataChangeListener listener = {
        .onGroupCreated = OnGroupCreated,
        .onGroupDeleted = OnGroupDeleted,
        .onDeviceNotTrusted = OnDeviceNotTrusted,
        .onDeviceBound = OnDeviceBound,
    };

    ret = RegTrustDataChangeListener(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = RegTrustDataChangeListener(&listener);
    EXPECT_TRUE(ret == SOFTBUS_OK || ret == SOFTBUS_AUTH_REG_DATA_FAIL);
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

    ret = HichainStartAuth(authSeq, nullptr, uid, DEFALUT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = HichainStartAuth(authSeq, udid, nullptr, DEFALUT_USERID);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    (void)HichainStartAuth(authSeq, udid, uid, DEFALUT_USERID);
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
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = TEST_DATA_LEN;
    int32_t ret;

    ret = HichainProcessData(authSeq, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = HichainProcessData(authSeq, data, len);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ADD_AUTH_REQUEST_Test_001
 * @tc.desc: add auth request test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, ADD_AUTH_REQUEST_Test_001, TestSize.Level1)
{
    const AuthRequest request = { 0 };

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
    AuthRequest request = { 0 };

    int32_t ret = GetAuthRequest(requestId, &request);
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
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    char udid[UDID_BUF_LEN] = { 0 };
    uint32_t size = UDID_BUF_LEN;
    int32_t ret;

    ret = AuthSessionGetUdid(authSeq, nullptr, size);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    authSeq = -1;
    ret = AuthSessionGetUdid(authSeq, udid, size);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = TEST_DATA_LEN;
    int32_t ret;

    ret = AuthSessionProcessCloseAckByConnId(connId, isServer, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthSessionProcessCloseAckByConnId(connId, isServer, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_SESSION_PROCESS_CANCEL_AUTH_BY_CONNID_Test_001
 * @tc.desc: auth session process cancel auth by connId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_CANCEL_AUTH_BY_CONNID_Test_001, TestSize.Level1)
{
    uint64_t connId = 0;
    bool isServer = true;
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = TEST_DATA_LEN;
    int32_t ret;

    ret = AuthSessionProcessCancelAuthByConnId(connId, isServer, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_GET_FSM_FAIL);
    ret = AuthSessionProcessCancelAuthByConnId(connId, isServer, data, len);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_GET_FSM_FAIL);
    ret = AuthSessionProcessCancelAuthByConnId(connId, !isServer, data, len);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_GET_FSM_FAIL);
    ret = AuthSessionProcessCancelAuthByConnId(connId, !isServer, nullptr, len);
    EXPECT_TRUE(ret == SOFTBUS_AUTH_GET_FSM_FAIL);
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
    ret = AuthSessionHandleDeviceNotTrusted(udid);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    const char *udid1 = "";
    ret = AuthSessionHandleDeviceNotTrusted(udid1);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ENCRYPT_INNER_Test_001
 * @tc.desc: encrypt inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, ENCRYPT_INNER_Test_001, TestSize.Level1)
{
    SessionKeyList list = { 0 };
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    int64_t authSeq = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = { 0 };
    uint8_t *outData = nullptr;
    uint32_t outLen = 0;
    int32_t ret;
    InDataInfo inDataInfo = { .inData = nullptr, .inLen = CRYPT_DATA_LEN };
    ret = EncryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    inDataInfo.inData = inData;
    ret = EncryptInner(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ret = EncryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ret = EncryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    inDataInfo.inLen = 0;
    ret = EncryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ListInit(&list);
    ret = AddSessionKey(&list, TO_INT32(authSeq), &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    inDataInfo.inLen = CRYPT_DATA_LEN;
    ret = EncryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    SoftBusFree(outData);
}

/*
 * @tc.name: DENCRYPT_INNER_Test_001
 * @tc.desc: dencrypt inner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, DENCRYPT_INNER_Test_001, TestSize.Level1)
{
    SessionKeyList list = { 0 };
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    int64_t authSeq = 0;
    const uint8_t inData[CRYPT_DATA_LEN] = { 0 };
    uint8_t *outData = nullptr;
    uint32_t outLen = 0;
    int32_t ret;
    InDataInfo inDataInfo = { .inData = nullptr, .inLen = CRYPT_DATA_LEN };
    ret = DecryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    inDataInfo.inData = inData;
    ret = DecryptInner(nullptr, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ret = DecryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ret = DecryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    inDataInfo.inLen = 0;
    ret = DecryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    SoftBusFree(outData);
    ListInit(&list);
    ret = AddSessionKey(&list, TO_INT32(authSeq), &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    inDataInfo.inLen = CRYPT_DATA_LEN;
    ret = DecryptInner(&list, AUTH_LINK_TYPE_WIFI, &inDataInfo, &outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_DECRYPT_ERR);
    SoftBusFree(outData);
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
    const AuthSessionInfo info = { 0 };
    int32_t ret;

    ret = PostDeviceIdMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = PostDeviceIdMessage(authSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const AuthSessionInfo info = { 0 };
    int32_t ret;

    ret = PostDeviceInfoMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = PostDeviceInfoMessage(authSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    AuthSessionInfo info = { 0 };
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = TEST_DATA_LEN;

    int32_t ret = ProcessDeviceInfoMessage(authSeq, &info, data, len);
    EXPECT_TRUE(ret == SOFTBUS_DECRYPT_ERR);
    info.normalizedType = NORMALIZED_SUPPORT;
    ret = ProcessDeviceInfoMessage(authSeq, &info, data, len);
    EXPECT_TRUE(ret == SOFTBUS_DECRYPT_ERR);
    info.normalizedType = NORMALIZED_KEY_ERROR;
    ret = ProcessDeviceInfoMessage(authSeq, &info, data, len);
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
    const AuthSessionInfo info = { 0 };
    int32_t ret;

    ret = PostDeviceInfoMessage(errAuthSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = PostDeviceInfoMessage(authSeq, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const AuthSessionInfo info = { 0 };
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    uint32_t len = TEST_DATA_LEN;

    int32_t ret = PostHichainAuthMessage(authSeq, &info, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: POST_DEVICE_MESSAGE_Test_001
 * @tc.desc: post device message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, POST_DEVICE_MESSAGE_Test_001, TestSize.Level1)
{
    AuthManager auth = { 0 };
    int32_t flagRelay = 1;
    DeviceMessageParse messageParse = { CODE_VERIFY_DEVICE, DEFAULT_FREQ_CYCLE };
    InitSessionKeyList(&auth.sessionKeyList);
    int32_t ret = PostDeviceMessage(&auth, flagRelay, AUTH_LINK_TYPE_WIFI, &messageParse);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    messageParse.messageType = CODE_TCP_KEEPALIVE;
    ret = PostDeviceMessage(&auth, flagRelay, AUTH_LINK_TYPE_WIFI, &messageParse);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: POST_DEVICE_MESSAGE_Test_002
 * @tc.desc: post device message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, POST_DEVICE_MESSAGE_Test_002, TestSize.Level1)
{
    const AuthManager *auth = nullptr;
    AuthManager authManager;
    int32_t flagRelay = 1;
    int32_t type = 0;
    DeviceMessageParse messageParse = { CODE_VERIFY_DEVICE, DEFAULT_FREQ_CYCLE };
    (void)memset_s(&authManager, sizeof(AuthManager), 0, sizeof(AuthManager));
    int32_t ret = PostDeviceMessage(auth, flagRelay, AUTH_LINK_TYPE_WIFI, &messageParse);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = PostDeviceMessage(&authManager, flagRelay, AuthLinkType(type), nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = PostDeviceMessage(&authManager, flagRelay, AuthLinkType(type), &messageParse);
    EXPECT_NE(ret, SOFTBUS_OK);
    type = LINK_TYPE;
    ret = PostDeviceMessage(&authManager, flagRelay, AuthLinkType(type), &messageParse);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: START_SOCKET_LISTENING_Test_001
 * @tc.desc: start socket listening test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, START_SOCKET_LISTENING_Test_001, TestSize.Level1)
{
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "192.168.12.1",
            .port = 22,
            .moduleId = AUTH,
            .protocol = LNN_PROTOCOL_IP,
        },
    };
    int32_t ret = StartSocketListening(AUTH, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOCKET_CONNECT_DEVICE_Test_001
 * @tc.desc: socket connect device test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, SOCKET_CONNECT_DEVICE_Test_001, TestSize.Level1)
{
    const char *ip = "***.***.**.*";
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
    const AuthDataHead head = { 0 };
    const uint8_t data[TEST_DATA_LEN] = { 0 };

    int32_t ret = SocketPostBytes(fd, &head, data);
    EXPECT_NE(ret, SOFTBUS_OK);
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
    EXPECT_NE(ret, SOFTBUS_OK);
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
    AuthChannelListener listener = { 0 };
    int32_t ret;

    ret = RegAuthChannelListener(module, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    listener.onDataReceived = nullptr;
    ret = RegAuthChannelListener(module, &listener);
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
    const char *ip = "***.***.**.*";
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
    const uint8_t testData[TEST_DATA_LEN] = { 0 };
    AuthChannelData data = {
        .module = 0,
        .flag = 0,
        .seq = 0,
        .len = TEST_DATA_LEN,
        .data = nullptr,
    };
    int32_t ret;

    ret = AuthPostChannelData(channelId, &data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    channelId = 0;
    ret = AuthPostChannelData(channelId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    data.len = 0;
    ret = AuthPostChannelData(channelId, &data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    data.len = 0;
    data.data = testData;
    ret = AuthPostChannelData(channelId, &data);
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
    AuthSessionInfo info = { 0 };
    const SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };

    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    int32_t ret = AuthManagerSetSessionKey(authSeq, &info, &sessionKey, false, false);
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
    AuthSessionInfo info = { 0 };
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };

    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    int32_t ret = AuthManagerGetSessionKey(authSeq, &info, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
    const AuthVerifyCallback callback = { 0 };
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = AuthStartVerify(nullptr, requestId, &callback, AUTH_MODULE_LNN, true);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthStartVerify(&connInfo, requestId, nullptr, AUTH_MODULE_LNN, true);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_START_CONN_VERIFY_Test_001
 * @tc.desc: auth start conn verify test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_START_CONN_VERIFY_Test_001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    uint32_t requestId = 0;
    const AuthConnCallback callback = { 0 };
    int32_t ret;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthStartConnVerify(nullptr, requestId, &callback, AUTH_MODULE_LNN, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthStartConnVerify(&connInfo, requestId, &callback, AUTH_MODULE_LNN, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    ret = AuthFlushDevice(const_cast<const char *>(uuid));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthFlushDevice(const_cast<const char *>(uuid));
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_SEND_KEEPALIVE_OPTION_Test_001
 * @tc.desc: auth send keepalive test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SEND_KEEPALIVE_OPTION_Test_001, TestSize.Level1)
{
    char uuid[TEST_DATA_LEN] = "testdata";
    int32_t time = 0;
    int32_t ret;

    ret = AuthSendKeepaliveOption(nullptr, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthSendKeepaliveOption(uuid, (ModeCycle)time);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '\0';
    ret = AuthSendKeepaliveOption(const_cast<const char *>(uuid), HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthSendKeepaliveOption(const_cast<const char *>(uuid), HIGH_FREQ_CYCLE);
    EXPECT_NE(ret, SOFTBUS_OK);
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
    ret = AuthDeviceGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    uuid[0] = '1';
    ret = AuthDeviceGetPreferConnInfo(const_cast<const char *>(uuid), nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDeviceGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo);
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
    AuthHandle authHandle = { .authId = authId, .type = AUTH_LINK_TYPE_BLE };
    int32_t ret;
    const AuthTransData dataInfo = { 0 };
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthDevicePostTransData(authHandle, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDevicePostTransData(authHandle, &dataInfo);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = AuthDeviceGetIdByConnInfo(&connInfo, true);
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
    AuthLinkType type = AUTH_LINK_TYPE_WIFI;
    bool isServer = true;
    int64_t ret;
    ret = AuthDeviceGetIdByUuid(nullptr, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthDeviceGetIdByUuid(P2P_MAC2, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthDeviceGetIdByUuid(P2P_MAC, type, isServer);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
}

static void AuthOnDataReceived(AuthHandle authHandle, const AuthTransData *data)
{
    (void)authHandle;
    (void)data;
}

static void AuthOnDisconnected(AuthHandle authHandle)
{
    (void)authHandle;
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
    AuthTransListener listener = {
        .onDataReceived = AuthOnDataReceived,
        .onDisconnected = AuthOnDisconnected,
        .onException = NULL,
    };
    int32_t ret;
    ret = RegAuthTransListener(module, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = RegAuthTransListener(module, &listener);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    RegAuthTransListener(MODULE_UDP_INFO, &listener);
    UnregAuthTransListener(MODULE_UDP_INFO);
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
    ret = AuthGetPreferConnInfo(nullptr, &connInfo, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), nullptr, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), nullptr, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    uuid[0] = '\0';
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    uuid[0] = '1';
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = AuthGetPreferConnInfo(const_cast<const char *>(uuid), &connInfo, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const AuthConnCallback callback = { 0 };
    int32_t ret;

    (void)memset_s(&info, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = AuthOpenConn(nullptr, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn(&info, requestId, nullptr, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn(nullptr, requestId, nullptr, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn(&info, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    info.type = AUTH_LINK_TYPE_WIFI;
    ret = AuthOpenConn(&info, requestId, &callback, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenConn(&info, requestId, &callback, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    int32_t ret;
    const AuthTransData dataInfo = { 0 };
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthHandle authHandle = { .authId = 0, .type = info.connInfo.type };

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthPostTransData(authHandle, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthPostTransData(authHandle, &dataInfo);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    AuthCloseConn(authHandle);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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

    const GroupChangeListener listener = { 0 };
    ret = RegGroupChangeListener(&listener);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    UnregGroupChangeListener();
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
    ret = AuthGetIdByConnInfo(nullptr, true, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: AUTH_GET_ID_BY_P2P_MAC_Test_001
 * @tc.desc: auth get id by p2p mac test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_GET_ID_BY_P2P_MAC_Test_001, TestSize.Level1)
{
    AuthLinkType type;
    int64_t ret;

    type = AUTH_LINK_TYPE_BR;
    ret = AuthGetIdByUuid(nullptr, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthGetIdByUuid(nullptr, type, true, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = AuthGetIdByUuid(UUID_TEST, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthGetIdByUuid(UUID_TEST, type, true, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = AuthGetIdByUuid(UUID_TEST2, type, true, false);
    EXPECT_TRUE(ret == AUTH_INVALID_ID);
    ret = AuthGetIdByUuid(UUID_TEST2, type, true, true);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const uint8_t inData[CRYPT_DATA_LEN] = { 0 };
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t outData[CRYPT_DATA_LEN] = { 0 };
    uint32_t outLen = CRYPT_DATA_LEN;
    uint32_t errLen = 0;
    int32_t ret;
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthHandle authHandle = { .authId = authId, .type = AUTH_LINK_TYPE_WIFI };
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthEncrypt(&authHandle, nullptr, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(&authHandle, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(&authHandle, inData, inLen, outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(&authHandle, inData, errLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthEncrypt(&authHandle, inData, inLen, outData, &errLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    const uint8_t inData[CRYPT_DATA_LEN] = { 0 };
    uint32_t inLen = CRYPT_DATA_LEN;
    uint8_t outData[CRYPT_DATA_LEN] = { 0 };
    uint32_t outLen = CRYPT_DATA_LEN;
    uint32_t errLen = 0;
    int32_t ret;
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthHandle authHandle = { .authId = authId, .type = AUTH_LINK_TYPE_WIFI };
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthDecrypt(&authHandle, nullptr, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(&authHandle, inData, inLen, nullptr, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(&authHandle, inData, inLen, outData, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(&authHandle, inData, errLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(&authHandle, inData, inLen, outData, &errLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthDecrypt(&authHandle, inData, inLen, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_ENCRYPT_ERR);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
}

/*
 * @tc.name: AUTH_SET_P2P_MAC_Test_001
 * @tc.desc: auth set p2p mac test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SET_P2P_MAC_Test_001, TestSize.Level1)
{
    int64_t authId = 0;
    int32_t ret;
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthSetP2pMac(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthSetP2pMac(authId, P2P_MAC);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
    ret = AuthSetP2pMac(authId, P2P_MAC2);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;
    AuthHandle authHandle = { .authId = authId, .type = info.connInfo.type };
    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthGetConnInfo(authHandle, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthGetServerSide(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    int32_t ret;
    char uuid[TEST_DATA_LEN] = "testdata";
    uint16_t size = TEST_DATA_LEN;
    AuthSessionInfo info;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    (void)strcpy_s(info.udid, TEST_DATA_LEN, uuid);
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthGetDeviceUuid(authId, nullptr, size);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetDeviceUuid(authId, uuid, size);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    int32_t ret;
    SoftBusVersion version;
    AuthSessionInfo info;
    version = SOFTBUS_OLD_V1;

    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = true;
    info.connInfo.type = AUTH_LINK_TYPE_BLE;

    AuthManager *auth = NewAuthManager(authId, &info);
    EXPECT_TRUE(auth != nullptr);
    ret = AuthGetVersion(authId, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthGetVersion(authId, &version);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    DelAuthManager(auth, 0);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX + 1);
    DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
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
    EXPECT_NE(ret, SOFTBUS_OK);
    AuthDeinit();
}

static void AuthOnDataReceivedTest(AuthHandle authHandle, const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    (void)authHandle;
    (void)head;
    (void)data;
    (void)len;
}

static void AuthOnDisconnectedTest(AuthHandle authHandle)
{
    (void)authHandle;
}

/*
 * @tc.name: AUTH_INIT_Test_001
 * @tc.desc: auth init test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_DEVICE_INIT_Test_001, TestSize.Level1)
{
    int32_t ret;
    AuthTransCallback callBack = {
        .onDataReceived = AuthOnDataReceivedTest,
        .onDisconnected = AuthOnDisconnectedTest,
        .onException = NULL,
    };
    ret = AuthDeviceInit(&callBack);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = AuthDeviceInit(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: POST_AUTH_EVENT_INIT_Test_001
 * @tc.desc: post suth event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, POST_AUTH_EVENT_INIT_Test_001, TestSize.Level1)
{
    EventHandler handler = { 0 };
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
    ret = CompareConnInfo(&info1, &info2, false);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_BR;
    info2.type = AUTH_LINK_TYPE_BR;
    ret = CompareConnInfo(&info1, &info2, false);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_BLE;
    info2.type = AUTH_LINK_TYPE_BLE;
    ret = CompareConnInfo(&info1, &info2, false);
    EXPECT_TRUE(ret == true);
    info1.type = AUTH_LINK_TYPE_P2P;
    info2.type = AUTH_LINK_TYPE_P2P;
    ret = CompareConnInfo(&info1, &info2, false);
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
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_BLE;
    ret = ConvertToConnectOption(&connInfo, &option);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    connInfo.type = AUTH_LINK_TYPE_P2P;
    ret = ConvertToConnectOption(&connInfo, &option);
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
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    info.socketInfo.protocol = LNN_PROTOCOL_BR;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    info.type = CONNECT_BR;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    info.type = CONNECT_BLE;
    ret = ConvertToAuthConnInfo(&info, &connInfo);
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
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    const char *ip = "***.***.**.*";
    int32_t port = 22;
    int32_t ret;

    ret = AuthStartListening(AUTH_LINK_TYPE_WIFI, nullptr, port);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthStartListening(AUTH_LINK_TYPE_WIFI, ip, port);
    EXPECT_TRUE(ret != SOFTBUS_INVALID_PARAM);
    ret = AuthStartListening(AUTH_LINK_TYPE_P2P, ip, port);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM || ret == SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT);
}

/*
 * @tc.name: FIND_AUTH_REQUEST_BY_CONN_INFO_Test_001
 * @tc.desc: Find Auth Request By Conn Info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, FIND_AUTH_REQUEST_BY_CONN_INFO_Test_001, TestSize.Level1)
{
    AuthConnInfo *authConnInfo = nullptr;
    AuthRequest *request = nullptr;
    AuthConnInfo authConnInfoValue;
    AuthRequest requestValue;
    (void)memset_s(&authConnInfoValue, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    (void)memset_s(&requestValue, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    int32_t ret = FindAuthRequestByConnInfo(authConnInfo, request);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = FindAuthRequestByConnInfo(&authConnInfoValue, request);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CHECK_VERIFY_CALLBACK_Test_001
 * @tc.desc: Check Verify Callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, CHECK_VERIFY_CALLBACK_Test_001, TestSize.Level1)
{
    bool ret = CheckVerifyCallback(LnnGetVerifyCallback());
    EXPECT_TRUE(ret == true);
    ret = CheckVerifyCallback(nullptr);
    EXPECT_TRUE(ret == false);
    AuthVerifyCallback verifyCb = {
        .onVerifyPassed = nullptr,
        .onVerifyFailed = nullptr,
    };
    ret = CheckVerifyCallback(&verifyCb);
    EXPECT_TRUE(ret == false);

    uint32_t requestId = 0;
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_MAX };
    NodeInfo nodeinfo;
    (void)memset_s(&nodeinfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    PerformVerifyCallback(requestId, SOFTBUS_INVALID_PARAM, authHandle, &nodeinfo);
    authHandle.type = 0;
    PerformVerifyCallback(requestId, SOFTBUS_INVALID_PARAM, authHandle, &nodeinfo);
    authHandle.type = AUTH_LINK_TYPE_WIFI;
    PerformVerifyCallback(requestId, SOFTBUS_INVALID_PARAM, authHandle, &nodeinfo);
}

static void OnConnOpenedTest(uint32_t requestId, AuthHandle authHandle)
{
    AUTH_LOGI(AUTH_TEST, "requestId=%{public}d, authId=%{public}" PRId64, requestId, authHandle.authId);
}

static void OnConnOpenFailedTest(uint32_t requestId, int32_t reason)
{
    AUTH_LOGI(AUTH_TEST, "requestId=%{public}d, reason=%{public}d", requestId, reason);
}
/*
 * @tc.name: CHECK_AUTH_CONN_CALLBACK_Test_001
 * @tc.desc: Check Auth Conn Callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, CHECK_AUTH_CONN_CALLBACK_Test_001, TestSize.Level1)
{
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedTest,
        .onConnOpenFailed = OnConnOpenFailedTest,
    };
    AuthConnCallback connCb = {
        .onConnOpened = nullptr,
        .onConnOpenFailed = nullptr,
    };
    bool ret = CheckAuthConnCallback(nullptr);
    EXPECT_TRUE(ret == false);
    ret = CheckAuthConnCallback(&connCb);
    EXPECT_TRUE(ret == false);
    ret = CheckAuthConnCallback(&cb);
    EXPECT_TRUE(ret == true);

    AuthRequest request = { 0 };
    uint32_t requestId = 0;
    int64_t authId = 0;
    PerformAuthConnCallback(requestId, SOFTBUS_OK, authId);
    request.connCb = cb;
    int32_t result = AddAuthRequest(&request);
    EXPECT_EQ(result, SOFTBUS_OK);
    PerformAuthConnCallback(requestId, SOFTBUS_OK, authId);
}

/*
 * @tc.name: AUTH_SESSION_START_AUTH_Test_001
 * @tc.desc: Auth Session Start Auth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_START_AUTH_Test_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    uint64_t connId = 0;
    AuthConnInfo *connInfo = nullptr;
    AuthParam authInfo = {
        .authSeq = GenSeq(false),
        .requestId = requestId,
        .connId = connId,
        .isServer = false,
        .isFastAuth = true,
    };
    int32_t ret = AuthSessionStartAuth(&authInfo, connInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    AuthConnInfo authConnInfo;
    authConnInfo.type = AUTH_LINK_TYPE_WIFI;
    constexpr char NODE1_BR_MAC[] = "12345TTU";
    const char *ip = "***.***.**.*";
    (void)strcpy_s(authConnInfo.info.brInfo.brMac, BT_MAC_LEN, NODE1_BR_MAC);
    authConnInfo.info.ipInfo.port = 20;
    authConnInfo.info.ipInfo.authId = 1024;
    (void)strcpy_s(authConnInfo.info.ipInfo.ip, IP_LEN, ip);
    ret = AuthSessionStartAuth(&authInfo, &authConnInfo);
    EXPECT_TRUE(ret == SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: AUTH_SESSION_PROCESS_DEV_ID_DATA_Test_001
 * @tc.desc: Auth Session Process Dev Id Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_DEV_ID_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = AuthSessionProcessDevIdData(authSeq, data, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_SESSION_SAVE_SESSION_KEY_Test_001
 * @tc.desc: Auth Session Save Session Key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_SAVE_SESSION_KEY_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    uint8_t *key = nullptr;
    uint32_t len = 0;
    int32_t ret = AuthSessionSaveSessionKey(authSeq, key, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_SESSION_PROCESS_DEV_INFO_DATA_Test_001
 * @tc.desc: Auth Session Process Dev Info Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_DEV_INFO_DATA_Test_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    const uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = AuthSessionProcessDevInfoData(authSeq, data, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_SESSION_PROCESS_DEV_INFO_DATA_BY_CONN_ID_Test_001
 * @tc.desc: Auth Session Process Dev Info Data By Conn Id test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_DEV_INFO_DATA_BY_CONN_ID_Test_001, TestSize.Level1)
{
    int64_t connId = 0;
    bool isServer = false;
    const uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = AuthSessionProcessDevInfoDataByConnId(connId, isServer, data, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_SESSION_PROCESS_CLOSE_ACK_BY_CONN_ID_Test_001
 * @tc.desc: Auth Session Process Close Ack By Conn Id test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SESSION_PROCESS_CLOSE_ACK_BY_CONN_ID_Test_001, TestSize.Level1)
{
    int64_t connId = 0;
    bool isServer = false;
    const uint8_t *data = nullptr;
    uint32_t len = 0;
    int32_t ret = AuthSessionProcessCloseAckByConnId(connId, isServer, data, len);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DUP_SESSION_KEY_LIST_Test_001
 * @tc.desc: Dup Session Key List test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, DUP_SESSION_KEY_LIST_Test_001, TestSize.Level1)
{
    SessionKeyList *srcList = nullptr;
    SessionKeyList *dstList = nullptr;
    int32_t ret = DupSessionKeyList(srcList, dstList);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: HAS_SESSION_KEY_Test_001
 * @tc.desc: Has Session Key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, HAS_SESSION_KEY_Test_001, TestSize.Level1)
{
    SessionKeyList *list = nullptr;
    int32_t ret = HasSessionKey(list);
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: ADD_SESSION_KEY_Test_001
 * @tc.desc: Add Session Key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, ADD_SESSION_KEY_Test_001, TestSize.Level1)
{
    SessionKeyList *list = nullptr;
    int32_t index = 0;
    SessionKey *key = nullptr;
    SessionKey keyValue;
    SessionKeyList listValue;
    int32_t ret = AddSessionKey(list, index, key, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    (void)memset_s(&keyValue, sizeof(SessionKey), 0, sizeof(SessionKey));
    (void)memset_s(&listValue, sizeof(SessionKeyList), 0, sizeof(SessionKeyList));
    ListInit(&listValue);
    ret = AddSessionKey(&listValue, index, &keyValue, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ENCRYPT_DATA_Test_001
 * @tc.desc: Encrypt Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, ENCRYPT_DATA_Test_001, TestSize.Level1)
{
    SessionKeyList *list = nullptr;
    SessionKeyList listValue;
    (void)memset_s(&listValue, sizeof(SessionKeyList), 0, sizeof(SessionKeyList));
    uint8_t indata[TEST_DATA_LEN] = "1234";
    uint8_t outData[TEST_DATA_LEN];
    uint32_t outLen = TEST_DATA_LEN;
    InDataInfo inDataInfo = { .inData = indata, .inLen = TEST_DATA_LEN };
    int32_t ret = EncryptData(list, AUTH_LINK_TYPE_WIFI, &inDataInfo, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: DECRYPT_DATA_Test_001
 * @tc.desc: Decrypt Data test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, DECRYPT_DATA_Test_001, TestSize.Level1)
{
    SessionKeyList *list = nullptr;
    uint8_t indata[TEST_DATA_LEN] = "1234";
    uint8_t outData[TEST_DATA_LEN];
    uint32_t outLen = TEST_DATA_LEN;
    InDataInfo inDataInfo = { .inData = indata, .inLen = ENCRYPT_OVER_HEAD_LEN_TEST + 1 };
    int32_t ret = DecryptData(list, AUTH_LINK_TYPE_WIFI, &inDataInfo, outData, &outLen);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UNPACK_DEVICE_INFO_MESSAGE_Test_001
 * @tc.desc: Unpack Device Info Message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, UNPACK_DEVICE_INFO_MESSAGE_Test_001, TestSize.Level1)
{
    const char *msg = "";
    int32_t linkType = 1;
    SoftBusVersion version = SOFTBUS_OLD_V1;
    NodeInfo nodeInfo;
    AuthSessionInfo info;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    bool isMetaAuth = false;
    DevInfoData devInfo = { msg, 0, linkType, version };
    int32_t ret = UnpackDeviceInfoMessage(&devInfo, &nodeInfo, isMetaAuth, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: POST_DEVICE_ID_MESSAGE_Test_001
 * @tc.desc: Post Device Id Message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, POST_DEVICE_ID_MESSAGE_Test_001, TestSize.Level1)
{
    AuthSessionInfo *info = nullptr;
    AuthSessionInfo infoValue;
    (void)memset_s(&infoValue, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    int32_t ret = PostDeviceIdMessage(GenSeq(false), info);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = PostDeviceIdMessage(GenSeq(false), &infoValue);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_DEVICE_ID_MESSAGE_Test_001
 * @tc.desc: Process Device Id Message test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, PROCESS_DEVICE_ID_MESSAGE_Test_001, TestSize.Level1)
{
    AuthSessionInfo *info = nullptr;
    AuthSessionInfo infoValue;
    (void)memset_s(&infoValue, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    uint8_t data[TEST_DATA_LEN] = "123";
    int32_t ret = ProcessDeviceIdMessage(info, data, sizeof(data));
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = ProcessDeviceIdMessage(&infoValue, data, sizeof(data));
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: SET_SOCKET_CALLBACK_Test_001
 * @tc.desc: Set Socket Callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, SET_SOCKET_CALLBACK_Test_001, TestSize.Level1)
{
    const SocketCallback *cb = nullptr;
    int32_t ret = SetSocketCallback(cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SOCKET_POST_BYTES_Test_001
 * @tc.desc: Socket Post Bytes test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, SOCKET_POST_BYTES_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    const AuthDataHead *head = NULL;
    const uint8_t *data = NULL;
    int32_t ret = SocketPostBytes(fd, head, data);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    AuthDataHead headValue;
    uint8_t dataValue[TEST_DATA_LEN] = "123";
    (void)memset_s(&headValue, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    ret = SocketPostBytes(fd, &headValue, dataValue);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOCKET_GET_CONN_INFO_Test_001
 * @tc.desc: Socket Get Conn Info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, SOCKET_GET_CONN_INFO_Test_001, TestSize.Level1)
{
    int32_t fd = 0;
    AuthConnInfo *connInfo = NULL;
    bool isServer = false;
    int32_t ret = SocketGetConnInfo(fd, connInfo, &isServer);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    AuthConnInfo connInfoValue;
    (void)memset_s(&connInfoValue, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    ret = SocketGetConnInfo(fd, &connInfoValue, &isServer);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: REG_AUTH_CHANNEL_LISTENER_Test_001
 * @tc.desc: Reg Auth Channel Listener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, REG_AUTH_CHANNEL_LISTENER_Test_001, TestSize.Level1)
{
    int32_t module = MODULE_AUTH_CHANNEL;
    const AuthChannelListener *listener = nullptr;
    int32_t ret = RegAuthChannelListener(module, listener);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_OPEN_CHANNEL_Test_001
 * @tc.desc: Auth Open Channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_OPEN_CHANNEL_Test_001, TestSize.Level1)
{
    char *ip = nullptr;
    char ipValue[32] = "0";
    int32_t port = 22;
    int32_t ret = AuthOpenChannel(ip, port);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
    ret = AuthOpenChannel(ipValue, port);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
}

/*
 * @tc.name: AUTH_GET_DECRYPT_SIZE_Test_001
 * @tc.desc: Auth Get Decrypt Size test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_GET_DECRYPT_SIZE_Test_001, TestSize.Level1)
{
    uint32_t inLen = OVERHEAD_LEN;
    uint32_t ret = AuthGetDecryptSize(inLen);
    EXPECT_TRUE(ret == OVERHEAD_LEN);
    inLen = OVERHEAD_LEN + 1;
    ret = AuthGetDecryptSize(inLen);
    EXPECT_TRUE(ret == (inLen - OVERHEAD_LEN));
}

/*
 * @tc.name: NOTIFY_TRANS_DATA_RECEIVED_Test_001
 * @tc.desc: Notify Trans Data Received test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, NOTIFY_TRANS_DATA_RECEIVED_Test_001, TestSize.Level1)
{
    AuthTransListener listener = {
        .onDataReceived = AuthOnDataReceived,
        .onDisconnected = AuthOnDisconnected,
        .onException = NULL,
    };
    int32_t ret;
    ret = RegAuthTransListener(MODULE_UDP_INFO, &listener);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    AuthDataHead head = {
        .dataType = 0,
        .module = MODULE_UDP_INFO,
        .seq = 0,
        .flag = 0,
        .len = 20,
    };
    const char *data = "1111222233334444";
    uint32_t len = 0;
    NotifyTransDataReceived(authHandle, &head, reinterpret_cast<const uint8_t *>(data), len);
    NotifyTransDisconnected(authHandle);
    NotifyTransException(authHandle, SOFTBUS_INVALID_PARAM);
    UnregAuthTransListener(MODULE_UDP_INFO);
}

/*
 * @tc.name: AUTH_ON_CONNECT_EVENT_Test_001
 * @tc.desc: Auth On Connect Event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_ON_CONNECT_EVENT_Test_001, TestSize.Level1)
{
    ListenerModule module = AUTH;
    int32_t cfd = 0;
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = OnConnectEvent(module, cfd, &option);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetLatestAvailableSessionKeyTimeTest
 * @tc.desc: set and get session key available sessionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SET_AND_SET_SESSIONKEY_AVAILABLE_Test_001, TestSize.Level1)
{
    SessionKeyList list = { 0 };
    SessionKey sessionKey = { { 0 }, TEST_DATA_LEN };
    int32_t index = 0;
    ListInit(&list);
    int32_t ret = AddSessionKey(&list, index, &sessionKey, AUTH_LINK_TYPE_WIFI, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    uint64_t time = GetLatestAvailableSessionKeyTime(&list, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(time == 0);
    ret = SetSessionKeyAvailable(&list, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    time = GetLatestAvailableSessionKeyTime(&list, AUTH_LINK_TYPE_WIFI);
    EXPECT_TRUE(time != 0);
    DestroySessionKeyList(&list);
}

/*
 * @tc.name: AUTH_SET_TCP_KEEPALIVE_OPTION_Test_001
 * @tc.desc: Auth Set Tcp Keepalive option test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SET_TCP_KEEPALIVE_OPTION_Test_001, TestSize.Level1)
{
    int32_t fd = -1;
    int32_t cycle = 0;

    int32_t ret = AuthSetTcpKeepaliveOption(fd, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    fd = 0;
    ret = AuthSetTcpKeepaliveOption(fd, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    fd = 1;
    ret = AuthSetTcpKeepaliveOption(fd, (ModeCycle)cycle);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    cycle = KEEPALIVE_TIME;
    ret = AuthSetTcpKeepaliveOption(fd, (ModeCycle)cycle);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AUTH_SET_TCP_KEEPALIVE_OPTION_Test_002
 * @tc.desc: Auth Set Tcp Keepalive option test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SET_TCP_KEEPALIVE_OPTION_Test_002, TestSize.Level1)
{
    int32_t fd = 1;

    int32_t ret = AuthSetTcpKeepaliveOption(fd, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_ADAPTER_ERR);
    ret = AuthSetTcpKeepaliveOption(fd, MID_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_ADAPTER_ERR);
    ret = AuthSetTcpKeepaliveOption(fd, LOW_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_ADAPTER_ERR);
    ret = AuthSetTcpKeepaliveOption(fd, DEFAULT_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_ADAPTER_ERR);
}

/*
 * @tc.name: AUTH_SET_TCP_KEEPALIVE_OPTION_Test_003
 * @tc.desc: Auth Set Tcp Keepalive option test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_SET_TCP_KEEPALIVE_OPTION_Test_003, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);

    int32_t port = CLIENT_PORT;
    char ipAddress[] = "127.0.0.1";
    LocalListenerInfo info = {};
    info.type = CONNECT_TCP;
    info.socketOption.port = port;
    info.socketOption.moduleId = DIRECT_CHANNEL_SERVER_WIFI;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    (void)strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ipAddress);
    int32_t fd = tcp->OpenServerSocket(&info);

    int32_t ret = AuthSetTcpKeepaliveOption(fd, HIGH_FREQ_CYCLE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GET_TCP_KEEPALIVE_OPTION_BY_CYCLE_Test_001
 * @tc.desc: Get Tcp Keepalive Option By Cycle test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, GET_TCP_KEEPALIVE_OPTION_BY_CYCLE_Test_001, TestSize.Level1)
{
    TcpKeepaliveOption tcpKeepaliveOption = { 0 };

    int32_t ret = GetTcpKeepaliveOptionByCycle(HIGH_FREQ_CYCLE, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = GetTcpKeepaliveOptionByCycle((ModeCycle)tcpKeepaliveOption.keepaliveIdle, &tcpKeepaliveOption);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = GetTcpKeepaliveOptionByCycle(HIGH_FREQ_CYCLE, &tcpKeepaliveOption);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetTcpKeepaliveOptionByCycle(MID_FREQ_CYCLE, &tcpKeepaliveOption);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetTcpKeepaliveOptionByCycle(LOW_FREQ_CYCLE, &tcpKeepaliveOption);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetTcpKeepaliveOptionByCycle(DEFAULT_FREQ_CYCLE, &tcpKeepaliveOption);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: IS_ENHANCE_P2P_MODULE_ID_Test_001
 * @tc.desc: IsEnhanceP2pModuleId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, IS_ENHANCE_P2P_MODULE_ID_Test_001, TestSize.Level1)
{
    EXPECT_EQ(IsEnhanceP2pModuleId(AUTH_ENHANCED_P2P_START), true);
    EXPECT_EQ(IsEnhanceP2pModuleId(DIRECT_CHANNEL_SERVER_P2P), false);
    EXPECT_EQ(IsEnhanceP2pModuleId(AUTH_P2P), false);
}

/*
 * @tc.name: AUTH_GET_CONNINFO_BY_TYPE_Test_001
 * @tc.desc: AuthGetConnInfoByType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTest, AUTH_GET_CONNINFO_BY_TYPE_Test_001, TestSize.Level1)
{
    const char *uuid = "12345678";
    AuthConnInfo connInfo;

    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = AuthGetConnInfoByType(uuid, AUTH_LINK_TYPE_WIFI, &connInfo, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AuthGetConnInfoByType(nullptr, AUTH_LINK_TYPE_WIFI, &connInfo, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
