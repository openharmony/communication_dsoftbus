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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.c"
#include "trans_auth_mock.h"
#include "trans_common_mock.h"
#include "trans_conn_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_INVALID_HEAD_VERSION 2
#define TEST_MESSAGE_CHANNEL_ID 44
#define TEST_PARSE_MESSAGE_CHANNEL 45

#define TEST_AUTH_DECRYPT_SIZE 35
#define TEST_UDID_MAX_LENGTH 32
#define TEST_CONN_ID 1795

class TransProxyMessageTest : public testing::Test {
public:
    TransProxyMessageTest()
    {}
    ~TransProxyMessageTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProxyMessageTest::SetUpTestCase(void)
{}

void TransProxyMessageTest::TearDownTestCase(void)
{}

void TestMessageAddProxyChannel(int32_t channelId, AppType appType, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid).Times(0);

    AppInfo appInfo;
    ProxyChannelInfo *chan = static_cast<ProxyChannelInfo *>(SoftBusCalloc(sizeof(ProxyChannelInfo)));
    ASSERT_TRUE(nullptr != chan);
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = appType;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(chan);
}

int32_t TestGetUidAndPidSuccess(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidFail(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    return SOFTBUS_INVALID_PARAM;
}

void TestCallbackSuccess(void)
{
    IServerChannelCallBack cb;
    cb.GetUidAndPidBySessionName = TestGetUidAndPidSuccess;
    int32_t ret = TransProxySetCallBack(&cb);
    ASSERT_EQ(SOFTBUS_OK, ret);
}


void TestCallbackFail(void)
{
    IServerChannelCallBack cb;
    cb.GetUidAndPidBySessionName = TestGetUidAndPidFail;
    int32_t ret = TransProxySetCallBack(&cb);
    ASSERT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetRemoteUdidByBtMac001
 * @tc.desc: test get remote udid by btMac.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, GetRemoteUdidByBtMac001, TestSize.Level1)
{
    const char *peerMac = "ed:7f:06:60:88";
    char udid[TEST_UDID_MAX_LENGTH] = "84D6F03Q9B88";

    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByBtMac).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_GET_REMOTE_UUID_ERR));
    int32_t ret = GetRemoteUdidByBtMac(peerMac, udid, TEST_UDID_MAX_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_GET_REMOTE_UUID_ERR);
}

/**
 * @tc.name: GetRemoteUdidByBtMac002
 * @tc.desc: test get remote udid by btMac.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, GetRemoteUdidByBtMac002, TestSize.Level1)
{
    const char *peerMac = "ed:7f:06:60:88";
    char udid[TEST_UDID_MAX_LENGTH] = "84D6F03Q9B88";

    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByBtMac).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetRemoteUdidByBtMac(peerMac, udid, TEST_UDID_MAX_LENGTH);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: GetRemoteBtMacByUdidHash001
 * @tc.desc: test get remote btMac byUdidHash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, GetRemoteBtMacByUdidHash001, TestSize.Level1)
{
    uint8_t udidHash[UDID_HASH_LEN] = "default_udid_hash";
    char brMac[BT_MAC_LEN] = {0};

    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUdidHash).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_GET_REMOTE_UUID_ERR));
    int32_t ret = GetRemoteBtMacByUdidHash(udidHash, UDID_HASH_LEN, brMac, BT_MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_GET_REMOTE_UUID_ERR);
}

/**
 * @tc.name: GetRemoteBtMacByUdidHash002
 * @tc.desc: test get remote btMac byUdidHash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, GetRemoteBtMacByUdidHash002, TestSize.Level1)
{
    uint8_t udidHash[UDID_HASH_LEN] = "default_udid_hash";
    char brMac[BT_MAC_LEN] = {0};

    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, LnnGetNetworkIdByUdidHash).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetRemoteBtMacByUdidHash(udidHash, UDID_HASH_LEN, brMac, BT_MAC_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name:TransProxyGetAuthConnInfo001
 * @tc.desc: test get auth connInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyGetAuthConnInfo001, TestSize.Level1)
{
    ConnectionInfo mockInfo;
    mockInfo.type = CONNECT_TCP;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillOnce(DoAll(SetArgPointee<1>(mockInfo), Return(SOFTBUS_OK)));

    AuthConnInfo authConnInfo;
    int32_t ret = TransProxyGetAuthConnInfo(TEST_CONN_ID, &authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name:TransProxyGetAuthConnInfo002
 * @tc.desc: test get auth connInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyGetAuthConnInfo002, TestSize.Level1)
{
    ConnectionInfo mockInfo;
    mockInfo.type = CONNECT_BR;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillOnce(DoAll(SetArgPointee<1>(mockInfo), Return(SOFTBUS_OK)));

    AuthConnInfo authConnInfo;
    int32_t ret = TransProxyGetAuthConnInfo(TEST_CONN_ID, &authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name:TransProxyGetAuthConnInfo003
 * @tc.desc: test get auth connInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyGetAuthConnInfo003, TestSize.Level1)
{
    ConnectionInfo mockInfo;
    mockInfo.type = CONNECT_BLE;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillOnce(DoAll(SetArgPointee<1>(mockInfo), Return(SOFTBUS_OK)));

    AuthConnInfo authConnInfo;
    int32_t ret = TransProxyGetAuthConnInfo(TEST_CONN_ID, &authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name:TransProxyGetAuthConnInfo004
 * @tc.desc: test get auth connInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyGetAuthConnInfo004, TestSize.Level1)
{
    ConnectionInfo mockInfo;
    mockInfo.type = CONNECT_TYPE_MAX;

    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillOnce(DoAll(SetArgPointee<1>(mockInfo), Return(SOFTBUS_OK)));

    AuthConnInfo authConnInfo;
    int32_t ret = TransProxyGetAuthConnInfo(TEST_CONN_ID, &authConnInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UNEXPECTED_CONN_TYPE);
}

/**
 * @tc.name:PackHandshakeMsgForFastData001
 * @tc.desc: test pack handShakeMsg for fastData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, PackHandshakeMsgForFastData001, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        TRANS_LOGE(TRANS_TEST, "create json object failed");
        return;
    }
    appInfo.fastTransDataSize = 250;
    appInfo.routeType = BT_BR;
    appInfo.businessType = BUSINESS_TYPE_MESSAGE;

    int32_t ret = PackHandshakeMsgForFastData(&appInfo, root);
    ASSERT_NE(ret, SOFTBUS_MALLOC_ERR);

    ret = PackHandshakeMsgForFastData(&appInfo, root);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PACK_FAST_DATA_FAILED);

    cJSON_Delete(root);
}

/**
 * @tc.name: TransProxyHandshakeErrMsgTest001
 * @tc.desc: test pack or unpack handshake err message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeErrMsgTest001, TestSize.Level1)
{
    char *msg = TransProxyPackHandshakeErrMsg(SOFTBUS_MEM_ERR);
    ASSERT_TRUE(msg != nullptr);

    int32_t ret = TransProxyUnPackHandshakeErrMsg(msg, nullptr, strlen(msg));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    int32_t errCode = SOFTBUS_OK;
    ret = TransProxyUnPackHandshakeErrMsg(msg, &errCode, strlen(msg));
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeAckMsgTest001
 * @tc.desc: test pack or unpack handshake ack message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeAckMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    ProxyChannelInfo outChannel;
    uint16_t fastDataSize;
    chan.appInfo.appType = APP_TYPE_NOT_CARE;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    EXPECT_EQ(nullptr, msg);

    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.channelId = -1;
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(msg != nullptr);
    int32_t ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, strlen(msg), &fastDataSize);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);

    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    TestMessageAddProxyChannel(chan.channelId, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(msg != nullptr);
    outChannel.myId = chan.channelId;
    ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, strlen(msg), &fastDataSize);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeAckMsgTest002
 * @tc.desc: test pack or unpack handshake ack message, test normal app type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeAckMsgTest002, TestSize.Level1)
{
    ProxyChannelInfo chan;
    ProxyChannelInfo outChannel;
    uint16_t fastDataSize;

    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(msg != nullptr);

    int32_t ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, strlen(msg), &fastDataSize);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE, ret);

    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeMsgTest001
 * @tc.desc: test pack or unpack handshake normal message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeMsgTest001, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    ProxyChannelInfo outChannel;

    info.appInfo.appType = APP_TYPE_NORMAL;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(nullptr, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(msg != nullptr);

    TestCallbackFail();
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);

    TestCallbackSuccess();
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);

    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeMsgTest002
 * @tc.desc: test pack or unpack handshake auth message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeMsgTest002, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(nullptr, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(msg != nullptr);

    ProxyChannelInfo outChannel;
    TestCallbackFail();
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_OK, ret);

    TestCallbackSuccess();
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_OK, ret);

    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeMsgTest003
 * @tc.desc: test pack or unpack handshake inner message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeMsgTest003, TestSize.Level1)
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_INNER;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(nullptr, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(msg != nullptr);

    ProxyChannelInfo outChannel;
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, strlen(msg));
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);

    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyIdentityMsgTest001
 * @tc.desc: test pack or unpack identity message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyIdentityMsgTest001, TestSize.Level1)
{
    char identity[TEST_CHANNEL_IDENTITY_LEN] = "test-identity";
    char *msg = TransProxyPackIdentity(identity);
    ASSERT_TRUE(msg != nullptr);

    int32_t ret = TransProxyUnpackIdentity(msg, identity, TEST_CHANNEL_IDENTITY_LEN, strlen(msg));
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyPackMessageTest001
 * @tc.desc: TransProxyPackMessageTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyPackMessageTest001, TestSize.Level1)
{
    ProxyMessageHead msg;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    ProxyDataInfo dataInfo;
    int32_t ret = TransProxyPackMessage(nullptr, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPackMessage(&msg, authHandle, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    dataInfo.inData = nullptr;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    dataInfo.inData = 0;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    dataInfo.inData = reinterpret_cast<uint8_t *>(const_cast<char *>("1"));
    dataInfo.inLen = strlen((const char *)dataInfo.inData);
    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProxyPackMessageTest002
 * @tc.desc: TransProxyPackMessageTest002, use normal param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyPackMessageTest002, TestSize.Level1)
{
    ProxyMessageHead msg;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    ProxyDataInfo dataInfo;

    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).Times(0);

    dataInfo.inData = reinterpret_cast<uint8_t *>(const_cast<char *>("12345"));
    dataInfo.inLen = strlen((const char *)dataInfo.inData);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    int32_t ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
  * @tc.name: TransProxyParseMessageTest001
  * @tc.desc: TransProxyParseMessageTest001, use wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyParseMessageTest001, TestSize.Level1)
{
    ProxyMessage msg;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    int32_t len = sizeof(ProxyMessage);
    char *buf = static_cast<char *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(buf != nullptr);

    int32_t ret = TransProxyParseMessage(buf, PROXY_CHANNEL_HEAD_LEN, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (TEST_INVALID_HEAD_VERSION << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    msg.msgHead.cipher = 0;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = -1;
    ASSERT_TRUE(memcpy_s(buf, len, &msg, len) == EOK);
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyParseMessageTest002
  * @tc.desc: TransProxyParseMessageTest002, use normal param, run normal message
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyParseMessageTest002, TestSize.Level1)
{
    ProxyMessage msg, outMsg;
    int32_t len = sizeof(ProxyMessage);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    char *buf = static_cast<char *>(SoftBusCalloc(sizeof(ProxyMessage)));
    ASSERT_TRUE(buf != nullptr);
    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    TestMessageAddProxyChannel(TEST_PARSE_MESSAGE_CHANNEL, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);

    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthGetDecryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthDecrypt).Times(0);

    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    int32_t ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyAckHandshakeTest001
  * @tc.desc: TransProxyAckHandshakeTest001, use wrong param and normal param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyAckHandshakeTest001, TestSize.Level1)
{
    int32_t retCode = -1;
    uint32_t connId = -1;
    ProxyChannelInfo channelInfo;

    int32_t ret = TransProxyAckHandshake(connId, nullptr, retCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    retCode = SOFTBUS_OK;
    channelInfo.appInfo.appType = APP_TYPE_NOT_CARE;
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);

    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    retCode = SOFTBUS_MEM_ERR;
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);

    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyResetPeerTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo chanInfo;

    int32_t ret = TransProxyResetPeer(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    chanInfo.appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);

    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
