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

#include <securec.h>

#include "gtest/gtest.h"

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_callback.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_transmission_interface.h"
#include "trans_auth_mock.h"
#include "trans_common_mock.h"
#include "trans_conn_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_BASE_ENCODE_LEN 32
#define TEST_INVALID_HEAD_VERSION 2
#define TEST_MESSAGE_CHANNEL_ID 44
#define TEST_PARSE_MESSAGE_CHANNEL 45

#define TEST_AUTH_DECRYPT_SIZE 35

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
{
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, GenerateRandomStr).WillRepeatedly(Return(SOFTBUS_OK));

    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());

    IServerChannelCallBack callBack;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnSetConnectCallback).WillRepeatedly(Return(SOFTBUS_OK));
    ASSERT_EQ(SOFTBUS_OK, TransProxyManagerInit(&callBack));
}

void TransProxyMessageTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestMessageAddProxyChannel(int32_t channelId, AppType appType, const char *identity, ProxyChannelStatus status)
{
    TransCommInterfaceMock commMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(commMock, SoftBusGenerateRandomArray)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetLatestIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));

    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authId = channelId;
    chan->connId = channelId;
    chan->myId = channelId;
    chan->peerId = channelId;
    chan->reqId = channelId;
    chan->channelId = channelId;
    chan->seq = channelId;
    (void)strcpy_s(chan->identity, TEST_CHANNEL_IDENTITY_LEN, identity);
    chan->status = status;
    appInfo.appType = appType;
    int32_t ret = TransProxyCreateChanInfo(chan, chan->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
 * @tc.name: TransProxyHandshakeErrMsgTest001
 * @tc.desc: test pack or unpack handshake err message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeErrMsgTest001, TestSize.Level1)
{
    char* msg = TransProxyPackHandshakeErrMsg(SOFTBUS_MEM_ERR);
    ASSERT_TRUE(NULL != msg);

    int32_t ret = TransProxyUnPackHandshakeErrMsg(msg, nullptr, sizeof(msg));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    int32_t errCode = SOFTBUS_OK;
    ret = TransProxyUnPackHandshakeErrMsg(msg, &errCode, sizeof(msg));
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
    int32_t ret = SOFTBUS_OK;

    ProxyChannelInfo chan;
    ProxyChannelInfo outChannel;
    chan.appInfo.appType = APP_TYPE_NOT_CARE;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    EXPECT_EQ(NULL, msg);

    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.channelId = -1;
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);
    ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    TestMessageAddProxyChannel(chan.channelId, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);
    outChannel.myId = chan.channelId;
    ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);
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

    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);

    int32_t ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

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
    EXPECT_CALL(commMock, SoftBusBase64Encode)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = SOFTBUS_MEM_ERR;
    ProxyChannelInfo info;
    ProxyChannelInfo outChannel;

    info.appInfo.appType = APP_TYPE_NORMAL;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(NULL, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg);

    TestCallbackFail();
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

    TestCallbackSuccess();
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

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
    EXPECT_CALL(commMock, GenerateRandomStr)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(NULL, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg);

    ProxyChannelInfo outChannel;
    TestCallbackFail();
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

    TestCallbackSuccess();
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

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
    EXPECT_CALL(commMock, SoftBusBase64Encode)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_INNER;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_EQ(NULL, msg);
    msg = TransProxyPackHandshakeMsg(&info);
    ASSERT_TRUE(NULL != msg);

    ProxyChannelInfo outChannel;
    int32_t ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyUnpackHandshakeMsg(msg, &outChannel, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

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
    char identity[TEST_CHANNEL_IDENTITY_LEN] = "test identity";
    char* msg = TransProxyPackIdentity(identity);
    ASSERT_TRUE(NULL != msg);

    int32_t ret = TransProxyUnpackIdentity(msg, identity, TEST_CHANNEL_IDENTITY_LEN, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);
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
    int32_t ret = TransProxyPackMessage(NULL, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyPackMessage(&msg, authHandle, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = NULL;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = 0;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataInfo.inData = (uint8_t *)"1";
    dataInfo.inLen = strlen((const char*)dataInfo.inData);
    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
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
    int64_t authId = AUTH_INVALID_ID;
    ProxyDataInfo dataInfo;

    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(connMock, ConnGetHeadSize)
        .WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize)
        .WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    dataInfo.inData = (uint8_t *)"12345";
    dataInfo.inLen = strlen((const char*)dataInfo.inData);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    int32_t ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    authId = 1;
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPackMessage(&msg, authId, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    int32_t len = sizeof(ProxyMessage);
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);

    /* test invalid len */
    int32_t ret = TransProxyParseMessage(buf, PROXY_CHANNEL_HEAD_LEN, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test invalid head version */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (TEST_INVALID_HEAD_VERSION << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test invalid head type */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test message no encrypte */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    msg.msgHead.cipher = 0;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test normal message encrypte, and channel not exist */
    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = -1;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

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
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);
    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    TestMessageAddProxyChannel(TEST_PARSE_MESSAGE_CHANNEL, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);

    /* test normal message encrypte */
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthGetDecryptSize)
        .WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthDecrypt)
        .WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));

    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    int32_t ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyParseMessageTest003
  * @tc.desc: TransProxyParseMessageTest003, use normal param, run handshark message
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyParseMessageTest003, TestSize.Level1)
{
    ProxyMessage msg, outMsg;
    int32_t len = sizeof(ProxyMessage);
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);

    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(authMock, AuthGetDecryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthDecrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, AuthGetIdByConnInfo).WillRepeatedly(Return(1));
    EXPECT_CALL(authMock, LnnGetNetworkIdByBtMac).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    TransConnInterfaceMock connMock;
    ConnectionInfo errInfo;
    errInfo.type = CONNECT_TYPE_MAX;
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    ConnectionInfo brInfo;
    brInfo.type = CONNECT_BR;
    EXPECT_CALL(connMock, ConnGetConnectionInfo).WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillOnce(DoAll(SetArgPointee<1>(errInfo), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(tcpInfo), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(brInfo), Return(SOFTBUS_OK)));
    TransCommInterfaceMock commMock;
    EXPECT_CALL(commMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));

    /* test get auth connection info or type err */
    int32_t ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth connection type is invalid */
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth connection type is tcp, and isBr is false */
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    /* test auth connection type is tcp, and isBr is true */
    msg.msgHead.cipher |= USE_BLE_CIPHER;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    /* test connection type is br */
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyTransSendMsgTest001
  * @tc.desc: TransProxyTransSendMsgTest001, use wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyTransSendMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    int32_t priority = 0;
    const char *payLoad = "test payload data";
    uint32_t payLoadLen = strlen(payLoad);

    /* test info is null */
    int32_t ret = TransProxySendMessage(NULL, payLoad, payLoadLen, priority);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test appType no auth */
    info.appInfo.appType = APP_TYPE_INNER;
    info.authId = -1;
    ret = TransProxySendMessage(&info, payLoad, payLoadLen, priority);
    EXPECT_NE(SOFTBUS_OK, ret);

    TransAuthInterfaceMock authMock;
    TransConnInterfaceMock connMock;
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(Return(SOFTBUS_OK));

    info.authId = 1;
    ret = TransProxySendMessage(&info, payLoad, payLoadLen, priority);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxySendMessage(&info, payLoad, payLoadLen, priority);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyHandshakeTest001
  * @tc.desc: TransProxyHandshakeTest001, use wrong param and normal param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ProxyChannelInfo info;
    info.channelId = -1;
    info.appInfo.appType = APP_TYPE_INNER;
    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    TransCommInterfaceMock commMock;

    /* test info is null */
    ret = TransProxyHandshake(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test appType no auth and invalid channel */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);

    AuthConnInfo wifiInfo, bleInfo;
    wifiInfo.type = AUTH_LINK_TYPE_WIFI;
    bleInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(authMock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillOnce(DoAll(SetArgPointee<1>(wifiInfo), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(wifiInfo), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(bleInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(authMock, AuthGetServerSide).WillOnce(Return(SOFTBUS_MEM_ERR))
        .WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<1>(true), Return(SOFTBUS_OK)));
    info.channelId = TEST_PARSE_MESSAGE_CHANNEL;
    /* test auth mock get auth conn info fail */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth mock get auth server side fail */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack handshake msg failed after pass set cipher */
    EXPECT_CALL(commMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message failed after pass packhandshakemsg */
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message success and send msg fail */
    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test send msg success */
    ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    /* test channelInfo is null */
    int32_t ret = TransProxyAckHandshake(connId, NULL, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test payLoad is NULL */
    retCode = SOFTBUS_OK;
    channelInfo.appInfo.appType = APP_TYPE_NOT_CARE;
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test retCode not SOFTBUS_OK and pack message fail */
    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    retCode = SOFTBUS_MEM_ERR;
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message success and send fail */
    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyKeepAliveTest001
  * @tc.desc: test proxy keepalive and keepalive ack message.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(TransProxyMessageTest, TransProxyKeepAliveTest001, TestSize.Level1)
{
    ProxyChannelInfo chanInfo;
    uint32_t connId = -1;
    TransProxyKeepalive(connId, NULL);

    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    chanInfo.appInfo.appType = APP_TYPE_INNER;
    /* test auth encrypt fail */
    TransProxyKeepalive(connId, &chanInfo);
    /* test send msg fail */
    TransProxyKeepalive(connId, &chanInfo);
    /* test app type is auth */
    chanInfo.appInfo.appType = APP_TYPE_AUTH;
    TransProxyKeepalive(connId, &chanInfo);
    /* test ack keepalive info null */
    int32_t ret = TransProxyAckKeepalive(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message fail */
    chanInfo.appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyAckKeepalive(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test send message fail and pack success */
    ret = TransProxyAckKeepalive(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    chanInfo.appInfo.appType = APP_TYPE_AUTH;
    ret = TransProxyAckKeepalive(&chanInfo);
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

    int32_t ret = TransProxyResetPeer(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    TransConnInterfaceMock connMock;
    TransAuthInterfaceMock authMock;
    EXPECT_CALL(connMock, ConnGetHeadSize).WillRepeatedly(Return(sizeof(ConnPktHead)));
    EXPECT_CALL(authMock, AuthGetEncryptSize).WillRepeatedly(Return(TEST_AUTH_DECRYPT_SIZE));
    EXPECT_CALL(authMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(connMock, ConnPostBytes).WillOnce(Return(SOFTBUS_MEM_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    /* test apptype is inner, and pack message fail */
    chanInfo.appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test send msg fail */
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test apptype is auth, and success */
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
