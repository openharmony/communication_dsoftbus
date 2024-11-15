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
#include "softbus_proxychannel_message.c"
#include "softbus_transmission_interface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define FAST_TRANS_DATASIZE 256
#define FAST_ARRAY_SIZE 1024
#define TEST_AUTH_DECRYPT_SIZE 35
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_BASE_ENCODE_LEN 32
#define TEST_INIT_OUTLEN 0
#define TEST_INVALID_HEAD_VERSION 2
#define TEST_MESSAGE_CHANNEL_ID 44
#define TEST_NUMBER_FIVE 5
#define TEST_NUMBER_SIX 6
#define TEST_NUMBER_SEVEN 7
#define TEST_NUMBER_EIGHT 8
#define TEST_PARSE_MESSAGE_CHANNEL 45
#define TEST_UID 892
#define TEST_PID 800
#define TEST_PKGNAME "test pkgname"
#define TEST_REQUEST_ID "test request id"
#define TEST_FAST_TRANS_DATA "test fast Trans Data"
#define TEST_SESSION_KEY "test fast Trans Data"

static bool g_testProxyChannelOpenSuccessFlag = false;
static bool g_testProxyChannelOpenFailFlag = false;
static bool g_testProxyChannelClosedFlag = false;
static bool g_testProxyChannelReceiveFlag = false;
static bool g_testNetworkChannelOpenFailFlag = false;

class SoftbusProxyChannelMessageTest : public testing::Test {
public:
    SoftbusProxyChannelMessageTest()
    {}
    ~SoftbusProxyChannelMessageTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

int32_t TestOnDataReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)receiveData;
    g_testProxyChannelReceiveFlag = true;
    printf("TestOnDataReceived enter.\n");
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName, const ChannelInfo *channel)
{
    (void)pkgName;
    (void)sessionName;
    (void)channel;
    (void)pid;
    printf("TestOnChannelOpened enter.\n");
    g_testProxyChannelOpenSuccessFlag = true;
    return SOFTBUS_OK;
}

int32_t TestOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    g_testProxyChannelClosedFlag = true;
    printf("TestOnChannelClosed enter.\n");
    return SOFTBUS_OK;
}

int32_t TestOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    (void)pkgName;
    (void)pid;
    (void)channelId;
    (void)channelType;
    (void)errCode;
    g_testProxyChannelOpenFailFlag = true;
    printf("TestOnChannelOpenFailed enter.\n");
    return SOFTBUS_OK;
}

int32_t TestGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid)
{
    (void)sessionName;
    (void)uid;
    (void)pid;
    printf("TestGetUidAndPidBySessionName enter.\n");
    return SOFTBUS_OK;
}

extern "C" {
int32_t TestGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    (void)sessionName;
    (void)pkgName;
    (void)len;
    printf("TestGetPkgNameBySessionName enter.\n");
    return SOFTBUS_OK;
}
}

void TestOnNetworkingChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    g_testNetworkChannelOpenFailFlag = true;
    printf("TestOnNetworkingChannelOpenFailed enter.\n");
    return;
}

void SoftbusProxyChannelMessageTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ASSERT_EQ(SOFTBUS_OK, LooperInit());
    ASSERT_EQ(SOFTBUS_OK, SoftBusTimerInit());
}

void SoftbusProxyChannelMessageTest::TearDownTestCase(void)
{
    TransProxyManagerDeinit();
}

void TestMessageAddProxyChannel(int32_t channelId, AppType appType, const char *identity, ProxyChannelStatus status)
{
    AppInfo appInfo;
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    ASSERT_TRUE(NULL != chan);
    chan->authHandle.authId = channelId;
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
    EXPECT_NE(SOFTBUS_OK, ret);
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
 * @tc.name: TransProxyHandshakeErrMsgTest001
 * @tc.desc: test pack or unpack handshake err message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeErrMsgTest001, TestSize.Level1)
{
    char* msg = TransProxyPackHandshakeErrMsg(SOFTBUS_INVALID_PARAM);
    ASSERT_TRUE(NULL != msg);

    int32_t ret = TransProxyUnPackHandshakeErrMsg(msg, NULL, sizeof(msg));
    EXPECT_NE(SOFTBUS_OK, ret);

    int32_t errCode = SOFTBUS_OK;
    ret = TransProxyUnPackHandshakeErrMsg(msg, &errCode, sizeof(msg));
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeAckMsgTest001
 * @tc.desc: test pack or unpack handshake ack message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeAckMsgTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    uint16_t fastDataSize = FAST_TRANS_DATASIZE;

    ProxyChannelInfo chan;
    ProxyChannelInfo outChannel;
    chan.appInfo.appType = APP_TYPE_NOT_CARE;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    EXPECT_EQ(NULL, msg);

    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.channelId = -1;
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);
    ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg), &fastDataSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    TestMessageAddProxyChannel(chan.channelId, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);
    msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);
    outChannel.myId = chan.channelId;
    ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg), &fastDataSize);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeAckMsgTest002
 * @tc.desc: test pack or unpack handshake ack message, test normal app type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeAckMsgTest002, TestSize.Level1)
{
    ProxyChannelInfo chan;
    ProxyChannelInfo outChannel;
    uint16_t fastDataSize = FAST_TRANS_DATASIZE;

    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.channelId = TEST_MESSAGE_CHANNEL_ID;
    char *msg = TransProxyPackHandshakeAckMsg(&chan);
    ASSERT_TRUE(NULL != msg);

    int32_t ret = TransProxyUnpackHandshakeAckMsg(msg, &outChannel, sizeof(msg), &fastDataSize);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_free(msg);
}

/**
 * @tc.name: TransProxyHandshakeMsgTest001
 * @tc.desc: test pack or unpack handshake normal message.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    ProxyChannelInfo outChannel;

    info.appInfo.appType = APP_TYPE_NORMAL;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_NE(NULL, msg);
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
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeMsgTest002, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_AUTH;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_NE(NULL, msg);
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
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeMsgTest003, TestSize.Level1)
{
    ProxyChannelInfo info;
    info.appInfo.appType = APP_TYPE_INNER;
    char *msg = TransProxyPackHandshakeMsg(&info);
    EXPECT_NE(NULL, msg);
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
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyIdentityMsgTest001, TestSize.Level1)
{
    char identity[TEST_CHANNEL_IDENTITY_LEN] = "test identity";
    char *msg = TransProxyPackIdentity(nullptr);
    EXPECT_EQ(NULL, msg);
    msg = TransProxyPackIdentity(identity);
    EXPECT_NE(NULL, msg);

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
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyPackMessageTest001, TestSize.Level1)
{
    ProxyMessageHead msg;
    ProxyDataInfo dataInfo;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
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
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyPackMessageTest002, TestSize.Level1)
{
    ProxyMessageHead msg;
    ProxyDataInfo dataInfo;

    dataInfo.inData = (uint8_t *)"12345";
    dataInfo.inLen = strlen((const char*)dataInfo.inData);

    msg.cipher = 0;
    msg.type = PROXYCHANNEL_MSG_TYPE_HANDSHAKE;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    msg.cipher |= ENCRYPTED;
    msg.type = PROXYCHANNEL_MSG_TYPE_NORMAL;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    authHandle.authId = 1;
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyPackMessage(&msg, authHandle, &dataInfo);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
}

/**
  * @tc.name: TransProxyParseMessageTest001
  * @tc.desc: TransProxyParseMessageTest001, use wrong param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyParseMessageTest001, TestSize.Level1)
{
    ProxyMessage msg;
    int32_t len = sizeof(ProxyMessage);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);

    /* test invalid len */
    int32_t ret = TransProxyParseMessage(buf, PROXY_CHANNEL_HEAD_LEN, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test invalid head version */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (TEST_INVALID_HEAD_VERSION << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test invalid head type */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test message no encrypte */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    msg.msgHead.cipher = 0;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);

    /* test normal message encrypte, and channel not exist */
    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = -1;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &msg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyParseMessageTest002
  * @tc.desc: TransProxyParseMessageTest002, use normal param, run normal message
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyParseMessageTest002, TestSize.Level1)
{
    ProxyMessage msg, outMsg;
    int32_t len = sizeof(ProxyMessage);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);
    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    TestMessageAddProxyChannel(TEST_PARSE_MESSAGE_CHANNEL, APP_TYPE_AUTH, "44", PROXY_CHANNEL_STATUS_COMPLETED);

    /* test normal message encrypte */
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_NORMAL & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    int32_t ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyParseMessageTest003
  * @tc.desc: TransProxyParseMessageTest003, use normal param, run handshark message
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyParseMessageTest003, TestSize.Level1)
{
    ProxyMessage msg, outMsg;
    int32_t len = sizeof(ProxyMessage);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);

    msg.msgHead.cipher = 1;
    msg.msgHead.peerId = TEST_PARSE_MESSAGE_CHANNEL;
    msg.msgHead.type = (PROXYCHANNEL_MSG_TYPE_HANDSHAKE & FOUR_BIT_MASK) | (1 << VERSION_SHIFT);
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));

    ConnectionInfo errInfo;
    errInfo.type = CONNECT_TYPE_MAX;
    ConnectionInfo tcpInfo;
    tcpInfo.type = CONNECT_TCP;
    ConnectionInfo brInfo;
    brInfo.type = CONNECT_BR;

    /* test get auth connection info or type err */
    int32_t ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth connection type is invalid */
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth connection type is tcp, and isBr is false */
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test auth connection type is tcp, and isBr is true */
    msg.msgHead.cipher |= USE_BLE_CIPHER;
    ASSERT_TRUE(EOK == memcpy_s(buf, len, &msg, len));
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test connection type is br */
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyParseMessage(buf, len, &outMsg, &authHandle);
    EXPECT_NE(SOFTBUS_OK, ret);

    SoftBusFree(buf);
}

/**
  * @tc.name: TransProxyHandshakeTest001
  * @tc.desc: TransProxyHandshakeTest001, use wrong param and normal param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ProxyChannelInfo info;
    info.channelId = -1;
    info.appInfo.appType = APP_TYPE_INNER;

    /* test info is null */
    ret = TransProxyHandshake(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test appType no auth and invalid channel */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);

    AuthConnInfo wifiInfo, bleInfo;
    wifiInfo.type = AUTH_LINK_TYPE_WIFI;
    bleInfo.type = AUTH_LINK_TYPE_BLE;
    info.channelId = TEST_PARSE_MESSAGE_CHANNEL;
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message failed after pass packhandshakemsg */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message success and send msg fail */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test send msg success */
    ret = TransProxyHandshake(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyAckHandshakeTest001
  * @tc.desc: TransProxyAckHandshakeTest001, use wrong param and normal param.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyAckHandshakeTest001, TestSize.Level1)
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
    retCode = SOFTBUS_INVALID_PARAM;
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test pack message success and send fail */
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = TransProxyAckHandshake(connId, &channelInfo, retCode);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyKeepAliveTest001
  * @tc.desc: test proxy keepalive and keepalive ack message.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyKeepAliveTest001, TestSize.Level1)
{
    ProxyChannelInfo chanInfo;
    uint32_t connId = -1;
    TransProxyKeepalive(connId, NULL);
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
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyResetPeerTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo chanInfo;

    int32_t ret = TransProxyResetPeer(NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    /* test apptype is inner, and pack message fail */
    chanInfo.appInfo.appType = APP_TYPE_INNER;
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test send msg fail */
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    /* test apptype is auth, and success */
    ret = TransProxyResetPeer(&chanInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyPackFastDataTest001
  * @tc.desc: test trans proxy pack fast data.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyPackFastDataTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    uint32_t outLen = TEST_INIT_OUTLEN;
    char *sliceData = NULL;

    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    appInfo->routeType = WIFI_STA;
    appInfo->fastTransData = (uint8_t *)TEST_FAST_TRANS_DATA;

    sliceData = TransProxyPackFastData(appInfo, &outLen);
    EXPECT_EQ(NULL, sliceData);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->routeType = WIFI_STA;
    sliceData = TransProxyPackFastData(appInfo, &outLen);
    EXPECT_EQ(NULL, sliceData);

    appInfo->fastTransDataSize = FAST_TRANS_DATASIZE;
    strcpy_s(appInfo->sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    sliceData = TransProxyPackFastData(appInfo, &outLen);
    EXPECT_NE(NULL, sliceData);
    SoftBusFree(appInfo);
    SoftBusFree(sliceData);
}

/**
  * @tc.name: TransProxyByteDataTest001
  * @tc.desc: test trans proxy byte data.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyByteDataTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ProxyDataInfo *dataInfo = (ProxyDataInfo *)SoftBusCalloc(sizeof(ProxyDataInfo));
    dataInfo->inData = NULL;
    uint8_t inData = TEST_CHANNEL_IDENTITY_LEN;

    int32_t ret = TransProxyMessageData(appInfo, dataInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    dataInfo->inData = &inData;
    appInfo->fastTransDataSize = FAST_TRANS_DATASIZE;
    ret = TransProxyMessageData(appInfo, dataInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    appInfo->fastTransData = (uint8_t *)TEST_FAST_TRANS_DATA;
    ret = TransProxyMessageData(appInfo, dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
    SoftBusFree(dataInfo);
}

/**
  * @tc.name: TransFastDataPackSliceHeadTest001
  * @tc.desc: test fast data pack slice head.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransFastDataPackSliceHeadTest001, TestSize.Level1)
{
    SliceFastHead *data = (SliceFastHead *)SoftBusCalloc(sizeof(SliceFastHead));
    data->priority = TEST_NUMBER_FIVE;
    data->sliceNum = TEST_NUMBER_SIX;
    data->sliceSeq = TEST_NUMBER_SEVEN;
    data->reserved = TEST_NUMBER_EIGHT;

    FastDataPackSliceHead(data);
    EXPECT_EQ(TEST_NUMBER_FIVE, data->priority);
    EXPECT_NE(TEST_NUMBER_FIVE, data->sliceNum);
    EXPECT_NE(TEST_NUMBER_FIVE, data->sliceSeq);
    EXPECT_NE(TEST_NUMBER_FIVE, data->reserved);
    SoftBusFree(data);
}

/**
  * @tc.name: TransProxyPackFastDataHeadTest001
  * @tc.desc: test trans proxy pack fast data head.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyPackFastDataHeadTest001, TestSize.Level1)
{
    AppInfo *appInfo = NULL;
    ProxyDataInfo *dataInfo = (ProxyDataInfo *)SoftBusCalloc(sizeof(ProxyDataInfo));

    int32_t ret = TransProxyPackFastDataHead(dataInfo, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    dataInfo->inLen = FAST_TRANS_DATASIZE;
    dataInfo->inData = (uint8_t *)TEST_FAST_TRANS_DATA;
    dataInfo->outLen = TEST_INIT_OUTLEN;
    ret = TransProxyPackFastDataHead(dataInfo, appInfo);
    EXPECT_NE(SOFTBUS_MEM_ERR, ret);

    dataInfo->outLen = FAST_TRANS_DATASIZE;
    strcpy_s(appInfo->sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    ret = TransProxyPackFastDataHead(dataInfo, appInfo);
    EXPECT_NE(SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR, ret);

    ret = TransProxyPackFastDataHead(dataInfo, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(dataInfo);
}

/**
  * @tc.name: FastDataPackPacketHeadTest001
  * @tc.desc: test fast data pack packethead.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, FastDataPackPacketHeadTest001, TestSize.Level1)
{
    PacketFastHead *data = (PacketFastHead *)SoftBusCalloc(sizeof(PacketFastHead));
    data->magicNumber = TEST_NUMBER_FIVE;
    data->seq = TEST_NUMBER_SIX;
    data->flags = TEST_NUMBER_SEVEN;
    data->dataLen = TEST_NUMBER_EIGHT;

    FastDataPackPacketHead(data);
    EXPECT_EQ(TEST_NUMBER_FIVE, data->magicNumber);
    EXPECT_NE(TEST_NUMBER_FIVE, data->seq);
    EXPECT_NE(TEST_NUMBER_FIVE, data->flags);
    EXPECT_NE(TEST_NUMBER_FIVE, data->dataLen);
    SoftBusFree(data);
}

/**
  * @tc.name: TransProxyEncryptFastDataTest001
  * @tc.desc: test trans proxy encrypt fast data.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyEncryptFastDataTest001, TestSize.Level1)
{
    char sessionKey[FAST_TRANS_DATASIZE] = {0};
    int32_t seq = TEST_NUMBER_FIVE;
    char in[FAST_TRANS_DATASIZE] = {0};
    uint32_t inLen = TEST_BASE_ENCODE_LEN;
    char out[FAST_TRANS_DATASIZE] = {0};
    uint32_t outLen = 0;

    strcpy_s(in, TEST_CHANNEL_IDENTITY_LEN, TEST_FAST_TRANS_DATA);
    strcpy_s(sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    int32_t ret = TransProxyEncryptFastData(sessionKey, seq, in, inLen, out, &outLen);
    EXPECT_NE(SOFTBUS_ENCRYPT_ERR, ret);

    inLen = sizeof(in);
    ret = TransProxyEncryptFastData(sessionKey, seq, in, inLen, out, &outLen);
    EXPECT_NE(SOFTBUS_ENCRYPT_ERR, ret);
}

/**
  * @tc.name: TransProxyParseMessageHeadTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyParseMessageHeadTest001, TestSize.Level1)
{
    ProxyMessage msg;
    int32_t len = sizeof(ProxyMessage);
    char *buf = (char *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(NULL != buf);
    int32_t ret = TransProxyParseMessageHead(buf, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);

    char *bufHead = (char *)SoftBusCalloc(sizeof(ProxyMessage)+2);
    ASSERT_TRUE(NULL != bufHead);
    ret = TransProxyParseMessageHead(bufHead, len, &msg);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransProxyPackMessageHead(NULL, NULL, 0);
    SoftBusFree(buf);
    SoftBusFree(bufHead);
    ret = TransProxyUnPackRestErrMsg(NULL, NULL, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetRemoteTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyGetRemoteTest001, TestSize.Level1)
{
    char brMac[BT_MAC_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};
    int32_t ret = GetRemoteUdidByBtMac(brMac, udid, UDID_BUF_LEN);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint8_t deviceIdHash[UDID_HASH_LEN] = {0};
    ret = GetRemoteBtMacByUdidHash(deviceIdHash, UDID_HASH_LEN, brMac, BT_MAC_LEN);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetAuthConnInfoTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyGetAuthConnInfoTest001, TestSize.Level1)
{
    ProxyMessage msg;
    AuthConnInfo connInfo;
    msg.connId = 1;
    int32_t ret = TransProxyGetAuthConnInfo(msg.connId, &connInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyConvertBrConnInfoTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyConvertBrConnInfoTest001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    int32_t ret = ConvertBrConnInfo2BleConnInfo(&connInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyConvertBleConnInfoTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyConvertBleConnInfoTest001, TestSize.Level1)
{
    AuthConnInfo connInfo;
    int32_t ret = ConvertBleConnInfo2BrConnInfo(&connInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyGetAuthIdTest001
  * @tc.desc: test proxy reset peer.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyGetAuthIdTest001, TestSize.Level1)
{
    ProxyMessage msg;
    msg.connId = 1;
    msg.msgHead.cipher = 1;
    AuthHandle authHandle = { 0 };
    int32_t index = 1;
    int32_t ret = GetAuthIdByHandshakeMsg(msg.connId, msg.msgHead.cipher, &authHandle, index);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyUnpackInnerHandshakeMsgTest001
  * @tc.desc: test trans proxy unpack inner handshakemsg.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyUnpackInnerHandshakeMsgTest001, TestSize.Level1)
{
    char msg[FAST_TRANS_DATASIZE] = {
        "{\
            \"ESSION_KEY\": \"sdadad\",\
            \"ENCRYPT\": 30,\
            \"MY_HANDLE_ID\": 22,\
            \"PEER_HANDLE_ID\": 25,\
        }"
    };
    cJSON *root = cJSON_ParseWithLength(msg, FAST_TRANS_DATASIZE);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    char sessionKey[FAST_TRANS_DATASIZE] = {0};
    int32_t ret = TransProxyUnpackInnerHandshakeMsg(root, appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: TransProxyUnpackNormalHandshakeMsgTest001
  * @tc.desc: test trans proxy unpack inner handshakemsg.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyUnpackNormalHandshakeMsgTest001, TestSize.Level1)
{
    char msg[FAST_ARRAY_SIZE] = {
        "{\
            \"SESSION_KEY\": \"sdadad\",\
            \"PKG_NAME\": \"fdfdf\",\
            \"ENCRYPT\": 30,\
            \"MY_HANDLE_ID\": 55,\
            \"PEER_HANDLE_ID\": 69,\
            \"UID\": 111,\
            \"PID\": 5331,\
            \"ALGORITHM\": 66,\
            \"CRC\": 58,\
            \"BUSINESS_TYPE\": 4,\
            \"GROUP_ID\": \"10.11.11.11\",\
        }"
    };
    cJSON *root = cJSON_ParseWithLength(msg, FAST_TRANS_DATASIZE);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    char sessionKey[FAST_TRANS_DATASIZE] = {0};
    int32_t ret = TransProxyUnpackNormalHandshakeMsg(root, appInfo, sessionKey, BASE64KEY);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
  * @tc.name: UnpackPackHandshakeMsgForFastDataTest001
  * @tc.desc: test unpack pack handshakemsg for fastdata.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, UnpackPackHandshakeMsgForFastDataTest001, TestSize.Level1)
{
    char msg[FAST_TRANS_DATASIZE] = {
        "{\
            \"ROUTE_TYPE\": 2,\
            \"FIRST_DATA\": \"10.11.11.11\",\
            \"FIRST_DATA_SIZE\": 256,\
        }"
    };
    cJSON *root = cJSON_ParseWithLength(msg, FAST_TRANS_DATASIZE);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int32_t ret = UnpackPackHandshakeMsgForFastData(appInfo, root);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: GetBrMacFromConnInfoTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid len or null mac.
  * @tc.desc: Should return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT when given invalid parameter.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, GetBrMacFromConnInfoTest001, TestSize.Level1)
{
    char brMac[BT_MAC_LEN] = "testBrMac";
    uint32_t connId = 1;
    uint32_t len = 0;
    int32_t ret = GetBrMacFromConnInfo(connId, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetBrMacFromConnInfo(connId, brMac, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = 20;
    ret = GetBrMacFromConnInfo(connId, brMac, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = 10;
    ret = GetBrMacFromConnInfo(connId, brMac, len);
    EXPECT_EQ(SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT, ret);
}

/**
  * @tc.name: PackPlaintextMessageTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null message or datainfo.
  * @tc.desc: Should return SOFTBUS_OK when given valid parameter.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, PackPlaintextMessageTest001, TestSize.Level1)
{
    ProxyMessageHead msg;
    memset_s(&msg, sizeof(ProxyMessageHead), 0, sizeof(ProxyMessageHead));
    ProxyDataInfo dataInfo;
    memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    dataInfo.inLen = FAST_TRANS_DATASIZE;
    dataInfo.inData = (uint8_t *)TEST_FAST_TRANS_DATA;
    int32_t ret = PackPlaintextMessage(nullptr, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackPlaintextMessage(&msg, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackPlaintextMessage(&msg, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
  * @tc.name: PackHandshakeMsgForFastDataTest001
  * @tc.desc: Should return SOFTBUS_PARSE_JSON_ERR when given invalid parameter.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, PackHandshakeMsgForFastDataTest001, TestSize.Level1)
{
    char msg[FAST_TRANS_DATASIZE] = {
        "{\
            \"ROUTE_TYPE\": 2,\
            \"FIRST_DATA\": \"10.11.11.11\",\
            \"FIRST_DATA_SIZE\": 256,\
        }"
    };
    cJSON *root = cJSON_ParseWithLength(msg, FAST_TRANS_DATASIZE);
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo.fastTransDataSize = 1;
    int32_t ret = PackHandshakeMsgForFastData(&appInfo, root);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    appInfo.fastTransDataSize = 0;
    ret = PackHandshakeMsgForFastData(&appInfo, root);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
  * @tc.name: TransProxyUnpackNormalHandshakeMsgTest002
  * @tc.desc: Should return SOFTBUS_PARSE_JSON_ERR when given invalid msg.
  * @tc.desc: Should return SOFTBUS_DECRYPT_ERR when given invalid msg.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyUnpackNormalHandshakeMsgTest002, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    char sessionKey[FAST_TRANS_DATASIZE] = {0};
    strcpy_s(sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    (void)AddNumberToJsonObject(msg, "UID", TEST_UID);
    int32_t ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    (void)AddNumberToJsonObject(msg, "PID", TEST_PID);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    (void)AddStringToJsonObject(msg, "PKG_NAME", TEST_PKGNAME);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    (void)AddStringToJsonObject(msg, "SESSION_KEY", TEST_SESSION_KEY);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "ENCRYPT", APP_INFO_FILE_FEATURES_SUPPORT);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "ALGORITHM", APP_INFO_ALGORITHM_AES_GCM_256);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "CRC", APP_INFO_FILE_FEATURES_NO_SUPPORT);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "BUSINESS_TYPE", BUSINESS_TYPE_NOT_CARE);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "MY_HANDLE_ID", -1);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)AddNumberToJsonObject(msg, "PEER_HANDLE_ID", -1);
    ret = TransProxyUnpackNormalHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    cJSON_Delete(msg);
}

/**
  * @tc.name: TransProxyUnpackAuthHandshakeMsgTest001
  * @tc.desc: Should return SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_REQUEST_FAILED when given null appInfo.
  * @tc.desc: Should return SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_PKG_FAILED when given invalid msg.
  * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyUnpackAuthHandshakeMsgTest001, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = TransProxyUnpackAuthHandshakeMsg(nullptr, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_REQUEST_FAILED, ret);
    (void)AddStringToJsonObject(msg, "REQUEST_ID", TEST_REQUEST_ID);
    ret = TransProxyUnpackAuthHandshakeMsg(msg, &appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_PKG_FAILED, ret);
    (void)AddStringToJsonObject(msg, "PKG_NAME", TEST_PKGNAME);
    ret = TransProxyUnpackAuthHandshakeMsg(msg, &appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(msg);
}

/**
  * @tc.name: TransProxyUnpackInnerHandshakeMsgTest002
  * @tc.desc: Should return SOFTBUS_DECRYPT_ERR when given invalid parameters.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelMessageTest, TransProxyUnpackInnerHandshakeMsgTest002, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    char sessionKey[FAST_TRANS_DATASIZE] = {0};
    strcpy_s(sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    AppInfo appInfo;
    memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    (void)AddStringToJsonObject(msg, "SESSION_KEY", TEST_SESSION_KEY);
    int32_t ret = TransProxyUnpackInnerHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    (void)strcpy_s(appInfo.sessionKey, TEST_CHANNEL_IDENTITY_LEN, TEST_SESSION_KEY);
    ret = TransProxyUnpackInnerHandshakeMsg(msg, &appInfo, sessionKey, FAST_TRANS_DATASIZE);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    cJSON_Delete(msg);
}

} // namespace OHOS
