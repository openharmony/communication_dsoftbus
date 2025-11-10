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

#include "cJSON.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_control.c"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_message_struct.h"
#include "softbus_proxy_network_mock_test.h"
#include "softbus_proxychannel_network.c"
#include "softbus_transmission_interface.h"
#include "trans_proxy_process_data.h"

using namespace testing;
using namespace testing::ext;

#define TEST_VALID_SESSIONNAME "com.test.sessionname"
#define TEST_NUMBER_256 256

class SoftbusTransProxySessionInterface {
public:
    
    virtual int32_t TransProxyGetChannelCapaByChanId(int32_t channelId, uint32_t *channelCapability) = 0;

    virtual cJSON *cJSON_CreateObject(void) = 0;
};

class SoftbusTransProxySessionMock : public SoftbusTransProxySessionInterface {
public:
    static SoftbusTransProxySessionMock &GetMockObj(void)
    {
        return *gmock_;
    }
    SoftbusTransProxySessionMock();
    ~SoftbusTransProxySessionMock();
    
    MOCK_METHOD(int32_t, TransProxyGetChannelCapaByChanId,
        (int32_t channelId, uint32_t *channelCapability), (override));

    MOCK_METHOD(cJSON *, cJSON_CreateObject, (), (override));

private:
    static SoftbusTransProxySessionMock *gmock_;
};

SoftbusTransProxySessionMock *SoftbusTransProxySessionMock::gmock_;

SoftbusTransProxySessionMock::SoftbusTransProxySessionMock()
{
    gmock_ = this;
}

SoftbusTransProxySessionMock::~SoftbusTransProxySessionMock()
{
    gmock_ = nullptr;
}


int32_t TransProxyGetChannelCapaByChanId(int32_t channelId, uint32_t *channelCapability)
{
    std::cout << "TransProxyGetChannelCapaByChanId mock calling enter" << std::endl;
    return SoftbusTransProxySessionMock::GetMockObj().TransProxyGetChannelCapaByChanId(channelId, channelCapability);
}

cJSON *cJSON_CreateObject()
{
    return SoftbusTransProxySessionMock::GetMockObj().cJSON_CreateObject();
}

namespace OHOS {

class TransProxySessionTest : public testing::Test {
public:
    TransProxySessionTest()
    {}
    ~TransProxySessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}

    static void TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len);
    static void TestRegisterNetworkingChannelListener(void);
};

void TransProxySessionTest::SetUpTestCase(void)
{
}

void TransProxySessionTest::TearDownTestCase(void)
{
}

void TransProxySessionTest::TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
}

void TransProxySessionTest::TestRegisterNetworkingChannelListener(void)
{
    INetworkingListener listener;
    char sessionName[TEST_NUMBER_256] = {0};
    strcpy_s(sessionName, TEST_NUMBER_256, TEST_VALID_SESSIONNAME);
    listener.onMessageReceived = TransProxySessionTest::TestOnNetworkMessageReceived;
    int32_t ret = TransRegisterNetworkingChannelListener(sessionName, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransRegisterNetworkingChannelListener(nullptr, &listener);
    EXPECT_EQ(SOFTBUS_STRCPY_ERR, ret);
}

/*
 * @tc.name: NotifyNetworkingMsgReceived002
 * @tc.desc: Test the network message receiving notification function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, NotifyNetworkingMsgReceived002, TestSize.Level1)
{
    const char *data = "njfejfjpfjewpfqpFHEQWP";
    uint32_t channelCapability = 1u;

    SoftbusTransProxySessionMock networkObj;
    EXPECT_CALL(networkObj, TransProxyGetChannelCapaByChanId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channelCapability), Return(SOFTBUS_OK)));

    TransProxySessionTest::TestRegisterNetworkingChannelListener();
    EXPECT_NO_FATAL_FAILURE(NotifyNetworkingMsgReceived("test.com.session", 1024, data, 256));
}

/*
 * @tc.name: NotifyNetworkingMsgReceived003
 * @tc.desc: Test the network message receiving notification function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, NotifyNetworkingMsgReceived003, TestSize.Level1)
{
    const char *data = "njfejfjpfjewpfqpFHEQWP";
    uint32_t channelCapability = 1u;

    SoftbusTransProxySessionMock networkObj;
    EXPECT_CALL(networkObj, TransProxyGetChannelCapaByChanId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(channelCapability), Return(SOFTBUS_OK)));

    TransProxySessionTest::TestRegisterNetworkingChannelListener();
    EXPECT_NO_FATAL_FAILURE(NotifyNetworkingMsgReceived(TEST_VALID_SESSIONNAME, 1024, data, 256));
}

/*
 * @tc.name: TransProxySendEncryptInnerMessage001
 * @tc.desc: Test the TransProxySendEncryptInnerMessage function to return an encryption error
 *           when encrypting data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxySendEncryptInnerMessage001, TestSize.Level1)
{
    ProxyChannelInfo info;
    (void)strcpy_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, "testsessionkey");
    const char *inData = "nwq4";
    ProxyMessageHead proxyMsgHead;
    ProxyDataInfo proxyDataInfo;
    uint32_t outPayLoadLen = 35;

    SoftbusTransProxyNetworkMock networkObj;

    EXPECT_CALL(networkObj, SoftBusEncryptData).WillRepeatedly(
        DoAll(SetArgPointee<4>(outPayLoadLen), Return(SOFTBUS_ENCRYPT_ERR)));

    int32_t ret = TransProxySendEncryptInnerMessage(&info, inData, 5, &proxyMsgHead, &proxyDataInfo);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessage002
 * @tc.desc: Test the error handling capability of the TransProxySendEncryptInnerMessage function
 *           when message packaging fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxySendEncryptInnerMessage002, TestSize.Level1)
{
    ProxyChannelInfo info;
    (void)strcpy_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, "testsessionkey");
    const char *inData = "nwq4";
    ProxyMessageHead proxyMsgHead;
    ProxyDataInfo proxyDataInfo;
    uint32_t outPayLoadLen = 35;

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, SoftBusEncryptData).WillRepeatedly(
        DoAll(SetArgPointee<4>(outPayLoadLen), Return(SOFTBUS_OK)));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_TRANS_PROXY_PACKMSG_ERR));

    int32_t ret = TransProxySendEncryptInnerMessage(&info, inData, 5, &proxyMsgHead, &proxyDataInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_PACKMSG_ERR);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessage003
 * @tc.desc: Test the TransProxySendEncryptInnerMessage function is handling logic
 *           when sending encrypted internal messages with an invalid packet length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxySendEncryptInnerMessage003, TestSize.Level1)
{
    ProxyChannelInfo info;
    (void)strcpy_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, "testsessionkey");
    const char *inData = "nwq4";
    ProxyMessageHead proxyMsgHead;
    ProxyDataInfo proxyDataInfo;
    uint32_t outPayLoadLen = 35;

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, SoftBusEncryptData).WillRepeatedly(
        DoAll(SetArgPointee<4>(outPayLoadLen), Return(SOFTBUS_OK)));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID));

    int32_t ret = TransProxySendEncryptInnerMessage(&info, inData, 5, &proxyMsgHead, &proxyDataInfo);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessage004
 * @tc.desc: Test the correctness of the TransProxySendEncryptInnerMessage function
 *           when encrypting and sending internal messages
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxySendEncryptInnerMessage004, TestSize.Level1)
{
    ProxyChannelInfo info;
    (void)strcpy_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, "testsessionkey");
    const char *inData = "nwq4";
    ProxyMessageHead proxyMsgHead;
    ProxyDataInfo proxyDataInfo;
    uint32_t outPayLoadLen = 35;

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, SoftBusEncryptData).WillRepeatedly(
        DoAll(SetArgPointee<4>(outPayLoadLen), Return(SOFTBUS_OK)));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransProxySendEncryptInnerMessage(&info, inData, 5, &proxyMsgHead, &proxyDataInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransProxySendInnerMessageTest001
 * @tc.desc: Test whether the TransProxySendInnerMessage function
 *           correctly sends messages under normal conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxySendInnerMessageTest001, TestSize.Level1)
{
    ProxyChannelInfo info = {
        .myId = 1925,
        .peerId = 1524,
        .appInfo.channelCapability = 1
    };
    uint32_t payLoadLen = 12;
    int32_t priority = 1;

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransProxySendInnerMessage(&info, "testPayLoad", payLoadLen, priority);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest001
 * @tc.desc: Test the ConvertConnectType2AuthLinkType function
 *           from connection type to authentication link type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, ConvertConnectType2AuthLinkTypeTest001, TestSize.Level1)
{
    ConnectType type = CONNECT_SLE;
    AuthLinkType ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_SLE);

    type = CONNECT_SLE_DIRECT;
    ret = ConvertConnectType2AuthLinkType(type);
    EXPECT_EQ(ret, AUTH_LINK_TYPE_SLE);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest001
 * @tc.desc: Test the behavior of the SetCipherOfHandshakeMsg function under specific conditions
 *           particularly the return value when no channel is found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest001, TestSize.Level1)
{
    uint8_t cipher;
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));
    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND));

    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest002
 * @tc.desc: Test the behavior of the SetCipherOfHandshakeMsg function
 *           under specific conditions particularly the handling logic
 *           when AuthGetConnInfo returns SOFTBUS_AUTH_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest002, TestSize.Level1)
{
    uint8_t cipher;
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));
    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, AuthGetConnInfo).WillOnce(Return(SOFTBUS_AUTH_NOT_FOUND));

    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest003
 * @tc.desc: Test whether the return value of the SetCipherOfHandshakeMsg function
 *           meets the expected results under specific conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest003, TestSize.Level1)
{
    uint8_t cipher;
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));

    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, AuthGetConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, AuthGetServerSide).WillOnce(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest004
 * @tc.desc: Test the behavior of the SetCipherOfHandshakeMsg function
 *           under specific conditions to ensure that it can successfully set the encryption method for
 *           handshake messages when the proxy channel information and authentication information
 *           are correctly configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest004, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));

    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));

    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(networkObj, AuthGetConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));

    bool isAuthServer = true;
    EXPECT_CALL(networkObj, AuthGetServerSide)
        .WillRepeatedly(DoAll(SetArgPointee<1>(isAuthServer), Return(SOFTBUS_OK)));

    uint8_t cipher;
    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest005
 * @tc.desc: Test the behavior of the SetCipherOfHandshakeMsg function
 *           under specific conditions to ensure that it can successfully set the encryption method for
 *           handshake messages when the proxy channel information and authentication information
 *           are correctly configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest005, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));

    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));

    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(networkObj, AuthGetConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));

    bool isAuthServer = true;
    EXPECT_CALL(networkObj, AuthGetServerSide)
        .WillRepeatedly(DoAll(SetArgPointee<1>(isAuthServer), Return(SOFTBUS_OK)));

    uint8_t cipher;
    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest006
 * @tc.desc: Test the behavior of the SetCipherOfHandshakeMsg function
 *           under specific conditions to ensure that it can successfully set the encryption method for
 *           handshake messages when the proxy channel information and authentication information
 *           are correctly configured
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, SetCipherOfHandshakeMsgTest006, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.authHandle = { AUTH_LINK_TYPE_BR, CONNECT_TCP };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, AuthGetLatestIdByUuid)
        .WillRepeatedly(DoAll(SetArgPointee<3>(proxyChannelInfo.authHandle)));

    EXPECT_CALL(networkObj, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));

    AuthConnInfo connInfo;
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(networkObj, AuthGetConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));

    bool isAuthServer = false;
    EXPECT_CALL(networkObj, AuthGetServerSide)
        .WillRepeatedly(DoAll(SetArgPointee<1>(isAuthServer), Return(SOFTBUS_OK)));

    uint8_t cipher;
    int32_t ret = SetCipherOfHandshakeMsg(&proxyChannelInfo, &cipher);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransProxyHandshakeTest001
 * @tc.desc: Test the proxy is ability to handle errors under specific conditions
 *           during the hanshake process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.appInfo.appType = APP_TYPE_AUTH;

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackHandshakeMsg).WillOnce(Return(nullptr));

    int32_t ret = TransProxyHandshake(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR);
}

/*
 * @tc.name: TransProxyHandshakeTest002
 * @tc.desc: Test the proxy is ability to handle errors under specific conditions
 *           during the hanshake process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyHandshakeTest002, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.appInfo.appType = APP_TYPE_AUTH;

    char *payLoad = static_cast<char *>(SoftBusCalloc(32));
    ASSERT_TRUE(payLoad != nullptr);
    (void)strcpy_s(payLoad, 32, "testpayload");

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackHandshakeMsg).WillOnce(Return(payLoad));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_HEAD_ERR));

    int32_t ret = TransProxyHandshake(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_HEAD_ERR);
}

/*
 * @tc.name: TransProxyHandshakeTest003
 * @tc.desc: Test the behavior of the proxy handshake function under specific conditions
 *           especially when encountering an operation not supported error while sending messages
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyHandshakeTest003, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo;
    proxyChannelInfo.appInfo.appType = APP_TYPE_AUTH;

    char *payLoad = static_cast<char *>(SoftBusCalloc(32));
    ASSERT_TRUE(payLoad != nullptr);
    (void)strcpy_s(payLoad, 32, "testpayload");
    TransPagingHandshakeEvent(TEST_NUMBER_256, nullptr);

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackHandshakeMsg).WillOnce(Return(payLoad));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT));

    int32_t ret = TransProxyHandshake(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT);
}

/*
 * @tc.name: TransProxyHandshakeTest004
 * @tc.desc: test TransProxyHandshake
 *           Test the correctness of the proxy handshake function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyHandshakeTest004, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo = {
        .appInfo.appType = APP_TYPE_AUTH,
        .myId = 1916,
        .connId = 131041
    };

    char *payLoad = static_cast<char *>(SoftBusCalloc(32));
    ASSERT_TRUE(payLoad != nullptr);
    (void)strcpy_s(payLoad, 32, "testpayload");

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackHandshakeMsg).WillOnce(Return(payLoad));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransProxyHandshake(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransProxyKeepaliveTest001
 * @tc.desc: Test whether the keep-alive mechanism in the proxy session works properly，ensuring that the
 *           keep-alive function does not cause the program to crash or produce fatal errors under
 *           specific conditions (such as identity packaging failure)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyKeepaliveTest001, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo = {
        .appInfo.appType = APP_TYPE_AUTH,
        .myId = 1916,
        .peerId = 3035,
        .connId = 131041
    };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackIdentity).WillOnce(Return(nullptr));

    EXPECT_NO_FATAL_FAILURE(TransProxyKeepalive(1234, &proxyChannelInfo));
}

/*
 * @tc.name: TransProxyAckKeepaliveTest001
 * @tc.desc: Testing failure scenarios of the keepalive acknowledgment function
 *           in proxy sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyAckKeepaliveTest001, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo = {
        .appInfo.appType = APP_TYPE_AUTH,
        .myId = 1916,
        .peerId = 3035
    };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackIdentity).WillOnce(Return(nullptr));

    int32_t ret = TransProxyAckKeepalive(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest002
 * @tc.desc: Test whether the keep-alive mechanism of the proxy channel is functioning properly
 *           ensuring that when keep-alive acknowledgment messages are sent through the proxy channel
 *           the identity information and messages are correctly packaged and successfully transmitted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyAckKeepaliveTest002, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo = {
        .appInfo.appType = APP_TYPE_AUTH,
        .myId = 1916,
        .peerId = 3035
    };

    char *payLoad = static_cast<char *>(SoftBusCalloc(32));
    ASSERT_TRUE(payLoad != nullptr);
    (void)strcpy_s(payLoad, 32, "testpayload");

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackIdentity).WillOnce(Return(payLoad));
    EXPECT_CALL(networkObj, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(networkObj, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = TransProxyAckKeepalive(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransProxyResetPeerTest001
 * @tc.desc: Test the logic of the proxy channel handling keep-alive responses
 *           when packing identity information fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo proxyChannelInfo = {
        .appInfo.appType = APP_TYPE_AUTH,
        .myId = 1916,
        .peerId = 3035
    };

    SoftbusTransProxyNetworkMock networkObj;
    EXPECT_CALL(networkObj, TransProxyPackIdentity).WillOnce(Return(nullptr));

    int32_t ret = TransProxyAckKeepalive(&proxyChannelInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED);
}

/*
 * @tc.name: TransProxyPackHandshakeErrMsgTest001
 * @tc.desc: Test the behavior of the TransProxyPackHandshakeErrMsg function
 *           when cJSON_CreateObject returns a null pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxySessionTest, TransProxyPackHandshakeErrMsgTest001, TestSize.Level1)
{
    SoftbusTransProxySessionMock networkObj;
    EXPECT_CALL(networkObj, cJSON_CreateObject).WillOnce(Return(nullptr));

    char *ret = TransProxyPackHandshakeErrMsg(SOFTBUS_OK);
    EXPECT_EQ(ret, nullptr);
}
} // namespace OHOS
