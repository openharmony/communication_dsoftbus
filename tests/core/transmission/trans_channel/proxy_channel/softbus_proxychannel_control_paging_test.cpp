/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_control.c"
#include "softbus_proxychannel_control_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1069
#define TEST_CONN_ID 1

namespace OHOS {

class SoftbusProxyChannelControlPagingTest : public testing::Test {
public:
    SoftbusProxyChannelControlPagingTest()
    {}
    ~SoftbusProxyChannelControlPagingTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusProxyChannelControlPagingTest::SetUpTestCase(void)
{
}

void SoftbusProxyChannelControlPagingTest::TearDownTestCase(void)
{
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest001
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_TCP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest001, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_TCP);
    EXPECT_EQ(AUTH_LINK_TYPE_WIFI, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest002
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_BLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest002, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_BLE);
    EXPECT_EQ(AUTH_LINK_TYPE_BLE, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest003
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_BLE_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest003, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_BLE_DIRECT);
    EXPECT_EQ(AUTH_LINK_TYPE_BLE, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest004
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_BR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest004, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_BR);
    EXPECT_EQ(AUTH_LINK_TYPE_BR, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest005
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_SLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest005, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_SLE);
    EXPECT_EQ(AUTH_LINK_TYPE_SLE, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest006
 * @tc.desc: test ConvertConnectType2AuthLinkType CONNECT_SLE_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest006, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_SLE_DIRECT);
    EXPECT_EQ(AUTH_LINK_TYPE_SLE, ret);
}

/*
 * @tc.name: ConvertConnectType2AuthLinkTypeTest007
 * @tc.desc: test ConvertConnectType2AuthLinkType default P2P
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, ConvertConnectType2AuthLinkTypeTest007, TestSize.Level1)
{
    AuthLinkType ret = ConvertConnectType2AuthLinkType(CONNECT_P2P);
    EXPECT_EQ(AUTH_LINK_TYPE_P2P, ret);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest001
 * @tc.desc: test SetCipherOfHandshakeMsg authId invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest001, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle invalidHandle = { AUTH_INVALID_ID, 0 };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(invalidHandle));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_GET_AUTH_ID_FAILED, ret);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest002
 * @tc.desc: test SetCipherOfHandshakeMsg setAuthHandle fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest003
 * @tc.desc: test SetCipherOfHandshakeMsg getConnInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest004
 * @tc.desc: test SetCipherOfHandshakeMsg getServerSide fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest005
 * @tc.desc: test SetCipherOfHandshakeMsg isServer AUTH_SERVER_SIDE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest005, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(true), Return(SOFTBUS_OK)));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(cipher & AUTH_SERVER_SIDE, AUTH_SERVER_SIDE);
    EXPECT_EQ(cipher & ENCRYPTED, ENCRYPTED);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest006
 * @tc.desc: test SetCipherOfHandshakeMsg BLE USE_BLE_CIPHER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest006, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_BLE;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_BLE };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(cipher & USE_BLE_CIPHER, USE_BLE_CIPHER);
    EXPECT_EQ(cipher & ENCRYPTED, ENCRYPTED);
}

/*
 * @tc.name: SetCipherOfHandshakeMsgTest007
 * @tc.desc: test SetCipherOfHandshakeMsg success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, SetCipherOfHandshakeMsgTest007, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    uint8_t cipher = 0;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    int32_t ret = SetCipherOfHandshakeMsg(&info, &cipher);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(cipher & ENCRYPTED, ENCRYPTED);
    EXPECT_EQ(cipher & AUTH_SERVER_SIDE, 0);
    EXPECT_EQ(cipher & USE_BLE_CIPHER, 0);
}

/*
 * @tc.name: TransPagingHandshakeEventTest001
 * @tc.desc: test TransPagingHandshakeEvent info null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingHandshakeEventTest001, TestSize.Level1)
{
    TransPagingHandshakeEvent(TEST_CHANNEL_ID, nullptr);
}

/*
 * @tc.name: TransPagingHandshakeEventTest002
 * @tc.desc: test TransPagingHandshakeEvent valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingHandshakeEventTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    TransPagingHandshakeEvent(TEST_CHANNEL_ID, &info);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessageTest001
 * @tc.desc: test TransProxySendEncryptInnerMessage SoftBusEncryptData fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendEncryptInnerMessageTest001, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    uint32_t payLoadLen = strlen(payLoad) + 1;
    ProxyMessageHead msgHead = {0};
    ProxyDataInfo dataInfo = {0};
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = TransProxySendEncryptInnerMessage(&info, payLoad, payLoadLen, &msgHead, &dataInfo);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessageTest002
 * @tc.desc: test TransProxySendEncryptInnerMessage pack fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendEncryptInnerMessageTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    uint32_t payLoadLen = strlen(payLoad) + 1;
    ProxyMessageHead msgHead = {0};
    ProxyDataInfo dataInfo = {0};
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendEncryptInnerMessage(&info, payLoad, payLoadLen, &msgHead, &dataInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessageTest003
 * @tc.desc: test TransProxySendEncryptInnerMessage send fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendEncryptInnerMessageTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    uint32_t payLoadLen = strlen(payLoad) + 1;
    ProxyMessageHead msgHead = {0};
    ProxyDataInfo dataInfo = {0};
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendEncryptInnerMessage(&info, payLoad, payLoadLen, &msgHead, &dataInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySendEncryptInnerMessageTest004
 * @tc.desc: test TransProxySendEncryptInnerMessage success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendEncryptInnerMessageTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    uint32_t payLoadLen = strlen(payLoad) + 1;
    ProxyMessageHead msgHead = {0};
    ProxyDataInfo dataInfo = {0};
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxySendEncryptInnerMessage(&info, payLoad, payLoadLen, &msgHead, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest001
 * @tc.desc: test TransProxySendInnerMessage info null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest001, TestSize.Level1)
{
    char payLoad[] = "test";
    int32_t ret = TransProxySendInnerMessage(nullptr, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest002
 * @tc.desc: test TransProxySendInnerMessage payLoad null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    int32_t ret = TransProxySendInnerMessage(&info, nullptr, 0, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest003
 * @tc.desc: test TransProxySendInnerMessage encrypt branch encrypt fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = TRANS_CHANNEL_INNER_ENCRYPT;
    info.appInfo.myData.pid = 1;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest004
 * @tc.desc: test TransProxySendInnerMessage encrypt branch pack fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = TRANS_CHANNEL_INNER_ENCRYPT;
    info.appInfo.myData.pid = 1;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest005
 * @tc.desc: test TransProxySendInnerMessage encrypt branch send fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest005, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = TRANS_CHANNEL_INNER_ENCRYPT;
    info.appInfo.myData.pid = 1;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest006
 * @tc.desc: test TransProxySendInnerMessage non-encrypt branch pack fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest006, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = 0;
    info.appInfo.myData.pid = 1;
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest007
 * @tc.desc: test TransProxySendInnerMessage non-encrypt branch send fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest007, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = 0;
    info.appInfo.myData.pid = 1;
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest008
 * @tc.desc: test TransProxySendInnerMessage encrypt branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest008, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = TRANS_CHANNEL_INNER_ENCRYPT;
    info.appInfo.myData.pid = 1;
    (void)memset_s(info.appInfo.sessionKey, SESSION_KEY_LENGTH, 1, SESSION_KEY_LENGTH);
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxySendInnerMessageTest009
 * @tc.desc: test TransProxySendInnerMessage non-encrypt branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxySendInnerMessageTest009, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.channelCapability = 0;
    info.appInfo.myData.pid = 1;
    char payLoad[] = "test";
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxySendInnerMessage(&info, payLoad, strlen(payLoad) + 1, CONN_HIGH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest001
 * @tc.desc: test TransProxyHandshake info null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    int32_t ret = TransProxyHandshake(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest002
 * @tc.desc: test TransProxyHandshake APP_TYPE_AUTH skip cipher
 *           pack handshake fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackHandshakeMsg).WillOnce(Return(nullptr));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest003
 * @tc.desc: test TransProxyHandshake SetCipher fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle invalidHandle = { AUTH_INVALID_ID, 0 };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(invalidHandle));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest004
 * @tc.desc: test TransProxyHandshake PackHandshakeMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, TransProxyPackHandshakeMsg).WillOnce(Return(nullptr));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest005
 * @tc.desc: test TransProxyHandshake PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest005, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    cJSON *root = cJSON_CreateObject();
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeMsg).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_HEAD_ERR, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest006
 * @tc.desc: test TransProxyHandshake SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest006, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    cJSON *root = cJSON_CreateObject();
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeMsg).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyHandshakeTest007
 * @tc.desc: test TransProxyHandshake success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyHandshakeTest007, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = INVALID_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.peerData.deviceId[0] = '1';
    info.type = CONNECT_TCP;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    AuthHandle validHandle = { 1, AUTH_LINK_TYPE_WIFI };
    EXPECT_CALL(mock, AuthGetLatestIdByUuid).WillOnce(SetArgPointee<3>(validHandle));
    EXPECT_CALL(mock, TransProxySetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    EXPECT_CALL(mock, AuthGetConnInfo).WillOnce(DoAll(SetArgPointee<1>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, AuthGetServerSide).WillOnce(DoAll(SetArgPointee<1>(false), Return(SOFTBUS_OK)));
    cJSON *root = cJSON_CreateObject();
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeMsg).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyHandshake(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest001
 * @tc.desc: test TransProxyAckHandshake chan null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest001, TestSize.Level1)
{
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, nullptr, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest002
 * @tc.desc: test TransProxyAckHandshake APP_TYPE_AUTH skip encrypt
 *           errMsg payload null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest002, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackHandshakeErrMsg).WillOnce(Return(nullptr));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest003
 * @tc.desc: test TransProxyAckHandshake errMsg success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest003, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.connId = TEST_CONN_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddNumberToJsonObject(root, ERR_CODE, SOFTBUS_INVALID_PARAM);
    char *errMsgBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest004
 * @tc.desc: test TransProxyAckHandshake ackMsg payload null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest004, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackHandshakeAckMsg).WillOnce(Return(nullptr));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest005
 * @tc.desc: test TransProxyAckHandshake PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest005, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddNumberToJsonObject(root, ERR_CODE, SOFTBUS_INVALID_PARAM);
    char *errMsgBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest006
 * @tc.desc: test TransProxyAckHandshake SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest006, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddNumberToJsonObject(root, ERR_CODE, SOFTBUS_INVALID_PARAM);
    char *errMsgBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest007
 * @tc.desc: test TransProxyAckHandshake APP_TYPE_NORMAL encrypt
 *           errMsg PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest007, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddNumberToJsonObject(root, ERR_CODE, SOFTBUS_INVALID_PARAM);
    char *errMsgBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransProxyAckHandshakeTest008
 * @tc.desc: test TransProxyAckHandshake ackMsg success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckHandshakeTest008, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.myId = TEST_CHANNEL_ID;
    chan.peerId = TEST_CHANNEL_ID;
    chan.connId = TEST_CONN_ID;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *ackBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackHandshakeAckMsg).WillOnce(Return(ackBuf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyAckHandshake(TEST_CONN_ID, &chan, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyKeepaliveTest001
 * @tc.desc: test TransProxyKeepalive info null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest001, TestSize.Level1)
{
    TransProxyKeepalive(TEST_CONN_ID, nullptr);
}

/*
 * @tc.name: TransProxyKeepaliveTest002
 * @tc.desc: test TransProxyKeepalive APP_TYPE_AUTH skip encrypt
 *           pack identity fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(nullptr));
    TransProxyKeepalive(TEST_CONN_ID, &info);
}

/*
 * @tc.name: TransProxyKeepaliveTest003
 * @tc.desc: test TransProxyKeepalive PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransProxyKeepalive(TEST_CONN_ID, &info);
}

/*
 * @tc.name: TransProxyKeepaliveTest004
 * @tc.desc: test TransProxyKeepalive SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransProxyKeepalive(TEST_CONN_ID, &info);
}

/*
 * @tc.name: TransProxyKeepaliveTest005
 * @tc.desc: test TransProxyKeepalive APP_TYPE_NORMAL encrypt
 *           PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest005, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransProxyKeepalive(TEST_CONN_ID, &info);
}

/*
 * @tc.name: TransProxyKeepaliveTest006
 * @tc.desc: test TransProxyKeepalive success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyKeepaliveTest006, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    TransProxyKeepalive(TEST_CONN_ID, &info);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest001
 * @tc.desc: test TransProxyAckKeepalive info null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest001, TestSize.Level1)
{
    int32_t ret = TransProxyAckKeepalive(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest002
 * @tc.desc: test TransProxyAckKeepalive APP_TYPE_AUTH skip encrypt
 *           pack identity fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest002, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(nullptr));
    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED, ret);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest003
 * @tc.desc: test TransProxyAckKeepalive PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest003, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest004
 * @tc.desc: test TransProxyAckKeepalive SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest004, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest005
 * @tc.desc: test TransProxyAckKeepalive APP_TYPE_NORMAL encrypt
 *           PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest005, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_NORMAL;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyAckKeepaliveTest006
 * @tc.desc: test TransProxyAckKeepalive success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyAckKeepaliveTest006, TestSize.Level1)
{
    ProxyChannelInfo info = {0};
    info.myId = TEST_CHANNEL_ID;
    info.peerId = TEST_CHANNEL_ID;
    info.connId = TEST_CONN_ID;
    info.appInfo.appType = APP_TYPE_AUTH;
    info.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyAckKeepalive(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingHandshakeTest001
 * @tc.desc: test TransPagingHandshake param check and branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingHandshakeTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint8_t authKey[SESSION_KEY_LENGTH];
    (void)memset_s(authKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    (void)memset_s(authKey, SESSION_KEY_LENGTH - 1, 1, SESSION_KEY_LENGTH - 1);
    uint32_t keyLen = SESSION_KEY_LENGTH + 1;
    int32_t ret = TransPagingHandshake(channelId, authKey, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    keyLen = SESSION_KEY_LENGTH;
    ret = TransPagingHandshake(channelId, nullptr, keyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransProxyGetSendMsgChanInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransProxyGetSendMsgChanInfo).WillRepeatedly(Return(SOFTBUS_OK));
    cJSON *root = cJSON_CreateObject();
    bool res = AddStringToJsonObject(root, JSON_KEY_PKG_NAME, (char *)authKey);
    ASSERT_TRUE(res);
    char *payLoadBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandShakeMsg).WillRepeatedly(Return(payLoadBuf));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingGetAuthKeyTest001
 * @tc.desc: test TransPagingGetAuthKey branches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingGetAuthKeyTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    PagingProxyMessage msg;
    uint8_t authKey[SESSION_KEY_LENGTH];
    (void)memset_s(authKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransPagingGetAuthKey(&chan, &msg);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK)).WillOnce(
        Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingGetAuthKey(&chan, &msg);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingGetAuthKey(&chan, &msg);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(
        DoAll(SetArgPointee<1>(*authKey), Return(SOFTBUS_OK)));
    ret = TransPagingGetAuthKey(&chan, &msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest001
 * @tc.desc: test TransPagingAckHandshake NULL check and errMsg path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest001, TestSize.Level1)
{
    int32_t ret = TransPagingAckHandshake(nullptr, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeErrMsg).WillOnce(Return(nullptr));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
    cJSON *root = cJSON_CreateObject();
    AddNumberToJsonObject(root, ERR_CODE, SOFTBUS_INVALID_PARAM);
    AddNumberToJsonObject(root, JSON_KEY_PAGING_SINK_CHANNEL_ID, 0);
    char *errMsgBuf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest002
 * @tc.desc: test TransPagingAckHandshake ackMsg payload null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest002, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_OK;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeAckMsg).WillOnce(Return(nullptr));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest003
 * @tc.desc: test TransPagingAckHandshake getAuthKey fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest003, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_OK;
    cJSON *root = cJSON_CreateObject();
    bool res = AddNumberToJsonObject(root, JSON_KEY_PAGING_SINK_CHANNEL_ID, TEST_CHANNEL_ID);
    EXPECT_EQ(true, res);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeAckMsg).WillOnce(Return(buf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest004
 * @tc.desc: test TransPagingAckHandshake PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest004, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    cJSON *errMsgRoot = cJSON_CreateObject();
    AddNumberToJsonObject(errMsgRoot, ERR_CODE, SOFTBUS_INVALID_PARAM);
    AddNumberToJsonObject(errMsgRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, 0);
    char *errMsgBuf = cJSON_PrintUnformatted(errMsgRoot);
    cJSON_Delete(errMsgRoot);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest005
 * @tc.desc: test TransPagingAckHandshake SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest005, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    cJSON *errMsgRoot = cJSON_CreateObject();
    AddNumberToJsonObject(errMsgRoot, ERR_CODE, SOFTBUS_INVALID_PARAM);
    AddNumberToJsonObject(errMsgRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, 0);
    char *errMsgBuf = cJSON_PrintUnformatted(errMsgRoot);
    cJSON_Delete(errMsgRoot);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest006
 * @tc.desc: test TransPagingAckHandshake errMsg success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest006, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    cJSON *errMsgRoot = cJSON_CreateObject();
    AddNumberToJsonObject(errMsgRoot, ERR_CODE, SOFTBUS_INVALID_PARAM);
    AddNumberToJsonObject(errMsgRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, 0);
    char *errMsgBuf = cJSON_PrintUnformatted(errMsgRoot);
    cJSON_Delete(errMsgRoot);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeErrMsg).WillOnce(Return(errMsgBuf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest007
 * @tc.desc: test TransPagingAckHandshake ackMsg success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest007, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_OK;
    cJSON *root = cJSON_CreateObject();
    bool res = AddNumberToJsonObject(root, JSON_KEY_PAGING_SINK_CHANNEL_ID, TEST_CHANNEL_ID);
    EXPECT_EQ(true, res);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeAckMsg).WillOnce(Return(buf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest001
 * @tc.desc: test TransProxyResetPeer null check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    int32_t ret = TransProxyResetPeer(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest002
 * @tc.desc: test TransProxyResetPeer isD2D path
 *           TransProxyPagingPackChannelId fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest002, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = -1,
        .isD2D = true,
    };
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPagingPackChannelId).WillOnce(Return(nullptr));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest003
 * @tc.desc: test TransProxyResetPeer isD2D success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest003, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = TEST_CHANNEL_ID,
        .connId = TEST_CONN_ID,
        .isD2D = true,
    };
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *chanIdRoot = cJSON_CreateObject();
    AddNumberToJsonObject(chanIdRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, TEST_CHANNEL_ID);
    char *chanIdBuf = cJSON_PrintUnformatted(chanIdRoot);
    cJSON_Delete(chanIdRoot);
    EXPECT_CALL(mock, TransProxyPagingPackChannelId).WillOnce(Return(chanIdBuf));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest004
 * @tc.desc: test TransProxyResetPeer non-D2D PackIdentity fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest004, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = TEST_CHANNEL_ID,
        .isD2D = false,
    };
    chan.appInfo.appType = APP_TYPE_AUTH;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(nullptr));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest005
 * @tc.desc: test TransProxyResetPeer non-D2D PackMessage fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest005, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.peerId = TEST_CHANNEL_ID;
    chan.myId = TEST_CHANNEL_ID;
    chan.isD2D = false;
    chan.appInfo.appType = APP_TYPE_AUTH;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest006
 * @tc.desc: test TransProxyResetPeer non-D2D SendMsg fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest006, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.peerId = TEST_CHANNEL_ID;
    chan.myId = TEST_CHANNEL_ID;
    chan.channelId = TEST_CHANNEL_ID;
    chan.isD2D = false;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest007
 * @tc.desc: test TransProxyResetPeer non-D2D APP_TYPE_NORMAL success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest007, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.peerId = TEST_CHANNEL_ID;
    chan.myId = TEST_CHANNEL_ID;
    chan.channelId = TEST_CHANNEL_ID;
    chan.isD2D = false;
    chan.appInfo.appType = APP_TYPE_NORMAL;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest008
 * @tc.desc: test TransProxyResetPeer non-D2D APP_TYPE_AUTH success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest008, TestSize.Level1)
{
    ProxyChannelInfo chan = {0};
    chan.peerId = TEST_CHANNEL_ID;
    chan.myId = TEST_CHANNEL_ID;
    chan.channelId = TEST_CHANNEL_ID;
    chan.connId = TEST_CONN_ID;
    chan.isD2D = false;
    chan.appInfo.appType = APP_TYPE_AUTH;
    chan.appInfo.myData.pid = 1;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> mock;
    cJSON *root = cJSON_CreateObject();
    AddStringToJsonObject(root, JSON_KEY_IDENTITY, TEST_CHANNEL_INDENTITY);
    char *buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    EXPECT_CALL(mock, TransProxyPackIdentity).WillOnce(Return(buf));
    EXPECT_CALL(mock, TransProxyPackMessage).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS