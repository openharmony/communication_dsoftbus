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
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_control.c"
#include "softbus_proxychannel_control_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1069

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
 * @tc.name: TransPagingHandshakeTest001
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
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
    cJSON *root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    char *buf = NULL;
    bool res = AddStringToJsonObject(root, JSON_KEY_PKG_NAME, (char *)authKey);
    ASSERT_TRUE(res);
    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    char *testBuf = NULL;
    res = AddStringToJsonObject(testRoot, JSON_KEY_PKG_NAME, (char *)authKey);
    ASSERT_TRUE(res);
    testBuf = cJSON_PrintUnformatted(testRoot);
    cJSON_Delete(testRoot);
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
    ret = TransPagingHandshake(channelId, authKey, keyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
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
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest001, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
    };
    int32_t retCode = SOFTBUS_INVALID_PARAM;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingAckHandshakeTest002
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingAckHandshakeTest002, TestSize.Level1)
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
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeAckMsg).WillOnce(Return(nullptr));
    int32_t ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_PACKMSG_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackHandshakeAckMsg).WillOnce(Return(buf));
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransPagingAckHandshake(&chan, retCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransPagingResetTest001
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransPagingResetTest001, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = -1,
    };
    int32_t ret = TransPagingReset(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED, ret);
    chan.myId = TEST_CHANNEL_ID;
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingReset(&chan);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingReset(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingPackMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransPagingReset(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransProxyTransSendMsg).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransPagingReset(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyResetPeerTest001
 * @tc.desc: test proxy open proxy channel
 *           use wrong param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelControlPagingTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo chan = {
        .peerId = TEST_CHANNEL_ID,
        .myId = -1,
        .isD2D = true,
    };
    int32_t ret = TransProxyResetPeer(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<SoftbusProxychannelControlPagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyResetPeer(&chan);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_LEEPALIVE_ACK_FAILED, ret);
}
} // namespace OHOS

