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

#include "gmock/gmock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_message.c"
#include "softbus_proxychannel_message_paging_test_mock.h"

using namespace testing;
using namespace testing::ext;

static const char *TEST_DATA = "TEST_";
#define TEST_LEN 10
#define DATA_LEN 5
#define TEST_CHANNEL_ID 1058

namespace OHOS {

class SoftbusProxyChannelMessagePagingTest : public testing::Test {
public:
    SoftbusProxyChannelMessagePagingTest()
    {}
    ~SoftbusProxyChannelMessagePagingTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusProxyChannelMessagePagingTest::SetUpTestCase(void)
{
}

void SoftbusProxyChannelMessagePagingTest::TearDownTestCase(void)
{
}

/**@
 * @tc.name: TransParseMessageHeadTypeTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransParseMessageHeadTypeTest001, TestSize.Level1)
{
    uint8_t type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (VERSION_SHIFT << VERSION_SHIFT);
    int32_t len = TEST_LEN;
    ProxyMessage msg;
    char *data = reinterpret_cast<char *>(&type);
    int32_t ret = TransParseMessageHeadType(data, len, &msg);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);
    type = (PROXYCHANNEL_MSG_TYPE_MAX & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    ret = TransParseMessageHeadType(data, len, &msg);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_MESSAGE_TYPE, ret);
    type = (PROXYCHANNEL_MSG_TYPE_D2D & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    ret = TransParseMessageHeadType(data, len, &msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransParseMessageHeadType(data, 0, &msg);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**@
 * @tc.name: TransUnPackPagingExtraDataTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransUnPackPagingExtraDataTest001, TestSize.Level1)
{
    cJSON *root = nullptr;
    root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    char extraData[EXTRA_DATA_STR_MAX_LEN] = {0};
    char *data = const_cast<char *>(TEST_DATA);
    bool ret = TransUnPackPagingExtraData(root, extraData);
    EXPECT_EQ(false, ret);
    ret = AddStringToJsonObject(root, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, ret);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransUnPackPagingExtraData(root, extraData);
    EXPECT_EQ(false, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillOnce(Return(SOFTBUS_OK));
    ret = TransUnPackPagingExtraData(root, extraData);
    EXPECT_EQ(true, ret);
    cJSON_Delete(root);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest001, TestSize.Level1)
{
    cJSON *root = nullptr;
    root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    bool res = AddStringToJsonObject(root, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(root));
    ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest002, TestSize.Level1)
{
    cJSON *root = nullptr;
    root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    bool res = AddStringToJsonObject(root, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(root, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(root, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(root, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(root));
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest003
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest003, TestSize.Level1)
{
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    cJSON *testRoot1 = nullptr;
    testRoot1 = cJSON_CreateObject();
    ASSERT_TRUE(testRoot1 != nullptr);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot1));
    ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest004
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest004, TestSize.Level1)
{
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest005
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest005, TestSize.Level1)
{
    cJSON *testRoot1 = nullptr;
    testRoot1 = cJSON_CreateObject();
    ASSERT_TRUE(testRoot1 != nullptr);
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillRepeatedly(Return(testRoot1));

    bool res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeMsgTest006
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeMsgTest006, TestSize.Level1)
{
    cJSON *testRoot1 = nullptr;
    testRoot1 = cJSON_CreateObject();
    ASSERT_TRUE(testRoot1 != nullptr);
    ProxyMessage msg;
    AppInfo appInfo;
    uint32_t capability;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = DATA_LEN;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillRepeatedly(Return(testRoot1));

    bool res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot1, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot1, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    int32_t ret = TransPagingUnPackHandshakeMsg(&msg, &appInfo, &capability);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeAckMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeAckMsgTest001, TestSize.Level1)
{
    cJSON *root = nullptr;
    root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    ProxyMessage msg;
    AppInfo appInfo;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t channelCap;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    int32_t ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    bool res = AddNumberToJsonObject(root, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(root));
    ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    res = AddNumberToJsonObject(testRootTest, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeAckMsgTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeAckMsgTest002, TestSize.Level1)
{
    ProxyMessage msg;
    AppInfo appInfo;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t channelCap;

    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    bool res = AddNumberToJsonObject(testRootTest, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    int32_t ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_DEVICETYPE_ID, channelId);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeAckMsgTest003
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeAckMsgTest003, TestSize.Level1)
{
    ProxyMessage msg;
    AppInfo appInfo;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t channelCap;
    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    bool res = AddNumberToJsonObject(testRootTest, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRootTest, JSON_KEY_DEVICETYPE_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRootTest, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    int32_t ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_DEVICETYPE_ID, channelId);
    EXPECT_EQ(true, res);
    ret = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, ret);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, channelId);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusBase64Decode).WillOnce(Return(SOFTBUS_OK));
    ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
}

/**@
 * @tc.name: TransPagingUnPackHandshakeAckMsgTest004
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackHandshakeAckMsgTest004, TestSize.Level1)
{
    ProxyMessage msg;
    AppInfo appInfo;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t channelCap;
    int32_t dataLen = DATA_LEN;
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_SESSION_KEY, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_NONCE, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_DEVICETYPE_ID, channelId);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_D2D_CHANNEL_CAPABILITY, channelId);
    EXPECT_EQ(true, res);
    res = AddBoolToJsonObject(testRoot, JSON_KEY_D2D_SUPPORT_NEW_HEAD, true);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusBase64Decode).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransPagingUnPackHandshakeAckMsg(&msg, &appInfo, &channelCap);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
}

/**@
 * @tc.name: TransPagingProcessHandshakeAckMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingProcessHandshakeAckMsgTest001, TestSize.Level1)
{
    TransPagingProcessHandshakeAckMsg(nullptr);
    ProxyMessage *msg = (ProxyMessage *)SoftBusCalloc(sizeof(ProxyMessage));
    ASSERT_TRUE(msg != nullptr);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingHandshakeUnPackErrMsg).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ProxyPagingMock, TransProxyProcessErrMsg).Times(1);
    TransPagingProcessHandshakeAckMsg(msg);
    EXPECT_CALL(ProxyPagingMock, TransPagingHandshakeUnPackErrMsg).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyProcessErrMsg).Times(1);
    TransPagingProcessHandshakeAckMsg(msg);
    EXPECT_CALL(ProxyPagingMock, TransPagingBadKeyRetry).Times(1);
    TransPagingProcessBadKeyMsg(msg);
    SoftBusFree(msg);
}

/**@
 * @tc.name: TransPagingUnPackResetMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingUnPackResetMsgTest001, TestSize.Level1)
{
    ProxyMessage msg;
    int32_t peerId = TEST_CHANNEL_ID;
    cJSON *testRootTest = nullptr;
    testRootTest = cJSON_CreateObject();
    ASSERT_TRUE(testRootTest != nullptr);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    int32_t ret = TransPagingUnPackResetMsg(&msg, &peerId);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRootTest));
    ret = TransPagingUnPackResetMsg(&msg, &peerId);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *testRoot = nullptr;
    testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_SINK_CHANNEL_ID, peerId);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    ret = TransPagingUnPackResetMsg(&msg, &peerId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyFillPagingChannelInfoTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyFillPagingChannelInfoTest001, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    int32_t ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON *root = nullptr;
    root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    bool res = AddStringToJsonObject(root, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(root, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(root, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(root, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(root, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(root, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(root, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(root));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**@
 * @tc.name: TransProxyFillPagingChannelInfoTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyFillPagingChannelInfoTest002, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**@
 * @tc.name: TransProxyFillPagingChannelInfoTest003
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyFillPagingChannelInfoTest003, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**@
 * @tc.name: TransProxyFillPagingChannelInfoTest004
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyFillPagingChannelInfoTest004, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, GenerateChannelId).WillRepeatedly(Return(TEST_CHANNEL_ID));
    int32_t ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyFillPagingChannelInfoTest005
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyFillPagingChannelInfoTest005, TestSize.Level1)
{
    ProxyMessage msg;
    ProxyChannelInfo chan;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyFillPagingChannelInfo(&msg, &chan, accountHash, udidHash, authAccountHash);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**@
 * @tc.name: TransProxyPagingChannelOpenedTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyPagingChannelOpenedTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyPagingChannelOpened(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillRepeatedly(DoAll(
        SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingUpdatePidAndData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyPagingChannelOpened(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingUpdatePidAndData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelOpened).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyPagingChannelOpened(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyPagingChannelOpened(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyPagingCheckListenTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyPagingCheckListenTest001, TestSize.Level1)
{
    ProxyChannelInfo chan;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyPagingCheckListen(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillRepeatedly(DoAll(
        SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingUpdatePidAndData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyPagingCheckListen(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransProxyPagingCheckListenTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransProxyPagingCheckListenTest002, TestSize.Level1)
{
    ProxyChannelInfo chan;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(false));
    EXPECT_CALL(ProxyPagingMock, TransCheckPagingListenState).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransProxyPagingCheckListen(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransCheckPagingListenState).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransReversePullUpPacked).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransProxyPagingCheckListen(&chan);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, TransReversePullUpPacked).WillRepeatedly(Return(SOFTBUS_OK));
    ret = TransProxyPagingCheckListen(&chan);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransPagingProcessHandshakeMsgTest001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingProcessHandshakeMsgTest001, TestSize.Level1)
{
    ProxyMessage msg;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    TransPagingProcessHandshakeMsg(nullptr, accountHash, udidHash, authAccountHash);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(nullptr));
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    TransPagingProcessHandshakeMsg(&msg, accountHash, udidHash, authAccountHash);
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, GenerateChannelId).WillOnce(Return(TEST_CHANNEL_ID));
    EXPECT_CALL(ProxyPagingMock, TransGetPkgnameByBusinessFlagPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    TransPagingProcessHandshakeMsg(&msg, accountHash, udidHash, authAccountHash);
}

/**@
 * @tc.name: TransPagingProcessHandshakeMsgTest002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingProcessHandshakeMsgTest002, TestSize.Level1)
{
    ProxyMessage msg;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, GenerateChannelId).WillOnce(Return(TEST_CHANNEL_ID));
    EXPECT_CALL(ProxyPagingMock, TransGetPkgnameByBusinessFlagPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyCreatePagingChanInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    TransPagingProcessHandshakeMsg(&msg, accountHash, udidHash, authAccountHash);
}

/**@
 * @tc.name: TransPagingProcessHandshakeMsgTest003
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingProcessHandshakeMsgTest003, TestSize.Level1)
{
    ProxyMessage msg;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, GenerateChannelId).WillOnce(Return(TEST_CHANNEL_ID));
    EXPECT_CALL(ProxyPagingMock, TransGetPkgnameByBusinessFlagPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyCreatePagingChanInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    TransPagingProcessHandshakeMsg(&msg, accountHash, udidHash, authAccountHash);
}

/**@
 * @tc.name: TransPagingProcessHandshakeMsgTest004
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingProcessHandshakeMsgTest004, TestSize.Level1)
{
    ProxyMessage msg;
    char *data = const_cast<char *>(TEST_DATA);
    int32_t dataLen = TEST_LEN;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char *authAccountHash = const_cast<char *>(TEST_DATA);
    cJSON *testRoot = cJSON_CreateObject();
    ASSERT_TRUE(testRoot != nullptr);
    bool res = AddStringToJsonObject(testRoot, JSON_KEY_CALLER_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_CALLEE_ACCOUNT_ID, data);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_PAGING_EXT_DATA, data);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_DATA_LEN, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_PAGING_BUSINESS_FLAG, dataLen);
    EXPECT_EQ(true, res);
    res = AddNumberToJsonObject(testRoot, JSON_KEY_BUSINESS_TYPE, dataLen);
    EXPECT_EQ(true, res);
    res = AddStringToJsonObject(testRoot, JSON_KEY_DEVICE_ID, data);
    EXPECT_EQ(true, res);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    unsigned char str[SHA_256_HASH_LEN] = "TEST_";
    EXPECT_CALL(ProxyPagingMock, ConvertHexStringToBytes)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(str, str + SHA_256_HASH_LEN), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, cJSON_ParseWithLength).WillOnce(Return(testRoot));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AddNumberToSocketName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, GenerateChannelId).WillOnce(Return(TEST_CHANNEL_ID));
    EXPECT_CALL(ProxyPagingMock, TransGetPkgnameByBusinessFlagPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransProxyCreatePagingChanInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillRepeatedly(DoAll(
        SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingUpdatePidAndData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    TransPagingProcessHandshakeMsg(&msg, accountHash, udidHash, authAccountHash);
}

/**@
 * @tc.name: TransWaitListenResult001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransWaitListenResult001, TestSize.Level1)
{
    PagingListenCheckInfo checkInfo = {
        .businessFlag = 1,
        .channelId = TEST_CHANNEL_ID
    };
    int32_t reason = SOFTBUS_INVALID_PARAM;
    uint8_t *accountHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    uint8_t *udidHash = reinterpret_cast<uint8_t *>(const_cast<char *>(TEST_DATA));
    char authAccountHash[SHA_256_HEX_HASH_LEN] = { 0 };
    AesGcmCipherKey cipherKey;
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, TransPagingAckHandshake).WillRepeatedly(Return(SOFTBUS_OK));
    TransWaitListenResult(&checkInfo, reason);
    reason = SOFTBUS_OK;
    EXPECT_CALL(ProxyPagingMock, TransProxyGetChannelByCheckInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransWaitListenResult(&checkInfo, reason);
    EXPECT_CALL(ProxyPagingMock, TransProxyGetChannelByCheckInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillOnce(Return(false));
    TransWaitListenResult(&checkInfo, reason);
    EXPECT_CALL(ProxyPagingMock, TransHasAndUpdatePagingListenPacked).WillRepeatedly(Return(true));
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    TransWaitListenResult(&checkInfo, reason);
    EXPECT_CALL(ProxyPagingMock, TransPagingGetPidAndDataByFlgPacked).WillRepeatedly(DoAll(
        SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ProxyPagingMock, TransPagingUpdatePidAndData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, OnProxyChannelOpened).WillRepeatedly(Return(SOFTBUS_OK));
    TransWaitListenResult(&checkInfo, reason);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = PagingParseMsgGetAuthKey(accountHash, udidHash, &cipherKey, authAccountHash);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = PagingParseMsgGetAuthKey(accountHash, udidHash, &cipherKey, authAccountHash);
    EXPECT_EQ(SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = PagingParseMsgGetAuthKey(accountHash, udidHash, &cipherKey, authAccountHash);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(ProxyPagingMock, AuthFindApplyKey).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PagingParseMsgGetAuthKey(accountHash, udidHash, &cipherKey, authAccountHash);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**@
 * @tc.name: TransPagingPackHandshakeErrMsg001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingPackHandshakeErrMsg001, TestSize.Level1)
{
    char *buf = TransPagingPackHandshakeErrMsg(SOFTBUS_OK, TEST_CHANNEL_ID);
    EXPECT_TRUE(buf != nullptr);
    cJSON *root = cJSON_CreateObject();
    ASSERT_TRUE(root != nullptr);
    void *extraData = reinterpret_cast<void *>(const_cast<char *>(TEST_DATA));
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    bool ret = TransPackPagingExtraData(root, extraData);
    EXPECT_EQ(false, ret);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK));
    ret = TransPackPagingExtraData(root, extraData);
    EXPECT_EQ(true, ret);
    cJSON_Delete(root);
}

/**@
 * @tc.name: TransPagingPackHandshakeMsg001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingPackHandshakeMsg001, TestSize.Level1)
{
    ProxyChannelInfo info = {
        .appInfo.myData.dataLen = 1,
        .appInfo.myData.businessFlag = 1,
        .appInfo.businessType = BUSINESS_TYPE_BYTE,
    };
    char *buf = TransPagingPackHandshakeMsg(nullptr);
    EXPECT_TRUE(buf == nullptr);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    buf = TransPagingPackHandshakeMsg(&info);
    EXPECT_TRUE(buf == nullptr);
    EXPECT_CALL(ProxyPagingMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    buf = TransPagingPackHandshakeMsg(&info);
    EXPECT_TRUE(buf != nullptr);
}

/**@
 * @tc.name: TransPagingPackHandshakeAckMsg001
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingPackHandshakeAckMsg001, TestSize.Level1)
{
    ProxyChannelInfo info = {
        .appInfo.myData.dataLen = 1,
        .appInfo.myData.businessFlag = 1,
        .appInfo.businessType = BUSINESS_TYPE_BYTE,
    };
    char *buf = TransPagingPackHandshakeAckMsg(nullptr);
    EXPECT_TRUE(buf == nullptr);
    NiceMock<SoftbusProxychannelMessagePagingInterfaceMock> ProxyPagingMock;
    EXPECT_CALL(ProxyPagingMock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    buf = TransPagingPackHandshakeAckMsg(&info);
    EXPECT_TRUE(buf == nullptr);
    EXPECT_CALL(ProxyPagingMock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ProxyPagingMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    buf = TransPagingPackHandshakeAckMsg(&info);
    EXPECT_TRUE(buf == nullptr);
    EXPECT_CALL(ProxyPagingMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    buf = TransPagingPackHandshakeAckMsg(&info);
    EXPECT_TRUE(buf == nullptr);
    EXPECT_CALL(ProxyPagingMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    buf = TransPagingPackHandshakeAckMsg(&info);
    EXPECT_TRUE(buf != nullptr);
}

/**@
 * @tc.name: TransPagingPackHandshakeAckMsg002
 * @tc.desc: test proxy open proxy channel, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMessagePagingTest, TransPagingPackHandshakeAckMsg002, TestSize.Level1)
{
    int16_t channelId = -1;
    char *buf = TransProxyPagingPackChannelId(channelId);
    EXPECT_TRUE(buf == nullptr);
    channelId = TEST_CHANNEL_ID;
    buf = TransProxyPagingPackChannelId(channelId);
    EXPECT_TRUE(buf != nullptr);
}
} // namespace OHOS