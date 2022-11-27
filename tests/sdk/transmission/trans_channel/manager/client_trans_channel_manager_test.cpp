/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "securec.h"

#include "client_trans_channel_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

#define TEST_DATA_LENGTH 1024

using namespace std;
using namespace testing::ext;

namespace OHOS {
class ClientTransChannelManagerTest : public testing::Test {
public:
    ClientTransChannelManagerTest() {}
    ~ClientTransChannelManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransChannelManagerTest::SetUpTestCase(void) {}
void ClientTransChannelManagerTest::TearDownTestCase(void) {}

/**
 * @tc.name: ClientTransCloseChannelTest001
 * @tc.desc: client trans channel manager test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransCloseChannelTest001, TestSize.Level0)
{
    int channelId = 1;
    int ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_AUTH);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransCloseChannel(channelId, CHANNEL_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}


/**
 * @tc.name: ClientTransChannelSendBytesTest001
 * @tc.desc: client trans channel send byte test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendBytesTest001, TestSize.Level0)
{
    int channelId = 1;
    const void *data = (const void *)"test";

    int ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    
    ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ClientTransChannelSendBytes(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ClientTransChannelSendMessageTest001
 * @tc.desc: client trans channel send message test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendMessageTest001, TestSize.Level0)
{
    int channelId = 1;
    const void *data = (const void *)"test";

    int ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_AUTH, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_AUTH, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    
    ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_PROXY, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_TCP_DIRECT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);

    ret = ClientTransChannelSendMessage(channelId, CHANNEL_TYPE_BUTT, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/**
 * @tc.name: ClientTransChannelSendStreamTest001
 * @tc.desc: client trans channel send stream test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendStreamTest001, TestSize.Level0)
{
    int channelId = 1;
    const StreamData data = {0};
    const StreamData ext = {0};
    const StreamFrameInfo param = {0};

    int ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, nullptr, &ext, &param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_UDP, &data, &ext, &param);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = ClientTransChannelSendStream(channelId, CHANNEL_TYPE_BUTT, &data, &ext, &param);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/**
 * @tc.name: ClientTransChannelSendFileTest001
 * @tc.desc: client trans channel send file test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransChannelManagerTest, ClientTransChannelSendFileTest001, TestSize.Level0)
{
    int channelId = 1;
    int fileCnt = 1;
    const char *sFileList[] = { "/data/test.txt" };
    const char *dFileList[] = { "/data/test.txt" };
    int ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_UDP, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED, ret);

    ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_PROXY, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ClientTransChannelSendFile(channelId, CHANNEL_TYPE_BUTT, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}
} // namespace OHOS