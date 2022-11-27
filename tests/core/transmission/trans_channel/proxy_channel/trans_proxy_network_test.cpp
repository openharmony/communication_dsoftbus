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
#include "softbus_error_code.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_network.h"
#include "softbus_transmission_interface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

class TransProxyNetworkTest : public testing::Test {
public:
    TransProxyNetworkTest()
    {}
    ~TransProxyNetworkTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}

    static int TestOnNetworkChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer);
    static void TestOnNetworkChannelOpenFailed(int32_t channelId, const char *uuid);
    static void TestOnNetworkChannelClosed(int32_t channelId);
    static void TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len);
    static void TestRegisterNetworkingChannelListener(void);

    static bool m_channelOpenFailedFlag;
    static bool m_channelClosedFlag;
    static bool m_messageReceivedFlag;
};

bool TransProxyNetworkTest::m_channelClosedFlag = false;
bool TransProxyNetworkTest::m_channelOpenFailedFlag = false;
bool TransProxyNetworkTest::m_messageReceivedFlag = false;

void TransProxyNetworkTest::SetUpTestCase(void)
{
}

void TransProxyNetworkTest::TearDownTestCase(void)
{
}

int TransProxyNetworkTest::TestOnNetworkChannelOpened(int32_t channelId, const char *uuid, unsigned char isServer)
{
    (void)channelId;
    (void)uuid;
    (void)isServer;
    printf("test on networking channel opened.\n");
    return SOFTBUS_OK;
}

void TransProxyNetworkTest::TestOnNetworkChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)channelId;
    (void)uuid;
    printf("test on network channel open failed.\n");
    TransProxyNetworkTest::m_channelOpenFailedFlag = true;
}

void TransProxyNetworkTest::TestOnNetworkChannelClosed(int32_t channelId)
{
    (void)channelId;
    printf("test on networking channel closed.\n");
    TransProxyNetworkTest::m_channelClosedFlag = true;
}

void TransProxyNetworkTest::TestOnNetworkMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
    printf("test on networking message received.\n");
    TransProxyNetworkTest::m_messageReceivedFlag = true;
}

void TransProxyNetworkTest::TestRegisterNetworkingChannelListener(void)
{
    INetworkingListener listener;
    listener.onChannelClosed = TransProxyNetworkTest::TestOnNetworkChannelClosed;
    listener.onChannelOpened = TransProxyNetworkTest::TestOnNetworkChannelOpened;
    listener.onChannelOpenFailed = TransProxyNetworkTest::TestOnNetworkChannelOpenFailed;
    listener.onMessageReceived = TransProxyNetworkTest::TestOnNetworkMessageReceived;
    int32_t ret = TransRegisterNetworkingChannelListener(&listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransNoRegisterListenerTest001
 * @tc.desc: test callback after no register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, TransNoRegisterListenerTest001, TestSize.Level1)
{
    int32_t ret = NotifyNetworkingChannelOpened(1, NULL, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
    
    NotifyNetworkingChannelOpenFailed(1, NULL);
    EXPECT_NE(true, TransProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(1);
    EXPECT_NE(true, TransProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(1, NULL, 0);
    EXPECT_NE(true, TransProxyNetworkTest::m_messageReceivedFlag);
}

/**
 * @tc.name: TransRegisterListenerTest001
 * @tc.desc: test callback after register networking channel listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyNetworkTest, TransRegisterListenerTest001, TestSize.Level1)
{
    TransProxyNetworkTest::TestRegisterNetworkingChannelListener();

    int32_t ret = NotifyNetworkingChannelOpened(1, NULL, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    NotifyNetworkingChannelOpenFailed(1, NULL);
    EXPECT_EQ(true, TransProxyNetworkTest::m_channelOpenFailedFlag);
    NotifyNetworkingChannelClosed(1);
    EXPECT_EQ(true, TransProxyNetworkTest::m_channelClosedFlag);
    NotifyNetworkingMsgReceived(1, NULL, 0);
    EXPECT_EQ(true, TransProxyNetworkTest::m_messageReceivedFlag);
}

} // namespace OHOS
