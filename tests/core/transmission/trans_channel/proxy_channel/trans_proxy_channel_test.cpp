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
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "auth_interface.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_message.h"

using namespace testing::ext;

namespace OHOS {

class TransProxyChannelTest : public testing::Test {
public:
    TransProxyChannelTest()
    {}
    ~TransProxyChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransProxyChannelTest::SetUpTestCase(void)
{}

void TransProxyChannelTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransProxySendMessageTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxySendMessageTest001, TestSize.Level1)
{
    ProxyChannelInfo info;
    const char *payLoad = "12345678";
    uint32_t payLoadLen = strlen(payLoad);

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    
    int ret = TransProxySendMessage(&info, payLoad, payLoadLen, 0);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: TransProxyHandshakeTest001
 * @tc.desc: TransProxyHandshakeTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyHandshakeTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_NORMAL;
    info.myId = 0;
    info.peerId = 0;
    info.channelId = INVALID_CHANNEL_ID;
    
    int ret = TransProxyHandshake(&info);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: TransProxyAckHandshakeTest001
 * @tc.desc: TransProxyAckHandshake, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAckHandshakeTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    
    int ret = TransProxyAckHandshake(0, &info, SOFTBUS_ERR);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: TransProxyAckKeepaliveTest001
 * @tc.desc: TransProxyAckKeepaliveTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyAckKeepaliveTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), "12345678");
    
    int ret = TransProxyAckKeepalive(&info);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: TransProxyResetPeerTest001
 * @tc.desc: TransProxyResetPeerTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransProxyChannelTest, TransProxyResetPeerTest001, TestSize.Level1)
{
    ProxyChannelInfo info;

    info.appInfo.appType = APP_TYPE_AUTH;
    info.myId = 0;
    info.peerId = 0;
    info.authId = AUTH_INVALID_ID;
    (void)strcpy_s(info.identity, sizeof(info.identity), "12345678");
    
    int ret = TransProxyResetPeer(&info);
    EXPECT_TRUE(ret != 0);
}
} // namespace OHOS