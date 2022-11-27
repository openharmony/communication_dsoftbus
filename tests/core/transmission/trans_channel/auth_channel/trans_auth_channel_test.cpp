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
#include "trans_auth_manager.c"

using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"

class TransAuthChannelTest : public testing::Test {
public:
    TransAuthChannelTest()
    {}
    ~TransAuthChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthChannelTest::SetUpTestCase(void)
{}

void TransAuthChannelTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransAuthInitTest001
 * @tc.desc: TransAuthInitTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransAuthInitTest001, TestSize.Level1)
{
    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);

    int32_t ret = TransAuthInit(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransAuthDeinit();
}

/**
 * @tc.name: TransOpenAuthMsgChannelTest001
 * @tc.desc: TransOpenAuthMsgChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = TEST_AUTH_PORT,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_CONN_IP) != EOK) {
        return;
    }

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);
    int32_t ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, NULL, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    connInfo.type = CONNECT_BR;
    ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransAuthDeinit();
}

/**
 * @tc.name: TransOpenAuthMsgChannelTest002
 * @tc.desc: TransOpenAuthMsgChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransOpenAuthMsgChannelTest002, TestSize.Level1)
{
    int32_t channelId = 0;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = TEST_AUTH_PORT,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_CONN_IP) != EOK) {
        return;
    }

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);
    int32_t ret = TransOpenAuthMsgChannel(TEST_SESSION_NAME, &connInfo, &channelId);
    if (ret != SOFTBUS_OK) {
        printf("test open auth msg channel failed.\n");
    }

    const char *data = TEST_AUTH_DATA;
    ret = TransSendAuthMsg(channelId, data, strlen(data));
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransAuthDeinit();
}

/**
 * @tc.name: TransSendAuthMsgTest001
 * @tc.desc: TransSendAuthMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransSendAuthMsgTest001, TestSize.Level1)
{
    const char *data = "test auth message data";
    const char *sessionName = "com.test.trans.auth.demo";
    int32_t len = strlen(data);
    int32_t channelId = 0;

    IServerChannelCallBack cb;
    (void)TransAuthInit(&cb);

    AuthChannelInfo *channel = CreateAuthChannelInfo(sessionName);
    if (channel == NULL) {
        return;
    }
    channel->authId = 1;
    if (AddAuthChannelInfo(channel) != SOFTBUS_OK) {
        SoftBusFree(channel);
        return;
    }
    channelId = channel->appInfo.myData.channelId;
    int32_t ret = TransSendAuthMsg(channelId, NULL, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransSendAuthMsg(channelId, data, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransSendAuthMsg(-1, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransSendAuthMsg(channelId, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    
    (void)TransCloseAuthChannel(channelId);
    TransAuthDeinit();
}

/**
 * @tc.name: OnAuthChannelDataRecvTest001
 * @tc.desc: OnAuthChannelDataRecvTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnAuthChannelDataRecvTest001, TestSize.Level1)
{
    int32_t authId = -1;
    AuthChannelData data;

    OnAuthChannelDataRecv(authId, NULL);

    data.data = NULL;
    OnAuthChannelDataRecv(authId, &data);

    data.data = (uint8_t *)"test data";
    data.flag = AUTH_CHANNEL_REQ;
    OnAuthChannelDataRecv(authId, &data);

    data.flag = AUTH_CHANNEL_REPLY;
    OnAuthChannelDataRecv(authId, &data);

    data.flag = -1;
    OnAuthChannelDataRecv(authId, &data);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnAuthMsgDataRecvTest001
 * @tc.desc: OnAuthMsgDataRecvTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, OnAuthMsgDataRecvTest001, TestSize.Level1)
{
    int32_t authId = -1;
    AuthChannelData data;

    OnAuthMsgDataRecv(authId, NULL);

    data.data = NULL;
    OnAuthMsgDataRecv(authId, &data);

    data.data = (uint8_t *)"test data";
    OnAuthMsgDataRecv(authId, &data);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TransPostAuthChannelMsgTest001
 * @tc.desc: TransPostAuthChannelMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransPostAuthChannelMsgTest001, TestSize.Level1)
{
    int32_t authId = -1;
    AppInfo appInfo;
    int32_t flag = 1;

    int32_t ret = TransPostAuthChannelMsg(NULL, authId, flag);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransPostAuthChannelMsg(&appInfo, authId, flag);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransPostAuthChannelErrMsgTest001
 * @tc.desc: TransPostAuthChannelErrMsgTest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelTest, TransPostAuthChannelErrMsgTest001, TestSize.Level1)
{
    int32_t authId = -1;
    int32_t errcode = 0;
    const char *errMsg = "test error msg.";

    TransPostAuthChannelErrMsg(authId, errcode, NULL);
    TransPostAuthChannelErrMsg(authId, errcode, errMsg);
    EXPECT_TRUE(true);
}

} // namespace OHOS