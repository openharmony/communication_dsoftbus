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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "trans_channel_callback.h"
#include "softbus_def.h"
#include "softbus_app_info.h"
#include "trans_session_manager.h"
#include "trans_client_proxy.h"
#include "softbus_adapter_mem.h"
#include "trans_lane_manager.h"

using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

class TransChannelCallbackTest : public testing::Test {
public:
    TransChannelCallbackTest()
    {}
    ~TransChannelCallbackTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransChannelCallbackTest::SetUpTestCase(void)
{}

void TransChannelCallbackTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransServerOnChannelOpened001
 * @tc.desc: TransServerOnChannelOpened001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnChannelOpened001, TestSize.Level1)
{
    const char *pkgName = TEST_PKG_NAME;
    const char *sessionName = TEST_SESSION_NAME;
    int32_t pid = 2112;
    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));

    int32_t ret = TransServerGetChannelCb()->OnChannelOpened(NULL, pid, sessionName, channel);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, pid, NULL, channel);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, pid, NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channel->isServer = false;
    channel->channelType = CHANNEL_TYPE_UDP;
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, pid, sessionName, channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channel->isServer = true;
    channel->channelType = (CHANNEL_TYPE_UDP - 1);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, pid, sessionName, channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransServerOnChannelOpenFailed001
 * @tc.desc: TransServerOnChannelOpenFailed001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnChannelOpenFailed001, TestSize.Level1)
{
    int32_t pid = 2112;
    int32_t channelId = 12;
    int32_t channelType = 21;
    int32_t errCode = 2;
    int32_t ret = TransServerGetChannelCb()->OnChannelOpenFailed(NULL, pid, channelId, channelType, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransServerOnMsgReceived001
 * @tc.desc: TransServerOnMsgReceived001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnMsgReceived001, TestSize.Level1)
{
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = 2112;
    int32_t channelId = -1;
    int32_t channelType = -1;
    TransReceiveData *receiveData = (TransReceiveData *)SoftBusCalloc(sizeof(TransReceiveData));
    ASSERT_TRUE(receiveData != nullptr);

    int32_t ret = TransServerGetChannelCb()->OnDataReceived(NULL, pid, channelId, channelType, receiveData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnDataReceived(pkgName, pid, channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    receiveData->data = (void *)TEST_PKG_NAME;
    receiveData->dataLen = 2;
    channelId = -1;
    channelType = -2;
    ret = TransServerGetChannelCb()->OnDataReceived(pkgName, pid, channelId, channelType, receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    channelId = 1;
    channelType = 2;
    receiveData->dataLen = 1;
    ret = TransServerGetChannelCb()->OnDataReceived(pkgName, pid, channelId, channelType, receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (receiveData != NULL) {
        SoftBusFree(receiveData);
    }
}

/**
 * @tc.name: TransServerOnQosEvent001
 * @tc.desc: TransServerOnQosEvent001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnQosEvent001, TestSize.Level1)
{
    QosParam *param = (QosParam *)SoftBusCalloc(sizeof(QosParam));
    ASSERT_TRUE(param != nullptr);
    const char *pkgName = TEST_PKG_NAME;

    int32_t ret = TransServerGetChannelCb()->OnQosEvent(NULL, param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnQosEvent(pkgName, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    param->tvCount = 0;
    ret = TransServerGetChannelCb()->OnQosEvent(pkgName, param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    param->tvCount = 1;
    param->pid = -1000000000;
    ret = TransServerGetChannelCb()->OnQosEvent(pkgName, param);
    EXPECT_EQ(SOFTBUS_OK, ret);

    param->tvCount = 1;
    param->pid = 1;
    ret = TransServerGetChannelCb()->OnQosEvent(pkgName, param);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (param != NULL) {
        SoftBusFree(param);
    }
}

/**
 * @tc.name: TransServerOnChannelLinkDown001
 * @tc.desc: TransServerOnChannelLinkDown001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnChannelLinkDown001, TestSize.Level1)
{
    int32_t pid = 2112;
    const char *pkgName = TEST_PKG_NAME;
    const char *networkId = "1234";
    int32_t routeType = 123124;

    int32_t ret = TransServerOnChannelLinkDown(NULL, pid, NULL, NULL, NULL, networkId, routeType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    pid = -1;
    ret = TransServerOnChannelLinkDown(pkgName, pid, NULL, NULL, NULL, networkId, routeType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    pid = 1;
    ret = TransServerOnChannelLinkDown(pkgName, pid, NULL, NULL, NULL, networkId, routeType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransServerOnChannelClosed
 * @tc.desc: TransServerOnChannelClosed, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCallbackTest, TransServerOnChannelClosed, TestSize.Level1)
{
    int32_t channelId = 12;
    int32_t channelType = CHANNEL_TYPE_UDP;
    int32_t pid = 212;
    int32_t ret = TransServerGetChannelCb()->OnChannelClosed(NULL, pid, channelId, channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // OHOS
