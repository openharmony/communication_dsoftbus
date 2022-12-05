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
#include "softbus_log.h"
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

    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));

    int32_t ret = TransServerGetChannelCb()->OnChannelOpened(NULL, sessionName, channel);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, NULL, channel);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channel->isServer = false;
    channel->channelType = CHANNEL_TYPE_UDP;
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, sessionName, channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channel->isServer = true;
    channel->channelType = (CHANNEL_TYPE_UDP - 1);
    ret = TransServerGetChannelCb()->OnChannelOpened(pkgName, sessionName, channel);
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
    const char *pkgName = TEST_PKG_NAME;
    int32_t channelId = 12;
    int32_t channelType = 21;
    int32_t errCode = 33;

    int32_t ret = TransServerGetChannelCb()->OnChannelOpenFailed(NULL, channelType, channelId, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransLaneMgrDeinit();
    ret = TransServerGetChannelCb()->OnChannelOpenFailed(pkgName, channelId, channelType, errCode);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransServerGetChannelCb()->OnChannelOpenFailed(pkgName, channelId, channelType, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    int32_t channelId = -1;
    int32_t channelType = -1;
    uint32_t len = 1;
    int32_t type = 12;
    const void *data = "test";

    int32_t ret = TransServerGetChannelCb()->OnDataReceived(NULL, channelId, channelType, data, len, type);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransServerGetChannelCb()->OnDataReceived(pkgName, channelId, channelType, NULL, len, type);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    len = 0;
    ret = TransServerGetChannelCb()->OnDataReceived(pkgName, channelId, channelType, data, len, type);
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
    ret = TransServerGetChannelCb()->OnQosEvent(pkgName, param);
    EXPECT_EQ(SOFTBUS_OK, ret);

    param->tvCount = 1;
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
    const char *pkgName = TEST_PKG_NAME;
    const char *networkId = "1234";
    int32_t routeType = 123124;

    int32_t ret = TransServerOnChannelLinkDown(NULL, networkId, routeType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransServerOnChannelLinkDown(pkgName, networkId, routeType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransServerOnChannelLinkDown(pkgName, networkId, routeType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // OHOS
