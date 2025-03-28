/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "lnn_lane_link.h"
#include "message_handler.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_proxychannel_common.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_pipeline.h"
#include "softbus_proxychannel_pipeline.c"
#include "softbus_proxychannel_session.h"
#include "softbus_proxychannel_transceiver.h"
#include "softbus_transmission_interface.h"
#include "softbus_utils.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.h"
#include "trans_log.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {

#define TEST_CHANNEL_ID 1124
#define SLEEP_TIME 5

class SoftbusProxyChannelPipelineTest : public testing::Test {
public:
    SoftbusProxyChannelPipelineTest()
    {}
    ~SoftbusProxyChannelPipelineTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static void OnDataReceived(int32_t channelId, const char *data, uint32_t len)
{
    (void)channelId;
    (void)data;
    (void)len;
}

static void OnDisconnected(int32_t channelId)
{
    (void)channelId;
}

void SoftbusProxyChannelPipelineTest::SetUpTestCase(void)
{
    LooperInit();
    TransProxyPipelineInit();
    ITransProxyPipelineListener listener = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnected,
    };
    int32_t ret = TransProxyPipelineRegisterListener(MSG_TYPE_P2P_NEGO, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void SoftbusProxyChannelPipelineTest::TearDownTestCase(void) {}

static void testFunc(SoftBusMessage *msg)
{
    (void)msg;
}

static void OnProxyChannelOpened(int32_t channelRequestId, int32_t channelId)
{
    TRANS_LOGI(TRANS_TEST, "channelRequestId=%{public}d, channelId=%{public}d", channelRequestId, channelId);
    (void)channelRequestId;
    (void)channelId;
}

static void OnProxyChannelOpenFailed(int32_t channelRequestId, int32_t reason)
{
    (void)channelRequestId;
    (void)reason;
}

/**@
 * @tc.name: TransProxyPipelineGetChannelIdByNetworkIdTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null networkId.
 * @tc.desc: Should return INVALID_CHANNEL_ID when given invalid networkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineGetChannelIdByNetworkIdTest001, TestSize.Level1)
{
    char networkId[SESSIONKEYSIZE] = {0};
    strcpy_s(networkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    int32_t ret = TransProxyPipelineGetChannelIdByNetworkId(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPipelineGetChannelIdByNetworkId(networkId);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransProxyPipelineGetUuidByChannelIdTest001
 * @tc.desc: test trans proxy pipeline get uuid by channelid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineGetUuidByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_TWO;
    char uuid[SESSIONKEYSIZE] = {0};
    int32_t ret = TransProxyPipelineGetUuidByChannelId(channelId, uuid, SESSIONKEYSIZE);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: TransProxyPipelineCloseChannelTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null parameters.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineCloseChannelTest001, TestSize.Level1)
{
    char networkId[SESSIONKEYSIZE] = {0};
    strcpy_s(networkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    TransProxyPipelineChannelOption option = {
        .bleDirect = false,
    };
    ITransProxyPipelineCallback channelCallback = {
        .onChannelOpened = OnProxyChannelOpened,
        .onChannelOpenFailed = OnProxyChannelOpenFailed,
    };
    int32_t ret = TransProxyPipelineOpenChannel(TEST_NUMBER_THREE, nullptr, &option, &channelCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPipelineOpenChannel(TEST_NUMBER_THREE, networkId, nullptr, &channelCallback);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPipelineOpenChannel(TEST_NUMBER_THREE, networkId, &option, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransProxyPipelineCloseChannel(TEST_NUMBER_THREE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null uuid.
 * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyGetSessionKeyByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_TEN;
    char uuid[SESSIONKEYSIZE] = {0};
    strcpy_s(uuid, SESSIONKEYSIZE, TEST_STRING_ELEVEN);

    int32_t ret = InnerSaveChannel(channelId, uuid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = InnerSaveChannel(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_UUID, ret);
}

/**
  * @tc.name: TransProxyPipelineOnChannelOpenedTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null uuid.
  * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineOnChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_TEN;
    char uuid[SESSIONKEYSIZE] = {0};
    strcpy_s(uuid, SESSIONKEYSIZE, TEST_STRING_ELEVEN);
    unsigned char isServer = 0;

    channelId = TEST_MESSAGE_CHANNEL_ID;
    int32_t ret = TransProxyPipelineOnChannelOpened(channelId, nullptr, isServer);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_UUID, ret);
}

/**
  * @tc.name: TransProxyPipelineOnChannelClosed001
  * @tc.desc: test proxy get appinfo by chanid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineOnChannelClosed001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_25;
    char uuid[SESSIONKEYSIZE] = {0};
    strcpy_s(uuid, SESSIONKEYSIZE, TEST_STRING_ELEVEN);
    char data[SESSIONKEYSIZE] = {0};
    strcpy_s(data, SESSIONKEYSIZE, TEST_STRING_ELEVEN);

    int32_t ret = InnerSaveChannel(channelId, uuid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyPipelineOnMessageReceived(channelId, data, TEST_PKG_NAME_LEN);
    TransProxyPipelineOnChannelClosed(channelId);
}

/**
  * @tc.name: TransProxyReuseByChannelIdTest001
  * @tc.desc: Should return SOFTBUS_NOT_FIND when given invalid channelId.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyReuseByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_NUMBER_25;
    int32_t ret = TransProxyReuseByChannelId(channelId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
  * @tc.name: TransProxyPipelineGenRequestIdTest001
  * @tc.desc: test generate a new requestid.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineGenRequestIdTest001, TestSize.Level1)
{
    int32_t ret = TransProxyPipelineGenRequestId();
    EXPECT_TRUE(ret);
}

/**
  * @tc.name: TransProxyPipelineSendMessageTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid data or msgType.
  * @tc.desc: Should return SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID when given invalid parameters.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint8_t data = 1;
    uint32_t dataLen = 9;
    TransProxyPipelineMsgType type = MSG_TYPE_CNT;
    int32_t ret = TransProxyPipelineSendMessage(channelId, nullptr, dataLen, type);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyPipelineSendMessage(channelId, &data, dataLen, type);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    type = MSG_TYPE_P2P_NEGO;
    ret = TransProxyPipelineSendMessage(channelId, &data, dataLen, type);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/**
  * @tc.name: TransProxyPipelineCloseChannelDelayTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid channelId.
  * @tc.desc: Should return SOFTBUS_OK when given valid channelId.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineCloseChannelDelayTest001, TestSize.Level1)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t ret = TransProxyPipelineCloseChannelDelay(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    channelId = TEST_CHANNEL_ID;
    ret = TransProxyPipelineCloseChannelDelay(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
  * @tc.name: InnerOnChannelOpenedTest001
  * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid channelId.
  * @tc.desc: Should return SOFTBUS_OK when given valid channelId.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, InnerOnChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t ret = TransProxyPipelineCloseChannelDelay(channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
  * @tc.name: CompareByRequestIdTest001
  * @tc.desc: CompareByRequestId function test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, CompareByRequestIdTest001, TestSize.Level1)
{
    struct PipelineChannelItem *item =
        static_cast<struct PipelineChannelItem *>(SoftBusCalloc(sizeof(struct PipelineChannelItem)));
    EXPECT_NE(item, nullptr);

    int32_t param = 1;
    item->requestId = 1;

    bool flag = CompareByRequestId(static_cast<const struct PipelineChannelItem *>(item), &param);
    EXPECT_EQ(flag, true);

    flag = CompareByUuid(static_cast<const struct PipelineChannelItem *>(item), &param);
    EXPECT_EQ(flag, false);
    SoftBusFree(item);
}

/**
  * @tc.name: TransProxyPipelineHandleMessageTest001
  * @tc.desc: TransProxyPipelineHandleMessage function test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineHandleMessageTest001, TestSize.Level1)
{
    SoftBusMessage msg;
    (void)memset_s(&msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    msg.FreeMessage = testFunc;
    msg.what = LOOPER_MSG_TYPE_OPEN_CHANNEL;
    msg.arg1 = 1;
    char *clone = static_cast<char *>(SoftBusCalloc(UUID_BUF_LEN));
    EXPECT_NE(clone, nullptr);
    const char *uid = "111"; // test value
    (void)strcpy_s(clone, UUID_BUF_LEN, uid);
    msg.obj = clone;
    TransProxyPipelineHandleMessage(&msg);

    msg.what = LOOPER_MSG_TYPE_DELEY_CLOSE_CHANNEL;
    TransProxyPipelineHandleMessage(&msg);

    msg.what = LOOPER_MSG_TYPE_ON_CHANNEL_OPEN_FAILED;
    TransProxyPipelineHandleMessage(&msg);

    msg.what = LOOPER_MSG_TYPE_ON_CHANNEL_OPENED;
    TransProxyPipelineHandleMessage(&msg);

    msg.what = static_cast<PipelineLooperMsgType>(5); // test value
    TransProxyPipelineHandleMessage(&msg);
}

/**
  * @tc.name: TransProxyPipelineOnChannelOpenedTest002
  * @tc.desc: TransProxyPipelineOnChannelOpened function test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineOnChannelOpenedTest002, TestSize.Level1)
{
    const char *uuid = "111111111"; // test value
    int32_t channelId = TEST_CHANNEL_ID;
    unsigned char isServer = 1;
    int32_t ret = TransProxyPipelineOnChannelOpened(channelId, uuid, isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
  * @tc.name: TransProxyPipelineCloseChannelTest002
  * @tc.desc: TransProxyPipelineCloseChannel function test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineCloseChannelTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    PipelineChannelItem item;
    (void)memset_s(&item, sizeof(PipelineChannelItem), 0, sizeof(PipelineChannelItem));
    item.requestId = 1;
    const char *uuid = "1111111111"; // test value

    int32_t ret = InnerSaveChannel(channelId, uuid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransProxyPipelineCloseChannel(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
  * @tc.name: TransProxyPipelineOpenChannelTest002
  * @tc.desc: TransProxyPipelineOpenChannel function test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineOpenChannelTest002, TestSize.Level1)
{
    char networkId[SESSIONKEYSIZE] = {0};
    (void)strcpy_s(networkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    TransProxyPipelineChannelOption option = {
        .bleDirect = false,
    };

    ITransProxyPipelineCallback channelCallback = {
        .onChannelOpened = OnProxyChannelOpened,
        .onChannelOpenFailed = OnProxyChannelOpenFailed,
    };

    int32_t ret = TransProxyPipelineOpenChannel(TEST_NUMBER_THREE, networkId, &option, &channelCallback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(SLEEP_TIME);
}
} // namespace OHOS
