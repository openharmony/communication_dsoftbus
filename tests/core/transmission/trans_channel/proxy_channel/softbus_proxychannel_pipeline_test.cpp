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
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
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
#define TEST_AUTHSESSION "IShareAuthSession"
#define TEST_CHANNEL_INDENTITY "12345678"
#define TEST_PKG_NAME "com.trans.proxy.test.pkgname"
#define VALID_BUSNAME "testbusName"
#define VALID_PKGNAME "testPkgName"
#define VALID_SESSIONNAME "testSessionName"

#define TEST_ARRRY_SIZE 48
#define TEST_BUF_LEN 32
#define TEST_CHANNEL_IDENTITY_LEN 33
#define TEST_DEATH_CHANNEL_ID 14
#define TEST_INVALID_LARGE_SIZE (100 * 1024)
#define TEST_MESSAGE_CHANNEL_ID 13
#define TEST_MESSAGE_CHANNEL_VALID_ID 46
#define TEST_NUMBER_ELEVEN 11
#define TEST_NUMBER_ONE 1
#define TEST_NUMBER_TEN 10
#define TEST_NUMBER_THREE 3
#define TEST_NUMBER_TWENTY 20
#define TEST_NUMBER_TWO 2
#define TEST_NUMBER_VALID (-1)
#define TEST_NUMBER_ZERO (-1)
#define TEST_NUMBER_25 25
#define TEST_NUMBER_26 26
#define TEST_NUMBER_5000 5000
#define TEST_PARSE_MESSAGE_CHANNEL 45
#define TEST_PAY_LOAD "testPayLoad"
#define TEST_PKGNAME "com.test.pkgname"
#define TEST_PKG_NAME_LEN 65
#define PROXY_CHANNEL_BT_IDLE_TIMEOUT 240
#define TEST_RESET_MESSAGE_CHANNEL_ID 30
#define TEST_STRING_TEN "10"
#define TEST_STRING_ELEVEN "11"
#define SESSIONKEYSIZE 256

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
    TransProxyPipelineInit();
    ITransProxyPipelineListener listener = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnected,
    };
    int32_t ret = TransProxyPipelineRegisterListener(MSG_TYPE_P2P_NEGO, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void SoftbusProxyChannelPipelineTest::TearDownTestCase(void)
{
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

/**
 * @tc.name: TransProxyPipelineOpenChannelTest001
 * @tc.desc: test trans proxy pipeline open channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineOpenChannelTest001, TestSize.Level1)
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
    int32_t ret = TransProxyPipelineOpenChannel(TEST_NUMBER_TWO, networkId, &option, &channelCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    InnerOpenProxyChannel(TEST_NUMBER_TWO);
}

/**@
 * @tc.name: TransProxyPipelineGetChannelIdByNetworkIdTest001
 * @tc.desc: test trans proxy pipeline get channelid by networkiEQd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelPipelineTest, TransProxyPipelineGetChannelIdByNetworkIdTest001, TestSize.Level1)
{
    char networkId[SESSIONKEYSIZE] = {0};
    strcpy_s(networkId, SESSIONKEYSIZE, TEST_CHANNEL_INDENTITY);
    int32_t ret = TransProxyPipelineGetChannelIdByNetworkId(networkId);
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
 * @tc.desc: test trans proxy pipeline close channel.
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
    int32_t ret = TransProxyPipelineOpenChannel(TEST_NUMBER_THREE, networkId, &option, &channelCallback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyPipelineCloseChannel(TEST_NUMBER_THREE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProxyGetSessionKeyByChanIdTest001
 * @tc.desc: test proxy get session key by chanId.
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
}

/**
  * @tc.name: TransProxyPipelineOnChannelOpenedTest001
  * @tc.desc: test trans proxy pipeline onchannel opened.
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
    int ret = TransProxyPipelineOnChannelOpened(channelId, uuid, isServer);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransProxyPipelineOnChannelOpenFailed(TEST_NUMBER_TWENTY, uuid);
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
} // namespace OHOS
