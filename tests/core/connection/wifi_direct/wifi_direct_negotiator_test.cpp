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

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <pthread.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "wifi_direct_command_manager.h"
#include "wifi_direct_fast_connect.h"
#include "wifi_direct_initiator.h"
#include "wifi_direct_work_queue.h"
#include "wifi_direct_timer_list.h"
#include "default_negotiate_channel.h"
#include "fast_connect_negotiate_channel.h"
#include "broadcast_receiver.h"
#include "resource_manager.h"
#include "link_manager.h"
#include "broadcast_handler.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_negotiator.h"
#include "wifi_direct_coexist_rule.h"
#include "wifi_direct_protocol_factory.h"
#include "wifi_direct_negotiate_channel.h"
#include "wifi_direct_decision_center.h"
#include "wifi_direct_ip_manager.h"
#include "wifi_direct_ipv4_info.h"
#include "wifi_direct_types.h"
#include "wifi_direct_role_negotiator.h"
#include "wifi_direct_role_option.h"
#include "negotiate_message.h"
#include "wifi_direct_trigger_channel.h"
using namespace testing::ext;
struct WifiDirectNegotiateChannel;
namespace OHOS {

class WifiDirectNegotiatorTest : public testing::Test {
public:
    WifiDirectNegotiatorTest()
    {}
    ~WifiDirectNegotiatorTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectNegotiatorTest::SetUpTestCase(void)
{}

void WifiDirectNegotiatorTest::TearDownTestCase(void)
{}

void WifiDirectNegotiatorTest::SetUp(void)
{}

void WifiDirectNegotiatorTest::TearDown(void)
{}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    return SOFTBUS_OK;
}

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test WifiDirectNegotiatorInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator001, TestSize.Level1)
{
    int32_t ret = WifiDirectNegotiatorInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test ProcessNextCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator002, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    int32_t ret = self->processNextCommand();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test retryCurrentCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator003, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    int32_t ret = self->retryCurrentCommand();
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test isRetryErrorCode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator004, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    bool ret = self->isRetryErrorCode(V1_ERROR_BUSY);
    EXPECT_EQ(ret, true);
    ret = self->isRetryErrorCode(1);
    EXPECT_EQ(ret, false);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test closeLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator005, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    bool ret = self->isBusy();
    EXPECT_EQ(ret, false);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test postData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator006, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct NegotiateMessage* msg = NegotiateMessageNew();
    struct WifiDirectNegotiateChannel *channel = nullptr;
    (void)memset_s(channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    self->resetContext();
    self->updateCurrentRemoteDeviceId(channel);
    int32_t ret = self->handleMessageFromProcessor(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test processNewCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator007, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct WifiDirectNegotiateChannel *channel = nullptr;
    (void)memset_s(channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    const char *netWorkId = "123456xxx";
    enum WifiDirectLinkType type = WIFI_DIRECT_LINK_TYPE_P2P;
    int32_t ret = self->prejudgeAvailability(netWorkId, type);
    EXPECT_EQ(ret, V1_ERROR_IF_NOT_AVAILABLE);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test postData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator008, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct NegotiateMessage *msg = NegotiateMessageNew();
    int32_t ret = self->postData(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test handleMessageFromProcessor with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator009, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct NegotiateMessage* msg = NegotiateMessageNew();
    int32_t ret = self->handleMessageFromProcessor(msg);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test syncLnnInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator013, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct InnerLink *innerLink = InnerLinkNew();
    self->syncLnnInfo(innerLink);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test syncLnnInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectNegotiatorTest, WifiDirectNegotiator014, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    struct WifiDirectNegotiateChannel *channel = (struct WifiDirectNegotiateChannel*)SoftBusCalloc(sizeof(*channel));
    (void)memset_s(channel, sizeof(*channel), 0, sizeof(*channel));
    const uint8_t *data = nullptr;
    size_t len = 0;
    channel->isRemoteSupportTlv = true;
    channel->getDeviceId = GetDeviceId;
    self->onNegotiateChannelDataReceived(channel, data, len);
};
}