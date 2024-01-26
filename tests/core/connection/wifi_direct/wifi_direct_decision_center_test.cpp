/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "wifi_direct_processor_factory.h"
#include "wifi_direct_negotiate_channel.h"
#include "wifi_direct_decision_center.h"
#include "wifi_direct_ip_manager.h"
#include "wifi_direct_ipv4_info.h"
#include "wifi_direct_types.h"
#include "negotiate_message.h"
#include "wifi_direct_role_negotiator.h"
#include "wifi_direct_role_option.h"

using namespace testing::ext;
using namespace std;
namespace OHOS {

class WifiDirectDecision : public testing::Test {
public:
    WifiDirectDecision()
    {}
    ~WifiDirectDecision()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectDecision::SetUpTestCase(void)
{}

void WifiDirectDecision::TearDownTestCase(void)
{}

void WifiDirectDecision::SetUp(void)
{}

void WifiDirectDecision::TearDown(void)
{}

/*
* @tc.name: WifiDirectDecisionCenter001
* @tc.desc: test getProtocol PutProtocol
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDecision, WifiDirectDecisionCenter001, TestSize.Level1)
{
    struct WifiDirectDecisionCenter *self = GetWifiDirectDecisionCenter();
    EXPECT_NE(self, nullptr);
    struct WifiDirectNegotiateChannel *channel = nullptr;
    struct WifiDirectProtocol *protocol = nullptr;
    (void)memset_s(channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    (void)memset_s(protocol, sizeof(WifiDirectProtocol), 0, sizeof(WifiDirectProtocol));
    struct WifiDirectProtocol *ret = self->getProtocol(channel);
    EXPECT_NE(ret, nullptr);
};

/*
* @tc.name: WifiDirectDecisionCenter002
* @tc.desc: test GetProcessorByNegoChannel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDecision, WifiDirectDecisionCenter002, TestSize.Level1)
{
    struct WifiDirectDecisionCenter *self = GetWifiDirectDecisionCenter();
    EXPECT_NE(self, nullptr);
    struct WifiDirectNegotiateChannel *channel = nullptr;
    enum WifiDirectLinkType linkType = WIFI_DIRECT_LINK_TYPE_P2P;
    (void)memset_s(channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    struct WifiDirectProcessor *ret = self->getProcessorByChannelAndLinkType(channel, linkType);
    EXPECT_NE(ret, nullptr);
};

/*
* @tc.name: WifiDirectDecisionCenter003
* @tc.desc: test GetProcessorByNegoChannelAndConnectType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDecision, WifiDirectDecisionCenter003, TestSize.Level1)
{
    struct WifiDirectDecisionCenter *self = GetWifiDirectDecisionCenter();
    EXPECT_NE(self, nullptr);
    struct WifiDirectNegotiateChannel *channel = nullptr;
    (void)memset_s(channel, sizeof(WifiDirectNegotiateChannel), 0, sizeof(WifiDirectNegotiateChannel));
    enum WifiDirectConnectType connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    struct WifiDirectProcessor *ret = self->getProcessorByChannelAndConnectType(channel, connectType);
    EXPECT_NE(ret, nullptr);
};

/*
* @tc.name: WifiDirectDecisionCenter004
* @tc.desc: test GetProcessorByNegotiateMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectDecision, WifiDirectDecisionCenter004, TestSize.Level1)
{
    struct WifiDirectDecisionCenter *self = GetWifiDirectDecisionCenter();
    EXPECT_NE(self, nullptr);
    struct NegotiateMessage *msg = NegotiateMessageNew();
    EXPECT_NE(msg, nullptr);
    struct WifiDirectProcessor *ret = self->getProcessorByNegotiateMessage(msg);
    EXPECT_NE(ret, nullptr);
};
}