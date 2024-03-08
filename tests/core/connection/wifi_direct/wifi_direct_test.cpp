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
#include "wifi_direct_fast_connect.h"
#include "wifi_direct_initiator.h"
#include "wifi_direct_work_queue.h"
#include "wifi_direct_command_manager.h"
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
#include "negotiate_message.h"
#include "wifi_direct_role_negotiator.h"
#include "wifi_direct_role_option.h"

using namespace testing::ext;

namespace OHOS {

class WifiDirectTest : public testing::Test {
public:
    WifiDirectTest()
    {}
    ~WifiDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectTest::SetUpTestCase(void)
{}

void WifiDirectTest::TearDownTestCase(void)
{}

void WifiDirectTest::SetUp(void)
{}

void WifiDirectTest::TearDown(void)
{}

/*
* @tc.name: WifiDirectInitiator
* @tc.desc: test WifiDirectInitiator
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectInitiator, TestSize.Level1)
{
    int32_t ret = WifiDirectInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WifiDirectWorkQueueInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WifiDirectTimerListInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DefaultNegotiateChannelInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FastConnectNegotiateChannelInit();
    ret = BroadcastReceiverInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ResourceManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LinkManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = BroadcastHandlerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WifiDirectManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = WifiDirectNegotiatorInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test getRequestId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectManager001, TestSize.Level1)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    int32_t ret = self->getRequestId();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test getRemoteUuidByIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectManager002, TestSize.Level1)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    struct WifiDirectStatusListener *listener = (struct WifiDirectStatusListener*)SoftBusCalloc(sizeof(*listener));
    self->registerStatusListener(TRANS_LINK_MODULE, listener);
    const char *ipString = "192.168.0.1";
    char uuid[] = "b5f3c3ce-08b8-4c66-9a71-0b4641d9c769";
    int32_t uuidSize = 36;
    int32_t ret = self->getRemoteUuidByIp(ipString, uuid, uuidSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(listener);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test isDeviceOnline
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectManager003, TestSize.Level1)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    const char *remoteMac = "00:1A:2B:3C:4D:5E";
    bool status = self->isDeviceOnline(remoteMac);
    EXPECT_EQ(status, false);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test getLocalIpByRemoteIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectManager004, TestSize.Level1)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    const char *remoteIp = "192.168.0.1";
    char localIp[] = "192.168.1.1";
    int32_t localIpSize = 32;
    int32_t ret = self->getLocalIpByRemoteIp(remoteIp, localIp, localIpSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectManager
* @tc.desc: test getLocalIpByUuid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectManager005, TestSize.Level1)
{
    struct WifiDirectManager *self = GetWifiDirectManager();
    char localIp[] = "192.168.1.1";
    char uuid[] = "b5f3c3ce-08b8-4c66-9ff1-0b4641d9c769";
    int32_t localIpSize = 32;
    int32_t ret = self->getLocalIpByUuid(uuid, localIp, localIpSize);
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test WifiDirectNegotiatorInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectNegotiator001, TestSize.Level1)
{
    int32_t ret = WifiDirectNegotiatorInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testWifiDirectNegotiator
* @tc.desc: test processNextCommand
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectNegotiator002, TestSize.Level1)
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
HWTEST_F(WifiDirectTest, WifiDirectNegotiator003, TestSize.Level1)
{
    struct WifiDirectNegotiator *self = GetWifiDirectNegotiator();
    int32_t ret = self->retryCurrentCommand();
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: WifiDirectNegotiator004
* @tc.desc: test WifiDirectRoleNegotiator
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectTest, WifiDirectNegotiator004, TestSize.Level1)
{
    enum WifiDirectRole myRole = WIFI_DIRECT_ROLE_AUTO;
    enum WifiDirectRole peerRole = WIFI_DIRECT_ROLE_GC;
    enum WifiDirectRole expectedRole = WIFI_DIRECT_ROLE_BRIDGE_GC;
    const char *localGoMac = "00:0a:95:9d:68:16";
    const char *remoteGoMac = "08:00:27:ff:ff:ff";
    struct WifiDirectRoleNegotiator *self = GetRoleNegotiator();
    int state = self->getFinalRoleWithPeerExpectedRole(myRole, peerRole, expectedRole, localGoMac, remoteGoMac);
    EXPECT_EQ(state, SOFTBUS_INVALID_PARAM);
};
}