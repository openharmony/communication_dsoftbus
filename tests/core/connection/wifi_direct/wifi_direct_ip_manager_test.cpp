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
#include "negotiate_state.h"
#include "negotiate_message.h"
#include "wifi_direct_role_negotiator.h"
#include "wifi_direct_role_option.h"

using namespace testing::ext;

namespace OHOS {

class WifiDirectIpManagerTest : public testing::Test {
public:
    WifiDirectIpManagerTest()
    {}
    ~WifiDirectIpManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectIpManagerTest::SetUpTestCase(void)
{}

void WifiDirectIpManagerTest::TearDownTestCase(void)
{}

void WifiDirectIpManagerTest::SetUp(void)
{}

void WifiDirectIpManagerTest::TearDown(void)
{}

/*
* @tc.name: testWifiDirectIpManager
* @tc.desc: test applyIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectIpManagerTest, WifiDirectIpManager001, TestSize.Level1)
{
    struct WifiDirectIpManager *self = GetWifiDirectIpManager();
    struct WifiDirectIpv4Info remoteArray[INTERFACE_NUM_MAX];
    struct WifiDirectIpv4Info remote[INTERFACE_NUM_MAX];
    struct WifiDirectIpv4Info local[INTERFACE_NUM_MAX];
    int32_t remoteArraySize = INTERFACE_NUM_MAX;
    ListNode conflictList;
    ListInit(&conflictList);
    int32_t ret = self->applyIp(remoteArray, remoteArraySize, local, remote);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *interface = "\0 ";
    const char *macAddress = "\0 ";
    ret = self->configIp(interface, local, remote, macAddress);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    const char *remoteMac = "'\0's";
    const char *interface1 = " \0";
    const char *remoteMac1 = "\0-  \0";
    ret = self->configIp(interface1, local, remote, remoteMac1);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    self->releaseIp(interface, local, remote, remoteMac);
    self->cleanAllIps(interface);
    self->releaseIp(interface1, local, remote, remoteMac1);
    self->cleanAllIps(interface1);
};
}