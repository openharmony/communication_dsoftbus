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

class WifiDirectCoexist : public testing::Test {
public:
    WifiDirectCoexist()
    {}
    ~WifiDirectCoexist()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectCoexist::SetUpTestCase(void)
{}

void WifiDirectCoexist::TearDownTestCase(void)
{}

void WifiDirectCoexist::SetUp(void)
{}

void WifiDirectCoexist::TearDown(void)
{}

/*
* @tc.name: WifiDirectCoexistRule001
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule001, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    int32_t ret = self->setCoexistRule("configname");
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
};

/*
* @tc.name: WifiDirectCoexistRule002
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule002, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    int32_t ret = self->setCoexistRule("123.55.1.33");
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
* @tc.name: WifiDirectCoexistRule003
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule003, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    int32_t ret = self->setCoexistRule("[1,2,3]");
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectCoexistRule004
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule004, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    int32_t ret = self->setCoexistRule("[1],[2],[3]");
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectCoexistRule005
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule005, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    int32_t ret = self->setCoexistRule("[[1,2,3],[1,2,3],[1,2,3]]");
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectCoexistRule006
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule006, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    self->bypass = true;
    ListNode sortList;
    ListInit(&sortList);
    bool status =  GetWifiDirectCoexistRule()->isCombinationAvailable(&sortList);
    EXPECT_EQ(status, true);
};

/*
* @tc.name: WifiDirectCoexistRule007
* @tc.desc: test setCoexistRule with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectCoexist, WifiDirectCoexistRule007, TestSize.Level1)
{
    struct WifiDirectCoexistRule *self = GetWifiDirectCoexistRule();
    self->bypass = false;
    ListNode sortList;
    ListInit(&sortList);
    bool status =  GetWifiDirectCoexistRule()->isCombinationAvailable(&sortList);
    EXPECT_EQ(status, true);
};
}