/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <securec.h>

#include "lnn_event_monitor_impl.h"
#include "lnn_netmanager_monitor.h"
#include "net_conn_client.h"
#include "refbase.h"
#include "softbus_error_code.h"

#define NCM_LINK_NAME           "ncm0"
#define LOCAL_IP_LINK           "192.168.66.1"
#define DEFAULT_GATEWAY_POSTFIX "99"

namespace OHOS {

using namespace testing::ext;
using namespace testing;
class AdapterNetManagerMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void AdapterNetManagerMonitorTest::SetUpTestCase() { }
void AdapterNetManagerMonitorTest::TearDownTestCase() { }
void AdapterNetManagerMonitorTest::SetUp() { }
void AdapterNetManagerMonitorTest::TearDown() { }

/*
 * @tc.name: ConfigNetLinkUp
 * @tc.desc: config net link up test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigNetLinkUpTest001, TestSize.Level1)
{
    int32_t ret = ConfigNetLinkUp(NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    char ifName[] = NCM_LINK_NAME;
    ret = ConfigNetLinkUp(ifName);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CONFIG_NETLINK_UP_FAIL);
}

/*
 * @tc.name: ConfigLocalIp
 * @tc.desc: config net link local ip test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigLocalIpTest001, TestSize.Level1)
{
    char ifName[] = NCM_LINK_NAME;
    int32_t ret = ConfigLocalIp(ifName, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    char ip[] = LOCAL_IP_LINK;
    ret = ConfigLocalIp(ifName, ip);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CONFIG_NETLINK_IP_FAIL);
}

/*
 * @tc.name: ConfigRoute
 * @tc.desc: config net link route test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigRouteTest001, TestSize.Level1)
{
    int32_t id = 0;
    char ifName[] = NCM_LINK_NAME;
    char destination[] = DEFAULT_GATEWAY_POSTFIX;
    char gateway[] = "";
    int32_t ret = ConfigRoute(id, ifName, destination, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = ConfigRoute(id, ifName, destination, gateway);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CONFIG_NETLINK_ROUTE_FAIL);
}
} // namespace OHOS
