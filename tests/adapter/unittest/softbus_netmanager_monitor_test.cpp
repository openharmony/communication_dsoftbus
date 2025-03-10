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
#include "lnn_netlink_monitor.c"
#include "net_conn_client.h"
#include "network_mock.h"
#include "refbase.h"
#include "softbus_adapter_errcode.h"
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
    int32_t ret = ConfigNetLinkUp(nullptr);
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
    int32_t ret = ConfigLocalIp(ifName, nullptr);
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
    int32_t ret = ConfigRoute(id, ifName, destination, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = ConfigRoute(id, ifName, destination, gateway);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CONFIG_NETLINK_ROUTE_FAIL);
}

/**
 * @tc.name:LnnNetmanagerMonitorTest_001
 * @tc.desc: Verify the SetSoftBusWifiConnState function return value equal SOFTBUS_WIFI_UNKNOWN.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnInitNetManagerMonitorImpl_001, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> NetworkInterfaceMock;
    EXPECT_CALL(NetworkInterfaceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnInitNetManagerMonitorImpl();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_MONITOR_INIT_FAIL);
}

/**
 * @tc.name:LnnNetmanagerMonitorTest_001
 * @tc.desc: Verify the LnnInitNetlinkMonitorImpl function return value equal SOFTBUS_LOCK_ERR.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnInitNetlinkMonitorImpl_001, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> NetworkInterfaceMock;
    EXPECT_CALL(NetworkInterfaceMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));
    int32_t ret = LnnInitNetlinkMonitorImpl();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name:LnnInitNetlinkMonitorImpl_002
 * @tc.desc: Verify the LnnInitNetlinkMonitorImpl function return value SOFTBUS_NETWORK_CREATE_SOCKET_FAILED.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnInitNetlinkMonitorImpl_002, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> NetworkInterfaceMock;
    EXPECT_CALL(NetworkInterfaceMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
	EXPECT_CALL(NetworkInterfaceMock, SoftBusSocketCreate)
        .WillRepeatedly(Return(SOFTBUS_NETWORK_CREATE_SOCKET_FAILED));
    int32_t ret = LnnInitNetlinkMonitorImpl();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CREATE_SOCKET_FAILED);
}

/**
 * @tc.name:LnnInitNetlinkMonitorImpl_003
 * @tc.desc: Verify the LnnInitNetlinkMonitorImpl function return value equal SOFTBUS_LOCK_ERR.
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnInitNetlinkMonitorImpl_003, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> NetworkInterfaceMock;
    EXPECT_CALL(NetworkInterfaceMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketCreate).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketSetOpt).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketClose).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketBind).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(NetworkInterfaceMock, AddTrigger).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));
    int32_t ret = LnnInitNetlinkMonitorImpl();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}
} // namespace OHOS
