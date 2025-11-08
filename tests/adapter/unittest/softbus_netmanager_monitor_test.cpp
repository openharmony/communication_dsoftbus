/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "lnn_linkwatch.c"
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
#define IPV6_1 "aaaa"
#define IPV6_2 "bbbb"
#define IPV6_3 "cccc"
#define IPV6_4 "dddd"
#define IPV6_5 "0040"
#define IPV6_6 "8a2e"
#define IPV6_7 "0070"
#define IPV6_8 "7980"
#define LOCAL_IPV6_LINK IPV6_1 ":" IPV6_2 ":" IPV6_3 ":" IPV6_4 ":" IPV6_5 ":" IPV6_6 ":" IPV6_7 ":" IPV6_8

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
 * @tc.name: ConfigNetLinkUpTest001
 * @tc.desc: test ConfigNetLinkUp
 *           config net link up test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigNetLinkUpTest001, TestSize.Level1)
{
    int32_t ret = ConfigNetLinkUp(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    char ifName[] = NCM_LINK_NAME;
    ret = ConfigNetLinkUp(ifName);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CONFIG_NETLINK_UP_FAIL);
}

/*
 * @tc.name: ConfigLocalIpTest001
 * @tc.desc: test ConfigLocalIp
 *           config net link local ip test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigLocalIpTest001, TestSize.Level1)
{
    char ifName[] = NCM_LINK_NAME;
    int32_t ret = ConfigLocalIp(ifName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    char ip[] = LOCAL_IP_LINK;
    ret = ConfigLocalIp(ifName, ip);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CONFIG_NETLINK_IP_FAIL);
}

/*
 * @tc.name: ConfigRouteTest001
 * @tc.desc: test ConfigRoute
 *           config net link route test
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ConfigRoute(id, ifName, destination, gateway);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CONFIG_NETLINK_ROUTE_FAIL);
}

/*
 * @tc.name: LnnInitNetManagerMonitorImpl_001
 * @tc.desc: test LnnInitNetManagerMonitorImpl
 *           Verify the LnnInitNetManagerMonitorImpl function return value equal SOFTBUS_INVALID_PARAM
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

/*
 * @tc.name: LnnInitNetlinkMonitorImpl_001
 * @tc.desc: test LnnInitNetlinkMonitorImpl
 *           Verify the LnnInitNetlinkMonitorImpl function return value equal SOFTBUS_LOCK_ERR
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

/*
 * @tc.name: LnnInitNetlinkMonitorImpl_002
 * @tc.desc: test LnnInitNetlinkMonitorImpl
 *           Verify the LnnInitNetlinkMonitorImpl function return value SOFTBUS_NETWORK_CREATE_SOCKET_FAILED
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

/*
 * @tc.name: LnnInitNetlinkMonitorImpl_003
 * @tc.desc: test LnnInitNetlinkMonitorImpl
 *           Verify the LnnInitNetlinkMonitorImpl function return value equal SOFTBUS_LOCK_ERR
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

/*
 * @tc.name: LnnInitNetlinkMonitorImpl_004
 * @tc.desc: test LnnInitNetlinkMonitorImpl
 *           Verify the LnnInitNetlinkMonitorImpl function return value equal SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnInitNetlinkMonitorImpl_004, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> NetworkInterfaceMock;
    EXPECT_CALL(NetworkInterfaceMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketCreate).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketSetOpt).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketClose).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(NetworkInterfaceMock, SoftBusSocketBind).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(NetworkInterfaceMock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitNetlinkMonitorImpl();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConfigLocalIpv6_001
 * @tc.desc: test ConfigLocalIpv6
 *           ConfigLocalIpv6_001 function return value equal SOFTBUS_NETWORK_CONFIG_NETLINK_IPV6_FAILED
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, ConfigLocalIpv6_001, TestSize.Level1)
{
    char ifName[] = NCM_LINK_NAME;
    char localIpv6[] = LOCAL_IPV6_LINK;
    int32_t ret = ConfigLocalIpv6(ifName, localIpv6);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CONFIG_NETLINK_IPV6_FAILED);
}

/*
 * @tc.name: AddAttr_001
 * @tc.desc: test AddAttr
 *           AddAttr_001 function return value equal SOFTBUS_NETWORK_INVALID_NLMSG
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, AddAttr_001, TestSize.Level1)
{
    struct nlmsghdr my_nlmsghdr = {
        .nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsghdr)),
        .nlmsg_type = 1,
        .nlmsg_flags = 0,
        .nlmsg_seq = 12345,
        .nlmsg_pid = 6789
    };
    uint32_t maxLen = 20;
    uint16_t type = 1;
    const uint8_t data[] = {0x01, 0x02, 0x03};
    uint16_t attrLen = 4;
    int32_t ret = AddAttr(&my_nlmsghdr, maxLen, type, data, attrLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_INVALID_NLMSG);
}

/*
 * @tc.name: LnnIsLinkReady_001
 * @tc.desc: test LnnIsLinkReady
 *           LnnIsLinkReady function return false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, LnnIsLinkReady_001, TestSize.Level1)
{
    const char *iface = nullptr;
    EXPECT_FALSE(LnnIsLinkReady(iface));
}

/*
 * @tc.name: GetRtAttr_001
 * @tc.desc: test GetRtAttr
 *           GetRtAttr function return SOFTBUS_NETWORK_NETLINK_GET_ATTR_FAILED
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, GetRtAttr_001, TestSize.Level1)
{
    struct rtattr rta;
    rta.rta_len = sizeof(struct rtattr);
    rta.rta_type = 1;
    int32_t len = 10;
    uint16_t type = 3;
    uint8_t value[] = {0x01, 0x02, 0x03};
    uint32_t valueLen = 3;
    int32_t ret = GetRtAttr(&rta, len, type, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NETLINK_GET_ATTR_FAILED);
}

/*
 * @tc.name: GetRtAttr_002
 * @tc.desc: test GetRtAttr
 *           GetRtAttr function return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, GetRtAttr_002, TestSize.Level1)
{
    struct rtattr rta;
    rta.rta_len = sizeof(struct rtattr);
    rta.rta_type = 1;
    int32_t len = 4;
    uint16_t type = 1;
    uint8_t value[] = {0x01, 0x02, 0x03};
    uint32_t valueLen = 3;
    int32_t ret = GetRtAttr(&rta, len, type, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetRtAttr_003
 * @tc.desc: test GetRtAttr
 *           GetRtAttr function return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, GetRtAttr_003, TestSize.Level1)
{
    struct rtattr rta;
    rta.rta_len = sizeof(struct rtattr);
    rta.rta_type = 1;
    int32_t len = 4;
    uint16_t type = 1;
    uint8_t value[] = {0x01, 0x02, 0x03, 0x04};
    uint32_t valueLen = 4;
    int32_t ret = GetRtAttr(&rta, len, type, value, valueLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ProcessNetlinkAnswer_001
 * @tc.desc: test ProcessNetlinkAnswer
 *           ProcessNetlinkAnswer function return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterNetManagerMonitorTest, ProcessNetlinkAnswer_001, TestSize.Level1)
{
    struct nlmsghdr my_nlmsghdr = {
        .nlmsg_len = sizeof(struct nlmsghdr),
        .nlmsg_type = 1,
        .nlmsg_flags = 0,
        .nlmsg_seq = 12345,
        .nlmsg_pid = 6789
    };
    int32_t seq = 12345;
    int32_t ret = ProcessNetlinkAnswer(&my_nlmsghdr, sizeof(struct nlmsghdr), seq);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS