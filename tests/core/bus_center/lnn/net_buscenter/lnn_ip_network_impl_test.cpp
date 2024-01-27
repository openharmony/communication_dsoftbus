/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_event.h"
#include "lnn_ip_network_impl_mock.h"
#include "lnn_ip_network_impl.c"
#include "lnn_net_ledger_mock.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

#define BLE_DISABLE 0
#define SIZE 20
#define LNN_DEFAULT_IF_NAME_BR "br0"
namespace OHOS {
using namespace testing::ext;
using namespace testing;
LnnProtocolManager self;
LnnNetIfMgr netifMgr;
constexpr char WLAN_IP1[] = "127.0.0.1";
constexpr char WLAN_IP2[] = "127.0.0.2";
constexpr char IFNAME_TEST0[] = "wlan0";
constexpr char IFNAME_TEST1[] = "wlan1";
class LNNIpNetworkImplMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNIpNetworkImplMockTest::SetUpTestCase()
{
    LooperInit();
}

void LNNIpNetworkImplMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNIpNetworkImplMockTest::SetUp()
{
}

void LNNIpNetworkImplMockTest::TearDown()
{
}

/*
* @tc.name: LNN_IP_NETWORK_IMPL_TEST_001
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNIpNetworkImplMockTest, LNN_IP_NETWORK_IMPL_TEST_001, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> ipMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;

    ListenerModule ret = LnnGetIpListenerModule(LNN_LISTENER_MODE_PROXY);
    EXPECT_TRUE(ret == PROXY);

    ret = LnnGetIpListenerModule(LNN_LISTENER_MODE_DIRECT);
    EXPECT_TRUE(ret == DIRECT_CHANNEL_SERVER_WIFI);

    EXPECT_CALL(ipMock, LnnRegistPhysicalSubnet).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    
    memset_s(&self, sizeof(LnnProtocolManager), 0, sizeof(LnnProtocolManager));
    memset_s(&netifMgr, sizeof(LnnNetIfMgr), 0, sizeof(LnnNetIfMgr));
    strcpy_s(netifMgr.ifName, sizeof("name"), "name");
    int res = LnnEnableIpProtocol(nullptr, nullptr);
    EXPECT_TRUE(res == SOFTBUS_ERR);
    res = LnnEnableIpProtocol(&self, &netifMgr);
    EXPECT_TRUE(res == SOFTBUS_ERR);
    res = LnnEnableIpProtocol(&self, &netifMgr);
    EXPECT_TRUE(res == SOFTBUS_OK);

    EXPECT_CALL(ipMock, LnnRegisterEventHandler).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
        
    res = LnnInitIpProtocol(&self);
    EXPECT_TRUE(res == SOFTBUS_ERR);
    res = LnnInitIpProtocol(&self);
    EXPECT_TRUE(res == SOFTBUS_ERR);
    res = LnnInitIpProtocol(&self);
    EXPECT_TRUE(res == SOFTBUS_OK);

    WifiStateChangeEventHandler(nullptr);
    LnnEventBasicInfo info = {
        .event = LNN_EVENT_WIFI_STATE_CHANGED,
    };
    WifiStateChangeEventHandler(&info);
}

/*
* @tc.name: LNN_IP_NETWORK_IMPL_TEST_002
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNIpNetworkImplMockTest, LNN_IP_NETWORK_IMPL_TEST_002, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> ipMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ipMock, LnnNotifyPhysicalSubnetStatusChanged).WillRepeatedly(Return());
    EXPECT_CALL(ipMock, LnnVisitPhysicalSubnet).WillRepeatedly(Return(true));
    EXPECT_CALL(ipMock, LnnIsLinkReady).WillRepeatedly(Return(true));
    EXPECT_CALL(ipMock, GetNetworkIpByIfName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    VisitNextChoice visit = NotifyWlanAddressChanged(&netifMgr, nullptr);
    EXPECT_TRUE(visit == CHOICE_VISIT_NEXT);
    netifMgr.type = LNN_NETIF_TYPE_WLAN;
    visit = NotifyWlanAddressChanged(&netifMgr, nullptr);
    EXPECT_TRUE(visit == CHOICE_VISIT_NEXT);

    LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
    };
    LnnPhysicalSubnet subnet = {
        .protocol = &lnnProtocolManager,
        .status = LNN_SUBNET_RUNNING,
    };

    OnIpNetifStatusChanged(&subnet, nullptr);
    OnSoftbusIpNetworkDisconnected(&subnet);
    subnet.status = LNN_SUBNET_IDLE;
    OnIpNetifStatusChanged(&subnet, nullptr);
    OnSoftbusIpNetworkDisconnected(&subnet);
}

/*
* @tc.name: LNN_IP_NETWORK_IMPL_TEST_003
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNIpNetworkImplMockTest, LNN_IP_NETWORK_IMPL_TEST_003, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> ipMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ipMock, LnnIsLinkReady).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(ipMock, GetNetworkIpByIfName).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    int ret = GetAvailableIpAddr(IFNAME_TEST0, const_cast<char *>(WLAN_IP1), SIZE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetAvailableIpAddr(IFNAME_TEST1, const_cast<char *>(WLAN_IP2), SIZE);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(ipMock, GetNetworkIpByIfName).WillRepeatedly(LnnIpNetworkImplInterfaceMock::
        ActionOfGetNetworkIpByIfName);
    LnnPhysicalSubnet subnet = {
        .ifName = "noDeviceName",
        .status = LNN_SUBNET_RUNNING,
    };

    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo2);
    IpSubnetManagerEvent res = GetIpEventInRunning(&subnet);
    EXPECT_TRUE(res == IP_SUBNET_MANAGER_EVENT_IF_READY);

    strcpy_s(subnet.ifName, sizeof("DeviceName"), "DeviceName");
    res = GetIpEventInRunning(&subnet);
    EXPECT_TRUE(res != IP_SUBNET_MANAGER_EVENT_MAX);
}

/*
* @tc.name: LNN_IP_NETWORK_IMPL_TEST_004
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNIpNetworkImplMockTest, LNN_IP_NETWORK_IMPL_TEST_004, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> ipMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo2);
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    int ret = RequestMainPort("lo", "127.0.0.1");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RequestMainPort("lol", "127.0.0.1");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RequestMainPort("lol", "127.0.0.2");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RequestMainPort("lol", "127.0.0.2");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RequestMainPort("deviceName", "127.0.0.2");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = RequestMainPort("deviceName", "127.0.0.2");
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ipMock, AuthStartListening).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = OpenAuthPort();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = OpenAuthPort();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = OpenAuthPort();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = OpenIpLink();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(ipMock, LnnIsLinkReady).WillRepeatedly(Return(true));
    EXPECT_CALL(ipMock, GetNetworkIpByIfName).WillRepeatedly(LnnIpNetworkImplInterfaceMock::
        ActionOfGetNetworkIpByIfName);
    LnnPhysicalSubnet subnet = {
        .ifName = "deviceName",
        .status = LNN_SUBNET_RUNNING,
    };
    ret = EnableIpSubnet(&subnet);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
/*
* @tc.name: LNN_IP_NETWORK_IMPL_TEST_005
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LNNIpNetworkImplMockTest, LNN_IP_NETWORK_IMPL_TEST_005, TestSize.Level1)
{
    NiceMock<LnnIpNetworkImplInterfaceMock> ipMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetLocalStrInfo2);
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    int ret = ReleaseMainPort("deviceName");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = ReleaseMainPort("deviceName1");
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = ReleaseMainPort("deviceName");
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(ipMock, LnnGetAddrTypeByIfName).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ipMock, LnnRequestLeaveByAddrType).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    LeaveOldIpNetwork(nullptr);
    LeaveOldIpNetwork(nullptr);
    LeaveOldIpNetwork(nullptr);

    EXPECT_CALL(ledgerMock, LnnSetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ipMock, ConnStopLocalListening).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    CloseProxyPort();
    CloseProxyPort();
}
} // namespace OHOS
