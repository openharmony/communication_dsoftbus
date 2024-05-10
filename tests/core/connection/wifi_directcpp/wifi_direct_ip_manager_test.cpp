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

#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include "net_conn_client.h"
#include "softbus_error_code.h"
#include "wifi_direct_ip_manager.h"

using namespace testing::ext;
using testing::_;
using ::testing::Return;

namespace OHOS::SoftBus {
class WifiDirectIpManagerTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: GetEUI64Identifier
 * @tc.desc: check GetEUI64Identifier methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, GetEUI64Identifier, TestSize.Level1)
{
    std::string mac("00:00:02:0d:48:91");
    std::bitset<EUI_64_IDENTIFIER_LEN> ret = WifiDirectIpManager::GetInstance().GetEUI64Identifier(mac);
    EXPECT_EQ(ret.to_string(), "0000001000000000000000101111111111111110000011010100100010010001");
}

/*
 * @tc.name: ApplyIpv6
 * @tc.desc: check ApplyIpv6 methods,when mac is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv6, TestSize.Level1)
{
    std::string mac;
    std::string ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac);
    std::cout << ipv6 << std::endl;
    EXPECT_EQ(ipv6.empty(), true);
}

/*
 * @tc.name: ApplySubNet
 * @tc.desc: check ApplySubNet methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplySubNet, TestSize.Level1)
{
    std::vector<Ipv4Info> remoteArray;
    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(remoteArray);
    std::cout << subNet << std::endl;
    EXPECT_EQ(subNet.empty(), false);

    subNet = "";
    remoteArray.push_back(Ipv4Info("172.30.1.2"));
    subNet = WifiDirectIpManager::GetInstance().ApplySubNet(remoteArray);
    std::cout << subNet << std::endl;
    EXPECT_EQ(subNet.empty(), false);
}

/*
 * @tc.name: ApplyIpv4
 * @tc.desc: check ApplyIpv4 method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv4, TestSize.Level1)
{
    Ipv4Info sink;
    Ipv4Info source;
    std::vector<Ipv4Info> remoteArray;
    int32_t ret = WifiDirectIpManager::GetInstance().ApplyIpv4(remoteArray, sink, source);
    EXPECT_EQ(ret, 0);

    ret = -1;
    remoteArray.push_back(Ipv4Info("172.30.1.2"));
    ret = WifiDirectIpManager::GetInstance().ApplyIpv4(remoteArray, sink, source);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConfigAndReleaseIpv4
 * @tc.desc: check ConfigIpv4 and ReleaseIpv4 method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigAndReleaseIpv4, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;

    std::string interface("p2p0");
    Ipv4Info local("172.30.1.2");
    Ipv4Info remote("172.30.1.1");
    std::string remoteMac("08:fb:ea:19:78:38");
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, AddStaticArp).WillOnce(Return(0));
    int32_t ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    std::cout << ipManager.arps_[remote.ToIpString()] << std::endl;
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ipManager.ips_.size(), 1);

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(-1));
    ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    EXPECT_EQ(ipManager.ips_.size(), 1);

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, AddStaticArp).WillOnce(Return(-1));
    ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    EXPECT_EQ(ipManager.ips_.size(), 1);

    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(-1));
    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(-1));
    ipManager.ReleaseIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ipManager.ips_.size(), 0);

    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(0));
    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));
    ipManager.ReleaseIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ipManager.ips_.size(), 0);
}

/*
 * @tc.name: GetNetworkGateWay
 * @tc.desc: check GetNetworkGateWay method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, GetNetworkGateWay, TestSize.Level1)
{
    std::string ipString("192.168.1.255");
    std::string gateWay;
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();
    int32_t ret = ipManager.GetNetworkGateWay(ipString, gateWay);
    std::cout << gateWay << std::endl;
    EXPECT_EQ(ret, 0);

    ipString = "1234";
    ret = ipManager.GetNetworkGateWay(ipString, gateWay);
    std::cout << gateWay << std::endl;
    EXPECT_NE(ret, 0);
}

/*
 * @tc.name: GetNetworkDestination
 * @tc.desc: check GetNetworkDestination method
 * @tc.type: FUNC
 * @tc.require:
//  */
HWTEST_F(WifiDirectIpManagerTest, GetNetworkDestination, TestSize.Level1)
{
    std::string ipString("192.168.1.255");
    std::string destination;
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();
    int32_t ret = ipManager.GetNetworkDestination(ipString, destination);
    std::cout << destination << std::endl;
    EXPECT_EQ(ret, 0);

    ipString = "1234";
    ret = ipManager.GetNetworkDestination(ipString, destination);
    std::cout << destination << std::endl;
    EXPECT_NE(ret, 0);
}

/*
 * @tc.name: AddAndDeleteInterfaceAddress
 * @tc.desc: check AddInterfaceAddress method and DeleteInterfaceAddress method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, AddAndDeleteInterfaceAddress, TestSize.Level1)
{
    std::string ipString = "192.168.1.255";
    std::string interface = "p2p0";
    int32_t prefixLength = 24;
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();

    NetManagerStandard::MockNetConnClient client;

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute(_, _, _, _)).WillOnce(Return(0));

    int32_t ret = ipManager.AddInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute(_, _, _, _)).WillOnce(Return(-1));
    ret = ipManager.AddInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(-1));
    ret = ipManager.AddInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));

    ret = ipManager.DeleteInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(-1));
    ret = ipManager.DeleteInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(-1));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));

    ret = ipManager.DeleteInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, 0);

    ipString = "1234";
    ret = ipManager.AddInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = ipManager.DeleteInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

} // namespace OHOS::SoftBus