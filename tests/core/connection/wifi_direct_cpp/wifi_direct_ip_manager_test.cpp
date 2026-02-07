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

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include "net_conn_client.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "wifi_direct_ip_manager.h"
#include "wifi_direct_defines.h"

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
 * @tc.name: ApplyIpv6
 * @tc.desc: check ApplyIpv6 methods,when mac is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv6, TestSize.Level1)
{
    std::string mac("10:dc:b6:90:84:82");
    std::string mac2("FF:dc:b6:90:84:82");
    std::string ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac);
    EXPECT_EQ(ipv6.empty(), false);

    ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac2);
    EXPECT_EQ(ipv6.empty(), false);
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
    std::vector<Ipv4Info> localArray;
    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "172.30.1");

    subNet = "";
    remoteArray.push_back(Ipv4Info("172.30.1.2"));
    localArray.push_back(Ipv4Info("172.30.2.2"));
    subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "172.30.3");
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
    std::vector<Ipv4Info> localArray;
    int32_t ret = WifiDirectIpManager::GetInstance().ApplyIpv4(localArray, remoteArray, sink, source);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sink.ToIpString(), "172.30.1.2");
    EXPECT_EQ(source.ToIpString(), "172.30.1.1");

    ret = -1;
    remoteArray.push_back(Ipv4Info("172.30.1.2"));
    localArray.push_back(Ipv4Info("172.30.2.2"));
    ret = WifiDirectIpManager::GetInstance().ApplyIpv4(localArray, remoteArray, sink, source);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(sink.ToIpString(), "172.30.3.2");
    EXPECT_EQ(source.ToIpString(), "172.30.3.1");
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

    std::string interface(IF_NAME_P2P);
    Ipv4Info local("172.30.1.2");
    Ipv4Info remote("172.30.1.1");
    std::string remoteMac("08:fb:ea:19:78:38");
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, AddStaticArp).WillOnce(Return(0));
    int32_t ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(-1));
    ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(client, AddInterfaceAddress).WillOnce(Return(0));
    EXPECT_CALL(client, AddNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, AddStaticArp).WillOnce(Return(-1));
    ret = ipManager.ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(0));
    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(-1));
    ipManager.ReleaseIpv4(interface, local, remote, remoteMac);

    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(0));
    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));
    ipManager.ReleaseIpv4(interface, local, remote, remoteMac);

    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(0));
    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(-1));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));
    ipManager.ReleaseIpv4(interface, local, remote, remoteMac);
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
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(gateWay, "192.168.1.1");

    ipString = "1234";
    ret = ipManager.GetNetworkGateWay(ipString, gateWay);
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
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(destination, "192.168.1.0/24");

    ipString = "1234";
    ret = ipManager.GetNetworkDestination(ipString, destination);
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
    std::string interface = IF_NAME_P2P;
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
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(-1));
    ret = ipManager.AddInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, -1);

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
    EXPECT_EQ(ret, SOFTBUS_CONN_FIND_DOT_FAIL);

    ret = ipManager.DeleteInterfaceAddress(interface, ipString, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_CONN_FIND_DOT_FAIL);
}

/*
 * @tc.name: ConfigIpv6
 * @tc.desc: check ConfigIpv6 method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigIpv6, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string ipString = "192.168.1.255";
    std::string interface = IF_NAME_P2P;

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(0));
    auto ret = WifiDirectIpManager::GetInstance().ConfigIpv6(interface, ipString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConfigIpv6Failed
 * @tc.desc: check ConfigIpv6 method when add interface address fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigIpv6Failed, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string ipString = "fe80::1234:56ff:fe78:9abc%chba0";
    std::string interface = IF_NAME_P2P;

    EXPECT_CALL(client, AddInterfaceAddress(_, _, _)).WillOnce(Return(-1));
    auto ret = WifiDirectIpManager::GetInstance().ConfigIpv6(interface, ipString);
    EXPECT_EQ(ret, SOFTBUS_CONN_CONFIG_IPV6_CONFIG_IP_FAILED);
}

/*
 * @tc.name: ApplyIpv6WithEmptyMac
 * @tc.desc: check ApplyIpv6 with empty mac address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv6WithEmptyMac, TestSize.Level1)
{
    std::string mac = "";
    std::string ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac);
    EXPECT_EQ(ipv6.empty(), true);
}

/*
 * @tc.name: ApplyIpv6WithDifferentMacFormats
 * @tc.desc: check ApplyIpv6 with different mac formats (testing U_L_BIT branches)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv6WithDifferentMacFormats, TestSize.Level1)
{
    // Test with mac where array[0] & U_L_BIT == 0
    std::string mac1("00:dc:b6:90:84:82");
    std::string ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac1);
    EXPECT_EQ(ipv6.empty(), false);

    // Test with mac where array[0] & U_L_BIT != 0
    std::string mac2("02:dc:b6:90:84:82");
    ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac2);
    EXPECT_EQ(ipv6.empty(), false);

    // Test with another format
    std::string mac3("01:aa:bb:cc:dd:ee");
    ipv6 = WifiDirectIpManager::GetInstance().ApplyIpv6(mac3);
    EXPECT_EQ(ipv6.empty(), false);
}

/*
 * @tc.name: ApplySubNetWhenAllSubnetsOccupied
 * @tc.desc: check ApplySubNet when all subnets are occupied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplySubNetWhenAllSubnetsOccupied, TestSize.Level1)
{
    std::vector<Ipv4Info> localArray;
    std::vector<Ipv4Info> remoteArray;

    // Occupy all 256 subnets (except index 0 which is already marked)
    for (int i = 1; i < 256; i++) {
        if (i % 2 == 0) {
            localArray.push_back(Ipv4Info("172.30." + std::to_string(i) + ".2"));
        } else {
            remoteArray.push_back(Ipv4Info("172.30." + std::to_string(i) + ".2"));
        }
    }

    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "");
}

/*
 * @tc.name: ApplyIpv4WithSubNetFail
 * @tc.desc: check ApplyIpv4 when ApplySubNet fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplyIpv4WithSubNetFail, TestSize.Level1)
{
    Ipv4Info sink;
    Ipv4Info source;
    std::vector<Ipv4Info> localArray;
    std::vector<Ipv4Info> remoteArray;

    // Occupy all subnets to trigger ApplySubNet failure
    for (int i = 1; i < 256; i++) {
        if (i % 2 == 0) {
            localArray.push_back(Ipv4Info("172.30." + std::to_string(i) + ".2"));
        } else {
            remoteArray.push_back(Ipv4Info("172.30." + std::to_string(i) + ".2"));
        }
    }

    int32_t ret = WifiDirectIpManager::GetInstance().ApplyIpv4(localArray, remoteArray, source, sink);
    EXPECT_EQ(ret, SOFTBUS_CONN_APPLY_SUBNET_FAIL);
}

/*
 * @tc.name: ConfigIpv4WithInvalidLocalIp
 * @tc.desc: check ConfigIpv4 with invalid local IP (empty conversion result)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigIpv4WithInvalidLocalIp, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface(IF_NAME_P2P);
    std::string remoteMac("08:fb:ea:19:78:38");

    // Create an invalid Ipv4Info that will fail to convert
    Ipv4Info local;
    Ipv4Info remote("172.30.1.1");

    int32_t ret = WifiDirectIpManager::GetInstance().ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, SOFTBUS_CONN_CONVERT_LOCAL_IP_FAIL);
}

/*
 * @tc.name: ConfigIpv4WithInvalidRemoteIp
 * @tc.desc: check ConfigIpv4 with invalid remote IP (empty conversion result)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigIpv4WithInvalidRemoteIp, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface(IF_NAME_P2P);
    std::string remoteMac("08:fb:ea:19:78:38");

    Ipv4Info local("172.30.1.2");
    Ipv4Info remote;

    int32_t ret = WifiDirectIpManager::GetInstance().ConfigIpv4(interface, local, remote, remoteMac);
    EXPECT_EQ(ret, SOFTBUS_CONN_CONVERT_REMOTE_IP_FAIL);
}

/*
 * @tc.name: ReleaseIpv4WithInvalidLocalIp
 * @tc.desc: check ReleaseIpv4 with invalid local IP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ReleaseIpv4WithInvalidLocalIp, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface(IF_NAME_P2P);
    std::string remoteMac("08:fb:ea:19:78:38");

    Ipv4Info local;
    Ipv4Info remote("172.30.1.1");

    // Should not crash, just return early
    WifiDirectIpManager::GetInstance().ReleaseIpv4(interface, local, remote, remoteMac);
}

/*
 * @tc.name: ReleaseIpv4WithInvalidRemoteIp
 * @tc.desc: check ReleaseIpv4 with invalid remote IP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ReleaseIpv4WithInvalidRemoteIp, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface(IF_NAME_P2P);
    std::string remoteMac("08:fb:ea:19:78:38");

    Ipv4Info local("172.30.1.2");
    Ipv4Info remote;

    // Should not crash, just return early
    WifiDirectIpManager::GetInstance().ReleaseIpv4(interface, local, remote, remoteMac);
}

/*
 * @tc.name: ReleaseIpv4WithDeleteFailures
 * @tc.desc: check ReleaseIpv4 when delete operations fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ReleaseIpv4WithDeleteFailures, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface(IF_NAME_P2P);
    Ipv4Info local("172.30.1.2");
    Ipv4Info remote("172.30.1.1");
    std::string remoteMac("08:fb:ea:19:78:38");

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(-1));
    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(0));
    WifiDirectIpManager::GetInstance().ReleaseIpv4(interface, local, remote, remoteMac);

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(0));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(0));
    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(-1));
    WifiDirectIpManager::GetInstance().ReleaseIpv4(interface, local, remote, remoteMac);

    EXPECT_CALL(client, RemoveNetworkRoute).WillOnce(Return(-1));
    EXPECT_CALL(client, DelInterfaceAddress).WillOnce(Return(-1));
    EXPECT_CALL(client, DelStaticArp).WillOnce(Return(-1));
    WifiDirectIpManager::GetInstance().ReleaseIpv4(interface, local, remote, remoteMac);
}

/*
 * @tc.name: AddInterfaceAddressWithInvalidIp
 * @tc.desc: check AddInterfaceAddress with invalid IP (gateway/destination fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, AddInterfaceAddressWithInvalidIp, TestSize.Level1)
{
    std::string invalidIp = "invalid_ip_without_dots";
    std::string interface = IF_NAME_P2P;
    int32_t prefixLength = 24;
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();

    int32_t ret = ipManager.AddInterfaceAddress(interface, invalidIp, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_CONN_FIND_DOT_FAIL);
}

/*
 * @tc.name: DeleteInterfaceAddressWithInvalidIp
 * @tc.desc: check DeleteInterfaceAddress with invalid IP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, DeleteInterfaceAddressWithInvalidIp, TestSize.Level1)
{
    std::string invalidIp = "invalid_ip";
    std::string interface = IF_NAME_P2P;
    int32_t prefixLength = 24;
    WifiDirectIpManager &ipManager = WifiDirectIpManager::GetInstance();

    int32_t ret = ipManager.DeleteInterfaceAddress(interface, invalidIp, prefixLength);
    EXPECT_EQ(ret, SOFTBUS_CONN_FIND_DOT_FAIL);
}

/*
 * @tc.name: AddStaticArpAndDeleteStaticArp
 * @tc.desc: check AddStaticArp and DeleteStaticArp methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, AddStaticArpAndDeleteStaticArp, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface = IF_NAME_P2P;
    std::string ipString = "192.168.1.100";
    std::string macString = "aa:bb:cc:dd:ee:ff";

    EXPECT_CALL(client, AddStaticArp(_, _, _)).WillOnce(Return(0));
    int32_t ret = WifiDirectIpManager::GetInstance().AddStaticArp(interface, ipString, macString);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, AddStaticArp(_, _, _)).WillOnce(Return(-1));
    ret = WifiDirectIpManager::GetInstance().AddStaticArp(interface, ipString, macString);
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(client, DelStaticArp(_, _, _)).WillOnce(Return(0));
    ret = WifiDirectIpManager::GetInstance().DeleteStaticArp(interface, ipString, macString);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(client, DelStaticArp(_, _, _)).WillOnce(Return(-1));
    ret = WifiDirectIpManager::GetInstance().DeleteStaticArp(interface, ipString, macString);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: RemoveIpv6Suffix
 * @tc.desc: check RemoveIpv6Suffix method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, RemoveIpv6Suffix, TestSize.Level1)
{
    // Test with IPv6 address that has suffix
    std::string ipv6WithSuffix = "fe80::1234:56ff:fe78:9abc%chba0";
    std::string result = WifiDirectIpManager::GetInstance().RemoveIpv6Suffix(ipv6WithSuffix);
    EXPECT_EQ(result, "fe80::1234:56ff:fe78:9abc");

    // Test with IPv6 address without suffix
    std::string ipv6WithoutSuffix = "fe80::1234:56ff:fe78:9abc";
    result = WifiDirectIpManager::GetInstance().RemoveIpv6Suffix(ipv6WithoutSuffix);
    EXPECT_EQ(result, "fe80::1234:56ff:fe78:9abc");

    // Test with multiple suffixes (edge case)
    std::string ipv6MultipleSuffix = "fe80::1234:56ff:fe78:9abc%chba0%chba0";
    result = WifiDirectIpManager::GetInstance().RemoveIpv6Suffix(ipv6MultipleSuffix);
    EXPECT_EQ(result, "fe80::1234:56ff:fe78:9abc");

    // Test with empty string
    std::string emptyIpv6 = "";
    result = WifiDirectIpManager::GetInstance().RemoveIpv6Suffix(emptyIpv6);
    EXPECT_EQ(result, "");
}

/*
 * @tc.name: ConfigStaticIpv6AndReleaseStaticIpv6
 * @tc.desc: check ConfigStaticIpv6 and ReleaseStaticIpv6 methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ConfigStaticIpv6AndReleaseStaticIpv6, TestSize.Level1)
{
    NetManagerStandard::MockNetConnClient client;
    std::string interface = IF_NAME_P2P;
    std::string ipv6Addr = "fe80::1234:56ff:fe78:9abc%chba0";
    std::string macAddr = "aa:bb:cc:dd:ee:ff";

    EXPECT_CALL(client, AddStaticIpv6Addr).WillOnce(Return(0));
    WifiDirectIpManager::GetInstance().ConfigStaticIpv6(interface, ipv6Addr, macAddr);

    EXPECT_CALL(client, AddStaticIpv6Addr).WillOnce(Return(-1));
    WifiDirectIpManager::GetInstance().ConfigStaticIpv6(interface, ipv6Addr, macAddr);

    EXPECT_CALL(client, DelStaticIpv6Addr).WillOnce(Return(0));
    WifiDirectIpManager::GetInstance().ReleaseStaticIpv6(interface, ipv6Addr, macAddr);

    EXPECT_CALL(client, DelStaticIpv6Addr).WillOnce(Return(-1));
    WifiDirectIpManager::GetInstance().ReleaseStaticIpv6(interface, ipv6Addr, macAddr);
}

/*
 * @tc.name: ApplySubNetWithEmptyArrays
 * @tc.desc: check ApplySubNet with empty arrays
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplySubNetWithEmptyArrays, TestSize.Level1)
{
    std::vector<Ipv4Info> localArray;
    std::vector<Ipv4Info> remoteArray;

    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "172.30.1");
}

/*
 * @tc.name: ApplySubNetWithOnlyLocalArray
 * @tc.desc: check ApplySubNet with only local array populated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplySubNetWithOnlyLocalArray, TestSize.Level1)
{
    std::vector<Ipv4Info> localArray;
    std::vector<Ipv4Info> remoteArray;

    localArray.push_back(Ipv4Info("172.30.1.2"));
    localArray.push_back(Ipv4Info("172.30.2.2"));
    localArray.push_back(Ipv4Info("172.30.3.2"));

    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "172.30.4");
}

/*
 * @tc.name: ApplySubNetWithOnlyRemoteArray
 * @tc.desc: check ApplySubNet with only remote array populated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, ApplySubNetWithOnlyRemoteArray, TestSize.Level1)
{
    std::vector<Ipv4Info> localArray;
    std::vector<Ipv4Info> remoteArray;

    remoteArray.push_back(Ipv4Info("172.30.1.2"));
    remoteArray.push_back(Ipv4Info("172.30.5.2"));
    remoteArray.push_back(Ipv4Info("172.30.10.2"));

    std::string subNet = WifiDirectIpManager::GetInstance().ApplySubNet(localArray, remoteArray);
    EXPECT_EQ(subNet, "172.30.2");
}

/*
 * @tc.name: GetInstanceInitialization
 * @tc.desc: check GetInstance initializes and clears properly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectIpManagerTest, GetInstanceInitialization, TestSize.Level1)
{
    // Get instance multiple times to verify singleton behavior
    WifiDirectIpManager &instance1 = WifiDirectIpManager::GetInstance();
    WifiDirectIpManager &instance2 = WifiDirectIpManager::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}1
} // namespace OHOS::SoftBus
