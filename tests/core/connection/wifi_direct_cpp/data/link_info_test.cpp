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
#include "data/link_info.h"
#include "protocol/wifi_direct_protocol_factory.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class LinkInfoTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: SetAndGetBool
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, SetAndGetBool, TestSize.Level1)
{
    LinkInfo info;
    EXPECT_EQ(info.GetIsDhcp(), false);
    info.SetIsDhcp(true);
    EXPECT_EQ(info.GetIsDhcp(), true);

    EXPECT_EQ(info.GetIsClient(), false);
    info.SetIsClient(true);
    EXPECT_EQ(info.GetIsClient(), true);

    EXPECT_EQ(info.GetIsBeingUsedByRemote(), false);
    info.SetIsBeingUsedByRemote(true);
    EXPECT_EQ(info.GetIsBeingUsedByRemote(), true);

    EXPECT_EQ(info.GetIsDbac(), false);
    info.SetIsDbac(true);
    EXPECT_EQ(info.GetIsDbac(), true);
}

/*
 * @tc.name: SetAndGetInt
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, SetAndGetInt, TestSize.Level1)
{
    LinkInfo info;
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::INVALID);
    info.SetLocalLinkMode(LinkInfo::LinkMode::HML);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::HML);

    EXPECT_EQ(info.GetRemoteLinkMode(), LinkInfo::LinkMode::INVALID);
    info.SetRemoteLinkMode(LinkInfo::LinkMode::HML);
    EXPECT_EQ(info.GetRemoteLinkMode(), LinkInfo::LinkMode::HML);

    EXPECT_EQ(info.GetCenter20M(), 0);
    info.SetCenter20M(5180);
    EXPECT_EQ(info.GetCenter20M(), 5180);

    EXPECT_EQ(info.GetCenterFrequency1(), 0);
    info.SetCenterFrequency1(5240);
    EXPECT_EQ(info.GetCenterFrequency1(), 5240);

    EXPECT_EQ(info.GetCenterFrequency2(), 0);
    info.SetCenterFrequency2(5280);
    EXPECT_EQ(info.GetCenterFrequency2(), 5280);

    EXPECT_EQ(info.GetBandWidth(), 0);
    info.SetBandWidth(80);
    EXPECT_EQ(info.GetBandWidth(), 80);

    EXPECT_EQ(info.GetAuthPort(), 0);
    info.SetAuthPort(999);
    EXPECT_EQ(info.GetAuthPort(), 999);

    EXPECT_EQ(info.GetMaxPhysicalRate(), 0);
    info.SetMaxPhysicalRate(866);
    EXPECT_EQ(info.GetMaxPhysicalRate(), 866);

    EXPECT_EQ(info.GetStatus(), 0);
    info.SetStatus(5);
    EXPECT_EQ(info.GetStatus(), 5);

    EXPECT_EQ(info.GetLinkPowerMode(), 0);
    info.SetLinkPowerMode(1);
    EXPECT_EQ(info.GetLinkPowerMode(), 1);
}

/*
 * @tc.name: SetAndGetString
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, SetAndGetString, TestSize.Level1)
{
    LinkInfo info;
    EXPECT_EQ(info.GetLocalInterface(), "");
    info.SetLocalInterface(IF_NAME_HML);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_HML);

    EXPECT_EQ(info.GetRemoteInterface(), "");
    info.SetRemoteInterface(IF_NAME_HML);
    EXPECT_EQ(info.GetRemoteInterface(), IF_NAME_HML);

    EXPECT_EQ(info.GetSsid(), "");
    info.SetSsid("OHOS-1234");
    EXPECT_EQ(info.GetSsid(), "OHOS-1234");

    EXPECT_EQ(info.GetBssid(), "");
    info.SetBssid("01:02:03:04:05:06");
    EXPECT_EQ(info.GetBssid(), "01:02:03:04:05:06");

    EXPECT_EQ(info.GetPsk(), "");
    info.SetPsk("12345678");
    EXPECT_EQ(info.GetPsk(), "12345678");

    EXPECT_EQ(info.GetRemoteDevice(), "");
    info.SetRemoteDevice("abcdef");
    EXPECT_EQ(info.GetRemoteDevice(), "abcdef");

    EXPECT_EQ(info.GetLocalBaseMac(), "");
    info.SetLocalBaseMac("01:02:03:04:05:06");
    EXPECT_EQ(info.GetLocalBaseMac(), "01:02:03:04:05:06");

    EXPECT_EQ(info.GetRemoteBaseMac(), "");
    info.SetRemoteBaseMac("01:02:03:04:05:ab");
    EXPECT_EQ(info.GetRemoteBaseMac(), "01:02:03:04:05:ab");
}

/*
 * @tc.name: SetAndGetIpv4Info
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, SetAndGetIpv4Info, TestSize.Level1)
{
    LinkInfo info;
    Ipv4Info ipv4Info1("192.168.1.1");
    info.SetLocalIpv4Info(ipv4Info1);
    auto ipv4Info2 = info.GetLocalIpv4Info();
    EXPECT_EQ(ipv4Info2, ipv4Info1);

    Ipv4Info ipv4Info3("192.168.1.2");
    info.SetRemoteIpv4Info(ipv4Info3);
    auto ipv4Info4 = info.GetRemoteIpv4Info();
    EXPECT_EQ(ipv4Info4, ipv4Info3);
}

/*
 * @tc.name: MarshallingAndUnmarshalling
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, MarshallingAndUnmarshalling, TestSize.Level1)
{
    LinkInfo info1;
    info1.SetLocalInterface(IF_NAME_HML);
    info1.SetRemoteInterface(IF_NAME_HML);
    info1.SetLocalBaseMac("01:02:03:04:05:06");
    info1.SetRemoteBaseMac("06:05:04:03:02:01");
    info1.SetCenter20M(5180);
    Ipv4Info localIpv4Info("172.30.1.1");
    info1.SetLocalIpv4Info(localIpv4Info);
    Ipv4Info remoteIpv4Info("172.30.1.2");
    info1.SetRemoteIpv4Info(remoteIpv4Info);
    info1.SetIsDhcp(true);

    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    info1.Marshalling(*protocol1, output);

    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    LinkInfo info2;
    info2.Unmarshalling(*protocol2, output);

    LinkInfo info3;
    auto protocol3 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output3;
    info3.Marshalling(*protocol3, output3);
    auto protocol4 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    LinkInfo info4;
    info4.Unmarshalling(*protocol4, output);

    EXPECT_EQ(info2.GetLocalInterface(), IF_NAME_HML);
    EXPECT_EQ(info2.GetRemoteInterface(), IF_NAME_HML);
    EXPECT_EQ(info2.GetLocalBaseMac(), "01:02:03:04:05:06");
    EXPECT_EQ(info2.GetRemoteBaseMac(), "06:05:04:03:02:01");
    EXPECT_EQ(info2.GetCenter20M(), 5180);
    EXPECT_EQ(info2.GetLocalIpv4Info(), localIpv4Info);
    EXPECT_EQ(info2.GetRemoteIpv4Info(), remoteIpv4Info);
    EXPECT_EQ(info2.GetIsDhcp(), true);
}

/*
 * @tc.name: TestGetSet
 * @tc.desc: check set and get methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, TestGetSet, TestSize.Level1)
{
    LinkInfo linkInfo;
    std::string ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    linkInfo.SetLocalIpv6(ipv6);
    EXPECT_EQ(linkInfo.GetLocalIpv6(), ipv6);

    linkInfo.SetRemoteIpv6(ipv6);
    EXPECT_EQ(linkInfo.GetRemoteIpv6(), ipv6);

    linkInfo.SetCustomPort(1);
    EXPECT_EQ(linkInfo.GetCustomPort(), 1);
}

/*
 * @tc.name: TypeToString
 * @tc.desc: test the to string method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, TypeToString, TestSize.Level1)
{
    LinkInfo info;
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::INVALID), "INVALID");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::NONE), "NONE");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::STA), "STA");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::AP), "AP");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::GO), "GO");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::GC), "GC");
    EXPECT_EQ(info.ToString(LinkInfo::LinkMode::HML), "HML");
}

/*
 * @tc.name: ConstructorWithParameters
 * @tc.desc: test constructor with parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, ConstructorWithParameters, TestSize.Level1)
{
    std::string localIf = "wlan0";
    std::string remoteIf = "wlan1";
    LinkInfo::LinkMode localMode = LinkInfo::LinkMode::GO;
    LinkInfo::LinkMode remoteMode = LinkInfo::LinkMode::GC;

    LinkInfo info(localIf, remoteIf, localMode, remoteMode);

    EXPECT_EQ(info.GetLocalInterface(), localIf);
    EXPECT_EQ(info.GetRemoteInterface(), remoteIf);
    EXPECT_EQ(info.GetLocalLinkMode(), localMode);
    EXPECT_EQ(info.GetRemoteLinkMode(), remoteMode);
}

/*
 * @tc.name: RatePreferenceTest
 * @tc.desc: test rate preference set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, RatePreferenceTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetRatePreference(true);
    EXPECT_EQ(info.IsRatePreference(), true);

    info.SetRatePreference(false);
    EXPECT_EQ(info.IsRatePreference(), false);
}

/*
 * @tc.name: LinkPowerModeTest
 * @tc.desc: test link power mode set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, LinkPowerModeTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetLinkPowerMode(DEFAULT_POWER);
    EXPECT_EQ(info.GetLinkPowerMode(), DEFAULT_POWER);

    info.SetLinkPowerMode(LOW_POWER);
    EXPECT_EQ(info.GetLinkPowerMode(), LOW_POWER);

    info.SetLinkPowerMode(INVALID_POWER);
    EXPECT_EQ(info.GetLinkPowerMode(), INVALID_POWER);
}

/*
 * @tc.name: AllLinkModesTest
 * @tc.desc: test all link mode values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, AllLinkModesTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetLocalLinkMode(LinkInfo::LinkMode::INVALID);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::INVALID);

    info.SetLocalLinkMode(LinkInfo::LinkMode::NONE);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::NONE);

    info.SetLocalLinkMode(LinkInfo::LinkMode::STA);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::STA);

    info.SetLocalLinkMode(LinkInfo::LinkMode::AP);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::AP);

    info.SetLocalLinkMode(LinkInfo::LinkMode::GO);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::GO);

    info.SetLocalLinkMode(LinkInfo::LinkMode::GC);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::GC);

    info.SetLocalLinkMode(LinkInfo::LinkMode::HML);
    EXPECT_EQ(info.GetLocalLinkMode(), LinkInfo::LinkMode::HML);
}

/*
 * @tc.name: BandwidthTest
 * @tc.desc: test different bandwidth values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, BandwidthTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetBandWidth(20);
    EXPECT_EQ(info.GetBandWidth(), 20);

    info.SetBandWidth(40);
    EXPECT_EQ(info.GetBandWidth(), 40);

    info.SetBandWidth(80);
    EXPECT_EQ(info.GetBandWidth(), 80);

    info.SetBandWidth(160);
    EXPECT_EQ(info.GetBandWidth(), 160);
}

/*
 * @tc.name: FrequencyValuesTest
 * @tc.desc: test frequency center values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, FrequencyValuesTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetCenter20M(2412); // 2.4GHz channel 1
    EXPECT_EQ(info.GetCenter20M(), 2412);

    info.SetCenterFrequency1(5180); // 5GHz channel 36
    EXPECT_EQ(info.GetCenterFrequency1(), 5180);

    info.SetCenterFrequency2(5280); // 5GHz channel 44
    EXPECT_EQ(info.GetCenterFrequency2(), 5280);
}

/*
 * @tc.name: PortTest
 * @tc.desc: test port operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, PortTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetAuthPort(8080);
    EXPECT_EQ(info.GetAuthPort(), 8080);

    info.SetCustomPort(9999);
    EXPECT_EQ(info.GetCustomPort(), 9999);

    info.SetCustomPort(0);
    EXPECT_EQ(info.GetCustomPort(), 0);
}

/*
 * @tc.name: PhysicalRateTest
 * @tc.desc: test physical rate values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, PhysicalRateTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetMaxPhysicalRate(866); // 802.11n 5GHz
    EXPECT_EQ(info.GetMaxPhysicalRate(), 866);

    info.SetMaxPhysicalRate(6000); // 802.11ax
    EXPECT_EQ(info.GetMaxPhysicalRate(), 6000);

    info.SetMaxPhysicalRate(0);
    EXPECT_EQ(info.GetMaxPhysicalRate(), 0);
}

/*
 * @tc.name: StatusTest
 * @tc.desc: test status set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, StatusTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetStatus(0);
    EXPECT_EQ(info.GetStatus(), 0);

    info.SetStatus(1);
    EXPECT_EQ(info.GetStatus(), 1);

    info.SetStatus(-1);
    EXPECT_EQ(info.GetStatus(), -1);
}

/*
 * @tc.name: MacAddressFormatsTest
 * @tc.desc: test different MAC address formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, MacAddressFormatsTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetLocalBaseMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(info.GetLocalBaseMac(), "AA:BB:CC:DD:EE:FF");

    info.SetRemoteBaseMac("11:22:33:44:55:66");
    EXPECT_EQ(info.GetRemoteBaseMac(), "11:22:33:44:55:66");

    info.SetBssid("77:88:99:AA:BB:CC");
    EXPECT_EQ(info.GetBssid(), "77:88:99:AA:BB:CC");
}

/*
 * @tc.name: SsidTest
 * @tc.desc: test SSID operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, SsidTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetSsid("DIRECT-xy-Test");
    EXPECT_EQ(info.GetSsid(), "DIRECT-xy-Test");

    info.SetSsid("OHOS-WiFi");
    EXPECT_EQ(info.GetSsid(), "OHOS-WiFi");
}

/*
 * @tc.name: PskTest
 * @tc.desc: test PSK operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, PskTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetPsk("12345678");
    EXPECT_EQ(info.GetPsk(), "12345678");

    info.SetPsk("abcdefgh");
    EXPECT_EQ(info.GetPsk(), "abcdefgh");
}

/*
 * @tc.name: DhcpFlagTest
 * @tc.desc: test DHCP flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, DhcpFlagTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetIsDhcp(true);
    EXPECT_EQ(info.GetIsDhcp(), true);

    info.SetIsDhcp(false);
    EXPECT_EQ(info.GetIsDhcp(), false);
}

/*
 * @tc.name: ClientFlagTest
 * @tc.desc: test client flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, ClientFlagTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetIsClient(true);
    EXPECT_EQ(info.GetIsClient(), true);

    info.SetIsClient(false);
    EXPECT_EQ(info.GetIsClient(), false);
}

/*
 * @tc.name: RemoteDeviceTest
 * @tc.desc: test remote device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, RemoteDeviceTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetRemoteDevice("0123456789ABCDEF");
    EXPECT_EQ(info.GetRemoteDevice(), "0123456789ABCDEF");

    info.SetRemoteDevice("abcdef0123456789");
    EXPECT_EQ(info.GetRemoteDevice(), "abcdef0123456789");
}

/*
 * @tc.name: InterfaceNamesTest
 * @tc.desc: test interface name operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, InterfaceNamesTest, TestSize.Level1)
{
    LinkInfo info;

    info.SetLocalInterface(IF_NAME_P2P);
    EXPECT_EQ(info.GetLocalInterface(), IF_NAME_P2P);

    info.SetRemoteInterface(IF_NAME_HML);
    EXPECT_EQ(info.GetRemoteInterface(), IF_NAME_HML);
}

/*
 * @tc.name: EmptyValuesTest
 * @tc.desc: test operations with empty/default values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkInfoTest, EmptyValuesTest, TestSize.Level1)
{
    LinkInfo info;
    EXPECT_EQ(info.GetLocalInterface(), "");
    EXPECT_EQ(info.GetRemoteInterface(), "");
    EXPECT_EQ(info.GetSsid(), "");
    EXPECT_EQ(info.GetBssid(), "");
    EXPECT_EQ(info.GetPsk(), "");
    EXPECT_EQ(info.GetLocalBaseMac(), "");
    EXPECT_EQ(info.GetRemoteBaseMac(), "");
}

} // namespace OHOS::SoftBus
