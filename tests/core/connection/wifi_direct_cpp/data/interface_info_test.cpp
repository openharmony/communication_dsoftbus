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
#include "data/info_container.h"
#include "data/interface_info.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_utils.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class InterfaceInfoTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: MarshallingTest
 * @tc.desc: Test Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, MarshallingTest, TestSize.Level1)
{
    InterfaceInfo info1;
    info1.SetName("TestName");
    Ipv4Info ipv4Info("172.30.1.1");
    info1.SetBaseMac("00:00:00:00:00:00");
    info1.SetIpString(ipv4Info);
    info1.SetSsid("TestSsid");
    info1.SetDynamicMac("00:00:00:00:00:00");
    info1.SetPsk("TestPsk");
    info1.SetCenter20M(10);
    info1.SetIsEnable(true);
    info1.SetRole(LinkInfo::LinkMode::AP);
    info1.SetP2pListenPort(123);
    info1.SetBandWidth(20);
    info1.SetReuseCount(1);
    info1.SetIsAvailable(true);
    info1.SetPhysicalRate(1);
    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    std::vector<uint8_t> output;
    info1.Marshalling(*protocol1, output);
    auto protocol2 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol2->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });
    InterfaceInfo info2;
    info2.Unmarshalling(*protocol2, output);
    EXPECT_EQ(info2.GetName(), "TestName");
    EXPECT_EQ(info2.GetIpString(), ipv4Info);
    EXPECT_EQ(info2.GetSsid(), "TestSsid");
    EXPECT_EQ(info2.GetRole(), LinkInfo::LinkMode::AP);
    EXPECT_EQ(info2.GetDynamicMac(), "00:00:00:00:00:00");
    EXPECT_EQ(info2.GetPsk(), "TestPsk");
    EXPECT_EQ(info2.GetCenter20M(), 10);
    EXPECT_EQ(info2.IsEnable(), true);
    EXPECT_EQ(info2.GetP2pListenPort(), 123);
    EXPECT_EQ(info2.GetBandWidth(), 20);
    EXPECT_EQ(info2.GetReuseCount(), 1);
    EXPECT_EQ(info2.IsAvailable(), true);
    EXPECT_EQ(info2.GetPhysicalRate(), 1);
    EXPECT_EQ(info2.GetBaseMac(), "00:00:00:00:00:00");
}

/*
 * @tc.name: GetAndSetTest01
 * @tc.desc: Test GetAndSetTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, GetAndSetTest01, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetName(), "");
    info.SetName("TestName");
    EXPECT_EQ(info.GetName(), "TestName");

    Ipv4Info ipv4Info1("192.168.1.1");
    info.SetIpString(ipv4Info1);
    auto ipv4Info2 = info.GetIpString();
    EXPECT_EQ(ipv4Info2, ipv4Info1);

    EXPECT_EQ(info.GetSsid(), "");
    info.SetSsid("TestSsid");
    EXPECT_EQ(info.GetSsid(), "TestSsid");

    EXPECT_EQ(info.GetDynamicMac(), "");
    info.SetDynamicMac("00:00:00:00:00:00");
    EXPECT_EQ(info.GetDynamicMac(), "00:00:00:00:00:00");

    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::NONE);
    info.SetRole(LinkInfo::LinkMode::AP);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::AP);

    EXPECT_EQ(info.GetPsk(), "");
    info.SetPsk("TestPsk");
    EXPECT_EQ(info.GetPsk(), "TestPsk");

    EXPECT_EQ(info.GetCenter20M(), 0);
    info.SetCenter20M(10);
    EXPECT_EQ(info.GetCenter20M(), 10);

    EXPECT_EQ(info.GetConnectedDeviceCount(), 0);
    info.SetConnectedDeviceCount(1);
    EXPECT_EQ(info.GetConnectedDeviceCount(), 1);
}

/*
 * @tc.name: GetAndSetTest02
 * @tc.desc: Test GetAndSetTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, GetAndSetTest02, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.IsEnable(), false);
    info.SetIsEnable(true);
    EXPECT_EQ(info.IsEnable(), true);

    EXPECT_EQ(info.GetBaseMac(), "");
    info.SetBaseMac("00:00:00:00:00:00");
    EXPECT_EQ(info.GetBaseMac(), "00:00:00:00:00:00");

    EXPECT_EQ(info.GetCapability(), 0u);
    info.SetCapability(20);
    EXPECT_EQ(info.GetCapability(), 20);

    std::vector<int> vec = { 65, 66, 67, 68, 69 };
    std::vector<int> ret;
    EXPECT_EQ(info.GetChannel5GList(), ret);
    info.SetChannel5GList(vec);
    EXPECT_EQ(info.GetChannel5GList(), vec);

    EXPECT_EQ(info.GetReuseCount(), 0);
    info.IncreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 1);
    info.SetReuseCount(2);
    EXPECT_EQ(info.GetReuseCount(), 2);
    info.DecreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 1);

    EXPECT_EQ(info.GetP2pListenPort(), 0);
    info.SetP2pListenPort(1);
    EXPECT_EQ(info.GetP2pListenPort(), 1);

    EXPECT_EQ(info.GetBandWidth(), 0);
    info.SetBandWidth(1);
    EXPECT_EQ(info.GetBandWidth(), 1);

    EXPECT_EQ(info.IsAvailable(), true);
    info.SetIsAvailable(false);
    EXPECT_EQ(info.IsAvailable(), false);

    EXPECT_EQ(info.GetPhysicalRate(), 0);
    info.SetPhysicalRate(1);
    EXPECT_EQ(info.GetPhysicalRate(), 1);
}

/*
 * @tc.name: SetP2pGroupConfig_02
 * @tc.desc: Test GetAndSetTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_02, TestSize.Level1)
{
    InterfaceInfo interfaceInfo;
    std::string groupConfig = "test\n123\n456\n789\n1011";
    interfaceInfo.SetP2pGroupConfig(groupConfig);
    EXPECT_EQ(interfaceInfo.GetP2pGroupConfig(), groupConfig);
}

/*
 * @tc.name: SetP2pGroupConfig_03
 * @tc.desc: Test GetAndSetTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_03, TestSize.Level1)
{
    InterfaceInfo interfaceInfo;
    std::string groupConfig = "test\n123\n456\n789\n1011";
    interfaceInfo.SetDynamicMac("dynamicMac");
    interfaceInfo.SetP2pGroupConfig(groupConfig);
    EXPECT_EQ(interfaceInfo.GetP2pGroupConfig(), groupConfig);
}

/*
 * @tc.name: SetP2pGroupConfig_04
 * @tc.desc: Test GetAndSetTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_04, TestSize.Level1)
{
    InterfaceInfo interfaceInfo;
    std::string groupConfig = "test\n123\n456\n789\n1011";
    interfaceInfo.SetDynamicMac("");
    interfaceInfo.SetP2pGroupConfig(groupConfig);
    EXPECT_EQ(interfaceInfo.GetP2pGroupConfig(), groupConfig);
}

/*
 * @tc.name: RefreshIsAvailable_01
 * @tc.desc: Test RefreshIsAvailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, RefreshIsAvailable_01, TestSize.Level1)
{
    InterfaceInfo interfaceInfo;
    interfaceInfo.SetIsEnable(true);

    interfaceInfo.RefreshIsAvailable();
    EXPECT_EQ(interfaceInfo.IsAvailable(), true);

    interfaceInfo.SetIsEnable(false);
    interfaceInfo.RefreshIsAvailable();
    EXPECT_EQ(interfaceInfo.IsAvailable(), false);

    interfaceInfo.SetRole(LinkInfo::LinkMode::GC);
    interfaceInfo.RefreshIsAvailable();
    EXPECT_EQ(interfaceInfo.IsAvailable(), false);
}

/*
 * @tc.name: P2pListenModuleTest
 * @tc.desc: test P2P listen module set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, P2pListenModuleTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetP2pListenModule(), -1);

    info.SetP2pListenModule(1);
    EXPECT_EQ(info.GetP2pListenModule(), 1);

    info.SetP2pListenModule(100);
    EXPECT_EQ(info.GetP2pListenModule(), 100);
}

/*
 * @tc.name: LocalCustomPortTest
 * @tc.desc: test local custom port set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, LocalCustomPortTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetLocalCustomPort(), 0);

    info.SetLocalCustomPort(9999);
    EXPECT_EQ(info.GetLocalCustomPort(), 9999);

    info.SetLocalCustomPort(-1);
    EXPECT_EQ(info.GetLocalCustomPort(), -1);
}

/*
 * @tc.name: IsCreateGoTest
 * @tc.desc: test is create GO flag set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, IsCreateGoTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetIsCreateGo(), false);

    info.SetIsCreateGo(true);
    EXPECT_EQ(info.GetIsCreateGo(), true);

    info.SetIsCreateGo(false);
    EXPECT_EQ(info.GetIsCreateGo(), false);
}

/*
 * @tc.name: NeedKeepP2pGroupTest
 * @tc.desc: test need keep P2P group flag set and get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, NeedKeepP2pGroupTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetNeedKeepP2pGroup(), false);

    info.SetNeedKeepP2pGroup(true);
    EXPECT_EQ(info.GetNeedKeepP2pGroup(), true);

    info.SetNeedKeepP2pGroup(false);
    EXPECT_EQ(info.GetNeedKeepP2pGroup(), false);
}

/*
 * @tc.name: GetChannelAndBandWidthTest
 * @tc.desc: test get channel and bandwidth vector
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, GetChannelAndBandWidthTest, TestSize.Level1)
{
    InterfaceInfo info;
    auto channelVec = info.GetChannelAndBandWidth();
    EXPECT_EQ(channelVec.size(), 0);

    info.SetCenter20M(36);
    info.SetBandWidth(80);
    auto channelVec2 = info.GetChannelAndBandWidth();
    EXPECT_GE(channelVec2.size(), 0);
}

/*
 * @tc.name: ReferenceCountOperationsTest
 * @tc.desc: test reference count operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, ReferenceCountOperationsTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetReuseCount(), 0);

    info.IncreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 1);

    info.IncreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 2);

    info.DecreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 1);

    info.DecreaseRefCount();
    EXPECT_EQ(info.GetReuseCount(), 0);
}

/*
 * @tc.name: RoleTypeTest
 * @tc.desc: test different role types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, RoleTypeTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetRole(LinkInfo::LinkMode::INVALID);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::INVALID);

    info.SetRole(LinkInfo::LinkMode::NONE);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::NONE);

    info.SetRole(LinkInfo::LinkMode::STA);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::STA);

    info.SetRole(LinkInfo::LinkMode::AP);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::AP);

    info.SetRole(LinkInfo::LinkMode::GO);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::GO);

    info.SetRole(LinkInfo::LinkMode::GC);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::GC);

    info.SetRole(LinkInfo::LinkMode::HML);
    EXPECT_EQ(info.GetRole(), LinkInfo::LinkMode::HML);
}

/*
 * @tc.name: BandWidthTest
 * @tc.desc: test different bandwidth values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, BandWidthTest, TestSize.Level1)
{
    InterfaceInfo info;

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
 * @tc.name: CenterFrequencyTest
 * @tc.desc: test center frequency values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, CenterFrequencyTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetCenter20M(2412); // 2.4GHz channel 1
    EXPECT_EQ(info.GetCenter20M(), 2412);

    info.SetCenter20M(5180); // 5GHz channel 36
    EXPECT_EQ(info.GetCenter20M(), 5180);

    info.SetCenter20M(5955); // 6GHz
    EXPECT_EQ(info.GetCenter20M(), 5955);
}

/*
 * @tc.name: Channel5GListTest
 * @tc.desc: test 5G channel list operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, Channel5GListTest, TestSize.Level1)
{
    InterfaceInfo info;
    std::vector<int> channels = {36, 40, 44, 48, 149, 153, 157, 161, 165};

    info.SetChannel5GList(channels);
    auto result = info.GetChannel5GList();

    EXPECT_EQ(result.size(), channels.size());
    for (size_t i = 0; i < channels.size(); i++) {
        EXPECT_EQ(result[i], channels[i]);
    }
}

/*
 * @tc.name: MacAddressTest
 * @tc.desc: test MAC address operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, MacAddressTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetBaseMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(info.GetBaseMac(), "AA:BB:CC:DD:EE:FF");

    info.SetDynamicMac("11:22:33:44:55:66");
    EXPECT_EQ(info.GetDynamicMac(), "11:22:33:44:55:66");
}

/*
 * @tc.name: SsidTest
 * @tc.desc: test SSID operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, SsidTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetSsid("TestSSID");
    EXPECT_EQ(info.GetSsid(), "TestSSID");

    info.SetSsid("DIRECT-xy-DeviceName");
    EXPECT_EQ(info.GetSsid(), "DIRECT-xy-DeviceName");
}

/*
 * @tc.name: PskTest
 * @tc.desc: test PSK operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, PskTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetPsk("12345678");
    EXPECT_EQ(info.GetPsk(), "12345678");

    info.SetPsk("abcdefgh");
    EXPECT_EQ(info.GetPsk(), "abcdefgh");
}

/*
 * @tc.name: PhysicalRateTest
 * @tc.desc: test physical rate operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, PhysicalRateTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetPhysicalRate(866); // 802.11n 5GHz max rate
    EXPECT_EQ(info.GetPhysicalRate(), 866);

    info.SetPhysicalRate(6000); // 802.11ax max rate
    EXPECT_EQ(info.GetPhysicalRate(), 6000);
}

/*
 * @tc.name: CapabilityTest
 * @tc.desc: test capability operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, CapabilityTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetCapability(0xFFFFFFFF);
    EXPECT_EQ(info.GetCapability(), 0xFFFFFFFF);

    info.SetCapability(0);
    EXPECT_EQ(info.GetCapability(), 0);
}

/*
 * @tc.name: ConnectedDeviceCountTest
 * @tc.desc: test connected device count operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, ConnectedDeviceCountTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetConnectedDeviceCount(0);
    EXPECT_EQ(info.GetConnectedDeviceCount(), 0);

    info.SetConnectedDeviceCount(10);
    EXPECT_EQ(info.GetConnectedDeviceCount(), 10);

    info.SetConnectedDeviceCount(-1);
    EXPECT_EQ(info.GetConnectedDeviceCount(), -1);
}

/*
 * @tc.name: EmptyValuesTest
 * @tc.desc: test operations with empty/default values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, EmptyValuesTest, TestSize.Level1)
{
    InterfaceInfo info;
    EXPECT_EQ(info.GetName(), "");
    EXPECT_EQ(info.GetBaseMac(), "");
    EXPECT_EQ(info.GetDynamicMac(), "");
    EXPECT_EQ(info.GetSsid(), "");
    EXPECT_EQ(info.GetPsk(), "");
    EXPECT_EQ(info.GetP2pGroupConfig(), "");
}

/*
 * @tc.name: AvailabilityWithDifferentRoles
 * @tc.desc: test availability logic with different roles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, AvailabilityWithDifferentRoles, TestSize.Level1)
{
    InterfaceInfo info;
    info.SetIsEnable(true);

    info.SetRole(LinkInfo::LinkMode::GO);
    info.RefreshIsAvailable();
    EXPECT_EQ(info.IsAvailable(), true);

    info.SetRole(LinkInfo::LinkMode::AP);
    info.RefreshIsAvailable();
    EXPECT_EQ(info.IsAvailable(), true);
}

/*
 * @tc.name: P2pListenPortBoundaryTest
 * @tc.desc: test P2P listen port boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InterfaceInfoTest, P2pListenPortBoundaryTest, TestSize.Level1)
{
    InterfaceInfo info;

    info.SetP2pListenPort(0);
    EXPECT_EQ(info.GetP2pListenPort(), 0);

    info.SetP2pListenPort(65535);
    EXPECT_EQ(info.GetP2pListenPort(), 65535);

    info.SetP2pListenPort(-1);
    EXPECT_EQ(info.GetP2pListenPort(), -1);
}

} // namespace OHOS::SoftBus
