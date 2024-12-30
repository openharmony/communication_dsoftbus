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
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_02, TestSize.Level0)
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
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_03, TestSize.Level0)
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
HWTEST_F(InterfaceInfoTest, SetP2pGroupConfig_04, TestSize.Level0)
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
HWTEST_F(InterfaceInfoTest, RefreshIsAvailable_01, TestSize.Level0)
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
} // namespace OHOS::SoftBus