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

#include "data/wifi_config_info.h"
#include "protocol/wifi_direct_protocol_factory.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class WifiConfigInfoTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: MarshallingAndUnmarshallingTest
 * @tc.desc: check Marshalling And Unmarshalling methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, MarshallingAndUnmarshallingTest, TestSize.Level1)
{
    std::vector<uint8_t> config;
    WifiConfigInfo wifiCfg;

    InterfaceInfo info;
    info.SetName("TestName");
    Ipv4Info ipv4Info("172.30.1.1");
    info.SetIpString(ipv4Info);
    info.SetSsid("TestSsid");
    info.SetDynamicMac("00:00:00:00:00:00");
    info.SetPsk("TestPsk");
    info.SetCenter20M(10);
    info.SetIsEnable(true);
    info.SetRole(LinkInfo::LinkMode::AP);
    info.SetP2pListenPort(123);
    info.SetBandWidth(20);
    info.SetReuseCount(1);
    info.SetIsAvailable(true);
    info.SetPhysicalRate(1);

    std::vector<InterfaceInfo> infos = { info };
    wifiCfg.SetInterfaceInfoArray(infos);
    wifiCfg.SetDeviceId("123");
    auto protocol1 = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol1->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE1 });
    wifiCfg.Marshalling(*protocol1, config);

    WifiConfigInfo wifiCfg2(config);
    auto infoArray = wifiCfg2.GetInterfaceInfoArray();
    EXPECT_EQ(infoArray.size(), 1);

    for (auto item : infoArray) {
        std::cout << item.GetName() << std::endl;
    }
}

/*
 * @tc.name: GetInterfaceInfoTest
 * @tc.desc: check GetInterfaceInfo, SetInterfaceInfoArray and GetInterfaceInfoArray methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, GetInterfaceInfoTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> infos;
    InterfaceInfo info;
    info.SetName(IF_NAME_HML);
    infos.push_back(info);

    wifiCfg.SetInterfaceInfoArray(infos);
    auto ret = wifiCfg.GetInterfaceInfo(IF_NAME_P2P);
    EXPECT_EQ(ret.GetName(), "");

    ret = wifiCfg.GetInterfaceInfo(IF_NAME_HML);
    EXPECT_EQ(ret.GetName(), IF_NAME_HML);

    wifiCfg.SetDeviceId("test");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "test");
}

/*
 * @tc.name: EmptyConfigTest
 * @tc.desc: test with empty configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, EmptyConfigTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;

    EXPECT_EQ(wifiCfg.GetDeviceId(), "");
    EXPECT_EQ(wifiCfg.GetInterfaceInfoArray().size(), 0);
}

/*
 * @tc.name: MultipleInterfaceInfosTest
 * @tc.desc: test with multiple interface infos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, MultipleInterfaceInfosTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> infos;

    InterfaceInfo info1;
    info1.SetName(IF_NAME_P2P);
    info1.SetIsEnable(true);

    InterfaceInfo info2;
    info2.SetName(IF_NAME_HML);
    info2.SetIsEnable(true);

    infos.push_back(info1);
    infos.push_back(info2);

    wifiCfg.SetInterfaceInfoArray(infos);

    auto resultArray = wifiCfg.GetInterfaceInfoArray();
    EXPECT_EQ(resultArray.size(), 2);

    auto retrieved1 = wifiCfg.GetInterfaceInfo(IF_NAME_P2P);
    EXPECT_EQ(retrieved1.GetName(), IF_NAME_P2P);

    auto retrieved2 = wifiCfg.GetInterfaceInfo(IF_NAME_HML);
    EXPECT_EQ(retrieved2.GetName(), IF_NAME_HML);
}

/*
 * @tc.name: SetDeviceIdTest
 * @tc.desc: test set and get device ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, SetDeviceIdTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;

    wifiCfg.SetDeviceId("testDeviceId123");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "testDeviceId123");

    wifiCfg.SetDeviceId("");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "");

    wifiCfg.SetDeviceId("0123456789ABCDEF");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "0123456789ABCDEF");
}

/*
 * @tc.name: GetInterfaceInfoNotFoundTest
 * @tc.desc: test getting non-existent interface info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, GetInterfaceInfoNotFoundTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> infos;

    InterfaceInfo info;
    info.SetName(IF_NAME_HML);
    infos.push_back(info);

    wifiCfg.SetInterfaceInfoArray(infos);

    auto result = wifiCfg.GetInterfaceInfo("nonExistentInterface");
    EXPECT_EQ(result.GetName(), "");
}

/*
 * @tc.name: MarshallingWithTLV2Test
 * @tc.desc: test marshalling with TLV length size 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, MarshallingWithTLV2Test, TestSize.Level1)
{
    std::vector<uint8_t> config;
    WifiConfigInfo wifiCfg;

    InterfaceInfo info;
    info.SetName("TestInterface");
    info.SetIsEnable(true);
    std::vector<InterfaceInfo> infos = { info };
    wifiCfg.SetInterfaceInfoArray(infos);

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::TLV);
    protocol->SetFormat({ TlvProtocol::TLV_TAG_SIZE, TlvProtocol::TLV_LENGTH_SIZE2 });

    int ret = wifiCfg.Marshalling(*protocol, config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: EmptyInterfaceArrayTest
 * @tc.desc: test with empty interface array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, EmptyInterfaceArrayTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> emptyArray;

    wifiCfg.SetInterfaceInfoArray(emptyArray);
    EXPECT_EQ(wifiCfg.GetInterfaceInfoArray().size(), 0);

    auto result = wifiCfg.GetInterfaceInfo(IF_NAME_P2P);
    EXPECT_EQ(result.GetName(), "");
}

/*
 * @tc.name: InterfaceInfoWithMultiplePropertiesTest
 * @tc.desc: test interface info with multiple properties
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, InterfaceInfoWithMultiplePropertiesTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> infos;

    InterfaceInfo info;
    info.SetName(IF_NAME_HML);
    info.SetIsEnable(true);
    info.SetRole(LinkInfo::LinkMode::HML);
    info.SetBaseMac("AA:BB:CC:DD:EE:FF");
    info.SetCenter20M(149);
    info.SetBandWidth(80);
    Ipv4Info ipv4("192.168.1.1");
    info.SetIpString(ipv4);

    infos.push_back(info);
    wifiCfg.SetInterfaceInfoArray(infos);

    auto retrieved = wifiCfg.GetInterfaceInfo(IF_NAME_HML);
    EXPECT_EQ(retrieved.GetName(), IF_NAME_HML);
    EXPECT_EQ(retrieved.IsEnable(), true);
    EXPECT_EQ(retrieved.GetRole(), LinkInfo::LinkMode::HML);
    EXPECT_EQ(retrieved.GetBaseMac(), "AA:BB:CC:DD:EE:FF");
}

/*
 * @tc.name: GetNonExistentDeviceIdTest
 * @tc.desc: test getting device ID when not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, GetNonExistentDeviceIdTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;

    // Initially empty
    EXPECT_EQ(wifiCfg.GetDeviceId(), "");

    // Set and verify
    wifiCfg.SetDeviceId("deviceId123");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "deviceId123");

    // Clear and verify
    wifiCfg.SetDeviceId("");
    EXPECT_EQ(wifiCfg.GetDeviceId(), "");
}

/*
 * @tc.name: UpdateInterfaceInfoArrayTest
 * @tc.desc: test updating interface info array
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, UpdateInterfaceInfoArrayTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;

    // Set initial array
    std::vector<InterfaceInfo> infos1;
    InterfaceInfo info1;
    info1.SetName(IF_NAME_P2P);
    infos1.push_back(info1);
    wifiCfg.SetInterfaceInfoArray(infos1);

    // Update with new array
    std::vector<InterfaceInfo> infos2;
    InterfaceInfo info2;
    info2.SetName(IF_NAME_HML);
    infos2.push_back(info2);
    wifiCfg.SetInterfaceInfoArray(infos2);

    // Verify updated array
    auto result = wifiCfg.GetInterfaceInfoArray();
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].GetName(), IF_NAME_HML);
}

/*
 * @tc.name: ComplexInterfaceInfoTest
 * @tc.desc: test complex interface info configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiConfigInfoTest, ComplexInterfaceInfoTest, TestSize.Level1)
{
    WifiConfigInfo wifiCfg;
    std::vector<InterfaceInfo> infos;

    // P2P interface
    InterfaceInfo p2pInfo;
    p2pInfo.SetName(IF_NAME_P2P);
    p2pInfo.SetIsEnable(true);
    p2pInfo.SetRole(LinkInfo::LinkMode::GO);
    p2pInfo.SetP2pListenPort(8888);
    infos.push_back(p2pInfo);

    // HML interface
    InterfaceInfo hmlInfo;
    hmlInfo.SetName(IF_NAME_HML);
    hmlInfo.SetIsEnable(true);
    hmlInfo.SetRole(LinkInfo::LinkMode::HML);
    infos.push_back(hmlInfo);

    wifiCfg.SetInterfaceInfoArray(infos);
    wifiCfg.SetDeviceId("complexTestDevice");

    EXPECT_EQ(wifiCfg.GetDeviceId(), "complexTestDevice");
    EXPECT_EQ(wifiCfg.GetInterfaceInfoArray().size(), 2);

    auto p2p = wifiCfg.GetInterfaceInfo(IF_NAME_P2P);
    EXPECT_EQ(p2p.GetRole(), LinkInfo::LinkMode::GO);

    auto hml = wifiCfg.GetInterfaceInfo(IF_NAME_HML);
    EXPECT_EQ(hml.GetRole(), LinkInfo::LinkMode::HML);
}

} // namespace OHOS::SoftBus
