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

} // namespace OHOS::SoftBus