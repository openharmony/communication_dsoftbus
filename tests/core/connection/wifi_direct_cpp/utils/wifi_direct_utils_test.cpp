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

#define private   public
#define protected public
#include "duration_statistic.h"
#undef protected
#undef private

#include "wifi_direct_mock.h"
#include "wifi_direct_utils.h"
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <securec.h>
#include <string>

using namespace testing::ext;
using testing::_;
using ::testing::Return;

namespace OHOS::SoftBus {
class WifiDirectUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: BytesToIntTest
 * @tc.desc: check BytesToInt method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, BytesToIntTest, TestSize.Level1)
{
    std::vector<uint8_t> data = { 58, 76 };
    auto ret = WifiDirectUtils::BytesToInt(data);
    EXPECT_EQ(ret, 19514);
}

/*
 * @tc.name: ToBinary
 * @tc.desc: check ToBinary method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, ToBinaryTest, TestSize.Level1)
{
    std::string input("010203040506070809");
    std::vector<uint8_t> expected = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    auto ret = WifiDirectUtils::ToBinary(input);
    EXPECT_EQ(ret, expected);

    input = "zzzz";
    std::vector<uint8_t> expected2 = { '\0', '\0' };
    ret = WifiDirectUtils::ToBinary(input);
    EXPECT_EQ(ret, expected2);
}

/*
 * @tc.name: ChannelToFrequencyTest
 * @tc.desc: check ChannelToFrequency method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, ChannelToFrequencyTest, TestSize.Level1)
{
    int channel = 36;
    int frequency = 5180;
    auto ret = WifiDirectUtils::ChannelToFrequency(channel);
    EXPECT_EQ(ret, frequency);

    channel = -1;
    frequency = -1;
    ret = WifiDirectUtils::ChannelToFrequency(channel);
    EXPECT_EQ(ret, frequency);
}

/*
 * @tc.name: UuidToNetworkIdTest
 * @tc.desc: check UuidToNetworkId method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, UuidToNetworkIdTest, TestSize.Level1)
{
    std::string uuid = "0123456789ABCDEF";
    char networkId[NETWORK_ID_BUF_LEN] = { 1 };
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(_, _, _))
        .WillRepeatedly([&networkId](const std::string &uuid, char *buf, uint32_t len) {
            (void)strcpy_s(buf, len, networkId);
            return SOFTBUS_OK;
        });

    auto ret = WifiDirectUtils::UuidToNetworkId(uuid);
    EXPECT_EQ(ret, networkId);
}

/*
 * @tc.name: GetLocalPtkTest
 * @tc.desc: check GetLocalPtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, GetLocalPtkTest, TestSize.Level1)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 1 };
    std::string remoteDeviceId = "01234567890ABCDEF";
    char ptkBytes[PTK_DEFAULT_LEN] = { 3 };
    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalPtkByUuid).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(mock, LnnGetLocalDefaultPtkByUuid(_, _, _))
        .WillOnce([&ptkBytes](const std::string &uuid, char *localPtk, uint32_t len) {
            (void)strcpy_s(localPtk, len, ptkBytes);
            return SOFTBUS_OK;
        });
    auto ret = WifiDirectUtils::GetLocalPtk(networkId);

    EXPECT_NE(ret.size(), 0);

    EXPECT_CALL(mock, LnnGetLocalPtkByUuid).WillOnce(Return(SOFTBUS_OK));
    ret = WifiDirectUtils::GetLocalPtk(networkId);

    EXPECT_NE(ret.size(), 0);
}

/*
 * @tc.name: GetRemotePtkTest
 * @tc.desc: check GetRemotePtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, GetRemotePtkTest, TestSize.Level1)
{
    char remoteNetworkId[NETWORK_ID_BUF_LEN] = { 1 };
    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteByteInfo).WillOnce(Return(-1));
    auto ret = WifiDirectUtils::GetRemotePtk(remoteNetworkId);
    EXPECT_EQ(ret.size(), 0);

    EXPECT_CALL(mock, LnnGetRemoteByteInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteDefaultPtkByUuid).WillOnce(Return(SOFTBUS_OK));
    ret = WifiDirectUtils::GetRemotePtk(remoteNetworkId);
    EXPECT_NE(ret.size(), 0);
}

/*
 * @tc.name: IsRemoteSupportTlvTest
 * @tc.desc: check IsRemoteSupportTlv method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, IsRemoteSupportTlvTest, TestSize.Level1)
{
    std::string remoteDeviceId = "01234567890ABCDEF";
    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteBoolInfo(_, _, _))
        .WillRepeatedly([](const std::string &networkId, InfoKey key, bool *info) {
            *info = true;
            return SOFTBUS_OK;
        });
    auto ret = WifiDirectUtils::IsRemoteSupportTlv(remoteDeviceId);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: IsInChannelListTest
 * @tc.desc: check IsInChannelList method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, IsInChannelListTest, TestSize.Level1)
{
    std::string channels = "";
    auto ret = WifiDirectUtils::StringToChannelList(channels);
    EXPECT_EQ(ret.empty(), true);

    channels = "36##37";
    ret = WifiDirectUtils::StringToChannelList(channels);
    EXPECT_EQ(ret.empty(), false);
}

/*
 * @tc.name: StringToChannelListTest
 * @tc.desc: check StringToChannelList method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, StringToChannelListTest, TestSize.Level1)
{
    int channel = 36;
    std::vector<int> channelArray = { 35, 36, 37 };
    auto ret = WifiDirectUtils::IsInChannelList(channel, channelArray);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: ToWifiDirectRoleTest
 * @tc.desc: check ToWifiDirectRole method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, ToWifiDirectRoleTest, TestSize.Level1)
{
    LinkInfo::LinkMode mode = LinkInfo::LinkMode::INVALID;
    auto ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_INVALID);

    mode = LinkInfo::LinkMode::STA;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_INVALID);

    mode = LinkInfo::LinkMode::AP;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_INVALID);

    mode = LinkInfo::LinkMode::GO;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_GO);

    mode = LinkInfo::LinkMode::GC;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_GC);

    mode = LinkInfo::LinkMode::HML;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_HML);

    mode = static_cast<LinkInfo::LinkMode>(17);
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_INVALID);
}

/*
 * @tc.name: BandWidthEnumToNumberTest
 * @tc.desc: check BandWidthEnumToNumber method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, BandWidthEnumToNumberTest, TestSize.Level1)
{
    WifiDirectBandWidth bandWidth = BAND_WIDTH_160M;
    auto ret = WifiDirectUtils::BandWidthEnumToNumber(bandWidth);
    EXPECT_EQ(ret, WifiDirectUtils::BAND_WIDTH_160M_NUMBER);

    bandWidth = BAND_WIDTH_20M;
    ret = WifiDirectUtils::BandWidthEnumToNumber(bandWidth);
    EXPECT_EQ(ret, WifiDirectUtils::BAND_WIDTH_80M_NUMBER);
}

/*
 * @tc.name: CalculateStringLengthTest
 * @tc.desc: check CalculateStringLength method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, CalculateStringLengthTest, TestSize.Level1)
{
    std::string str("123456");
    auto ret = WifiDirectUtils::CalculateStringLength(str.c_str(), str.size() + 1);
    EXPECT_EQ(ret, 6);
}

/*
 * @tc.name: SyncLnnInfoForP2pTest
 * @tc.desc: check SyncLnnInfoForP2p method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, SyncLnnInfoForP2pTest, TestSize.Level1)
{
    WifiDirectRole role = WIFI_DIRECT_ROLE_AUTO;
    const std::string localMac = "11:22:33:44:55";
    const std::string goMac = "11:22:33:44:66";
    bool expect = true;

    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnSetLocalNumInfo).WillOnce(Return(-1));
    EXPECT_CALL(mock, LnnSetLocalStrInfo).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, LnnSyncP2pInfo).WillOnce(Return(SOFTBUS_OK));
    WifiDirectUtils::SyncLnnInfoForP2p(role, localMac, goMac);
    EXPECT_EQ(expect, true);
}

/*
 * @tc.name: DurationStatisticEndTest
 * @tc.desc: check DurationStatistic::End method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, DurationStatisticEndTest, TestSize.Level1)
{
    int requestid = 0;
    DurationStatistic::GetInstance().End(requestid);

    DurationStatistic::GetInstance().calculators_[requestid] =
        OHOS::SoftBus::DurationStatisticCalculatorFactory::GetInstance().NewInstance(
            WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P);

    DurationStatistic::GetInstance().End(requestid);
    DurationStatisticCalculatorFactory::GetInstance().creator_ = [](enum WifiDirectConnectType type) {
        return std::make_shared<P2pCalculator>(P2pCalculator::GetInstance());
    };
    auto ptr = OHOS::SoftBus::DurationStatisticCalculatorFactory::GetInstance().NewInstance(
        WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P);
    EXPECT_EQ(requestid, 0);
    EXPECT_NE(ptr, nullptr);
}
} // namespace OHOS::SoftBus