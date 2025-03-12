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
#include "dfx/duration_statistic.h"
#include "dfx/wifi_direct_dfx.h"
#undef protected
#undef private

#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <securec.h>
#include <string>
#include "data/link_manager.h"
#include "net_conn_client.h"
#include "wifi_direct_anonymous.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_utils.h"

using namespace testing::ext;
using testing::_;
using ::testing::Return;

constexpr int32_t FREQ1 = 1500;
constexpr int32_t FREQ2 = 2437;
constexpr int32_t FREQ3 = 5300;
constexpr int32_t FREQ4 = 5745;
constexpr int32_t CHAN1 = 6;
constexpr int32_t CHAN2 = 149;
constexpr int32_t INVALID_CHANNEL = -1;

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
    int32_t channel = 36;
    int32_t frequency = 5180;
    auto ret = WifiDirectUtils::ChannelToFrequency(channel);
    EXPECT_EQ(ret, frequency);

    channel = -1;
    frequency = -1;
    ret = WifiDirectUtils::ChannelToFrequency(channel);
    EXPECT_EQ(ret, frequency);

    channel = CHAN1;
    frequency = FREQ2;
    ret = WifiDirectUtils::ChannelToFrequency(channel);
    EXPECT_EQ(ret, frequency);
}

/*
 * @tc.name: FrequencyToChannelTest
 * @tc.desc: check FrequencyToChannel method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, FrequencyToChannelTest, TestSize.Level1)
{
    auto ret = WifiDirectUtils::FrequencyToChannel(FREQ2);
    EXPECT_EQ(ret, CHAN1);
    ret = WifiDirectUtils::FrequencyToChannel(FREQ4);
    EXPECT_EQ(ret, CHAN2);
    ret = WifiDirectUtils::FrequencyToChannel(FREQ1);
    EXPECT_EQ(ret, INVALID_CHANNEL);
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
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(_, _, _))
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
    int32_t channel = 36;
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

    mode = LinkInfo::LinkMode::NONE;
    ret = WifiDirectUtils::ToWifiDirectRole(mode);
    EXPECT_EQ(ret, WifiDirectRole::WIFI_DIRECT_ROLE_NONE);

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

    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnSetLocalNumInfo).WillOnce(Return(-1));
    EXPECT_CALL(mock, LnnSetLocalStrInfo).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, LnnSyncP2pInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(WifiDirectUtils::SyncLnnInfoForP2p(role, localMac, goMac));
}

/*
 * @tc.name: DurationStatisticEndTest
 * @tc.desc: check DurationStatistic::End method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, DurationStatisticEndTest, TestSize.Level1)
{
    int32_t requestid = 0;
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

/*
 * @tc.name: GetLocalIpv4InfosTest
 * @tc.desc: check GetLocalIpv4Infos method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, GetLocalIpv4InfosTest, TestSize.Level1)
{
    auto ret = WifiDirectUtils::GetLocalIpv4Infos();
    EXPECT_EQ(ret.empty(), true);
}

/*
 * @tc.name: IpStringToIntArrayTest
 * @tc.desc: check IpStringToIntArray method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, IpStringToIntArrayTest, TestSize.Level1)
{
    static char addrString[] = "255.255.255.0";
    static const uint32_t LEN = 4;
    uint32_t addrArray[LEN];
    auto ret = WifiDirectUtils::IpStringToIntArray(addrString, addrArray, LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ChannelListToStringTest
 * @tc.desc: check ChannelListToString method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, ChannelListToStringTest, TestSize.Level1)
{
    std::vector<int> channels = {36, 40, 52};
    auto ret = WifiDirectUtils::ChannelListToString(channels);
    EXPECT_EQ(ret, "36##40##52");
}

/*
 * @tc.name: IsDfsChannelTest
 * @tc.desc: check IsDfsChannel method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, IsDfsChannelTest, TestSize.Level1)
{
    auto ret = WifiDirectUtils::IsDfsChannel(FREQ2);
    EXPECT_EQ(ret, false);
    ret = WifiDirectUtils::IsDfsChannel(FREQ3);
    EXPECT_EQ(ret, true);
    ret = WifiDirectUtils::IsDfsChannel(FREQ4);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: CheckLinkAtDfsChannelConflictTest
 * @tc.desc: check CheckLinkAtDfsChannelConflict method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, CheckLinkAtDfsChannelConflictTest, TestSize.Level1)
{
    std::string uuid = "0123456789ABCDEF";
    std::string remoteDeviceId = "abcdefg";
    int32_t frequency = FREQ4;
    InnerLink::LinkType linkType = InnerLink::LinkType::HML;
    int32_t type = HO_OS_TYPE;
    char networkId[NETWORK_ID_BUF_LEN] = { 1 };
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(_, _, _))
        .WillRepeatedly([&networkId](const std::string &uuid, char *buf, uint32_t len) {
            (void)strcpy_s(buf, len, networkId);
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_WIFI_DIRECT_INIT_FAILED));
    auto ret = WifiDirectUtils::CheckLinkAtDfsChannelConflict(uuid, linkType);
    EXPECT_EQ(ret, false);

    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = WifiDirectUtils::CheckLinkAtDfsChannelConflict(uuid, linkType);
    EXPECT_EQ(ret, false);

    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId(_, _))
        .WillRepeatedly([&type](const char *networkId, int32_t *osType) {
            *osType = type;
            return SOFTBUS_OK;
        });
    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteDeviceId, [frequency](InnerLink &innerLink) {
            innerLink.SetFrequency(frequency);
        });
    ret = WifiDirectUtils::CheckLinkAtDfsChannelConflict(uuid, linkType);
    EXPECT_EQ(ret, false);
    LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::HML, remoteDeviceId);

    frequency = FREQ3;
    linkType = InnerLink::LinkType::P2P;
    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::P2P, remoteDeviceId, [frequency](InnerLink &innerLink) {
            innerLink.SetFrequency(frequency);
        });
    ret = WifiDirectUtils::CheckLinkAtDfsChannelConflict(uuid, linkType);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: WifiDirectAnonymizeIpTest
 * @tc.desc: check WifiDirectAnonymizeIp method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, WifiDirectAnonymizeIpTest, TestSize.Level1)
{
    std::string ip = "192";
    auto ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "**2");
    ip = "192.168";
    ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "1****68");
    ip = "192..";
    ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "1***.");
    ip = "70:60";
    ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "7***0");
    ip = "192.168.1.2";
    ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "192.168.1.*");
    ip = "70:f8:56:s5:80:9a";
    ret = WifiDirectAnonymizeIp(ip);
    EXPECT_EQ(ret, "70:f*********0:9a");
}

/*
 * @tc.name: WifiDirectAnonymizeSsidTest
 * @tc.desc: check WifiDirectAnonymizeSsid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, WifiDirectAnonymizeSsidTest, TestSize.Level1)
{
    std::string ssid = "";
    auto ret = WifiDirectAnonymizeSsid(ssid);
    EXPECT_EQ(ret, "");
    ssid = "te";
    ret = WifiDirectAnonymizeSsid(ssid);
    EXPECT_EQ(ret, "*e");
    ssid = "aaaaaaaa";
    ret = WifiDirectAnonymizeSsid(ssid);
    EXPECT_EQ(ret, "aa****aa");
}

/*
 * @tc.name: WifiDirectAnonymizePskTest
 * @tc.desc: check WifiDirectAnonymizePsk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, WifiDirectAnonymizePskTest, TestSize.Level1)
{
    std::string psk = "";
    WifiDirectConnectInfo conInfo{};
    ConnEventExtra conEventExtra = { 0 };
    WifiDirectInterfaceMock mock;
    conInfo.dfxInfo.linkType = STATISTIC_TRIGGER_HML;
    DurationStatistic::GetInstance().Record(1, TOTAL_START);
    DurationStatistic::GetInstance().Record(1, TOTAL_END);
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillOnce(Return(SOFTBUS_OK));
    WifiDirectDfx::GetInstance().ReportConnEventExtra(conEventExtra, conInfo);
    auto ret = WifiDirectAnonymizePsk(psk);
    EXPECT_EQ(ret, "");
    psk = "1234";
    ret = WifiDirectAnonymizePsk(psk);
    EXPECT_EQ(ret, "1**4");
    psk = "123456789";
    ret = WifiDirectAnonymizePsk(psk);
    EXPECT_EQ(ret, "12*****89");
}

/*
 * @tc.name: WifiDirectAnonymizePtkTest
 * @tc.desc: check WifiDirectAnonymizePtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, WifiDirectAnonymizePtkTest, TestSize.Level1)
{
    std::string ptk = "";
    auto ret = WifiDirectAnonymizePtk(ptk);
    EXPECT_EQ(ret, "");
    ptk = "123456";
    ret = WifiDirectAnonymizePtk(ptk);
    EXPECT_EQ(ret, "1***56");
    ptk = "123456789000000";
    ret = WifiDirectAnonymizePtk(ptk);
    EXPECT_EQ(ret, "123********0000");
}

/*
 * @tc.name: WifiDirectAnonymizeDataTest
 * @tc.desc: check WifiDirectAnonymizeData method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, WifiDirectAnonymizeDataTest, TestSize.Level1)
{
    std::string data = "";
    auto ret = WifiDirectAnonymizeData(data);
    EXPECT_EQ(ret, "");
    data = "12345";
    ret = WifiDirectAnonymizeData(data);
    EXPECT_EQ(ret, "1***5");
    data = "0123456789";
    ret = WifiDirectAnonymizeData(data);
    EXPECT_EQ(ret, "01*****789");
}

/*
 * @tc.name: GetLocalConnSubFeatureTest
 * @tc.desc: check GetLocalConnSubFeature method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, GetLocalConnSubFeatureTest, TestSize.Level1)
{
    uint64_t feature = 0;
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalNumU64Info(_, _)).WillOnce([](InfoKey key, uint64_t *info) {
        *info = 1;
        return SOFTBUS_OK;
    });

    auto ret = WifiDirectUtils::GetLocalConnSubFeature(feature);
    EXPECT_EQ(feature, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetRemoteConnSubFeatureTest
 * @tc.desc: check GetRemoteConnSubFeature method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectUtilsTest, GetRemoteConnSubFeatureTest, TestSize.Level1)
{
    uint64_t feature = 0;
    std::string networkId = "1234567890";
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info(_, _, _))
        .WillOnce([](const std::string &networkId, InfoKey key, uint64_t *info) {
            return SOFTBUS_OK;
        });

    auto ret = WifiDirectUtils::GetRemoteConnSubFeature(networkId, feature);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS::SoftBus