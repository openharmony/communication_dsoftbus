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
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>
#include "conn_log.h"

#include "softbus_error_code.h"
#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "entity/p2p_connect_state.h"
#include "entity/p2p_entity.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
namespace OHOS::SoftBus {
static constexpr int32_t CHANNEL_ARRAY_NUM_MAX = 256;
class P2pAdapterTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiDirectInterfaceMock mock;
        EXPECT_CALL(mock, GetP2pEnableStatus).WillOnce(Return(WIFI_SUCCESS));
        P2pEntity::Init();
    }
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: IsWifiEnableTest
* @tc.desc: is wifi enable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, IsWifiEnableTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, IsWifiActive).WillOnce(Return(1));
    bool flag = P2pAdapter::IsWifiEnable();
    EXPECT_TRUE(flag);
}

/*
* @tc.name: IsWifiConnectedTest
* @tc.desc: is wifi connected
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, IsWifiConnectedTest, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = WIFI_CONNECTED;
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetLinkedInfo).WillOnce(Return(WIFI_SUCCESS))
        .WillOnce(DoAll(SetArgPointee<0>(linkedInfo), Return(WIFI_SUCCESS)));
    bool flag = P2pAdapter::IsWifiConnected();
    EXPECT_FALSE(flag);
    flag = P2pAdapter::IsWifiConnected();
    EXPECT_TRUE(flag);
}

/*
* @tc.name: P2pConnectGroupTest
* @tc.desc: p2p connect group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, P2pConnectGroupTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pConnectParam param{"123\n01:02:03:04:05:06\n555\n16\n1", true, false};
    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: DestroyGroupTest
* @tc.desc: p2p destroy group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, DestroyGroupTest, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(
            InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
            info.SetRole(LinkInfo::LinkMode::INVALID);
            return SOFTBUS_OK;
    });
    P2pDestroyGroupParam param;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_EQ(ret, SOFTBUS_CONN_UNKNOWN_ROLE);
}

/*
* @tc.name: GetStationFrequencyWithFilterTest
* @tc.desc: get station frequence with filter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetStationFrequencyWithFilterTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = 5170;
    EXPECT_CALL(mock, GetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
    int32_t size = CHANNEL_ARRAY_NUM_MAX;
    std::vector<int> array(CHANNEL_ARRAY_NUM_MAX, 34);
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce(
        [&array, size](int32_t *chanList, int32_t len) {
        array[0] = 34;
        chanList[0] = array[0];
        len = size;
        return WIFI_SUCCESS;
    });
    result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, info.frequency);

    EXPECT_CALL(mock, Hid2dGetChannelListFor5G).WillOnce(Return(WIFI_SUCCESS));
    result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, FREQUENCY_INVALID);

    info.frequency = 2412;
    EXPECT_CALL(mock, GetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, info.frequency);
    info.frequency = 1;
    EXPECT_CALL(mock, GetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, FREQUENCY_INVALID);
}

/*
* @tc.name: GetRecommendChannelTest
* @tc.desc: get recommend channel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetRecommendChannelTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dGetRecommendChannel).WillRepeatedly(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
* @tc.name: GetInterfaceCoexistCapTest
* @tc.desc: get interface coexistCap
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetInterfaceCoexistCapTest, TestSize.Level1)
{
    std::string result = P2pAdapter::GetInterfaceCoexistCap();

    EXPECT_TRUE(result.empty());
}
/*
* @tc.name: GetRecommendChannelTest002
* @tc.desc: get recommend channel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetRecommendChannelTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    RecommendChannelResponse response;
    response.centerFreq = 0;
    response.centerFreq1 = 1;
    EXPECT_CALL(mock, Hid2dGetRecommendChannel).WillOnce(DoAll(SetArgPointee<1>(response),
        Return(WIFI_SUCCESS)));

    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_EQ(ret, CHANNEL_INVALID);

    response.centerFreq1 = 0;
    EXPECT_CALL(mock, Hid2dGetRecommendChannel).WillOnce(Return(WIFI_SUCCESS));
    ret = P2pAdapter::GetRecommendChannel();
    EXPECT_EQ(ret, CHANNEL_INVALID);
}

/*
* @tc.name: GetSelfWifiConfigInfoTest001
* @tc.desc: get self wifi config info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetSelfWifiConfigInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    int32_t wifiConfigSize = 0;
    std::string config;
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo).WillOnce(DoAll(SetArgPointee<2>(wifiConfigSize), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetSelfWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);

    wifiConfigSize = 1;
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo).WillOnce(DoAll(SetArgPointee<2>(wifiConfigSize), Return(WIFI_SUCCESS)));
    EXPECT_CALL(mock, SoftBusBase64Encode).WillOnce(Return(WIFI_SUCCESS));
    ret = P2pAdapter::GetSelfWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: SetPeerWifiConfigInfoTest001
* @tc.desc: get self wifi config info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, SetPeerWifiConfigInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config = "ssss8888123456";
    EXPECT_CALL(mock, SoftBusBase64Decode).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret =P2pAdapter::SetPeerWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(mock, Hid2dSetPeerWifiCfgInfo).WillOnce(Return(WIFI_SUCCESS));
    ret = P2pAdapter::SetPeerWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: SetPeerWifiConfigInfoV2Test001
* @tc.desc: check create group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, SetPeerWifiConfigInfoV2Test001, TestSize.Level1)
{
    const uint8_t cfg[] = {0, 0, 0, 0, 0};
    int32_t ret = P2pAdapter::SetPeerWifiConfigInfoV2(cfg, sizeof(cfg));
    EXPECT_EQ(ret, SOFTBUS_CONN_SET_PEER_WIFI_CONFIG_FAIL);
}

/*
* @tc.name: IsWideBandSupportedTest001
* @tc.desc: check create group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, IsWideBandSupportedTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config = "ssss8888123456";
    EXPECT_CALL(mock, Hid2dIsWideBandwidthSupported).WillOnce(Return(true));
    bool result = P2pAdapter::IsWideBandSupported();
    EXPECT_EQ(result, true);
}

/*
* @tc.name: GetGroupInfoTest001
* @tc.desc: get group info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetGroupInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo info {};
    P2pAdapter::WifiDirectP2pGroupInfo groupInfoOut {};
    info.clientDevicesSize = 1;
    EXPECT_CALL(mock, GetCurrentGroup).WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetGroupInfo(groupInfoOut);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: GetGroupInfoTest002
* @tc.desc: get group info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetGroupInfoTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pAdapter::WifiDirectP2pGroupInfo p2pGroupInfo;
    WifiP2pGroupInfo info {};
    info.clientDevicesSize = 1;
    EXPECT_CALL(mock, GetCurrentGroup).WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetGroupInfo(p2pGroupInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: GetGroupConfigTest001
* @tc.desc: get group config
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetGroupConfigTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo info {};
    std::string groupConfigString;
    EXPECT_CALL(mock, GetCurrentGroup)
        .WillOnce(Return(ERROR_WIFI_UNKNOWN))
        .WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret =P2pAdapter::GetGroupConfig(groupConfigString);
     
    EXPECT_EQ(ret, ToSoftBusErrorCode(static_cast<int32_t>(ERROR_WIFI_UNKNOWN)));
    ret =P2pAdapter::GetGroupConfig(groupConfigString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}


/*
* @tc.name: GetIpAddressTest001
* @tc.desc: get ip address
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetIpAddressTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string ipString = "127.0.0.X";
    EXPECT_CALL(mock, GetCurrentGroup).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetIpAddress(ipString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(static_cast<int32_t>(ERROR_WIFI_UNKNOWN)));
}

/*
* @tc.name: GetDynamicMacAddressTest001
* @tc.desc: get dynamic mac adress
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, GetDynamicMacAddressTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString;
    WifiP2pGroupInfo info;
    if (strcpy_s(info.interface, sizeof(info.interface), "wlan0") != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "strcpy interfaceName fail");
        return;
    }
    EXPECT_CALL(mock, GetCurrentGroup).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetDynamicMacAddress(macString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
* @tc.name: DestroyGroupTest002
* @tc.desc: check destroy group
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAdapterTest, DestroyGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString = "";
    std::string ipString;
    int32_t ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(mock, Hid2dRequestGcIp)
        .WillOnce(Return(ERROR_WIFI_UNKNOWN))
        .WillOnce(Return(WIFI_SUCCESS));
    macString = "11:22:33:44:55:66";
    ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));

    ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, WIFI_SUCCESS);
}
}