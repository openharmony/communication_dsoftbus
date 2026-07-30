/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "conn_log.h"
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "data/interface_info.h"
#include "data/interface_manager.h"
#include "entity/p2p_connect_state.h"
#include "entity/p2p_entity.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
namespace OHOS::SoftBus {
static constexpr int32_t WIFI_5G_FREQ_5170 = 5170;
static constexpr int32_t WIFI_5G_FREQ_5180 = 5180;
static constexpr int32_t WIFI_2G_FREQ_2412 = 2412;
static constexpr int32_t WIFI_FREQ_NOT_IN_BAND = 5000;
static constexpr int32_t WIFI_5G_CHANNEL_34 = 34;
static constexpr int32_t WIFI_AP_CHANNEL_6 = 6;
static constexpr int32_t TEST_CHANNEL_ARRAY_SIZE = 4;
static constexpr int32_t TEST_CONFIG_DATA_SIZE = 5;
static constexpr int32_t EXPECTED_COEX_CONFLICT_CODE = 0;
static constexpr int32_t WIFI_CONFIG_SIZE_ZERO = 0;
static constexpr int32_t WIFI_CONFIG_SIZE_NON_ZERO = 1;
static constexpr int32_t WIFI_5G_CHANNEL_ARRAY_SIZE = 3;

class P2pAdapterAiTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiDirectInterfaceMock mock;
        EXPECT_CALL(mock, GetP2pEnableStatus).WillOnce(Return(WIFI_SUCCESS));
        P2pEntity::Init();
    }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: IsWifiEnableTest001
 * @tc.desc: test IsWifiEnable when wifi is active
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiEnableTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, IsWifiActive).WillOnce(Return(WIFI_STA_ACTIVE));
    bool flag = P2pAdapter::IsWifiEnable();
    EXPECT_TRUE(flag);
}

/*
 * @tc.name: IsWifiEnableTest002
 * @tc.desc: test IsWifiEnable when wifi is not active
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiEnableTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, IsWifiActive).WillOnce(Return(WIFI_STA_NOT_ACTIVE));
    bool flag = P2pAdapter::IsWifiEnable();
    EXPECT_FALSE(flag);
}

/*
 * @tc.name: IsWifiConnectedTest001
 * @tc.desc: test IsWifiConnected when GetLinkedInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiConnectedTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    bool flag = P2pAdapter::IsWifiConnected();
    EXPECT_FALSE(flag);
}

/*
 * @tc.name: IsWifiConnectedTest002
 * @tc.desc: test IsWifiConnected when wifi is not connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiConnectedTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo linkedInfo;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillOnce(DoAll(SetArgPointee<0>(linkedInfo), Return(WIFI_SUCCESS)));
    bool flag = P2pAdapter::IsWifiConnected();
    EXPECT_FALSE(flag);
}

/*
 * @tc.name: IsWifiConnectedTest003
 * @tc.desc: test IsWifiConnected when wifi is connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiConnectedTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = WIFI_CONNECTED;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillOnce(DoAll(SetArgPointee<0>(linkedInfo), Return(WIFI_SUCCESS)));
    bool flag = P2pAdapter::IsWifiConnected();
    EXPECT_TRUE(flag);
}

/*
 * @tc.name: IsWifiP2pEnabledTest001
 * @tc.desc: test IsWifiP2pEnabled when P2P is started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiP2pEnabledTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pState state = P2P_STATE_STARTED;
    EXPECT_CALL(mock, GetP2pEnableStatus(_)).WillOnce(DoAll(SetArgPointee<0>(state), Return(WIFI_SUCCESS)));
    bool ret = P2pAdapter::IsWifiP2pEnabled();
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsWifiP2pEnabledTest002
 * @tc.desc: test IsWifiP2pEnabled when P2P is idle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiP2pEnabledTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pState state = P2P_STATE_IDLE;
    EXPECT_CALL(mock, GetP2pEnableStatus(_)).WillOnce(DoAll(SetArgPointee<0>(state), Return(WIFI_SUCCESS)));
    bool ret = P2pAdapter::IsWifiP2pEnabled();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsWifiP2pEnabledTest003
 * @tc.desc: test IsWifiP2pEnabled when GetP2pEnableStatus fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWifiP2pEnabledTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetP2pEnableStatus(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    bool ret = P2pAdapter::IsWifiP2pEnabled();
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GetInterfaceCoexistCapTest
 * @tc.desc: test GetInterfaceCoexistCap returns empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetInterfaceCoexistCapTest, TestSize.Level1)
{
    std::string result = P2pAdapter::GetInterfaceCoexistCap();
    EXPECT_TRUE(result.empty());
}

/*
 * @tc.name: GetStationFrequencyTest001
 * @tc.desc: test GetStationFrequency when GetLinkedInfo succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo linkedInfo;
    linkedInfo.frequency = WIFI_2G_FREQ_2412;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillOnce(DoAll(SetArgPointee<0>(linkedInfo), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetStationFrequency();
    EXPECT_EQ(ret, WIFI_2G_FREQ_2412);
}

/*
 * @tc.name: GetStationFrequencyTest002
 * @tc.desc: test GetStationFrequency when GetLinkedInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetStationFrequency();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: P2pCreateGroupTest001
 * @tc.desc: test P2pCreateGroup with wide band supported and default freq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pCreateGroupTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pCreateGroupParam param;
    param.frequency = WIFI_5G_FREQ_5180;
    param.isWideBandSupported = true;
    param.freqType = SOFTBUS_FREQUENCY_DEFAULT;

    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pCreateGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pCreateGroupTest002
 * @tc.desc: test P2pCreateGroup with Hid2dCreateGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pCreateGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pCreateGroupParam param;
    param.frequency = WIFI_5G_FREQ_5180;
    param.isWideBandSupported = true;
    param.freqType = SOFTBUS_FREQUENCY_DEFAULT;

    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::P2pCreateGroup(param);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pCreateGroupWithFreqTypeTest
 * @tc.desc: test P2pCreateGroup with 11AX freq type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pCreateGroupWithFreqTypeTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pCreateGroupParam param;
    param.frequency = WIFI_5G_FREQ_5180;
    param.isWideBandSupported = false;
    param.freqType = SOFTBUS_FREQUENCY_DEFAULT_11AX;

    EXPECT_CALL(mock, Hid2dCreateGroup(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pCreateGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pConnectGroupTest001
 * @tc.desc: test P2pConnectGroup with legacy GO and winpc mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConnectGroupTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pConnectParam param;
    param.groupConfig = "123\n01:02:03:04:05:06\n555\n16\n1";
    param.isLegacyGo = true;
    param.isNeedDhcp = false;

    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pConnectGroupTest002
 * @tc.desc: test P2pConnectGroup with non-winpc mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConnectGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pConnectParam param;
    param.groupConfig = "123\n01:02:03:04:05:06\n555\n16";
    param.isLegacyGo = true;
    param.isNeedDhcp = false;

    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pConnectGroupTest003
 * @tc.desc: test P2pConnectGroup with empty groupConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConnectGroupTest003, TestSize.Level1)
{
    P2pConnectParam param;
    param.groupConfig = "";
    param.isLegacyGo = true;
    param.isNeedDhcp = false;

    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_EQ(ret, SOFTBUS_CONN_REMOTE_CONFIG_NULL);
}

/*
 * @tc.name: P2pConnectGroupTest004
 * @tc.desc: test P2pConnectGroup with partial groupConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConnectGroupTest004, TestSize.Level1)
{
    P2pConnectParam param;
    param.groupConfig = "123\n01:02:03:04:05:06";
    param.isLegacyGo = true;
    param.isNeedDhcp = false;

    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_EQ(ret, SOFTBUS_CONN_REMOTE_CONFIG_NULL);
}

/*
 * @tc.name: P2pConnectGroupConnectFailTest
 * @tc.desc: test P2pConnectGroup when Hid2dConnect fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConnectGroupConnectFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pConnectParam param;
    param.groupConfig = "123\n01:02:03:04:05:06\n555\n16";
    param.isLegacyGo = false;
    param.isNeedDhcp = false;

    EXPECT_CALL(mock, Hid2dConnect(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::P2pConnectGroup(param);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pShareLinkReuseTest001
 * @tc.desc: test P2pShareLinkReuse when success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pShareLinkReuseTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pShareLinkReuse();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pShareLinkReuseTest002
 * @tc.desc: test P2pShareLinkReuse when fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pShareLinkReuseTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSharedlinkIncrease).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::P2pShareLinkReuse();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pShareLinkRemoveGroupTest001
 * @tc.desc: test P2pShareLinkRemoveGroup when success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pShareLinkRemoveGroupTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pDestroyGroupParam param;
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pShareLinkRemoveGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pShareLinkRemoveGroupTest002
 * @tc.desc: test P2pShareLinkRemoveGroup when fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pShareLinkRemoveGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pDestroyGroupParam param;
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::P2pShareLinkRemoveGroup(param);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DestroyGroupTest001
 * @tc.desc: test DestroyGroup with INVALID role
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, DestroyGroupTest001, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::INVALID);
        return SOFTBUS_OK;
    });
    P2pDestroyGroupParam param;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_EQ(ret, SOFTBUS_CONN_UNKNOWN_ROLE);
}

/*
 * @tc.name: DestroyGroupTest002
 * @tc.desc: test DestroyGroup with GO role success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, DestroyGroupTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, RemoveGroup).WillOnce(Return(WIFI_SUCCESS));
    P2pDestroyGroupParam param;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DestroyGroupTest003
 * @tc.desc: test DestroyGroup with GC role success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, DestroyGroupTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GC);
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, Hid2dRemoveGcGroup(_)).WillOnce(Return(WIFI_SUCCESS));
    P2pDestroyGroupParam param;
    param.interface = IF_NAME_P2P;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::INVALID);
        return SOFTBUS_OK;
    });
}

/*
 * @tc.name: DestroyGroupRemoveGroupFailTest
 * @tc.desc: test DestroyGroup with GO role and RemoveGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, DestroyGroupRemoveGroupFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GO);
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, RemoveGroup).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    P2pDestroyGroupParam param;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DestroyGroupRemoveGcGroupFailTest
 * @tc.desc: test DestroyGroup with GC role and Hid2dRemoveGcGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, DestroyGroupRemoveGcGroupFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P, [](InterfaceInfo &info) {
        info.SetRole(LinkInfo::LinkMode::GC);
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, Hid2dRemoveGcGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    P2pDestroyGroupParam param;
    param.interface = IF_NAME_P2P;
    int32_t ret = P2pAdapter::DestroyGroup(param);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetChannel5GListIntArrayTest
 * @tc.desc: test GetChannel5GListIntArray success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetChannel5GListIntArrayTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::vector<int> channels;
    int32_t array[] = { WIFI_5G_CHANNEL_34, WIFI_5G_CHANNEL_34 + WIFI_5G_CHANNEL_ARRAY_SIZE,
        WIFI_5G_CHANNEL_34 + WIFI_5G_CHANNEL_ARRAY_SIZE + 1, 0 };

    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce([&array](int32_t *chanList, int32_t len) {
        for (int i = 0; i < TEST_CHANNEL_ARRAY_SIZE && i < len; i++) {
            chanList[i] = array[i];
        }
        return WIFI_SUCCESS;
    });
    int32_t ret = P2pAdapter::GetChannel5GListIntArray(channels);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(channels.size(), WIFI_5G_CHANNEL_ARRAY_SIZE);
}

/*
 * @tc.name: GetChannel5GListIntArrayFailTest
 * @tc.desc: test GetChannel5GListIntArray when Hid2dGetChannelListFor5G fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetChannel5GListIntArrayFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::vector<int> channels;
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetChannel5GListIntArray(channels);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetStationFrequencyWithFilterTest001
 * @tc.desc: test GetStationFrequencyWithFilter with 5G and channel list fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyWithFilterTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = WIFI_5G_FREQ_5170;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: GetStationFrequencyWithFilterTest002
 * @tc.desc: test GetStationFrequencyWithFilter with 5G and channel in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyWithFilterTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = WIFI_5G_FREQ_5170;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t chanArray[] = { WIFI_5G_CHANNEL_34, 0 };
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce([&chanArray](int32_t *chanList, int32_t len) {
        if (len >= TEST_CHANNEL_ARRAY_SIZE) {
            chanList[0] = chanArray[0];
            chanList[1] = chanArray[1];
        }
        return WIFI_SUCCESS;
    });
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, info.frequency);
}

/*
 * @tc.name: GetStationFrequencyWithFilterTest003
 * @tc.desc: test GetStationFrequencyWithFilter with 5G and channel not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyWithFilterTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = WIFI_5G_FREQ_5170;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, FREQUENCY_INVALID);
}

/*
 * @tc.name: GetStationFrequencyWithFilterTest004
 * @tc.desc: test GetStationFrequencyWithFilter with 2G band
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyWithFilterTest004, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = WIFI_2G_FREQ_2412;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, info.frequency);
}

/*
 * @tc.name: GetStationFrequencyWithFilterTest005
 * @tc.desc: test GetStationFrequencyWithFilter with frequency not in any band
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetStationFrequencyWithFilterTest005, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiLinkedInfo info;
    info.frequency = WIFI_FREQ_NOT_IN_BAND;
    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t result = P2pAdapter::GetStationFrequencyWithFilter();
    EXPECT_EQ(result, FREQUENCY_INVALID);
}

/*
 * @tc.name: GetRecommendChannelTest001
 * @tc.desc: test GetRecommendChannel when Hid2dGetRecommendChannel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetRecommendChannelTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: GetRecommendChannelTest002
 * @tc.desc: test GetRecommendChannel with both centerFreq and centerFreq1 zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetRecommendChannelTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_EQ(ret, CHANNEL_INVALID);
}

/*
 * @tc.name: GetRecommendChannelWithCenterFreqTest
 * @tc.desc: test GetRecommendChannel with valid centerFreq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetRecommendChannelWithCenterFreqTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    RecommendChannelResponse response;
    response.centerFreq = WIFI_5G_FREQ_5180;
    response.centerFreq1 = 0;

    EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _)).WillOnce(DoAll(SetArgPointee<1>(response), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: GetRecommendChannelWithCenterFreq1Test
 * @tc.desc: test GetRecommendChannel with centerFreq1 when centerFreq is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetRecommendChannelWithCenterFreq1Test, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    RecommendChannelResponse response;
    response.centerFreq = 0;
    response.centerFreq1 = WIFI_5G_FREQ_5180;

    EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _)).WillOnce(DoAll(SetArgPointee<1>(response), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetRecommendChannel();
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: GetSelfWifiConfigInfoTest001
 * @tc.desc: test GetSelfWifiConfigInfo with empty config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetSelfWifiConfigInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config;
    int32_t wifiConfigSize = WIFI_CONFIG_SIZE_ZERO;
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(wifiConfigSize), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetSelfWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetSelfWifiConfigInfoTest002
 * @tc.desc: test GetSelfWifiConfigInfo with non-empty config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetSelfWifiConfigInfoTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config;
    int32_t wifiConfigSize = WIFI_CONFIG_SIZE_NON_ZERO;
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(wifiConfigSize), Return(WIFI_SUCCESS)));
    EXPECT_CALL(mock, SoftBusBase64Encode(_, _, _, _, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::GetSelfWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetSelfWifiConfigInfoFailTest
 * @tc.desc: test GetSelfWifiConfigInfo when Hid2dGetSelfWifiCfgInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetSelfWifiConfigInfoFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config;
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo(_, _, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetSelfWifiConfigInfo(config);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetPeerWifiConfigInfoTest001
 * @tc.desc: test SetPeerWifiConfigInfo when decode fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetPeerWifiConfigInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config = "test_config_data";
    EXPECT_CALL(mock, SoftBusBase64Decode(_, _, _, _, _)).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = P2pAdapter::SetPeerWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SetPeerWifiConfigInfoTest002
 * @tc.desc: test SetPeerWifiConfigInfo when success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetPeerWifiConfigInfoTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config = "test_config_data";
    EXPECT_CALL(mock, SoftBusBase64Decode(_, _, _, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, Hid2dSetPeerWifiCfgInfo(_, _, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::SetPeerWifiConfigInfo(config);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetPeerWifiConfigInfoSetFailTest
 * @tc.desc: test SetPeerWifiConfigInfo when Hid2dSetPeerWifiCfgInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetPeerWifiConfigInfoSetFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string config = "test_config_data";
    EXPECT_CALL(mock, SoftBusBase64Decode(_, _, _, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, Hid2dSetPeerWifiCfgInfo(_, _, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::SetPeerWifiConfigInfo(config);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetPeerWifiConfigInfoV2Test
 * @tc.desc: test SetPeerWifiConfigInfoV2 always returns fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetPeerWifiConfigInfoV2Test, TestSize.Level1)
{
    const uint8_t cfg[TEST_CONFIG_DATA_SIZE] = { 0 };
    int32_t ret = P2pAdapter::SetPeerWifiConfigInfoV2(cfg, sizeof(cfg));
    EXPECT_EQ(ret, SOFTBUS_CONN_SET_PEER_WIFI_CONFIG_FAIL);
}

/*
 * @tc.name: IsWideBandSupportedTest
 * @tc.desc: test IsWideBandSupported returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, IsWideBandSupportedTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dIsWideBandwidthSupported).WillOnce(Return(true));
    bool result = P2pAdapter::IsWideBandSupported();
    EXPECT_TRUE(result);
}

/*
 * @tc.name: GetGroupInfoTest001
 * @tc.desc: test GetGroupInfo success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetGroupInfoTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo info { };
    P2pAdapter::WifiDirectP2pGroupInfo groupInfoOut { };
    info.clientDevicesSize = 1;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetGroupInfo(groupInfoOut);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetGroupInfoFailTest
 * @tc.desc: test GetGroupInfo when GetCurrentGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetGroupInfoFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    P2pAdapter::WifiDirectP2pGroupInfo groupInfoOut;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetGroupInfo(groupInfoOut);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetGroupConfigTest001
 * @tc.desc: test GetGroupConfig when GetCurrentGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetGroupConfigTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string groupConfigString;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetGroupConfig(groupConfigString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(static_cast<int32_t>(ERROR_WIFI_UNKNOWN)));
}

/*
 * @tc.name: GetGroupConfigTest002
 * @tc.desc: test GetGroupConfig success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetGroupConfigTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo info { };
    std::string groupConfigString;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetGroupConfig(groupConfigString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetIpAddressTest001
 * @tc.desc: test GetIpAddress when GetCurrentGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetIpAddressTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string ipString;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetIpAddress(ipString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(static_cast<int32_t>(ERROR_WIFI_UNKNOWN)));
}

/*
 * @tc.name: GetDynamicMacAddressTest001
 * @tc.desc: test GetDynamicMacAddress when GetCurrentGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetDynamicMacAddressTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetDynamicMacAddress(macString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: GetDynamicMacAddressTest002
 * @tc.desc: test GetDynamicMacAddress success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetDynamicMacAddressTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString;
    WifiP2pGroupInfo info;
    if (strcpy_s(info.interface, sizeof(info.interface), "wlan0") != EOK) {
        return;
    }
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(DoAll(SetArgPointee<0>(info), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetDynamicMacAddress(macString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RequestGcIpTest001
 * @tc.desc: test RequestGcIp with empty mac string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, RequestGcIpTest001, TestSize.Level1)
{
    std::string macString = "";
    std::string ipString;
    int32_t ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RequestGcIpTest002
 * @tc.desc: test RequestGcIp when Hid2dRequestGcIp fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, RequestGcIpTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString = "11:22:33:44:55:66";
    std::string ipString;
    EXPECT_CALL(mock, Hid2dRequestGcIp(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: RequestGcIpTest003
 * @tc.desc: test RequestGcIp success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, RequestGcIpTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string macString = "11:22:33:44:55:66";
    std::string ipString;
    EXPECT_CALL(mock, Hid2dRequestGcIp(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::RequestGcIp(macString, ipString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pConfigGcIpTest001
 * @tc.desc: test P2pConfigGcIp with valid IP and success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConfigGcIpTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string interface = IF_NAME_P2P;
    std::string ipString = "255.255.255.0";
    EXPECT_CALL(mock, Hid2dConfigIPAddr(_, _)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::P2pConfigGcIp(interface, ipString);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: P2pConfigGcIpTest002
 * @tc.desc: test P2pConfigGcIp with invalid IP format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConfigGcIpTest002, TestSize.Level1)
{
    std::string interface = IF_NAME_P2P;
    std::string ipString = "255.255.255";
    int32_t ret = P2pAdapter::P2pConfigGcIp(interface, ipString);
    EXPECT_EQ(ret, SOFTBUS_CONN_SCAN_IP_NUMBER_FAILED);
}

/*
 * @tc.name: P2pConfigGcIpConvertGatewayFailTest
 * @tc.desc: test P2pConfigGcIp when Hid2dConfigIPAddr fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, P2pConfigGcIpConvertGatewayFailTest, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    std::string interface = IF_NAME_P2P;
    std::string ipString = "192.168.1.1";
    EXPECT_CALL(mock, Hid2dConfigIPAddr(_, _)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::P2pConfigGcIp(interface, ipString);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetApChannelTest001
 * @tc.desc: test GetApChannel when hotspot is not active
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetApChannelTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, IsHotspotActive).WillOnce(Return(WIFI_HOTSPOT_NOT_ACTIVE));
    int ret = P2pAdapter::GetApChannel();
    EXPECT_EQ(ret, CHANNEL_INVALID);
}

/*
 * @tc.name: GetApChannelTest002
 * @tc.desc: test GetApChannel when hotspot active but GetHotspotConfig fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetApChannelTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, IsHotspotActive).WillOnce(Return(WIFI_HOTSPOT_ACTIVE));
    EXPECT_CALL(mock, GetHotspotConfig(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int ret = P2pAdapter::GetApChannel();
    EXPECT_EQ(ret, CHANNEL_INVALID);
}

/*
 * @tc.name: GetApChannelTest003
 * @tc.desc: test GetApChannel when hotspot active and GetHotspotConfig success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetApChannelTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    HotspotConfig hotspotConfig;
    hotspotConfig.channelNum = WIFI_AP_CHANNEL_6;
    EXPECT_CALL(mock, IsHotspotActive).WillOnce(Return(WIFI_HOTSPOT_ACTIVE));
    EXPECT_CALL(mock, GetHotspotConfig(_)).WillOnce(DoAll(SetArgPointee<0>(hotspotConfig), Return(WIFI_SUCCESS)));
    int ret = P2pAdapter::GetApChannel();
    EXPECT_EQ(ret, WIFI_AP_CHANNEL_6);
}

/*
 * @tc.name: GetP2pGroupFrequencyTest001
 * @tc.desc: test GetP2pGroupFrequency when GetCurrentGroup fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetP2pGroupFrequencyTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::GetP2pGroupFrequency();
    EXPECT_EQ(ret, ToSoftBusErrorCode(ERROR_WIFI_UNKNOWN));
}

/*
 * @tc.name: GetP2pGroupFrequencyTest002
 * @tc.desc: test GetP2pGroupFrequency success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetP2pGroupFrequencyTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    WifiP2pGroupInfo groupInfo;
    groupInfo.frequency = WIFI_5G_FREQ_5180;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillOnce(DoAll(SetArgPointee<0>(groupInfo), Return(WIFI_SUCCESS)));
    int32_t ret = P2pAdapter::GetP2pGroupFrequency();
    EXPECT_EQ(ret, WIFI_5G_FREQ_5180);
}

/*
 * @tc.name: GetCoexConflictCodeTest001
 * @tc.desc: test GetCoexConflictCode with invalid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetCoexConflictCodeTest001, TestSize.Level1)
{
    int ret = P2pAdapter::GetCoexConflictCode("wlan0", CHANNEL_INVALID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetCoexConflictCodeTest002
 * @tc.desc: test GetCoexConflictCode with registered hook and valid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetCoexConflictCodeTest002, TestSize.Level1)
{
    P2pAdapter::GetInstance().Register([](const char *, int32_t) {
        return EXPECTED_COEX_CONFLICT_CODE;
    });
    int ret = P2pAdapter::GetCoexConflictCode("wlan0", WIFI_AP_CHANNEL_6);
    EXPECT_EQ(ret, EXPECTED_COEX_CONFLICT_CODE);
}

/*
 * @tc.name: GetCoexConflictCodeTest003
 * @tc.desc: test GetCoexConflictCode without registered hook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, GetCoexConflictCodeTest003, TestSize.Level1)
{
    P2pAdapter::GetInstance().Register(nullptr);
    int ret = P2pAdapter::GetCoexConflictCode("wlan0", WIFI_AP_CHANNEL_6);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetP2pGroupLiveTypeTest001
 * @tc.desc: test SetP2pGroupLiveType with stop alive success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetP2pGroupLiveTypeTest001, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSetGroupType(_)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::SetP2pGroupLiveType(P2pAdapter::P2P_GROUP_STOP_ALIVE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetP2pGroupLiveTypeTest002
 * @tc.desc: test SetP2pGroupLiveType with keep alive success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetP2pGroupLiveTypeTest002, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSetGroupType(_)).WillOnce(Return(WIFI_SUCCESS));
    int32_t ret = P2pAdapter::SetP2pGroupLiveType(P2pAdapter::P2P_GROUP_KEEP_ALIVE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetP2pGroupLiveTypeTest003
 * @tc.desc: test SetP2pGroupLiveType when Hid2dSetGroupType fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, SetP2pGroupLiveTypeTest003, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, Hid2dSetGroupType(_)).WillOnce(Return(ERROR_WIFI_UNKNOWN));
    int32_t ret = P2pAdapter::SetP2pGroupLiveType(P2pAdapter::P2P_GROUP_STOP_ALIVE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: FastWakeUpTest001
 * @tc.desc: test FastWakeUp without registered hook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, FastWakeUpTest001, TestSize.Level1)
{
    P2pAdapter::GetInstance().RegisterFastWakeUp(nullptr);
    int32_t ret = P2pAdapter::FastWakeUp("11:22:33:44:55:66", 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/*
 * @tc.name: FastWakeUpTest002
 * @tc.desc: test FastWakeUp with registered hook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pAdapterAiTest, FastWakeUpTest002, TestSize.Level1)
{
    P2pAdapter::GetInstance().RegisterFastWakeUp([](const std::string &, int32_t) {
        return SOFTBUS_OK;
    });
    int32_t ret = P2pAdapter::FastWakeUp("11:22:33:44:55:66", 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS::SoftBus
