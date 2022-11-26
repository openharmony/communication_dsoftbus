/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>


#include "bus_center_info_key.h"
#include "lnn_lane.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_wifi_adpter_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr uint32_t WLAN_2PG_BAND = 1;
constexpr uint32_t WLAN_5G_BAND = 0;
constexpr uint32_t WLAN_2PG_FREQUENCY = 2642;
constexpr uint32_t WLAN_5G_FREQUENCY = 5188;


using namespace testing;
class LNNLaneTestMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneTestMock::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneTestMock start";
}

void LNNLaneTestMock::TearDownTestCase()
{
    DeinitLane();
    LooperDeinit();
    GTEST_LOG_(INFO) << "LNNLaneTestMock end";
}

void LNNLaneTestMock::SetUp()
{
}

void LNNLaneTestMock::TearDown()
{
}

static void OnLaneRequestSuccess(uint32_t laneId, const LaneConnInfo *info)
{
    printf("LaneRequestSucc: laneId:0x%x, linkType:%d\n", laneId, info->type);
    int32_t ret = LnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneRequestFail(uint32_t laneId, LaneRequestFailReason reason)
{
    printf("LaneRequestFail: laneId:0x%x, reason:%d\n", laneId, reason);
    int32_t ret = LnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneStateChange(uint32_t laneId, LaneState state)
{
    printf("LaneStateChange: laneId:0x%x, state:%d\n", laneId, state);
    int32_t ret = LnnFreeLane(laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

// wlan 2.4G
HWTEST_F(LNNLaneTestMock, LANE_REQUEST_Test_001, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId = ApplyLaneId(laneType);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);

    LaneDepsInterfaceMock mock;
    mock.SetDefaultResult();
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));

    auto linkedInfo = [](LnnWlanLinkedInfo *info) {
        info->band = WLAN_2PG_BAND;
        info->frequency = WLAN_2PG_FREQUENCY;
        info->isConnected = true;};
    EXPECT_CALL(mock, LnnGetWlanLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(linkedInfo), Return(SOFTBUS_OK)));
    
    auto setLinkedInfo = [](SoftBusWifiLinkedInfo *info) {
        info->band = WLAN_2PG_BAND;
        info->frequency = WLAN_2PG_FREQUENCY;
        info->connState = SOFTBUS_API_WIFI_CONNECTED;};

    LnnWifiAdpterInterfaceMock wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(setLinkedInfo), Return(SOFTBUS_OK)));

    ILaneListener listener = {
        .OnLaneRequestSuccess = OnLaneRequestSuccess,
        .OnLaneRequestFail = OnLaneRequestFail,
        .OnLaneStateChange = OnLaneStateChange,
    };
    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    requestOption.type = laneType;
    (void)strncpy_s(requestOption.requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    requestOption.requestInfo.trans.transType = LANE_T_FILE;
    requestOption.requestInfo.trans.expectedBw = 0;
    int32_t ret = LnnRequestLane(laneId, &requestOption, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

// wlan 5G byte
HWTEST_F(LNNLaneTestMock, LANE_REQUEST_Test_002, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId = ApplyLaneId(laneType);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);

    LaneDepsInterfaceMock mock;
    mock.SetDefaultResult();
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));

    auto linkedInfo = [](LnnWlanLinkedInfo *info) {
        info->band = WLAN_5G_BAND;
        info->frequency = WLAN_5G_FREQUENCY;
        info->isConnected = true;};
    EXPECT_CALL(mock, LnnGetWlanLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(linkedInfo), Return(SOFTBUS_OK)));
    
    auto setLinkedInfo = [](SoftBusWifiLinkedInfo *info) {
        info->band = WLAN_5G_BAND;
        info->frequency = WLAN_5G_FREQUENCY;
        info->connState = SOFTBUS_API_WIFI_CONNECTED;};

    LnnWifiAdpterInterfaceMock wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(setLinkedInfo), Return(SOFTBUS_OK)));

    ILaneListener listener = {
        .OnLaneRequestSuccess = OnLaneRequestSuccess,
        .OnLaneRequestFail = OnLaneRequestFail,
        .OnLaneStateChange = OnLaneStateChange,
    };
    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    requestOption.type = laneType;
    (void)strncpy_s(requestOption.requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    requestOption.requestInfo.trans.transType = LANE_T_BYTE;
    requestOption.requestInfo.trans.expectedBw = 0;
    int32_t ret = LnnRequestLane(laneId, &requestOption, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(500);
}

// P2P MSG
HWTEST_F(LNNLaneTestMock, LANE_REQUEST_Test_003, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId = ApplyLaneId(laneType);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);

    LaneDepsInterfaceMock mock;
    mock.SetDefaultResult();
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumInfo(NUM_KEY_NET_CAP, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(62), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, NUM_KEY_NET_CAP, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(62), Return(SOFTBUS_OK)));

    ILaneListener listener = {
        .OnLaneRequestSuccess = OnLaneRequestSuccess,
        .OnLaneRequestFail = OnLaneRequestFail,
        .OnLaneStateChange = OnLaneStateChange,
    };
    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    requestOption.type = laneType;
    (void)strncpy_s(requestOption.requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    requestOption.requestInfo.trans.transType = LANE_T_MSG;
    requestOption.requestInfo.trans.expectedBw = 0;
    requestOption.requestInfo.trans.expectedLink.linkTypeNum = 1;
    requestOption.requestInfo.trans.expectedLink.linkType[0] = LANE_P2P;
    int32_t ret = LnnRequestLane(laneId, &requestOption, &listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusSleepMs(500);
}

// WLAN 5G RAW-STREAM
HWTEST_F(LNNLaneTestMock, LANE_REQUEST_Test_004, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneId = ApplyLaneId(laneType);
    EXPECT_TRUE(laneId != INVALID_LANE_ID);

    LaneDepsInterfaceMock mock;
    mock.SetDefaultResult();
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    
    auto linkedInfo = [](LnnWlanLinkedInfo *info) {
        info->band = WLAN_5G_BAND;
        info->frequency = WLAN_5G_FREQUENCY;
        info->isConnected = true;};
    EXPECT_CALL(mock, LnnGetWlanLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(linkedInfo), Return(SOFTBUS_OK)));
    
    auto setLinkedInfo = [](SoftBusWifiLinkedInfo *info) {
        info->band = WLAN_5G_BAND;
        info->frequency = WLAN_5G_FREQUENCY;
        info->connState = SOFTBUS_API_WIFI_CONNECTED;};

    LnnWifiAdpterInterfaceMock wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(WithArg<0>(setLinkedInfo), Return(SOFTBUS_OK)));

    ILaneListener listener = {
        .OnLaneRequestSuccess = OnLaneRequestSuccess,
        .OnLaneRequestFail = OnLaneRequestFail,
        .OnLaneStateChange = OnLaneStateChange,
    };
    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    requestOption.type = laneType;
    (void)strncpy_s(requestOption.requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    requestOption.requestInfo.trans.transType = LANE_T_RAW_STREAM;
    requestOption.requestInfo.trans.expectedBw = 0;
    requestOption.requestInfo.trans.expectedLink.linkTypeNum = 1;
    requestOption.requestInfo.trans.expectedLink.linkType[0] = LANE_WLAN_5G;
    int32_t ret = LnnRequestLane(laneId, &requestOption, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(500);
}
} // namespace OHOS
