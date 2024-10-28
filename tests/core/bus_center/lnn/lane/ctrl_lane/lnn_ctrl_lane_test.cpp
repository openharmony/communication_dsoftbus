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

#include <thread>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_ctrl_lane.h"
#include "lnn_ctrl_lane_deps_mock.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint64_t LANE_ID = 1122334455667788;
constexpr char NETWORK_ID[] = "123456789";
constexpr char UDID[] = "1122334455667788";
static int32_t g_errCode = SOFTBUS_LANE_ERR_BASE;

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    ASSERT_NE(info, nullptr) << "invalid info";
    g_errCode = SOFTBUS_OK;
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
    g_errCode = errCode;
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
}

static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "free lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
}

static LaneAllocListener g_listener = {
    .onLaneAllocSuccess = OnLaneAllocSuccess,
    .onLaneAllocFail = OnLaneAllocFail,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    return false;
}

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
};

class LNNCtrlLaneMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNCtrlLaneMockTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNCtrlLaneMockTest start";
    LnnInitLnnLooper();
}

void LNNCtrlLaneMockTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNCtrlLaneMockTest end";
}

void LNNCtrlLaneMockTest::SetUp()
{
}

void LNNCtrlLaneMockTest::TearDown()
{
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_001
* @tc.desc: ctrl alloclane -> test param check
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_001, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->deinit();
    ctrlObj->init(nullptr);
    ctrlObj->init(nullptr);

    uint32_t laneReqId = 1;
    int32_t ret = ctrlObj->allocLaneByQos(INVALID_LANE_REQ_ID, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ctrlObj->allocLaneByQos(laneReqId, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneAllocInfo info = {};
    info.type = LANE_TYPE_BUTT;
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_002
* @tc.desc: ctrl alloclane -> test ConvertAuthLinkToLaneLink(wifi/br/ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_002, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->init(nullptr);

    AuthLinkTypeList authList = {};
    authList.linkTypeNum = 1;
    authList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    EXPECT_CALL(ctrlMock, SelectAuthLane).WillRepeatedly(Return(SOFTBUS_LANE_NO_AVAILABLE_LINK));
    EXPECT_CALL(ctrlMock, FreeLaneReqId).WillRepeatedly(Return());
    uint32_t laneReqId = 1;
    LaneAllocInfo info = {};
    info.type = LANE_TYPE_CTRL;
    int32_t ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    authList.linkType[0] = AUTH_LINK_TYPE_BR;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList)
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    authList.linkType[0] = AUTH_LINK_TYPE_BLE;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList)
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_003
* @tc.desc: ctrl alloclane -> test ConvertAuthLinkToLaneLink(p2p/enhanced_p2p/max)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_003, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->init(nullptr);

    AuthLinkTypeList authList = {};
    authList.linkTypeNum = 1;
    authList.linkType[0] = AUTH_LINK_TYPE_P2P;
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    EXPECT_CALL(ctrlMock, SelectAuthLane).WillRepeatedly(Return(SOFTBUS_LANE_NO_AVAILABLE_LINK));
    EXPECT_CALL(ctrlMock, FreeLaneReqId).WillRepeatedly(Return());
    uint32_t laneReqId = 1;
    LaneAllocInfo info = {};
    info.type = LANE_TYPE_CTRL;
    int32_t ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    authList.linkType[0] = AUTH_LINK_TYPE_ENHANCED_P2P;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList)
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    authList.linkType[0] = AUTH_LINK_TYPE_MAX;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList)
        .WillOnce(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_004
* @tc.desc: ctrl alloclane -> test build fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_004, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->init(nullptr);

    AuthLinkTypeList authList = {};
    authList.linkTypeNum = 1;
    authList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList).WillRepeatedly(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    EXPECT_CALL(ctrlMock, SelectAuthLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, BuildLink).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(ctrlMock, FreeLaneReqId).WillRepeatedly(Return());
    uint32_t laneReqId = 1;
    LaneAllocInfo info = {};
    info.type = LANE_TYPE_CTRL;
    g_errCode = SOFTBUS_LANE_ERR_BASE;
    int32_t ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_errCode, SOFTBUS_INVALID_PARAM);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_005
* @tc.desc: ctrl alloclane -> test build success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_005, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->init(nullptr);

    AuthLinkTypeList authList = {};
    authList.linkTypeNum = 1;
    authList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList).WillRepeatedly(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    EXPECT_CALL(ctrlMock, SelectAuthLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, BuildLink(_, _, NotNull())).WillRepeatedly(ctrlMock.BuildLinkSuccess);
    EXPECT_CALL(ctrlMock, GenerateLaneId).WillOnce(Return(INVALID_LANE_ID)).WillRepeatedly(Return(LANE_ID));
    EXPECT_CALL(ctrlMock, FreeLaneReqId).WillRepeatedly(Return());
    EXPECT_CALL(ctrlMock, AddLaneResourceToPool).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, LaneInfoProcess).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t laneReqId = 1;
    LaneAllocInfo info = {};
    info.type = LANE_TYPE_CTRL;
    g_errCode = SOFTBUS_LANE_ERR_BASE;
    int32_t ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);

    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_ID_GENERATE_FAIL);

    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_INVALID_PARAM);

    g_errCode = SOFTBUS_LANE_ERR_BASE;
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_ERR_BASE);

    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_OK);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_ALLOC_LANE_006
* @tc.desc: ctrl alloclane -> test free
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_ALLOC_LANE_006, TestSize.Level1)
{
    LaneInterface *ctrlObj = CtrlLaneGetInstance();
    EXPECT_TRUE(ctrlObj != nullptr);
    ctrlObj->init(nullptr);

    AuthLinkTypeList authList = {};
    authList.linkTypeNum = 1;
    authList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, GetAuthLinkTypeList).WillRepeatedly(DoAll(SetArgPointee<1>(authList), Return(SOFTBUS_OK)));
    EXPECT_CALL(ctrlMock, SelectAuthLane).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, BuildLink(_, _, NotNull())).WillRepeatedly(ctrlMock.BuildLinkSuccess);
    EXPECT_CALL(ctrlMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID));
    EXPECT_CALL(ctrlMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ctrlMock, FreeLaneReqId).WillRepeatedly(Return());
    EXPECT_CALL(ctrlMock, LaneInfoProcess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetNetworkIdByUdid).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t laneReqId = 1;
    LaneAllocInfo info = {};
    info.type = LANE_TYPE_CTRL;
    g_errCode = SOFTBUS_LANE_ERR_BASE;
    int32_t ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_OK);
    ret = ctrlObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_errCode = SOFTBUS_LANE_ERR_BASE;
    ret = ctrlObj->allocLaneByQos(laneReqId, &info, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(g_errCode, SOFTBUS_OK);
    ret = ctrlObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ctrlObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ctrlObj->deinit();
}

/*
* @tc.name: LNN_CRTL_IS_AUTH_REUSE_P2P_001
* @tc.desc: test IsAuthReuseP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNCtrlLaneMockTest, LNN_CRTL_IS_AUTH_REUSE_P2P_001, TestSize.Level1)
{
    NiceMock<CtrlLaneDepsInterfaceMock> ctrlMock;
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(ctrlMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    bool ret = IsAuthReuseP2p(NETWORK_ID, UDID, AUTH_LINK_TYPE_ENHANCED_P2P);
    EXPECT_TRUE(ret);
    ret = IsAuthReuseP2p(NETWORK_ID, UDID, AUTH_LINK_TYPE_P2P);
    EXPECT_TRUE(ret);
    ret = IsAuthReuseP2p(NETWORK_ID, UDID, AUTH_LINK_TYPE_MAX);
    EXPECT_FALSE(ret);
}
} // namespace OHOS
