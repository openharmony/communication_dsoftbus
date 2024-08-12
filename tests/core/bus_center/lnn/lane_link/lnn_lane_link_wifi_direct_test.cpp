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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_link_wifi_direct.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr uint64_t DEFAULT_LINK_LATENCY = 30000;

int32_t g_laneLinkResult = SOFTBUS_INVALID_PARAM;
int32_t g_connectDeviceTimes = 0;
bool g_isNeedNegotiateChannel = false;

class LNNLaneLinkWifiDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkWifiDirectTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkWifiDirectTest start";
    int32_t ret = LnnInitLnnLooper();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitLinkWifiDirect();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNLaneLinkWifiDirectTest::TearDownTestCase()
{
    DeInitLinkWifiDirect();
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNLaneLinkWifiDirectTest end";
}

void LNNLaneLinkWifiDirectTest::SetUp()
{
}

void LNNLaneLinkWifiDirectTest::TearDown()
{
}

static void OnLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
    g_laneLinkResult = SOFTBUS_OK;
    return;
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)reason;
    (void)linkType;
    g_laneLinkResult = SOFTBUS_LANE_BUILD_LINK_FAIL;
    return;
}

static LaneLinkCb g_linkCb = {
    .onLaneLinkSuccess = OnLaneLinkSuccess,
    .onLaneLinkFail = OnLaneLinkFail,
};

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    return g_isNeedNegotiateChannel;
}

static uint32_t GetRequestId(void)
{
    return 1;
}

static int32_t ConnectDeviceForForceDown(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ConnectDeviceForForceDown enter";
    (void)info;
    g_connectDeviceTimes++;
    if (g_connectDeviceTimes >  1) {
        struct WifiDirectLink link = {
            .linkId = 1,
            .linkType = WIFI_DIRECT_LINK_TYPE_P2P,
        };
        callback->onConnectSuccess(info->requestId, &link);
    } else {
        callback->onConnectFailure(info->requestId, SOFTBUS_INVALID_PARAM);
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceSuccess(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ConnectDeviceSuccess enter";
    (void)info;
    struct WifiDirectLink link = {
        .linkId = 1,
        .linkType = WIFI_DIRECT_LINK_TYPE_P2P,
    };
    callback->onConnectSuccess(info->requestId, &link);
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceFail(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ConnectDeviceFail enter";
    (void)info;
    callback->onConnectFailure(info->requestId, SOFTBUS_INVALID_PARAM);
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_OK;
}

static int32_t ForceDisconnectDeviceSucc(struct WifiDirectForceDisconnectInfo *info,
    struct WifiDirectDisconnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ForceDisconnectDeviceSucc enter";
    callback->onDisconnectSuccess(info->requestId);
    return SOFTBUS_OK;
}

static int32_t ForceDisconnectDeviceFail(struct WifiDirectForceDisconnectInfo *info,
    struct WifiDirectDisconnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ForceDisconnectDeviceFail enter";
    callback->onDisconnectFailure(info->requestId, SOFTBUS_INVALID_PARAM);
    return SOFTBUS_OK;
}

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDeviceForForceDown,
    .disconnectDevice = DisconnectDevice,
    .forceDisconnectDevice = ForceDisconnectDeviceSucc,
};

/*
* @tc.name: HandleWifiDirectConflict_001
* @tc.desc: test HandleWifiDirectConflict
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, HandleWifiDirectConflict_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 21;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_THREE_VAP));
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    g_connectDeviceTimes = 0;
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: WifiDirectForceDown_001
* @tc.desc: test WifiDirectForceDownWithoutAuth success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, WifiDirectForceDown_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 22;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_THREE_VAP));
    LinkConflictInfo conflictItem = {};
    conflictItem.devIdCnt = 1;
    char (*devId)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    EXPECT_NE(devId, nullptr);
    EXPECT_EQ(memcpy_s(devId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN), EOK);
    conflictItem.devIdList = devId;
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(conflictItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, RemoveConflictInfoTimelinessMsg).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, DelLinkConflictInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    g_connectDeviceTimes = 0;

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: WifiDirectForceDown_002
* @tc.desc: test WifiDirectForceDownWithoutAuth fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, WifiDirectForceDown_002, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 23;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.forceDisconnectDevice = ForceDisconnectDeviceFail;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_ROLE));
    LinkConflictInfo conflictItem = {};
    conflictItem.devIdCnt = 1;
    char (*devId)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    EXPECT_NE(devId, nullptr);
    EXPECT_EQ(memcpy_s(devId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN), EOK);
    conflictItem.devIdList = devId;
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(conflictItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, RemoveConflictInfoTimelinessMsg).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, DelLinkConflictInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    g_connectDeviceTimes = 0;

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.forceDisconnectDevice = ForceDisconnectDeviceSucc;
}

/*
* @tc.name: WifiDirectForceDown_003
* @tc.desc: test WifiDirectForceDownWithoutAuth success & reconnect fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, WifiDirectForceDown_003, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 23;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.forceDisconnectDevice = ForceDisconnectDeviceFail;
    g_manager.connectDevice = ConnectDeviceFail;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_ROLE));
    LinkConflictInfo conflictItem = {};
    conflictItem.devIdCnt = 1;
    char (*devId)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    EXPECT_NE(devId, nullptr);
    EXPECT_EQ(memcpy_s(devId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN), EOK);
    conflictItem.devIdList = devId;
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(conflictItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, RemoveConflictInfoTimelinessMsg).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, DelLinkConflictInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    g_connectDeviceTimes = 0;

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.forceDisconnectDevice = ForceDisconnectDeviceSucc;
    g_manager.connectDevice = ConnectDeviceForForceDown;
}

/*
* @tc.name: WifiDirectForceDown_004
* @tc.desc: test WifiDirectForceDownWithAuth success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, WifiDirectForceDown_004, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 24;
    uint32_t authRequestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_LINK_NUM_LIMITED));
    LinkConflictInfo conflictItem = {};
    conflictItem.devIdCnt = 1;
    char (*devId)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    EXPECT_NE(devId, nullptr);
    EXPECT_EQ(memcpy_s(devId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN), EOK);
    conflictItem.devIdList = devId;
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(conflictItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, RemoveConflictInfoTimelinessMsg).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, DelLinkConflictInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthOpenConn(_, authRequestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(authRequestId));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    g_connectDeviceTimes = 0;
    g_isNeedNegotiateChannel = true;

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_isNeedNegotiateChannel = false;
}

/*
* @tc.name: WifiDirectForceDown_005
* @tc.desc: test WifiDirectForceDownWithAuth fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, WifiDirectForceDown_005, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 24;
    uint32_t authRequestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetConflictTypeWithErrcode).WillRepeatedly(Return(CONFLICT_LINK_NUM_LIMITED));
    LinkConflictInfo conflictItem = {};
    conflictItem.devIdCnt = 1;
    char (*devId)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    EXPECT_NE(devId, nullptr);
    EXPECT_EQ(memcpy_s(devId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, NETWORK_ID_BUF_LEN), EOK);
    conflictItem.devIdList = devId;
    EXPECT_CALL(laneLinkMock, FindLinkConflictInfoByDevId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(conflictItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneLinkMock, RemoveConflictInfoTimelinessMsg).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, DelLinkConflictInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthOpenConn(_, authRequestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(authRequestId));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    g_connectDeviceTimes = 0;
    g_isNeedNegotiateChannel = true;

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_isNeedNegotiateChannel = false;
}

/*
* @tc.name: RecycleP2pLinkedReq_001
* @tc.desc: test RecycleP2pLinkedReqByLinkType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkWifiDirectTest, RecycleP2pLinkedReq_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 123;
    uint32_t laneReqId = 25;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceSuccess;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    RecycleP2pLinkedReqByLinkType(NODE_NETWORK_ID, LANE_P2P);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDeviceForForceDown;
}
} // namespace OHOS
