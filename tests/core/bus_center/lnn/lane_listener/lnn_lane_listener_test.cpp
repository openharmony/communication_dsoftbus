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

#include "lnn_lane_common.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "lnn_trans_lane.h"
#include "lnn_lane_listener.h"
#include "lnn_lane_listener.c"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

//constexpr char PEER_UUID[] = "111122223333abcdef";
//constexpr char PEER_IP[] = "127.0.0.1";
//constexpr char INVALID_PEER_IP[] = "127.0.0.2";
//constexpr char PEER_MAC[] = "de:4f";

static void OnLaneOnLine(LaneStatusInfo *laneStatusInfoOn);
static void OnLaneOffLine(LaneStatusInfo *laneStatusInfoOn);
static void OnLaneStateChange(LaneStatusInfoChange *laneStatusInfoChange);

static LaneStatusListener g_listener = {
    .onLaneOnLine = OnLaneOnLine,
    .onLaneOffLine = OnLaneOffLine,
    .onLaneStateChange = OnLaneStateChange,
};

class LNNLaneListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneListenerTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneListenerTest start";
    LnnInitLaneLooper();
}

void LNNLaneListenerTest::TearDownTestCase()
{
    LnnDeinitLaneLooper();
    GTEST_LOG_(INFO) << "LNNLaneListenerTest end";
}

void LNNLaneListenerTest::SetUp()
{
}

void LNNLaneListenerTest::TearDown()
{
}

static void OnLaneOnLine(LaneStatusInfo *laneStatusInfoOn)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneStatusInfoOn->laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneOffLine(LaneStatusInfo *laneStatusInfoOn)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneStatusInfoOn->laneId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

static void OnLaneStateChange(LaneStatusInfoChange *laneStatusInfoChange)
{
    return;
}
/*
* @tc.name: LNN_INIT_LANE_LISTENER_001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_INIT_LANE_LISTENER_001, TestSize.Level1)
{
    int32_t ret  = InitLaneListener();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_REGISTER_LISTENER_001
* @tc.desc: Register listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REGISTER_LISTENER_001, TestSize.Level1)
{
    LaneType type = LANE_TYPE_TRANS;
    int32_t ret = RegisterLaneListener(type, &g_listener);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnRegisterLaneListener(type);
    EXPECT_TRUE(ret == SOFTBUS_OK);   
}

/*
* @tc.name: LNN_LANE_ADD_LANE_TYPE_INFO_002
* @tc.desc: Register listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REGISTER_LISTENER_002, TestSize.Level1)
{
    // int32_t ret = AddLaneTypeInfoItem(NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM); 
}

/*
* @tc.name: LNN_LANE_REGISTER_LISTENER_003
* @tc.desc: Register listener 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REGISTER_LISTENER_003, TestSize.Level1)
{
    // LaneType type = LANE_TYPE_BUTT;
    // int32_t ret = RegisterLaneListener(type, &g_listener);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    // ret = UnRegisterLaneListener(type);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    
}

/*
* @tc.name: LNN_LANE_REGISTER_LISTENER_004
* @tc.desc: Register listener 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REGISTER_LISTENER_004, TestSize.Level1)
{
    // LaneType type = LANE_TYPE_TRANS;
    // int32_t ret = RegisterLaneListener(type, &g_listener);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
    // FindLaneListenerInfoByLaneType(type, NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    // ret = UnRegisterLaneListener(type);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_REGISTER_LISTENER_005
* @tc.desc: Register listener 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REGISTER_LISTENER_005, TestSize.Level1)
{
    // LaneType type = LANE_TYPE_TRANS;
    // int32_t ret = RegisterLaneListener(type, &g_listener);
    // EXPECT_TRUE(ret == SOFTBUS_OK);

    // LaneListenerInfo outLaneListener;
    // ret = FindLaneListenerInfoByLaneType(type, &outLaneListener);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
    // ret = UnRegisterLaneListener(type);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
    
}

/*
* @tc.name: LNN_LANE_CREATE_LANE_TYPE_INFO_001
* @tc.desc: Register listener 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_CREATE_LANE_TYPE_INFO_001, TestSize.Level1)
{
    // const char *ipAddr = "127.0.0.1";
    // LaneLinkInfo linkInfo;
    // LaneTypeInfo laneTypeInfo;
    // if (strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, ipAddr) != EOK) {
    //     return;
    // }
    // const LnnLaneManager *laneManager = GetLaneManager();
    // LaneType laneType = LANE_TYPE_TRANS;
    // uint32_t laneId = laneManager->applyLaneReqId(laneType);

    // int32_t ret = CreateLaneTypeInfoByLaneReqId(laneId, &linkInfo);
    // EXPECT_TRUE(ret == SOFTBUS_OK);

    // ret = FindLaneTypeInfoByPeerIp(linkInfo.linkInfo.p2p.connInfo.peerIp, &laneTypeInfo);
    // EXPECT_TRUE(ret == SOFTBUS_ERR);

    // ret = DelLaneTypeInfoItem(linkInfo.linkInfo.p2p.connInfo.peerIp);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
    // ret = laneManager->lnnFreeLane(laneId);
    // EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_CREATE_LANE_TYPE_INFO_002
* @tc.desc: Register listener 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_CREATE_LANE_TYPE_INFO_002, TestSize.Level1)
{
    // LaneLinkInfo linkInfo;
    // if (strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP) != EOK) {
    //     return;
    // }
    // int32_t ret = CreateLaneTypeInfoByLaneReqId(INVALID_LANE_REQ_ID, &linkInfo);
    // EXPECT_TRUE(ret == SOFTBUS_ERR);
    // ret = FindLaneTypeInfoByPeerIp(linkInfo.linkInfo.p2p.connInfo.peerIp, NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    // ret = DelLaneTypeInfoItem(NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_CREATE_LANE_TYPE_INFO_003
* @tc.desc: Create LaneTypeInfo 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_CREATE_LANE_TYPE_INFO_003, TestSize.Level1)
{
    // NiceMock<LaneDepsInterfaceMock> mock;
    // LaneLinkInfo linkInfo;
    // if (strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP) != EOK) {
    //     return;
    // }
    // EXPECT_CALL(mock, ParseLaneTypeByLaneReqId)
    //     .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_ERR)));
    // int32_t ret = CreateLaneTypeInfoByLaneReqId(INVALID_LANE_REQ_ID, &linkInfo);
    // EXPECT_TRUE(ret == SOFTBUS_ERR);
    // ret = FindLaneTypeInfoByPeerIp(linkInfo.linkInfo.p2p.connInfo.peerIp, NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    // ret = DelLaneTypeInfoItem(NULL);
    // EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_GET_LANE_RESOURCE_001
* @tc.desc: Get LaneResource 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_GET_LANE_RESOURCE_001, TestSize.Level1)
{
    // int32_t ret = GetLaneResourceByPeerIp(NULL, NULL);
    // EXPECT_EQ(SOFTBUS_ERR, ret);
    // LaneLinkDepsInterfaceMock laneLinkMock;
    // EXPECT_CALL(laneLinkMock, FindLaneResourceByPeerIp).WillOnce(Return(SOFTBUS_ERR));
    // LaneResource *inputResource;
    // inputResource->type = LANE_P2P;
    // inputResource->linkInfo.p2p.connInfo.peerIp = PEER_IP;
    // AddLaneResourceItem(inputResource);
    // ret = GetLaneResourceByPeerIp(PEER_IP, inputResource);
    // EXPECT_EQ(SOFTBUS_ERR, ret);
    // EXPECT_CALL(laneLinkMock, FindLaneResourceByPeerIp).WillRepeatedly(Return(SOFTBUS_OK));
    // ret = GetLaneResourceByPeerIp(PEER_IP, inputResource);
    // EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_ON_WIFI_DIRECT_DEVICE_ON_LINE_NOTIFY_001
* @tc.desc: LnnOnWifiDirectDeviceOnLineNotify 
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_ON_WIFI_DIRECT_DEVICE_ON_LINE_NOTIFY_001, TestSize.Level1)
{
    // int32_t ret = LnnOnWifiDirectDeviceOnLineNotify(NULL, NULL);
    // EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    // ret = LnnOnWifiDirectDeviceOnLineNotify(INVALID_PEER_IP, LANE_P2P);
    // EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_ON_WIFI_DIRECT_DEVICE_ON_OFFLINE_001
* @tc.desc: LnnOnWifiDirectDeviceOffLine
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_ON_WIFI_DIRECT_DEVICE_ON_OFFLINE_001, TestSize.Level1)
{
    // LnnOnWifiDirectDeviceOffLine(NULL, NULL, NULL);
    // LaneLinkDepsInterfaceMock laneLinkMock;
    // EXPECT_CALL(laneLinkMock, FindLaneResourceByPeerIp).WillOnce(Return(SOFTBUS_ERR));
    // LnnOnWifiDirectDeviceOffLine(PEER_MAC, PEER_IP, PEER_UUID);
    // EXPECT_CALL(laneLinkMock, FindLaneResourceByPeerIp).WillRepeatedly(Return(SOFTBUS_OK));
    // LnnOnWifiDirectDeviceOffLine(PEER_MAC, PEER_IP, PEER_UUID);
    // LaneTypeInfo inputLaneTypeInfo;
    // inputLaneTypeInfo.laneType = LANE_TYPE_TRANS;
    // inputLaneTypeInfo.peerIp = PEER_IP;
    // AddLaneTypeInfoItem((const LaneTypeInfo *)&inputLaneTypeInfo);
    // LnnOnWifiDirectDeviceOffLine(PEER_MAC, PEER_IP, PEER_UUID);
}

} // namespace OHOS
