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
#include "lnn_lane_listener.h"
#include "lnn_lane_listener.c"
#include "lnn_lane_listener_deps_mock.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define LANE_REQ_ID 111

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char PEER_UUID[] = "111122223333abcdef";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr char PEER_IP_HML[] = "127.30.0.1";
constexpr char PEER_IP_P2P[] = "127.31.0.1";
constexpr uint64_t LANE_ID_P2P = 0x1000000000000001;
constexpr uint64_t LANE_ID_HML = 0x1000000000000002;

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
    InitLaneListener();
    GTEST_LOG_(INFO) << "LNNLaneListenerTest init end";
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

static void OnLaneLinkup(uint64_t laneId, const char *peerUdid, const LaneConnInfo *laneConnInfo)
{
    GTEST_LOG_(INFO) << "OnLaneLinkup enter";
}

static void OnLaneLinkdown(uint64_t laneId, const char *peerUdid, const LaneConnInfo *laneConnInfo)
{
    GTEST_LOG_(INFO) << "OnLaneLinkdown enter";
}

static void OnLaneStateChange(uint64_t laneId, LaneState state)
{
    GTEST_LOG_(INFO) << "OnLaneStateChange enter";
}

static LaneStatusListener g_listener = {
    .onLaneLinkup = OnLaneLinkup,
    .onLaneLinkdown = OnLaneLinkdown,
    .onLaneStateChange = OnLaneStateChange,
};

/*
* @tc.name: LNN_INIT_LANE_LISTENER_001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_INIT_LANE_LISTENER_001, TestSize.Level1)
{
    int32_t ret  = InitLaneListener();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_REG_UNREG_LISTENER_001
* @tc.desc: Reg&Unreg listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REG_UNREG_LISTENER_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->registerLaneListener(LANE_TYPE_BUTT, &g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_BUTT, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_REG_UNREG_LISTENER_002
* @tc.desc: Reg&Unreg listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_REG_UNREG_LISTENER_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_CTRL, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_CTRL);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_CTRL);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_TYPE_CHECK_001
* @tc.desc: LaneTypeCheck
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_TYPE_CHECK_001, TestSize.Level1)
{
    LaneType type = LANE_TYPE_BUTT;
    bool ret = LaneTypeCheck(type);
    EXPECT_EQ(false, ret);

    type = LANE_TYPE_TRANS;
    ret = LaneTypeCheck(type);
    EXPECT_EQ(true, ret);
}

/*
* @tc.name: LNN_LANE_GET_BUSINFO_WITHOUT_LOCK_001
* @tc.desc: GetLaneBusinessInfoWithoutLock
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_GET_BUSINFO_WITHOUT_LOCK_001, TestSize.Level1)
{
    LaneBusinessInfo *ret = GetLaneBusinessInfoWithoutLock(nullptr);
    EXPECT_EQ(ret, nullptr);

    LaneType type = LANE_TYPE_TRANS;
    int32_t retAdd = AddLaneBusinessInfoItem(type, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, retAdd);

    LaneBusinessInfo laneBusinessInfo;
    (void)memset_s(&laneBusinessInfo, sizeof(LaneBusinessInfo), 0, sizeof(LaneBusinessInfo));
    laneBusinessInfo.laneType = LANE_TYPE_TRANS;
    laneBusinessInfo.laneId = LANE_ID_P2P;
    ret = GetLaneBusinessInfoWithoutLock(&laneBusinessInfo);
    EXPECT_NE(ret, nullptr);

    retAdd = DelLaneBusinessInfoItem(type, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, retAdd);
}

/*
* @tc.name: LNN_LANE_ADD_DEL_BUSINESS_INFO_ITEM_001
* @tc.desc: Add&DelLaneBusinessInfoItem
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_ADD_DEL_BUSINESS_INFO_ITEM_001, TestSize.Level1)
{
    int32_t ret = AddLaneBusinessInfoItem(LANE_TYPE_BUTT, INVALID_LANE_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    AddLaneBusinessInfoItem(LANE_TYPE_TRANS, INVALID_LANE_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_BUTT, INVALID_LANE_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_ADD_DEL_BUSINESS_INFO_ITEM_002
* @tc.desc: Add&DelLaneBusinessInfoItem-mutil
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_ADD_DEL_BUSINESS_INFO_ITEM_002, TestSize.Level1)
{
    int32_t ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_FIND_BUSINESS_INFO_BY_LANE_INFO_001
* @tc.desc: FindLaneBusinessInfoByLinkInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_FIND_BUSINESS_INFO_BY_LANE_INFO_001, TestSize.Level1)
{
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    uint32_t resNum;
    LaneBusinessInfo laneBusinessInfo[LANE_TYPE_BUTT];
    (void)memset_s(&laneBusinessInfo, sizeof(LaneBusinessInfo), 0, sizeof(LaneBusinessInfo));

    LaneResource laneResource;
    (void)memset_s(&laneResource, sizeof(LaneResource), 0, sizeof(LaneResource));
    laneResource.laneId = LANE_ID_P2P;
    LaneListenerDepsInterfaceMock listenerMock;
    EXPECT_CALL(listenerMock, FindLaneResourceByLinkAddr)
        .WillRepeatedly(DoAll(SetArgPointee<1>(laneResource), Return(SOFTBUS_OK)));

    int32_t ret = FindLaneBusinessInfoByLinkInfo(nullptr, &resNum, laneBusinessInfo, LANE_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FindLaneBusinessInfoByLinkInfo(&laneLinkInfo, &resNum, nullptr, LANE_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FindLaneBusinessInfoByLinkInfo(&laneLinkInfo, &resNum, laneBusinessInfo, LANE_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);

    uint32_t addCount = 0;
    ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);
    addCount++;
    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);
    addCount++;

    ret = FindLaneBusinessInfoByLinkInfo(&laneLinkInfo, &resNum, laneBusinessInfo, LANE_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(resNum, addCount);

    ret = FindLaneBusinessInfoByLinkInfo(&laneLinkInfo, &resNum, laneBusinessInfo, --addCount);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(resNum, addCount);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_P2P);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_LANE_LISTENER_IS_EXISTS_001
* @tc.desc: LaneListenerIsExist
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_LANE_LISTENER_IS_EXISTS_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneListenerInfo *ret = LaneListenerIsExist(LANE_TYPE_TRANS);
    EXPECT_EQ(ret, nullptr);

    int32_t retReg = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, retReg);
    ret = LaneListenerIsExist(LANE_TYPE_TRANS);
    EXPECT_NE(ret, nullptr);
    ret = LaneListenerIsExist(LANE_TYPE_HDLC);
    EXPECT_EQ(ret, nullptr);

    retReg = laneManager->registerLaneListener(LANE_TYPE_HDLC, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, retReg);
    ret = LaneListenerIsExist(LANE_TYPE_HDLC);
    EXPECT_NE(ret, nullptr);

    retReg = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, retReg);

    retReg = laneManager->unRegisterLaneListener(LANE_TYPE_HDLC);
    EXPECT_EQ(SOFTBUS_OK, retReg);
}

/*
* @tc.name: LNN_LANE_FIND_LANE_LISTENER_INFO_BY_LANE_TYPE_001
* @tc.desc: FindLaneListenerInfoByLaneType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_FIND_LANE_LISTENER_INFO_BY_LANE_TYPE_001, TestSize.Level1)
{
    LaneListenerInfo laneListenerInfo;
    (void)memset_s(&laneListenerInfo, sizeof(LaneListenerInfo), 0, sizeof(LaneListenerInfo));
    int32_t ret = FindLaneListenerInfoByLaneType(LANE_TYPE_BUTT, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FindLaneListenerInfoByLaneType(LANE_TYPE_TRANS, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const LnnLaneManager *laneManager = GetLaneManager();
    ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = FindLaneListenerInfoByLaneType(LANE_TYPE_HDLC, &laneListenerInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = FindLaneListenerInfoByLaneType(LANE_TYPE_TRANS, &laneListenerInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_GET_STATE_NOTIFY_INFO_001
* @tc.desc: GetStateNotifyInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_GET_STATE_NOTIFY_INFO_001, TestSize.Level1)
{
    char peerUdid[UDID_BUF_LEN] = {0};
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));

    int32_t ret = GetStateNotifyInfo(nullptr, PEER_UUID, peerUdid, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetStateNotifyInfo(PEER_IP_HML, nullptr, peerUdid, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetStateNotifyInfo(PEER_IP_HML, PEER_UUID, nullptr, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetStateNotifyInfo(PEER_IP_HML, PEER_UUID, peerUdid, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    (void)strncpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, PEER_UDID, UDID_BUF_LEN);
    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(DoAll(SetArgPointee<2>(nodeInfo), Return(SOFTBUS_OK)));
    ret = GetStateNotifyInfo(PEER_IP_HML, PEER_UUID, peerUdid, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = GetStateNotifyInfo(PEER_IP_HML, PEER_UUID, peerUdid, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetStateNotifyInfo(PEER_IP_P2P, PEER_UUID, peerUdid, &laneLinkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_LINKUP_NOTIFY_001
* @tc.desc: LaneLinkupNotify
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_LINKUP_NOTIFY_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_HML;
    (void)strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, IP_LEN);

    int32_t ret = LaneLinkupNotify(nullptr, &linkInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = LaneLinkupNotify(PEER_UDID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    LaneListenerDepsInterfaceMock listenerMock;
    EXPECT_CALL(listenerMock, LaneInfoProcess).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(listenerMock, ApplyLaneId).WillRepeatedly(Return(LANE_ID_HML));
    ret = LaneLinkupNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    const LnnLaneManager *laneManager = GetLaneManager();
    ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_HDLC, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = LaneLinkupNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = LaneLinkupNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_HDLC);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_LINKDOWN_NOTIFY_001
* @tc.desc: LaneLinkdownNotify
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_LINKDOWN_NOTIFY_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_HML;
    (void)strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, IP_LEN);

    LaneResource laneResource;
    (void)memset_s(&laneResource, sizeof(LaneResource), 0, sizeof(LaneResource));
    laneResource.laneId = LANE_ID_HML;
    LaneListenerDepsInterfaceMock listenerMock;
    EXPECT_CALL(listenerMock, FindLaneResourceByLinkAddr)
        .WillRepeatedly(DoAll(SetArgPointee<1>(laneResource), Return(SOFTBUS_OK)));

    int32_t ret = LaneLinkdownNotify(nullptr, &linkInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = LaneLinkdownNotify(PEER_UDID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = LaneLinkdownNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = LaneLinkdownNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const LnnLaneManager *laneManager = GetLaneManager();
    static LaneStatusListener listener = {
        .onLaneLinkup = OnLaneLinkup,
        .onLaneStateChange = OnLaneStateChange,
    };

    ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = LaneLinkdownNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_LANE_LINKDOWN_NOTIFY_002
* @tc.desc: LaneLinkdownNotify
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneListenerTest, LNN_LANE_LINKDOWN_NOTIFY_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->registerLaneListener(LANE_TYPE_TRANS, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->registerLaneListener(LANE_TYPE_CTRL, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    LaneResource laneResource;
    (void)memset_s(&laneResource, sizeof(LaneResource), 0, sizeof(LaneResource));
    laneResource.laneId = LANE_ID_HML;
    LaneListenerDepsInterfaceMock listenerMock;
    EXPECT_CALL(listenerMock, FindLaneResourceByLinkAddr)
        .WillRepeatedly(DoAll(SetArgPointee<1>(laneResource), Return(SOFTBUS_OK)));
    EXPECT_CALL(listenerMock, LaneInfoProcess)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_HML;
    (void)strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, IP_LEN);
    ret = AddLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = LaneLinkdownNotify(PEER_UDID, &linkInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_TRANS);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = laneManager->unRegisterLaneListener(LANE_TYPE_CTRL);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_TRANS, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = DelLaneBusinessInfoItem(LANE_TYPE_CTRL, LANE_ID_HML);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
