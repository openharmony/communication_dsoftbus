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

#include "bus_center_info_key.h"
#include "dsoftbus_enhance_interface.h"
#include "g_enhance_lnn_func_pack.h"
#include "g_enhance_lnn_func.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_power_ctrl_deps_mock.h"
#include "lnn_lane_reliability.c"
#include "lnn_lane_select.h"
#include "lnn_select_rule.h"
#include "lnn_wifi_adpter_mock.h"
#include "lnn_lane_link_ledger.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
#include "wifi_direct_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr char PEER_IP_HML[] = "172.30.0.1";
constexpr char PEER_WLAN_ADDR[] = "172.30.0.1";
constexpr char PEER_MAC[] = "a1:b2:c3:d4:e5:f6";
constexpr char LOCAL_MAC[] = "a2:b2:c3:d4:e5:f6";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr char LOCAL_UDID[] = "444455556666abcdef";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;

static NodeInfo g_NodeInfo = {
    .p2pInfo.p2pRole = 1,
    .p2pInfo.p2pMac = "abc",
    .p2pInfo.goMac = "abc",
};

class LNNLaneExtMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneExtMockTest::SetUpTestCase()
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->enablePowerControl = EnablePowerControl;
    int32_t ret = LnnInitLnnLooper();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(nullptr));
    ret = InitLane();
    EXPECT_EQ(ret, SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneExtMockTest start";
}

void LNNLaneExtMockTest::TearDownTestCase()
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    DeinitLane();
    LooperDeinit();
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNLaneExtMockTest end";
}

void LNNLaneExtMockTest::SetUp()
{
}

void LNNLaneExtMockTest::TearDown()
{
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    GTEST_LOG_(INFO) << "PrejudgeAvailability Enter";
    return SOFTBUS_OK;
}

static int32_t GetLocalAndRemoteMacByLocalIp(const char *localIp, char *localMac, size_t localMacSize,
    char *remoteMac, size_t remoteMacSize)
{
    (void)localIp;
    (void)localMac;
    (void)localMacSize;
    (void)remoteMac;
    (void)remoteMacSize;
    return SOFTBUS_OK;
}

static int32_t GetLocalAndRemoteMacByLocalIpError(const char *localIp, char *localMac, size_t localMacSize,
    char *remoteMac, size_t remoteMacSize)
{
    (void)localIp;
    (void)localMac;
    (void)localMacSize;
    (void)remoteMac;
    (void)remoteMacSize;
    return SOFTBUS_INVALID_PARAM;
}

static struct WifiDirectManager g_manager = {
    .prejudgeAvailability = PrejudgeAvailability,
    .getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIp,
};

/*
* @tc.name: LANE_INFO_001
* @tc.desc: LaneInfoProcess BR
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_001, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_BR;
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_002
* @tc.desc: LaneInfoProcess BLE
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_002, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_BLE;
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_003
* @tc.desc: LaneInfoProcess P2P
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_003, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_P2P;
    LaneConnInfo connInfo;
    LaneProfile profile = {};
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_004
* @tc.desc: LaneInfoProcess fail
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_004, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_LINK_TYPE_BUTT;
    LaneConnInfo *connInfo = nullptr;
    LaneProfile *profile = nullptr;
    int32_t ret = LaneInfoProcess(nullptr, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, nullptr, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LANE_INFO_005
* @tc.desc: LaneInfoProcess 2.4G
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_005, TestSize.Level1)
{
    LaneLinkInfo info = {};
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};

    info.type = LANE_WLAN_2P4G;
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_WLAN_5G;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_P2P_REUSE;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_BLE_DIRECT;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_COC;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_HML_RAW;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_LINK_TYPE_BUTT;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_DATA_001
* @tc.desc: LnnCreateData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_DATA_001, TestSize.Level1)
{
    int32_t ret = LnnCreateData(nullptr, 32, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LnnDeleteData(nullptr, 32);
}

/*
* @tc.name: LNN_LANE_PROFILE_001
* @tc.desc: BindLaneIdToProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_PROFILE_001, TestSize.Level1)
{
    uint64_t laneId = 0x1000000000000001;
    int32_t ret = BindLaneIdToProfile(laneId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneProfile profile = {};
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    profile.linkType = LANE_P2P;
    profile.content = LANE_T_FILE;
    profile.priority = LANE_PRI_LOW;
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneGenerateParam param = {};
    param.linkType = LANE_P2P;
    param.transType = LANE_T_FILE;
    param.priority = LANE_PRI_LOW;
    uint32_t profileId = GenerateLaneProfileId(&param);

    ret = GetLaneProfile(profileId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetLaneProfile(profileId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint64_t *laneReqIdList = nullptr;
    uint32_t listSize = 0;
    ret = GetLaneIdList(profileId, &laneReqIdList, &listSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(laneReqIdList);
    (void)GetActiveProfileNum();
    (void)UnbindLaneIdFromProfile(laneId, profileId);
    (void)UnbindLaneIdFromProfile(0, profileId);
}

/*
* @tc.name: LNN_LANE_PROFILE_002
* @tc.desc: BindLaneIdToProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_PROFILE_002, TestSize.Level1)
{
    uint64_t laneId = 0x1000000000000002;
    uint32_t profileId = 111111;
    LaneProfile profile = {};
    int32_t ret = GetLaneProfile(profileId, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint64_t *laneReqIdList = nullptr;
    uint32_t listSize = 0;
    ret = GetLaneIdList(profileId, &laneReqIdList, &listSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    profile.linkType = LANE_P2P;
    profile.content = LANE_T_FILE;
    profile.priority = LANE_PRI_LOW;
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)UnbindLaneIdFromProfile(laneId, profileId);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LINKADDR_001
* @tc.desc: LANE FIND LANERESOURCE BY LINK ADDR TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_FIND_LANERESOURCE_BY_LINKADDR_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    int32_t ret = FindLaneResourceByLinkAddr(nullptr, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkAddr(&linkInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkAddr(&linkInfo, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    LaneLinkInfo linkInfoFind;
    ASSERT_EQ(memset_s(&linkInfoFind, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfoFind.type = LANE_HML;
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ASSERT_EQ(strcpy_s(linkInfoFind.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ASSERT_EQ(strcpy_s(linkInfoFind.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LINKTYPE_001
* @tc.desc: LANE FIND LANERESOURCE BY LINK TYPE TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_FIND_LANERESOURCE_BY_LINKTYPE_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    int32_t ret = FindLaneResourceByLinkType(nullptr, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_LINK_TYPE_BUTT, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLinkType(LOCAL_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_P2P, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LANEID_001
* @tc.desc: LANE FIND LANERESOURCE BY LANEID TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_FIND_LANERESOURCE_BY_LANEID_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = FindLaneResourceByLaneId(laneId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLaneId(INVALID_LANE_ID, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_001
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM CLIENT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = AddLaneResourceToPool(nullptr, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddLaneResourceToPool(&linkInfo, INVALID_LANE_ID, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(INVALID_LANE_ID, false);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef--;
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
}

/*
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_002
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM SERVER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = AddLaneResourceToPool(nullptr, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    laneId = LANE_ID_BASE;
    uint32_t serverRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_LANE_TRIGGER_LINK_FAIL);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, serverRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DelLaneResourceByLaneId(laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_GENERATE_LANE_ID_001
* @tc.desc: LANE GENERATE LANE ID
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_GENERATE_LANE_ID_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);

    uint64_t laneId = GenerateLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
    EXPECT_EQ(laneId, INVALID_LANE_ID);

    laneId = GenerateLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
    EXPECT_NE(laneId, INVALID_LANE_ID);
}

/*
* @tc.name: LANE_CLEAR_LANE_RESOURCE_BYLANEID_001
* @tc.desc: ClearLaneResourceByLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_CLEAR_LANE_RESOURCE_BYLANEID_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    EXPECT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
}

/*
* @tc.name: LANE_PPOCESS_VAP_INFO_001
* @tc.desc: ProcessVapInfo hml
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_PPOCESS_VAP_INFO_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_P2P;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    EXPECT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdExt = LANE_ID_BASE + 1;
    uint32_t clientRef = 0;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_HML;
    ret = AddLaneResourceToPool(&linkInfo, laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLaneId(laneIdExt, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(!laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_PPOCESS_VAP_INFO_002
* @tc.desc: ProcessVapInfo p2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_PPOCESS_VAP_INFO_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    EXPECT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdExt = LANE_ID_BASE + 1;
    uint32_t clientRef = 0;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_P2P;
    ret = AddLaneResourceToPool(&linkInfo, laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLaneId(laneIdExt, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(!laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_MAC_INFO_TEST_01
* @tc.desc: GetMacInfoByLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_MAC_INFO_TEST_01, TestSize.Level1)
{
    LnnMacInfo macInfo;
    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_P2P;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.localIp, IP_LEN, PEER_IP_HML), EOK);
    EXPECT_EQ(strcpy_s(macInfo.localMac, MAX_MAC_LEN, LOCAL_MAC), EOK);
    EXPECT_EQ(strcpy_s(macInfo.remoteMac, MAX_MAC_LEN, PEER_MAC), EOK);
    int32_t ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_P2P_REUSE;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_HML;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_ETH;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_MAC_INFO_TEST_02
* @tc.desc: GetMacInfoByLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_MAC_INFO_TEST_02, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    LnnMacInfo macInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_P2P;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_UPDATE_LANE_ID_001
* @tc.desc: test UpdateLaneResourceLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_UPDATE_LANE_ID_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);

    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdNew = LANE_ID_BASE + 1;
    int32_t ret = UpdateLaneResourceLaneId(INVALID_LANE_ID, laneIdNew, PEER_UDID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneResourceLaneId(laneId, INVALID_LANE_ID, PEER_UDID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneResourceLaneId(laneId, laneIdNew, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneResourceLaneId(laneId, laneIdNew, PEER_UDID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneResourceLaneId(laneId, laneIdNew, PEER_UDID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneIdNew, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_DETECT_WIFI_DIRECT_APPLY_001
* @tc.desc: test DetectEnableWifiDirectApply & DetectDisableWifiDirectApply
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_LANE_DETECT_WIFI_DIRECT_APPLY_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    linkInfo.linkInfo.p2p.bw = LANE_BW_160M;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LanePowerCtrlDepsInterfaceMock> powerCtrlMock;
    struct WifiDirectManager manager = g_manager;
    manager.getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIpError;
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillOnce(Return(nullptr)).WillOnce(Return(&manager))
        .WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(powerCtrlMock, IsPowerControlEnabled).WillRepeatedly(Return(true));
    EXPECT_CALL(powerCtrlMock, EnablePowerControl).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DetectEnableWifiDirectApply();
    DetectDisableWifiDirectApply();
    DetectEnableWifiDirectApply();
    DetectDisableWifiDirectApply();
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.linkInfo.p2p.bw = LANE_BW_80P80M;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DetectEnableWifiDirectApply();
    DetectDisableWifiDirectApply();
    uint64_t laneIdRaw = LANE_ID_BASE + 1;
    linkInfo.type = LANE_HML_RAW;
    ret = AddLaneResourceToPool(&linkInfo, laneIdRaw, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DetectEnableWifiDirectApply();
    ret = DelLaneResourceByLaneId(laneIdRaw, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_CHECK_LANE_RESOURCE_NUM_001
* @tc.desc: test CheckLaneResourceNumByLinkType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_CHECK_LANE_RESOURCE_NUM_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t laneNum = 0;
    int32_t ret = CheckLaneResourceNumByLinkType(nullptr, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLaneResourceNumByLinkType(nullptr, LANE_LINK_TYPE_BUTT, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLaneResourceNumByLinkType(PEER_UDID, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    uint64_t laneId = LANE_ID_BASE;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckLaneResourceNumByLinkType(PEER_UDID, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ADD_LANE_IS_VALID_LINK_ADDR_001
* @tc.desc: test IsValidLinkAddr(hml/br/ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_ADD_LANE_IS_VALID_LINK_ADDR_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.br.brMac, BT_MAC_LEN, PEER_MAC), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, PEER_MAC), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_BR;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_BLE;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ADD_LANE_IS_VALID_LINK_ADDR_002
* @tc.desc: test IsValidLinkAddr(coc_direct/wlan)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LNN_ADD_LANE_IS_VALID_LINK_ADDR_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_COC_DIRECT;
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN,
        PEER_WLAN_ADDR), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_WLAN_5G;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_LINK_TYPE_BUTT;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_006
* @tc.desc: LaneInfoProcess fail
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, LANE_INFO_006, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_USB;
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LaneInfoProcess(nullptr, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, nullptr, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, &connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, nullptr, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: CHECK_LANE_LINK_EXIST_BY_TYPE_001
* @tc.desc: test CheckLaneLinkExistByType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneExtMockTest, CHECK_LANE_LINK_EXIST_BY_TYPE_001, TestSize.Level1)
{
    EXPECT_FALSE(CheckLaneLinkExistByType(LANE_LINK_TYPE_BUTT));
    EXPECT_FALSE(CheckLaneLinkExistByType(LANE_HML));

    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LaneLinkInfo linkInfo = { .type = LANE_HML };
    ASSERT_EQ(strcpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML), EOK);
    ASSERT_EQ(strcpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID), EOK);
    uint64_t laneId = LANE_ID_BASE;
    EXPECT_EQ(SOFTBUS_OK, AddLaneResourceToPool(&linkInfo, laneId, false));
    EXPECT_TRUE(CheckLaneLinkExistByType(LANE_HML));
    EXPECT_EQ(SOFTBUS_OK, DelLaneResourceByLaneId(laneId, false));
}
} // namespace OHOS