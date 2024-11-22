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

#include "bus_center_manager.h"
#include "lnn_lane_link_conflict.c"
#include "lnn_lane_link_conflict.h"
#include "lnn_lane_link_conflict_deps_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char PEER_NETWORK_ID[] = "111122223333abcdef";
constexpr char PEER_IP_P2P[] = "127.31.0.1";

class LNNLaneLinkConflictTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkConflictTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkConflictTest up";
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, InitLinkWifiDirect).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitLnnLooper();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = InitLaneLinkConflict();
    ASSERT_EQ(ret, SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneLinkConflictTest init end";
}

void LNNLaneLinkConflictTest::TearDownTestCase()
{
    LaneLinkConflictDepsInterfaceMock mock;
    EXPECT_CALL(mock, DeInitLinkWifiDirect).WillRepeatedly(Return());
    DeinitLaneLinkConflict();
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNLaneLinkConflictTest down";
}

void LNNLaneLinkConflictTest::SetUp()
{
}

void LNNLaneLinkConflictTest::TearDown()
{
}

static void FreeConflictDevInfo(LinkConflictInfo *inputInfo)
{
    if (inputInfo == nullptr) {
        return;
    }
    if (inputInfo->devIdCnt > 0) {
        SoftBusFree(inputInfo->devIdList);
        inputInfo->devIdList = nullptr;
        inputInfo->devIdCnt = 0;
    }
    if (inputInfo->devIpCnt > 0) {
        SoftBusFree(inputInfo->devIpList);
        inputInfo->devIpList = nullptr;
        inputInfo->devIpCnt = 0;
    }
}

static int32_t GenerateConflictDevInfo(LinkConflictInfo *inputInfo)
{
    if (inputInfo == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    char (*devIdList)[NETWORK_ID_BUF_LEN] = (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(NETWORK_ID_BUF_LEN);
    if (devIdList == NULL) {
        GTEST_LOG_(INFO) << "calloc devIdList fail";
        return SOFTBUS_MALLOC_ERR;
    }
    inputInfo->devIdList = devIdList;
    if (memcpy_s(devIdList, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID, strlen(PEER_NETWORK_ID)) != EOK) {
        GTEST_LOG_(INFO) << "strcpy devIdList fail";
        FreeConflictDevInfo(inputInfo);
        return SOFTBUS_STRCPY_ERR;
    }
    inputInfo->devIdCnt++;
    char (*devIpList)[CONFLICT_DEV_IP_LEN] = (char (*)[CONFLICT_DEV_IP_LEN])SoftBusCalloc(CONFLICT_DEV_IP_LEN);
    if (devIpList == NULL) {
        GTEST_LOG_(INFO) << "calloc devIpList fail";
        FreeConflictDevInfo(inputInfo);
        return SOFTBUS_MALLOC_ERR;
    }
    inputInfo->devIpList = devIpList;
    if (memcpy_s(devIpList, CONFLICT_DEV_IP_LEN, PEER_IP_P2P, strlen(PEER_IP_P2P)) != EOK) {
        GTEST_LOG_(INFO) << "strcpy devIpList fail";
        FreeConflictDevInfo(inputInfo);
        return SOFTBUS_STRCPY_ERR;
    }
    inputInfo->devIpCnt++;
    return SOFTBUS_OK;
}

/*
* @tc.name: LNN_INIT_DEINIT_LINK_CONFLICT_001
* @tc.desc: Init&DeInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_INIT_DEINIT_LINK_CONFLICT_001, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, InitLinkWifiDirect).WillOnce(Return(SOFTBUS_NO_INIT)).WillRepeatedly(Return(SOFTBUS_OK));
    DeinitLaneLinkConflict();
    LnnDeinitLnnLooper();

    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = PostConflictInfoTimelinessMsg(nullptr, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = PostConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitLaneLinkConflict();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = LnnInitLnnLooper();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitLaneLinkConflict();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = InitLaneLinkConflict();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_CALL(mock, DeInitLinkWifiDirect).WillRepeatedly(Return());
    DeinitLaneLinkConflict();
    FreeConflictDevInfo(&inputInfo);

    ret = LnnInitLnnLooper();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitLaneLinkConflict();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ADD_DEL_CONFLICT_INFO_001
* @tc.desc: Add&Del conflictInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_ADD_DEL_CONFLICT_INFO_001, TestSize.Level1)
{
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLinkConflictInfo(nullptr, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_ADD_DEL_CONFLICT_INFO_002
* @tc.desc: Add&Del conflictInfo for update exist node
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_ADD_DEL_CONFLICT_INFO_002, TestSize.Level1)
{
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_FIND_CONFLICT_INFO_BY_DEV_ID_001
* @tc.desc: find conflictInfo by peerDevId when saved identifyType is DEV_ID
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_FIND_CONFLICT_INFO_BY_DEV_ID_001, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString)
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    LinkConflictInfo outputInfo;
    (void)memset_s(&outputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    ret = FindLinkConflictInfoByDevId(nullptr, inputInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = FindLinkConflictInfoByDevId(&inputInfo.identifyInfo, inputInfo.conflictType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = FindLinkConflictInfoByDevId(&inputInfo.identifyInfo, inputInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(outputInfo.releaseLink, inputInfo.releaseLink);
    EXPECT_EQ(outputInfo.identifyInfo.type, IDENTIFY_TYPE_DEV_ID);
    EXPECT_EQ(outputInfo.devIdCnt, inputInfo.devIdCnt);
    EXPECT_EQ(outputInfo.devIpCnt, 0);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_FIND_CONFLICT_INFO_BY_DEV_ID_002
* @tc.desc: find conflictInfo by peerUdidHashStr when saved identifyType is UDID_HASH
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_FIND_CONFLICT_INFO_BY_DEV_ID_002, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString)
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_UDID_HASH;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.udidHash, CONFLICT_UDIDHASH_STR_LEN + 1,
        PEER_UDID_HASH_STR), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    LinkConflictInfo outputInfo;
    (void)memset_s(&outputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    ret = FindLinkConflictInfoByDevId(&inputInfo.identifyInfo, inputInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(outputInfo.releaseLink, inputInfo.releaseLink);
    EXPECT_EQ(outputInfo.identifyInfo.type, IDENTIFY_TYPE_UDID_HASH);
    EXPECT_EQ(outputInfo.devIdCnt, inputInfo.devIdCnt);
    EXPECT_EQ(outputInfo.devIpCnt, 0);

    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_FIND_CONFLICT_INFO_BY_DEV_ID_003
* @tc.desc: find conflictInfo by peerDevId when saved identifyType is UDID_HASH
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_FIND_CONFLICT_INFO_BY_DEV_ID_003, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_ENCRYPT_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_UDID_HASH;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.udidHash, CONFLICT_UDIDHASH_STR_LEN + 1,
        PEER_UDID_HASH_STR), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    LinkConflictInfo outputInfo;
    (void)memset_s(&outputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    LinkConflictInfo findInfo;
    (void)memset_s(&findInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    findInfo.conflictType = CONFLICT_THREE_VAP;
    findInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(findInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    ret = FindLinkConflictInfoByDevId(&findInfo.identifyInfo, findInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = FindLinkConflictInfoByDevId(&findInfo.identifyInfo, findInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = FindLinkConflictInfoByDevId(&findInfo.identifyInfo, findInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = FindLinkConflictInfoByDevId(&findInfo.identifyInfo, findInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(outputInfo.releaseLink, inputInfo.releaseLink);
    EXPECT_EQ(outputInfo.identifyInfo.type, IDENTIFY_TYPE_UDID_HASH);
    EXPECT_EQ(outputInfo.devIdCnt, inputInfo.devIdCnt);
    EXPECT_EQ(outputInfo.devIpCnt, 0);

    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_GET_CONFLICT_TYPE_001
* @tc.desc: get conflict type : CONFLICT_ROLE
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_GET_CONFLICT_TYPE_001, TestSize.Level1)
{
    LinkConflictType type = CONFLICT_BUTT;
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_P2P_GO_GC_CONFLICT);
    EXPECT_EQ(type, CONFLICT_ROLE);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_PV1_BOTH_GO_ERR);
    EXPECT_EQ(type, CONFLICT_ROLE);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE);
    EXPECT_EQ(type, CONFLICT_ROLE);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_PV2_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
    EXPECT_EQ(type, CONFLICT_ROLE);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_PV2_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE);
    EXPECT_EQ(type, CONFLICT_ROLE);
    type = GetConflictTypeWithErrcode(SOFTBUS_LANE_NOT_FOUND);
    EXPECT_EQ(type, CONFLICT_BUTT);
}

/*
* @tc.name: LNN_GET_CONFLICT_TYPE_002
* @tc.desc: get conflict type : CONFLICT_LINK_NUM_LIMITED
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_GET_CONFLICT_TYPE_002, TestSize.Level1)
{
    LinkConflictType type = CONFLICT_BUTT;
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_HML_NUM_LIMITED_CONFLICT);
    EXPECT_EQ(type, CONFLICT_LINK_NUM_LIMITED);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_HML_NUM_LIMITED_CONFLICT);
    EXPECT_EQ(type, CONFLICT_LINK_NUM_LIMITED);
}

/*
* @tc.name: LNN_GET_CONFLICT_TYPE_003
* @tc.desc: get conflict type : CONFLICT_THREE_VAP
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_GET_CONFLICT_TYPE_003, TestSize.Level1)
{
    LinkConflictType type = CONFLICT_BUTT;
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_225_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_255_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_525_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_555_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_HML_P2P_DFS_CHANNEL_CONFLICT);
    EXPECT_EQ(type, CONFLICT_THREE_VAP);
}

/*
* @tc.name: LNN_GET_CONFLICT_TYPE_004
* @tc.desc: get conflict type : CONFLICT_SOFTAP
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_GET_CONFLICT_TYPE_004, TestSize.Level1)
{
    LinkConflictType type = CONFLICT_BUTT;
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_HML_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_HML_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_P2P_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
    type = GetConflictTypeWithErrcode(SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_HML_CHIP_CONFLICT);
    EXPECT_EQ(type, CONFLICT_SOFTAP);
}

/*
* @tc.name: LNN_LINK_CONFLICT_POST_MSG_001
* @tc.desc: test LinkConflictPostMsgToHandler MSG_TYPE_CONFLICT_TIMELINESS
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_LINK_CONFLICT_POST_MSG_001, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString)
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    LinkConflictInfo *conflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    ASSERT_NE(conflictItem, nullptr);
    EXPECT_EQ(memcpy_s(&conflictItem->identifyInfo, sizeof(DevIdentifyInfo), &inputInfo.identifyInfo,
        sizeof(DevIdentifyInfo)), EOK);
    conflictItem->conflictType = inputInfo.conflictType;
    ret = LinkConflictPostMsgToHandler(MSG_TYPE_CONFLICT_TIMELINESS, 0, 0, conflictItem, 0);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conflictItem);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    LinkConflictInfo outputInfo;
    (void)memset_s(&outputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    ret = FindLinkConflictInfoByDevId(&inputInfo.identifyInfo, inputInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_LINK_CONFLICT_POST_MSG_002
* @tc.desc: test LinkConflictPostMsgToHandler MSG_TYPE_CONFLICT_BUTT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_LINK_CONFLICT_POST_MSG_002, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString)
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    LinkConflictInfo *conflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    ASSERT_NE(conflictItem, nullptr);
    EXPECT_EQ(memcpy_s(&conflictItem->identifyInfo, sizeof(DevIdentifyInfo), &inputInfo.identifyInfo,
        sizeof(DevIdentifyInfo)), EOK);
    conflictItem->conflictType = inputInfo.conflictType;
    ret = LinkConflictPostMsgToHandler(MSG_TYPE_CONFLICT_BUTT, 0, 0, conflictItem, 0);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conflictItem);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    LinkConflictInfo outputInfo;
    (void)memset_s(&outputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    ret = FindLinkConflictInfoByDevId(&inputInfo.identifyInfo, inputInfo.conflictType, &outputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(conflictItem);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_LINK_CONFLICT_REMOVE_MSG_001
* @tc.desc: test RemoveConflictInfoTimelinessMsg
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_LINK_CONFLICT_REMOVE_MSG_001, TestSize.Level1)
{
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(nullptr, inputInfo.conflictType);
    inputInfo.conflictType = CONFLICT_ROLE;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_UDID_HASH;
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    SoftBusMessage msg;
    (void)memset_s(&msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    ret = RemoveConflictInfoTimeliness(nullptr, &inputInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    msg.obj = nullptr;
    ret = RemoveConflictInfoTimeliness(&msg, &inputInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RemoveConflictInfoTimeliness(&msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_UPDATE_EXISTS_LINK_CONFLICT_INFO_001
* @tc.desc: test UpdateExistsLinkConflictInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_UPDATE_EXISTS_LINK_CONFLICT_INFO_001, TestSize.Level1)
{
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_P2P;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);
    ret = UpdateExistsLinkConflictInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateConflictInfo(nullptr, &inputInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GenerateConflictInfo(&inputInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateExistsLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    FreeConflictDevInfo(&inputInfo);
}

/*
* @tc.name: LNN_CHECK_LINK_CONFLICT_BY_RELEASE_LINK_001
* @tc.desc: check conflictInfo by releaseLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkConflictTest, LNN_CHECK_LINK_CONFLICT_BY_RELEASE_LINK_001, TestSize.Level1)
{
    NiceMock<LaneLinkConflictDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString)
        .WillRepeatedly(LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString);
    LinkConflictInfo inputInfo;
    (void)memset_s(&inputInfo, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    inputInfo.conflictType = CONFLICT_THREE_VAP;
    inputInfo.identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    EXPECT_EQ(strcpy_s(inputInfo.identifyInfo.devInfo.peerDevId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID), EOK);
    inputInfo.releaseLink = LANE_HML;
    int32_t ret = GenerateConflictDevInfo(&inputInfo);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddLinkConflictInfo(&inputInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveConflictInfoTimelinessMsg(&inputInfo.identifyInfo, inputInfo.conflictType);

    ret = CheckLinkConflictByReleaseLink(LANE_P2P);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLinkConflictByReleaseLink(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLinkConflictInfo(&inputInfo.identifyInfo, inputInfo.conflictType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckLinkConflictByReleaseLink(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    FreeConflictDevInfo(&inputInfo);
}
} // namespace OHOS
