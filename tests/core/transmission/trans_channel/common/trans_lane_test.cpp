/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <securec.h>

#include "bus_center_manager.h"
#include "device_auth.h"
#include "lnn_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "trans_channel_common.c"
#include "trans_channel_limit.h"
#include "trans_lane_manager.c"
#include "trans_lane_pending_ctl.c"
#include "trans_session_service.h"

using namespace testing::ext;

namespace OHOS {

#define MAX_COUNT (4)
static int32_t g_count = 0;
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_invalidName = "ohos.invalid.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupId = "TEST_GROUP_ID";

static SessionAttribute g_sessionAttr[] = {
    {.dataType = TYPE_MESSAGE},
    {.dataType = TYPE_BYTES},
    {.dataType = TYPE_FILE},
    {.dataType = TYPE_STREAM},
    {.dataType = LANE_T_BUTT},
};

class TransLaneTest : public testing::Test {
public:
    TransLaneTest(void)
    {}
    ~TransLaneTest(void)
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override
    {}
    void TearDown(void) override
    {}
};

void TransLaneTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    InitDeviceAuthService();
    BusCenterServerInit();
    TransServerInit();
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransFreeLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void TransLaneTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
    TransReqLanePendingDeinit();
    TransFreeLanePendingDeinit();
}

SessionParam* GenerateCommParamTest(void)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    if (sessionParam == nullptr) {
        return nullptr;
    }
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = &g_sessionAttr[g_count];
    if (g_count > MAX_COUNT) {
        g_count = 0;
    }
    g_count++;
    return sessionParam;
}

SessionParam* GenerateParamTest(SessionAttribute *sessionAttr)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    if (sessionParam == nullptr) {
        return nullptr;
    }
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = sessionAttr;
    return sessionParam;
}

/*
 * @tc.name: TransReqLanePendingInitTest001
 * @tc.desc: TransReqLanePendingInit returns ok when module already initialized
 *           and after deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransReqLanePendingInitTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
    ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransReqLanePendingDeinitTest001
 * @tc.desc: Double deinit does not crash, and add/del lane req fail after deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransReqLanePendingDeinitTest001, TestSize.Level1)
{
    TransReqLanePendingDeinit();
    TransReqLanePendingDeinit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    (void)TransReqLanePendingInit();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransAddLaneReqFromPendingListTest001
 * @tc.desc: TransAddLaneReqFromPendingList with valid handle returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAddLaneReqFromPendingListTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransDelLaneReqFromPendingListTest001
 * @tc.desc: TransDelLaneReqFromPendingList with nonexistent id returns
 *           node not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransDelLaneReqFromPendingListTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint32_t invalidId = 111;
    ret = TransDelLaneReqFromPendingList(invalidId, false);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransDelLaneReqFromPendingListTest002
 * @tc.desc: TransDelLaneReqFromPendingList with valid handle returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransDelLaneReqFromPendingListTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneReqItemByLaneHandleTest001
 * @tc.desc: TransGetLaneReqItemByLaneHandle with nonexistent id returns
 *           node not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneReqItemByLaneHandleTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    uint32_t invalidId = 111;
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    ret = TransGetLaneReqItemByLaneHandle(invalidId, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(connInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneReqItemByLaneHandleTest002
 * @tc.desc: TransGetLaneReqItemByLaneHandle with valid handle returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneReqItemByLaneHandleTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(connInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneReqItemByLaneHandleTest003
 * @tc.desc: TransGetLaneReqItemByLaneHandle with null connInfo returns mem err.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneReqItemByLaneHandleTest003, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, nullptr, &errCode);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneReqItemByLaneHandleTest004
 * @tc.desc: TransGetLaneReqItemByLaneHandle after deinit returns invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneReqItemByLaneHandleTest004, TestSize.Level1)
{
    TransReqLanePendingDeinit();
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    uint32_t laneHandle = 1;
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, connInfo, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(connInfo);
    (void)TransReqLanePendingInit();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransUpdateLaneConnInfoByLaneHandleTest001
 * @tc.desc: TransUpdateLaneConnInfoByLaneHandle with nonexistent id returns
 *           node not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransUpdateLaneConnInfoByLaneHandleTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint32_t invalidId = 111;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    ret = TransUpdateLaneConnInfoByLaneHandle(invalidId, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(connInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransUpdateLaneConnInfoByLaneHandleTest002
 * @tc.desc: TransUpdateLaneConnInfoByLaneHandle with valid handle and connInfo
 *           returns ok, and update with protocol set also returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransUpdateLaneConnInfoByLaneHandleTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    connInfo->connInfo.p2p.protocol = 1;
    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(connInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransUpdateLaneConnInfoByLaneHandleTest003
 * @tc.desc: TransUpdateLaneConnInfoByLaneHandle after deinit returns invalid
 *           param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransUpdateLaneConnInfoByLaneHandleTest003, TestSize.Level1)
{
    TransReqLanePendingDeinit();
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    uint32_t laneHandle = 1;
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, &connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransReqLanePendingInit();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransOnLaneRequestSuccessTest001
 * @tc.desc: TransOnLaneRequestSuccess with valid handle updates pending item
 *           bSucc to true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransOnLaneRequestSuccessTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    connInfo->connInfo.p2p.protocol = 1;
    TransOnLaneRequestSuccess(laneHandle, connInfo);
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    LaneConnInfo *outConnInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(outConnInfo, nullptr);
    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, outConnInfo, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_TRUE(bSucc);
    SoftBusFree(connInfo);
    SoftBusFree(outConnInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransOnLaneRequestSuccessTest002
 * @tc.desc: TransOnLaneRequestSuccess with nonexistent handle does not crash
 *           and does not affect valid item.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransOnLaneRequestSuccessTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransOnLaneRequestSuccess(invalidId, connInfo);
    bool bSucc = false;
    int32_t errCode = SOFTBUS_OK;
    LaneConnInfo *outInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(outInfo, nullptr);
    ret = TransGetLaneReqItemByLaneHandle(laneHandle, &bSucc, outInfo, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_FALSE(bSucc);
    SoftBusFree(connInfo);
    SoftBusFree(outInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransOnLaneRequestFailTest001
 * @tc.desc: TransOnLaneRequestFail with valid handle marks pending item as
 *           failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransOnLaneRequestFailTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LaneRequestFailReason reason = LANE_LINK_FAILED;
    TransOnLaneRequestFail(laneHandle, reason);
    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(connInfo);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransOnLaneRequestFailTest002
 * @tc.desc: TransOnLaneRequestFail with nonexistent handle does not crash and
 *           valid item still deletable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransOnLaneRequestFailTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    uint32_t invalidId = 111;
    LaneConnInfo *connInfo = reinterpret_cast<LaneConnInfo *>(SoftBusCalloc(sizeof(LaneConnInfo)));
    ASSERT_NE(connInfo, nullptr);
    (void)memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LaneRequestFailReason reason = LANE_LINK_FAILED;
    TransOnLaneRequestFail(invalidId, reason);
    connInfo->connInfo.p2p.protocol = 1;
    TransOnLaneRequestFail(laneHandle, reason);
    ret = TransDelLaneReqFromPendingList(laneHandle, false);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(connInfo);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: GetStreamLaneTypeTest001
 * @tc.desc: GetStreamLaneType returns LANE_T_RAW_STREAM for RAW_STREAM and
 *           not other lane types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetStreamLaneTypeTest001, TestSize.Level1)
{
    int32_t ret = GetStreamLaneType(RAW_STREAM);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);
    EXPECT_NE(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_COMMON_VIDEO);
    EXPECT_NE(ret, LANE_T_BYTE);
}

/*
 * @tc.name: GetStreamLaneTypeTest002
 * @tc.desc: GetStreamLaneType returns LANE_T_COMMON_VIDEO for
 *           COMMON_VIDEO_STREAM and not other lane types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetStreamLaneTypeTest002, TestSize.Level1)
{
    int32_t ret = GetStreamLaneType(COMMON_VIDEO_STREAM);
    EXPECT_EQ(ret, LANE_T_COMMON_VIDEO);
    EXPECT_NE(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_RAW_STREAM);
    EXPECT_NE(ret, LANE_T_BYTE);
}

/*
 * @tc.name: GetStreamLaneTypeTest003
 * @tc.desc: GetStreamLaneType returns LANE_T_COMMON_VOICE for
 *           COMMON_AUDIO_STREAM and not other lane types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetStreamLaneTypeTest003, TestSize.Level1)
{
    int32_t ret = GetStreamLaneType(COMMON_AUDIO_STREAM);
    EXPECT_EQ(ret, LANE_T_COMMON_VOICE);
    EXPECT_NE(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_RAW_STREAM);
    EXPECT_NE(ret, LANE_T_BYTE);
}

/*
 * @tc.name: GetStreamLaneTypeTest004
 * @tc.desc: GetStreamLaneType returns LANE_T_BUTT for LANE_T_BUTT input and
 *           not other lane types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetStreamLaneTypeTest004, TestSize.Level1)
{
    int32_t ret = GetStreamLaneType(LANE_T_BUTT);
    EXPECT_EQ(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_RAW_STREAM);
    EXPECT_NE(ret, LANE_T_COMMON_VIDEO);
    EXPECT_NE(ret, LANE_T_BYTE);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest001
 * @tc.desc: TransGetLaneTransTypeBySession with null param returns LANE_T_BUTT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest001, TestSize.Level1)
{
    int32_t ret = TransGetLaneTransTypeBySession(nullptr);
    EXPECT_EQ(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_MSG);
    EXPECT_NE(ret, LANE_T_BYTE);
    EXPECT_NE(ret, LANE_T_FILE);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest002
 * @tc.desc: TransGetLaneTransTypeBySession with TYPE_MESSAGE attr returns
 *           LANE_T_MSG.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest002, TestSize.Level1)
{
    SessionAttribute attr = {.dataType = TYPE_MESSAGE};
    SessionParam *sessionParam = GenerateParamTest(&attr);
    ASSERT_NE(sessionParam, nullptr);
    int32_t ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_MSG);
    EXPECT_NE(ret, LANE_T_BYTE);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest003
 * @tc.desc: TransGetLaneTransTypeBySession with TYPE_BYTES attr returns
 *           LANE_T_BYTE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest003, TestSize.Level1)
{
    SessionAttribute attr = {.dataType = TYPE_BYTES};
    SessionParam *sessionParam = GenerateParamTest(&attr);
    ASSERT_NE(sessionParam, nullptr);
    int32_t ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_BYTE);
    EXPECT_NE(ret, LANE_T_MSG);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest004
 * @tc.desc: TransGetLaneTransTypeBySession with TYPE_FILE attr returns
 *           LANE_T_FILE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest004, TestSize.Level1)
{
    SessionAttribute attr = {.dataType = TYPE_FILE};
    SessionParam *sessionParam = GenerateParamTest(&attr);
    ASSERT_NE(sessionParam, nullptr);
    int32_t ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_FILE);
    EXPECT_NE(ret, LANE_T_MSG);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest005
 * @tc.desc: TransGetLaneTransTypeBySession with TYPE_STREAM attr returns
 *           LANE_T_RAW_STREAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest005, TestSize.Level1)
{
    SessionAttribute attr = {.dataType = TYPE_STREAM};
    SessionParam *sessionParam = GenerateParamTest(&attr);
    ASSERT_NE(sessionParam, nullptr);
    int32_t ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);
    EXPECT_NE(ret, LANE_T_MSG);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransGetLaneTransTypeBySessionTest006
 * @tc.desc: TransGetLaneTransTypeBySession with LANE_T_BUTT dataType returns
 *           LANE_T_BUTT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneTransTypeBySessionTest006, TestSize.Level1)
{
    SessionAttribute attr = {.dataType = LANE_T_BUTT};
    SessionParam *sessionParam = GenerateParamTest(&attr);
    ASSERT_NE(sessionParam, nullptr);
    int32_t ret = TransGetLaneTransTypeBySession(sessionParam);
    EXPECT_EQ(ret, LANE_T_BUTT);
    EXPECT_NE(ret, LANE_T_MSG);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransGetLaneLinkTypeBySessionLinkTypeTest001
 * @tc.desc: TransGetLaneLinkTypeBySessionLinkType maps WIFI_WLAN_5G to
 *           LANE_WLAN_5G.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneLinkTypeBySessionLinkTypeTest001, TestSize.Level1)
{
    LinkType type = static_cast<LinkType>(LINK_TYPE_WIFI_WLAN_5G);
    LaneLinkType ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_WLAN_5G);
    EXPECT_NE(ret, LANE_WLAN_2P4G);
    EXPECT_NE(ret, LANE_P2P);
    EXPECT_NE(ret, LANE_BR);
}

/*
 * @tc.name: TransGetLaneLinkTypeBySessionLinkTypeTest002
 * @tc.desc: TransGetLaneLinkTypeBySessionLinkType maps WIFI_WLAN_2G to
 *           LANE_WLAN_2P4G.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneLinkTypeBySessionLinkTypeTest002, TestSize.Level1)
{
    LinkType type = static_cast<LinkType>(LINK_TYPE_WIFI_WLAN_2G);
    LaneLinkType ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_WLAN_2P4G);
    EXPECT_NE(ret, LANE_WLAN_5G);
    EXPECT_NE(ret, LANE_P2P);
    EXPECT_NE(ret, LANE_BR);
}

/*
 * @tc.name: TransGetLaneLinkTypeBySessionLinkTypeTest003
 * @tc.desc: TransGetLaneLinkTypeBySessionLinkType maps WIFI_P2P to LANE_P2P.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneLinkTypeBySessionLinkTypeTest003, TestSize.Level1)
{
    LinkType type = static_cast<LinkType>(LINK_TYPE_WIFI_P2P);
    LaneLinkType ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_P2P);
    EXPECT_NE(ret, LANE_WLAN_5G);
    EXPECT_NE(ret, LANE_WLAN_2P4G);
    EXPECT_NE(ret, LANE_BR);
}

/*
 * @tc.name: TransGetLaneLinkTypeBySessionLinkTypeTest004
 * @tc.desc: TransGetLaneLinkTypeBySessionLinkType maps BR to LANE_BR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneLinkTypeBySessionLinkTypeTest004, TestSize.Level1)
{
    LinkType type = static_cast<LinkType>(LINK_TYPE_BR);
    LaneLinkType ret = TransGetLaneLinkTypeBySessionLinkType(type);
    EXPECT_EQ(ret, LANE_BR);
    EXPECT_NE(ret, LANE_WLAN_5G);
    EXPECT_NE(ret, LANE_P2P);
    EXPECT_NE(ret, LANE_WLAN_2P4G);
}

/*
 * @tc.name: TransformSessionPreferredToLanePreferredTest001
 * @tc.desc: Null param calls for TransformSessionPreferredToLanePreferred do
 *           not crash, and IsDbdSession with null returns false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransformSessionPreferredToLanePreferredTest001, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionAttribute sessionAttr = {.dataType = LANE_T_BUTT, .linkTypeNum = 4};
    SessionParam *sessionParam = GenerateParamTest(&sessionAttr);
    ASSERT_NE(sessionParam, nullptr);
    LanePreferredLinkList *preferred = reinterpret_cast<LanePreferredLinkList *>(
        SoftBusCalloc(sizeof(LanePreferredLinkList)));
    ASSERT_NE(preferred, nullptr);
    (void)memset_s(preferred, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam, preferred, nullptr);
    TransformSessionPreferredToLanePreferred(sessionParam, nullptr, nullptr);
    TransformSessionPreferredToLanePreferred(nullptr, preferred, nullptr);
    bool res = IsDbdSession(nullptr);
    EXPECT_FALSE(res);
    SoftBusFree(sessionParam);
    SoftBusFree(preferred);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransformSessionPreferredToLanePreferredTest002
 * @tc.desc: TransformSessionPreferredToLanePreferred with negative linkTypeNum
 *           does not crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransformSessionPreferredToLanePreferredTest002, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionAttribute sessionAttr = {.dataType = LANE_T_BUTT, .linkTypeNum = -1};
    SessionParam *sessionParam = GenerateParamTest(&sessionAttr);
    ASSERT_NE(sessionParam, nullptr);
    LanePreferredLinkList *preferred = reinterpret_cast<LanePreferredLinkList *>(
        SoftBusCalloc(sizeof(LanePreferredLinkList)));
    ASSERT_NE(preferred, nullptr);
    (void)memset_s(preferred, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam, preferred, nullptr);
    SoftBusFree(sessionParam);
    SoftBusFree(preferred);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransformSessionPreferredToLanePreferredTest003
 * @tc.desc: TransformSessionPreferredToLanePreferred with linkTypeNum exceeding
 *           max does not crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransformSessionPreferredToLanePreferredTest003, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionAttribute sessionAttr1 = {.dataType = LANE_T_BUTT, .linkTypeNum = 5};
    SessionParam *sessionParam1 = GenerateParamTest(&sessionAttr1);
    ASSERT_NE(sessionParam1, nullptr);
    LanePreferredLinkList *preferred1 = reinterpret_cast<LanePreferredLinkList *>(
        SoftBusCalloc(sizeof(LanePreferredLinkList)));
    ASSERT_NE(preferred1, nullptr);
    (void)memset_s(preferred1, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam1, preferred1, nullptr);
    SoftBusFree(sessionParam1);
    SoftBusFree(preferred1);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransformSessionPreferredToLanePreferredTest004
 * @tc.desc: TransformSessionPreferredToLanePreferred with linkTypeNum=7 does
 *           not crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransformSessionPreferredToLanePreferredTest004, TestSize.Level1)
{
    int32_t ret = TransReqLanePendingInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionAttribute sessionAttr2 = {.dataType = LANE_T_BUTT, .linkTypeNum = 7};
    SessionParam *sessionParam2 = GenerateParamTest(&sessionAttr2);
    ASSERT_NE(sessionParam2, nullptr);
    LanePreferredLinkList *preferred2 = reinterpret_cast<LanePreferredLinkList *>(
        SoftBusCalloc(sizeof(LanePreferredLinkList)));
    ASSERT_NE(preferred2, nullptr);
    (void)memset_s(preferred2, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    TransformSessionPreferredToLanePreferred(sessionParam2, preferred2, nullptr);
    SoftBusFree(sessionParam2);
    SoftBusFree(preferred2);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransSoftBusCondWaitTest001
 * @tc.desc: TransSoftBusCondWait with null cond and mutex returns invalid
 *           param for both zero and nonzero timeout.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransSoftBusCondWaitTest001, TestSize.Level1)
{
    int32_t ret = TransSoftBusCondWait(nullptr, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusCond *cond = nullptr;
    SoftBusMutex *mutex = nullptr;
    uint32_t timeMillis = 1;
    ret = TransSoftBusCondWait(cond, mutex, timeMillis);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransWaitingRequestCallbackTest001
 * @tc.desc: TransWaitingRequestCallback without init returns not find.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransWaitingRequestCallbackTest001, TestSize.Level1)
{
    TransReqLanePendingDeinit();
    uint32_t laneHandle = 1;
    int32_t ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    (void)TransReqLanePendingInit();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransWaitingRequestCallbackTest002
 * @tc.desc: TransWaitingRequestCallback with no pending item and nonexistent
 *           id returns not find.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransWaitingRequestCallbackTest002, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    uint32_t invalidId = 111;
    ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingRequestCallback(invalidId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransWaitingRequestCallbackTest003
 * @tc.desc: TransWaitingRequestCallback with valid handle after update returns
 *           ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransWaitingRequestCallbackTest003, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LaneConnInfo connInfo;
    connInfo.type = LANE_WLAN_5G;
    bool bSucc = true;
    ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, bSucc, &connInfo, false, SOFTBUS_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransWaitingRequestCallbackTest004
 * @tc.desc: TransWaitingRequestCallback after deinit returns no init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransWaitingRequestCallbackTest004, TestSize.Level1)
{
    TransReqLanePendingDeinit();
    uint32_t laneHandle = 1;
    int32_t ret = TransWaitingRequestCallback(laneHandle);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_NE(ret, SOFTBUS_NOT_FIND);
    EXPECT_NE(ret, SOFTBUS_OK);
    (void)TransReqLanePendingInit();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransAddLaneReqToPendingAndWaitingTest001
 * @tc.desc: TransAddLaneReqToPendingAndWaiting returns invalid param when
 *           module not initialized or request info is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAddLaneReqToPendingAndWaitingTest001, TestSize.Level1)
{
    (void)LnnInitDistributedLedger();
    TransOption trans = {
        .transType = LANE_T_MSG,
        .expectedBw = 1,
        .pid = 1,
        .expectedLink = {
            .linkTypeNum = 2,
            .linkType = { LANE_WLAN_2P4G, LANE_P2P },
        },
    };
    uint32_t laneHandle = 1;
    LaneRequestOption requestOption = {.type = LANE_TYPE_TRANS};
    (void)memcpy_s(&trans.networkId, NETWORK_ID_BUF_LEN, "networkId", strlen("networkId") + 1);
    NetWorkingChannelInfo info = {
        .channelId = INVALID_CHANNEL_ID,
        .isNetWorkingChannel = false,
    };
    (void)memcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, g_sessionName, SESSION_NAME_SIZE_MAX);
    int32_t ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransReqLanePendingInit();
    (void)memcpy_s(&requestOption.requestInfo, sizeof(TransOption), &trans, sizeof(TransOption));
    ret = TransAddLaneReqToPendingAndWaiting(&info, laneHandle, &requestOption);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)TransDelLaneReqFromPendingList(laneHandle, false);
    LnnDeinitDistributedLedger();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneInfoByOptionTest001
 * @tc.desc: TransGetLaneInfoByOption returns invalid param for null
 *           requestOption and incomplete requestInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneInfoByOptionTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    uint32_t laneHandle = 1;
    LaneRequestOption requestOption = {.type = LANE_TYPE_TRANS};
    LaneConnInfo connInfo;
    NetWorkingChannelInfo info = {
        .channelId = INVALID_CHANNEL_ID,
        .isNetWorkingChannel = false,
    };
    (void)memcpy_s(info.sessionName, SESSION_NAME_SIZE_MAX, g_sessionName, SESSION_NAME_SIZE_MAX);
    int32_t ret = TransGetLaneInfoByOption(nullptr, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetLaneInfoByOption(&requestOption, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)InitLane();
    ret = TransGetLaneInfoByOption(&requestOption, &connInfo, &laneHandle, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    (void)LnnFreeLane(laneHandle);
    DeinitLane();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransUpdateLaneConnInfoByLaneHandleTest004
 * @tc.desc: TransUpdateLaneConnInfoByLaneHandle with nonexistent handle after
 *           lane init returns node not found.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransUpdateLaneConnInfoByLaneHandleTest004, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    (void)InitLane();
    uint32_t laneHandle = 1;
    uint32_t errCode = SOFTBUS_OK;
    LaneConnInfo connInfo;
    int32_t ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, true, &connInfo, false, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
    (void)LnnFreeLane(laneHandle);
    DeinitLane();
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransSessionServerAddItemTest001
 * @tc.desc: TransSessionServerAddItem with valid node returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransSessionServerAddItemTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    SessionServer *node = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_NE(node, nullptr);
    (void)memcpy_s(node->sessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", strlen("normal sessionName") + 1);
    int32_t ret = TransSessionServerAddItem(node);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionServerDelItem(g_sessionName, 1);
    SoftBusFree(node);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: TransGetLaneInfoTest001
 * @tc.desc: TransGetLaneInfo with null param returns invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetLaneInfoTest001, TestSize.Level1)
{
    (void)TransReqLanePendingInit();
    LaneConnInfo connInfo = {
        .type = LANE_P2P,
        .connInfo.p2p.protocol = 1,
        .connInfo.p2p.localIp = {"local Ip"},
        .connInfo.p2p.peerIp = {"peer Ip"},
    };
    uint32_t laneHandle = 1;
    int32_t ret = TransGetLaneInfo(nullptr, &connInfo, &laneHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
    TransReqLanePendingDeinit();
}

/*
 * @tc.name: SetConnInfoTest001
 * @tc.desc: SetWlanConnInfo, SetBrConnInfo, and SetBleConnInfo all return ok
 *           with valid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, SetConnInfoTest001, TestSize.Level1)
{
    WlanConnInfo wlanInfo;
    ConnectOption wlanOpt;
    int32_t ret = SetWlanConnInfo(&wlanInfo, &wlanOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    BrConnInfo brInfo;
    ConnectOption brOpt;
    ret = SetBrConnInfo(&brInfo, &brOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    BleConnInfo bleInfo;
    ConnectOption bleOpt;
    ret = SetBleConnInfo(&bleInfo, &bleOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest001
 * @tc.desc: TransGetConnectOptByConnInfo with null connInfo returns invalid
 *           param, and LANE_LINK_TYPE_BUTT returns get conn opt failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest001, TestSize.Level1)
{
    ConnectOption connOpt;
    int32_t ret = TransGetConnectOptByConnInfo(nullptr, &connOpt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    LaneConnInfo info = {.type = LANE_LINK_TYPE_BUTT};
    ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CONN_OPT_FAILED, ret);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest002
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_P2P type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest002, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_P2P};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest003
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_P2P and peerIp returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest003, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_P2P};
    (void)strcpy_s(info.connInfo.p2p.peerIp, IP_LEN, "12.34.56.10");
    ConnectOption connOpt;
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest004
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_WLAN_2P4G type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest004, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_WLAN_2P4G};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest005
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_BR type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest005, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_BR};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest006
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_P2P_REUSE type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest006, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_P2P_REUSE};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest007
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_BLE_DIRECT type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest007, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_BLE_DIRECT};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest008
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_BLE type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest008, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_BLE};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest009
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_HML type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest009, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_HML};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetConnectOptByConnInfoTest010
 * @tc.desc: TransGetConnectOptByConnInfo with LANE_SOFTAP_P2P type returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectOptByConnInfoTest010, TestSize.Level1)
{
    LaneConnInfo info = {.type = LANE_SOFTAP_P2P};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(&info, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetAuthTypeByNetWorkIdTest001
 * @tc.desc: TransGetAuthTypeByNetWorkId without ledger returns false for
 *           valid and null networkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetAuthTypeByNetWorkIdTest001, TestSize.Level1)
{
    const char *peerNetWorkId = "peer networkId";
    bool ret = TransGetAuthTypeByNetWorkId(peerNetWorkId);
    EXPECT_FALSE(ret);
    EXPECT_NE(ret, true);
    ret = TransGetAuthTypeByNetWorkId(nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: TransGetAuthTypeByNetWorkIdTest002
 * @tc.desc: TransGetAuthTypeByNetWorkId with ledger initialized returns false
 *           for fake and null networkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetAuthTypeByNetWorkIdTest002, TestSize.Level1)
{
    (void)LnnInitDistributedLedger();
    const char *peerNetWorkId = "peer networkId";
    bool ret = TransGetAuthTypeByNetWorkId(peerNetWorkId);
    EXPECT_FALSE(ret);
    EXPECT_NE(ret, true);
    ret = TransGetAuthTypeByNetWorkId(nullptr);
    EXPECT_FALSE(ret);
    LnnDeinitDistributedLedger();
}

/*
 * @tc.name: CheckSessionNameValidOnAuthChannelTest001
 * @tc.desc: CheckSessionNameValidOnAuthChannel with null and invalid names
 *           returns false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, CheckSessionNameValidOnAuthChannelTest001, TestSize.Level1)
{
    bool ret = CheckSessionNameValidOnAuthChannel(nullptr);
    EXPECT_FALSE(ret);
    const char *invalidName = "invalid name";
    ret = CheckSessionNameValidOnAuthChannel(invalidName);
    EXPECT_FALSE(ret);
    EXPECT_NE(ret, true);
}

/*
 * @tc.name: CheckSessionNameValidOnAuthChannelTest002
 * @tc.desc: CheckSessionNameValidOnAuthChannel with valid auth channel names
 *           returns true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, CheckSessionNameValidOnAuthChannelTest002, TestSize.Level1)
{
    const char *sessionName = "ohos.distributedhardware.devicemanager.resident";
    bool ret = CheckSessionNameValidOnAuthChannel(sessionName);
    EXPECT_TRUE(ret);
    const char *newSessionName = "IShareAuthSession";
    ret = CheckSessionNameValidOnAuthChannel(newSessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: PeerDeviceIsLegacyOsTest001
 * @tc.desc: PeerDeviceIsLegacyOs with valid and null params returns false for
 *           non-legacy device.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, PeerDeviceIsLegacyOsTest001, TestSize.Level1)
{
    bool ret = PeerDeviceIsLegacyOs(g_networkId, g_sessionName);
    EXPECT_FALSE(ret);
    ret = PeerDeviceIsLegacyOs(nullptr, g_sessionName);
    EXPECT_FALSE(ret);
    ret = PeerDeviceIsLegacyOs(g_networkId, nullptr);
    EXPECT_FALSE(ret);
    EXPECT_NE(ret, true);
}

/*
 * @tc.name: SetHmlConnectInfoTest001
 * @tc.desc: SetHmlConnectInfo with valid p2pInfo and connOpt returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, SetHmlConnectInfoTest001, TestSize.Level1)
{
    P2pConnInfo *p2pInfo = reinterpret_cast<P2pConnInfo *>(SoftBusMalloc(sizeof(P2pConnInfo)));
    ASSERT_NE(p2pInfo, nullptr);
    ConnectOption *connOpt = reinterpret_cast<ConnectOption *>(SoftBusMalloc(sizeof(ConnectOption)));
    ASSERT_NE(connOpt, nullptr);
    int32_t ret = SetHmlConnectInfo(p2pInfo, connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(p2pInfo);
    SoftBusFree(connOpt);
}

/*
 * @tc.name: GetAllocInfoExtBySessionParamTest001
 * @tc.desc: GetAllocInfoExtBySessionParam with null param or null allocInfo
 *           returns invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetAllocInfoExtBySessionParamTest001, TestSize.Level1)
{
    SessionParam sessionParam;
    LaneAllocInfoExt laneInfoExt;
    int32_t ret = GetAllocInfoExtBySessionParam(nullptr, &laneInfoExt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetAllocInfoExtBySessionParam(&sessionParam, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetAllocInfoExtBySessionParamTest002
 * @tc.desc: GetAllocInfoExtBySessionParam with null attr returns invalid
 *           session type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetAllocInfoExtBySessionParamTest002, TestSize.Level1)
{
    SessionParam sessionParam = {
        .peerDeviceId = "test_device_id",
        .attr = nullptr
    };
    LaneAllocInfoExt laneInfoExt;
    int32_t ret = GetAllocInfoExtBySessionParam(&sessionParam, &laneInfoExt);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_TYPE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetAllocInfoExtBySessionParamTest003
 * @tc.desc: GetAllocInfoExtBySessionParam with TYPE_BYTES attr returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, GetAllocInfoExtBySessionParamTest003, TestSize.Level1)
{
    const SessionAttribute myAttr = {.dataType = TYPE_BYTES};
    SessionParam sessionParam = {
        .peerDeviceId = "test_device_id",
        .attr = &myAttr
    };
    LaneAllocInfoExt laneInfoExt;
    int32_t ret = GetAllocInfoExtBySessionParam(&sessionParam, &laneInfoExt);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransAsyncGetLaneInfoByExtTest001
 * @tc.desc: TransAsyncGetLaneInfoByExt with null param, null laneHandle, or
 *           null appInfo returns invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAsyncGetLaneInfoByExtTest001, TestSize.Level1)
{
    SessionParam sessionParam;
    uint32_t laneHandle = 2;
    AppInfo appInfo;
    int32_t ret = TransAsyncGetLaneInfoByExt(nullptr, &laneHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByExt(&sessionParam, nullptr, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAsyncGetLaneInfoByExt(&sessionParam, &laneHandle, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransAsyncGetLaneInfoByExtTest002
 * @tc.desc: TransAsyncGetLaneInfoByExt with null attr returns lane info err.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAsyncGetLaneInfoByExtTest002, TestSize.Level1)
{
    SessionParam sessionParam;
    sessionParam.attr = nullptr;
    uint32_t laneHandle = 2;
    AppInfo appInfo;
    int32_t ret = TransAsyncGetLaneInfoByExt(&sessionParam, &laneHandle, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LANE_INFO_ERR);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransAsyncGetLaneInfoByExtTest003
 * @tc.desc: TransAsyncGetLaneInfoByExt with valid session param and BR link
 *           type requests lane allocation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAsyncGetLaneInfoByExtTest003, TestSize.Level1)
{
    const SessionAttribute myAttr = {
        .dataType = TYPE_BYTES,
        .linkType = { LINK_TYPE_BR }
    };
    SessionParam sessionParam = {
        .peerDeviceId = "test_device_id",
        .sessionName = "test_session_name",
        .sessionId = 6,
        .isQosLane = true,
        .isAsync = false,
        .attr = &myAttr
    };
    AppInfo appInfo = {
        .callingTokenId = 358,
        .timeStart = 9181024
    };
    uint32_t laneHandle;
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SocketWithChannelInfo *socketChannelInfo =
        static_cast<SocketWithChannelInfo *>(SoftBusCalloc(sizeof(SocketWithChannelInfo)));
    ASSERT_NE(socketChannelInfo, nullptr);
    socketChannelInfo->sessionId = 6;
    (void)strcpy_s(socketChannelInfo->sessionName, SESSION_NAME_SIZE_MAX, "test_session_name");
    ListAdd(&g_socketChannelList->list, &socketChannelInfo->node);
    ret = TransAsyncReqLanePendingInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAsyncGetLaneInfoByExt(&sessionParam, &laneHandle, &appInfo);
    EXPECT_NE(ret, SOFTBUS_OK);
    TransAsyncReqLanePendingDeinit();
    ListDelete(&(socketChannelInfo->node));
    SoftBusFree(socketChannelInfo);
    TransSocketLaneMgrDeinit();
}

/*
 * @tc.name: SetP2pExtConnInfoTest001
 * @tc.desc: SetP2pExtConnInfo with valid p2pInfo and connOpt returns ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, SetP2pExtConnInfoTest001, TestSize.Level1)
{
    P2pConnInfo p2pInfo;
    (void)memset_s(&p2pInfo, sizeof(P2pConnInfo), 0, sizeof(P2pConnInfo));
    (void)strcpy_s(p2pInfo.peerIp, IP_LEN, "12.34.45.00");
    ConnectOption connOpt;
    int32_t ret = SetP2pExtConnInfo(&p2pInfo, &connOpt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransAddSocketChannelInfoTest001
 * @tc.desc: TransAddSocketChannelInfo with null sessionName or zero sessionId
 *           returns error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransAddSocketChannelInfoTest001, TestSize.Level1)
{
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    int32_t ret = TransAddSocketChannelInfo(nullptr, 1, 1024, 3, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_NAME);
    ret = TransAddSocketChannelInfo(g_sessionName, 0, 1024, 3, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransUpdateSocketChannelInfoBySessionTest001
 * @tc.desc: TransUpdateSocketChannelInfoBySession with null sessionName
 *           returns invalid session name, and without init returns no init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransUpdateSocketChannelInfoBySessionTest001, TestSize.Level1)
{
    int32_t ret = TransUpdateSocketChannelInfoBySession(nullptr, 2, 1024, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_NAME);
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    ret = TransUpdateSocketChannelInfoBySession(g_sessionName, 15, 1024, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransDeleteSocketChannelInfoBySessionTest001
 * @tc.desc: TransDeleteSocketChannelInfoBySession without init returns no init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransDeleteSocketChannelInfoBySessionTest001, TestSize.Level1)
{
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    int32_t ret = TransDeleteSocketChannelInfoBySession(g_sessionName, 2);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransDeleteSocketChannelInfoBySession(nullptr, 2);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransSetSocketChannelStateBySessionTest001
 * @tc.desc: TransSetSocketChannelStateBySession without init returns no init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransSetSocketChannelStateBySessionTest001, TestSize.Level1)
{
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    int32_t ret = TransSetSocketChannelStateBySession(g_sessionName, 2, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransSetSocketChannelStateBySession(nullptr, 2, CORE_SESSION_STATE_INIT);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransGetSocketChannelStateByChannelTest001
 * @tc.desc: TransGetSocketChannelStateByChannel with null state returns
 *           invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetSocketChannelStateByChannelTest001, TestSize.Level1)
{
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    int32_t ret = TransGetSocketChannelStateByChannel(1024, CHANNEL_TYPE_TCP_DIRECT, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_NE(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransGetConnectTypeByChannelIdTest001
 * @tc.desc: TransGetConnectTypeByChannelId without init returns no init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetConnectTypeByChannelIdTest001, TestSize.Level1)
{
    if (g_channelLaneList != nullptr) {
        g_channelLaneList = nullptr;
    }
    ConnectType connectType;
    int32_t ret = TransGetConnectTypeByChannelId(1024, &connectType);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransGetPidFromSocketChannelInfoBySessionTest001
 * @tc.desc: TransGetPidFromSocketChannelInfoBySession with zero sessionId
 *           returns invalid session id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneTest, TransGetPidFromSocketChannelInfoBySessionTest001, TestSize.Level1)
{
    if (g_socketChannelList != nullptr) {
        TransSocketLaneMgrDeinit();
    }
    int32_t ret = TransGetPidFromSocketChannelInfoBySession(g_sessionName, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = TransGetPidFromSocketChannelInfoBySession(nullptr, 1, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

} // namespace OHOS
