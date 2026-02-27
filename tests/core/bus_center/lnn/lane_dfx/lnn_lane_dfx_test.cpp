/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_lane_dfx.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char PEER_NETWORK_ID[] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
constexpr uint32_t LANE_REQ_ID = 268435436;
constexpr uint32_t MIN_BW = 83886080;
constexpr uint32_t MAX_LANE_LATENCY = 2000;
constexpr uint32_t MIN_LANE_LATENCY = 1000;
constexpr uint32_t NUM_ZERO = 0;
constexpr uint32_t NUM_ONE = 0;
constexpr uint32_t ERR_CODE = SOFTBUS_OK;
constexpr uint32_t DEVICE_CAP = 47;
constexpr uint32_t ONLINE_STATE = 6;
constexpr uint64_t LANE_ID = 268435437;
constexpr uint64_t COMMON_DELAY = 1000;

constexpr LaneTransType TRANS_TYPE = LANE_T_MSG;
constexpr LaneLinkType LANE_LINK_TYPE = LANE_HML;
constexpr WdGuideType GUIDE_TYPE = LANE_BLE_TRIGGER;
constexpr WifiDetectState WIFI_DETECT_STATE = WIFI_DETECT_SUCC;

class LNNLaneDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneDfxTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneDfxTest start";
    InitLaneEvent();
}

void LNNLaneDfxTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneDfxTest end";
    DeinitLaneEvent();
}

void LNNLaneDfxTest::SetUp()
{
}

void LNNLaneDfxTest::TearDown()
{
}

static LaneProcess InitLaneDfxEventInfo()
{
    LaneProcess processInfo;
    processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE] = LANE_REQ_ID;
    processInfo.laneProcessList32Bit[EVENT_LANE_LINK_TYPE] = LANE_LINK_TYPE_BUTT;
    processInfo.laneProcessList32Bit[EVENT_LANE_MIN_BW] = MIN_BW;
    processInfo.laneProcessList32Bit[EVENT_LANE_MAX_LANE_LATENCY] = MAX_LANE_LATENCY;
    processInfo.laneProcessList32Bit[EVENT_LANE_MIN_LANE_LATENCY] = MIN_LANE_LATENCY;
    processInfo.laneProcessList32Bit[EVENT_LANE_RTT_LEVEL] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_TRANS_TYPE] = LANE_T_FILE;
    processInfo.laneProcessList32Bit[EVENT_LOCAL_CAP] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_REMOTE_CAP] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_ONLINE_STATE] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_GUIDE_TYPE] = LANE_CHANNEL_BUTT;
    processInfo.laneProcessList32Bit[EVENT_GUIDE_RETRY] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_WIFI_DETECT_STATE] = WIFI_DETECT_BUTT;
    processInfo.laneProcessList32Bit[EVENT_HML_REUSE] = NUM_ZERO;
    processInfo.laneProcessList32Bit[EVENT_DELAY_FREE] = NUM_ZERO;
    processInfo.laneProcessList64Bit[EVENT_LANE_ID] = INVALID_LANE_ID;
    processInfo.laneProcessList64Bit[EVENT_WIFI_DETECT_TIME] = COMMON_DELAY;
    processInfo.laneProcessList64Bit[EVENT_COST_TIME] = COMMON_DELAY;
    int32_t ret = strcpy_s(processInfo.peerNetWorkId, NETWORK_ID_BUF_LEN, PEER_NETWORK_ID);
    if (ret != EOK) {
        GTEST_LOG_(ERROR) << "strcpy_s failed";
        return processInfo;
    }
    EXPECT_EQ(EOK, ret);
    return processInfo;
}

/*
* @tc.name: CREATE_LANE_EVENT_INFO_001
* @tc.desc: CreateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, CREATE_LANE_EVENT_INFO_001, TestSize.Level1)
{
    int32_t ret = CreateLaneEventInfo(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_001
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_001, TestSize.Level1)
{
    uint32_t invalidLaneHandle = INVALID_LANE_ID;
    int32_t ret = UpdateLaneEventInfo(invalidLaneHandle, EVENT_TRANS_TYPE,
        LANE_PROCESS_TYPE_UINT32, (void *)(&TRANS_TYPE));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_002
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_002, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_32_BIT_MAX, LANE_PROCESS_TYPE_UINT32, (void *)(&ERR_CODE));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_64_BIT_MAX, LANE_PROCESS_TYPE_UINT64, (void *)(&ERR_CODE));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_BUTT, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, INVALID_LANE_REQ_ID, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_003
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_003, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT32, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT64, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_BUTT, (void *)(&ERR_CODE));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_004
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_004, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_HANDLE,
        LANE_PROCESS_TYPE_UINT32, (void *)(&LANE_REQ_ID));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_MIN_BW, LANE_PROCESS_TYPE_UINT32, (void *)(&MIN_BW));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_MAX_LANE_LATENCY,
        LANE_PROCESS_TYPE_UINT32, (void *)(&MAX_LANE_LATENCY));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_MIN_LANE_LATENCY,
        LANE_PROCESS_TYPE_UINT32, (void *)(&MIN_LANE_LATENCY));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_RTT_LEVEL,
        LANE_PROCESS_TYPE_UINT32, (void *)(&NUM_ZERO));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT32, (void *)(&TRANS_TYPE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_005
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_005, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT32, (void *)(&TRANS_TYPE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_LINK_TYPE,
        LANE_PROCESS_TYPE_UINT32, (void *)(&LANE_LINK_TYPE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LOCAL_CAP, LANE_PROCESS_TYPE_UINT32, (void *)(&DEVICE_CAP));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_REMOTE_CAP, LANE_PROCESS_TYPE_UINT32, (void *)(&DEVICE_CAP));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_ONLINE_STATE,
        LANE_PROCESS_TYPE_UINT32, (void *)(&ONLINE_STATE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_GUIDE_TYPE, LANE_PROCESS_TYPE_UINT32, (void *)(&GUIDE_TYPE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_GUIDE_RETRY, LANE_PROCESS_TYPE_UINT32, (void *)(&NUM_ONE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_WIFI_DETECT_STATE,
        LANE_PROCESS_TYPE_UINT32, (void *)(&WIFI_DETECT_STATE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_DELAY_FREE, LANE_PROCESS_TYPE_UINT32, (void *)(&NUM_ONE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: UPDATE_LANE_EVENT_INFO_006
* @tc.desc: UpdateLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, UPDATE_LANE_EVENT_INFO_006, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_LANE_ID, LANE_PROCESS_TYPE_UINT64, (void *)(&LANE_ID));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_COST_TIME, LANE_PROCESS_TYPE_UINT64, (void *)(&COMMON_DELAY));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_WIFI_DETECT_TIME,
        LANE_PROCESS_TYPE_UINT64, (void *)(&COMMON_DELAY));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: REPORT_LANE_EVENT_INFO_001
* @tc.desc: ReportLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, REPORT_LANE_EVENT_INFO_001, TestSize.Level1)
{
    uint32_t invalidLaneHandle = INVALID_LANE_ID;
    int32_t ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, invalidLaneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: Get_LANE_EVENT_INFO_001
* @tc.desc: GetLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, Get_LANE_EVENT_INFO_001, TestSize.Level1)
{
    uint32_t invalidLaneHandle = INVALID_LANE_ID;
    LaneProcess laneProcess;
    int32_t ret = GetLaneEventInfo(invalidLaneHandle, &laneProcess);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: Get_LANE_EVENT_INFO_002
* @tc.desc: ReportLaneEventInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, Get_LANE_EVENT_INFO_002, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = GetLaneEventInfo(laneHandle, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}


/*
* @tc.name: LANE_EVENT_INFO_001
* @tc.desc: Create->Update->Report(del) test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, LANE_EVENT_INFO_001, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT32, (void *)(&TRANS_TYPE));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_EVENT_INFO_002
* @tc.desc: Create->Report(del)->Update test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, LANE_EVENT_INFO_002, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneEventInfo(laneHandle, EVENT_TRANS_TYPE, LANE_PROCESS_TYPE_UINT32, (void *)(&TRANS_TYPE));
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: LANE_EVENT_INFO_003
* @tc.desc: Create->Get->Report(del) test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, LANE_EVENT_INFO_003, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    LaneProcess laneProcess;
    GetLaneEventInfo(laneHandle, &laneProcess);
    EXPECT_EQ(laneHandle, laneProcess.laneProcessList32Bit[EVENT_LANE_HANDLE]);
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_EVENT_INFO_004
* @tc.desc: Create->Report(del)->Get test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneDfxTest, LANE_EVENT_INFO_004, TestSize.Level1)
{
    LaneProcess processInfo = InitLaneDfxEventInfo();
    int32_t ret = CreateLaneEventInfo(&processInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t laneHandle = processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE];
    ret = ReportLaneEventInfo(EVENT_STAGE_LANE_ALLOC, laneHandle, ERR_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LaneProcess laneProcess;
    ret = GetLaneEventInfo(laneHandle, &laneProcess);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}
} // namespace OHOS