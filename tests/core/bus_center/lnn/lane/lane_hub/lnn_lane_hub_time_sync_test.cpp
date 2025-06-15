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

#include "auth_mock.h"
#include "event_mock.h"
#include "ledger_mock.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_json_utils.h"
#include "softbus_error_code.h"
#include "softbus_bus_center.h"
#include "lnn_map_struct.h"
#include "lnn_node_info_struct.h"
#include "lnn_time_sync_manager.h"
#include "lnn_time_sync_manager.c"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
// data field
#define MY_ID "MY_ID"
#define TIME_SYNC_LV "TIME_SYNC_LV"
#define INTERFACE_TYPE "INTERFACE_TYPE"
#define PACKET_TYPE "PACKET_TYPE"
#define ROUND_NUM "ROUND_NUM"

#define TIMESTAMP_RECV_SEC "TIMESTAMP_RECV_SEC"
#define TIMESTAMP_RECV_USEC "TIMESTAMP_RECV_USEC"
#define TIMESTAMP_SEC "TIMESTAMP_SEC"
#define TIMESTAMP_USEC "TIMESTAMP_USEC"

class LNNTimeSyncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTimeSyncTest::SetUpTestCase()
{
    NiceMock<AuthInterfaceMock> tsLnnAuthmock;
    ON_CALL(tsLnnAuthmock, RegAuthTransListener(_, _)).WillByDefault(Return(SOFTBUS_OK));

    int32_t ret = LooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNTimeSyncTest::TearDownTestCase()
{
    NiceMock<AuthInterfaceMock> tsLnnAuthmock;
    ON_CALL(tsLnnAuthmock, UnregAuthTransListener(_)).WillByDefault(Return());

    LnnDeinitTimeSync();
    LooperDeinit();
}

void LNNTimeSyncTest::SetUp() {}

void LNNTimeSyncTest::TearDown() {}

/*
 * @tc.name: TryUpdateTimeSyncReqInfo_Test01
 * @tc.desc: try updata time sync req info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, TryUpdateTimeSyncReqInfo_Test01, TestSize.Level1)
{
    TimeSyncReqInfo info;
    bool flag;

    info.curAccuracy = NORMAL_ACCURACY;
    info.curPeriod = LONG_PERIOD;
    flag = TryUpdateTimeSyncReqInfo(&info, HIGH_ACCURACY, LONG_PERIOD);
    EXPECT_TRUE(flag);
    flag = TryUpdateTimeSyncReqInfo(&info, LOW_ACCURACY, SHORT_PERIOD);
    EXPECT_TRUE(flag);
    flag = TryUpdateTimeSyncReqInfo(&info, LOW_ACCURACY, LONG_PERIOD);
    EXPECT_FALSE(flag);
}

/*
 * @tc.name: ProcessStartTimeSyncRequest_Test01
 * @tc.desc: process start time sync req info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, ProcessStartTimeSyncRequest_Test01, TestSize.Level1)
{
    StartTimeSyncReqMsgPara *para = nullptr;
    int32_t ret = ProcessStartTimeSyncRequest(para);
    EXPECT_NE(ret, SOFTBUS_OK);
    double offset = 0;
    TimeSyncReqInfo *info = (TimeSyncReqInfo *)SoftBusCalloc(sizeof(TimeSyncReqInfo));
    ListInit(&info->node);
    ListInit(&info->startReqList);
    NotifyTimeSyncResult(info, offset, SOFTBUS_OK);
    RemoveAllStartTimeSyncReq(info);
}

/*
 * @tc.name: ProcessStopTimeSyncRequest_Test01
 * @tc.desc: process stop time sync req info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, ProcessStopTimeSyncRequest_Test01, TestSize.Level1)
{
    int32_t ret = ProcessStopTimeSyncRequest(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    StopTimeSyncReqMsgPara *para = (StopTimeSyncReqMsgPara *)SoftBusMalloc(sizeof(StopTimeSyncReqMsgPara));
    char targetNetworkId[] = "time_sync_test_targetNetworkId_001";
    EXPECT_EQ(strncpy_s(para->targetNetworkId, NETWORK_ID_BUF_LEN, targetNetworkId, strlen(targetNetworkId)), EOK);
    ret = ProcessStopTimeSyncRequest(para);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ProcessTimeSyncComplete_Test01
 * @tc.desc: process sync req info result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, ProcessTimeSyncComplete_Test01, TestSize.Level1)
{
    int32_t ret = ProcessTimeSyncComplete(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
    TimeSyncMessageHandler(nullptr);
    SoftBusMessage msg;
    msg.what = MSG_TYPE_REMOVE_ALL;
    TimeSyncMessageHandler(&msg);
    OnTimeSyncImplComplete(nullptr, 0, 0);
}

/*
 * @tc.name: CheckTimeSyncReqInfo_Test01
 * @tc.desc: check time sync req info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, CheckTimeSyncReqInfo_Test01, TestSize.Level1)
{
    NiceMock<LedgerInterfaceMock> timeSyncLedgerMock;
    ON_CALL(timeSyncLedgerMock, LnnGetRemoteStrInfo(_, _, _, _)).WillByDefault(Return(SOFTBUS_INVALID_PARAM));
    StartTimeSyncReqMsgPara info;
    bool flag = CheckTimeSyncReqInfo(&info);
    EXPECT_FALSE(flag);
}
} // namespace OHOS
