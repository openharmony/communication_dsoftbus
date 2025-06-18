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

#include "time_sync_other_mock.h"
#include "lnn_time_sync_manager.h"
#include "lnn_time_sync_manager.c"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
// data field

constexpr char TEST_PKG_NAME[] = "com.softbus.test";
constexpr char TEST_NODE1_NETWORK_ID[] = "235689BNHFCA";
constexpr char TEST_NODE2_NETWORK_ID[] = "235689BNHFCB";
constexpr int32_t TEST_PID = 1;

class LNNTimeSyncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTimeSyncTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void LNNTimeSyncTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNTimeSyncTest::SetUp() {}

void LNNTimeSyncTest::TearDown() {}

static void MyPostMessageFunc(const SoftBusLooper *looper, SoftBusMessage *msg)
{
    (void)looper;
    (void)msg;
}

static SoftBusLooper g_Looper = {
    .PostMessage = MyPostMessageFunc,
};

/*
 * @tc.name: LnnTimeSyncManager_Test01
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test01, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnStartTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnStopTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara para;
    para.accuracy = LOW_ACCURACY;
    para.period = SHORT_PERIOD;
    para.pid = TEST_PID;
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&para);
    ASSERT_TRUE(info != nullptr);
    StartTimeSyncReq *item = CreateStartTimeSyncReq(
        TEST_PKG_NAME, LOW_ACCURACY, SHORT_PERIOD, TEST_PID);
    ASSERT_TRUE(item != nullptr);
    item->pid = TEST_PID;
    ListAdd(&info->startReqList, &item->node);
    TryUpdateTimeSyncReq(info);
    StartTimeSyncReqMsgPara startReq;
    startReq.accuracy = HIGH_ACCURACY;
    startReq.period = LONG_PERIOD;
    startReq.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startReq.pkgName, PKG_NAME_SIZE_MAX, TEST_PKG_NAME), EOK);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TryUpdateStartTimeSyncReq(info, &startReq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveAllStartTimeSyncReq(info);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test02
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test02, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnStartTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnStopTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara para;
    para.accuracy = HIGH_ACCURACY;
    para.period = LONG_PERIOD;
    para.pid = TEST_PID;
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&para);
    ASSERT_TRUE(info != nullptr);
    StartTimeSyncReq *item = CreateStartTimeSyncReq(
        TEST_PKG_NAME, HIGH_ACCURACY, LONG_PERIOD, TEST_PID);
    ASSERT_TRUE(item != nullptr);
    item->pid = TEST_PID;
    ListAdd(&info->startReqList, &item->node);
    TryUpdateTimeSyncReq(info);
    StartTimeSyncReqMsgPara startReq;
    startReq.accuracy = NORMAL_ACCURACY;
    startReq.period = NORMAL_PERIOD;
    startReq.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startReq.pkgName, PKG_NAME_SIZE_MAX, TEST_PKG_NAME), EOK);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TryUpdateStartTimeSyncReq(info, &startReq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveAllStartTimeSyncReq(info);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test03
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test03, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnStartTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnStopTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara para;
    para.accuracy = HIGH_ACCURACY;
    para.period = SHORT_PERIOD;
    para.pid = TEST_PID;
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&para);
    ASSERT_TRUE(info != nullptr);
    StartTimeSyncReq *item = CreateStartTimeSyncReq(
        TEST_PKG_NAME, HIGH_ACCURACY, SHORT_PERIOD, TEST_PID);
    ASSERT_TRUE(item != nullptr);
    item->pid = TEST_PID;
    ListAdd(&info->startReqList, &item->node);
    TryUpdateTimeSyncReq(info);
    StartTimeSyncReqMsgPara startReq;
    startReq.accuracy = NORMAL_ACCURACY;
    startReq.period = LONG_PERIOD;
    startReq.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startReq.pkgName, PKG_NAME_SIZE_MAX, TEST_PKG_NAME), EOK);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TryUpdateStartTimeSyncReq(info, &startReq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveAllStartTimeSyncReq(info);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test04
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test04, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnStartTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnStopTimeSyncImplPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara para;
    para.accuracy = LOW_ACCURACY;
    para.period = LONG_PERIOD;
    para.pid = TEST_PID;
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&para);
    ASSERT_TRUE(info != nullptr);
    StartTimeSyncReq *item = CreateStartTimeSyncReq(
        TEST_PKG_NAME, LOW_ACCURACY, LONG_PERIOD, TEST_PID);
    ASSERT_TRUE(item != nullptr);
    item->pid = TEST_PID;
    ListAdd(&info->startReqList, &item->node);
    TryUpdateTimeSyncReq(info);
    StartTimeSyncReqMsgPara startReq;
    startReq.accuracy = HIGH_ACCURACY;
    startReq.period = NORMAL_PERIOD;
    startReq.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startReq.pkgName, PKG_NAME_SIZE_MAX, TEST_PKG_NAME), EOK);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TryUpdateStartTimeSyncReq(info, &startReq);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveAllStartTimeSyncReq(info);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test05
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test05, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillOnce(Return(nullptr)).WillRepeatedly(Return(&g_Looper));
    SoftBusMessage msg;
    msg.what = MSG_TYPE_MAX;
    TimeSyncMessageHandler(&msg);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_LOOPER_ERR);
    ret = LnnStartTimeSync(TEST_PKG_NAME, 0, TEST_NODE1_NETWORK_ID, LOW_ACCURACY, SHORT_PERIOD);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = LnnStopTimeSync(TEST_PKG_NAME, TEST_NODE1_NETWORK_ID, 0);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test06
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test06, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplInitPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplDeinitPacked).WillRepeatedly(Return());
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara startPara;
    startPara.accuracy = HIGH_ACCURACY;
    startPara.period = LONG_PERIOD;
    startPara.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startPara.targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&startPara);
    ASSERT_TRUE(info != nullptr);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListAdd(&g_timeSyncCtrl.reqList, &info->node);
    TimeSyncCompleteMsgPara *timePara = (TimeSyncCompleteMsgPara *)SoftBusMalloc(sizeof(TimeSyncCompleteMsgPara));
    ASSERT_NE(timePara, nullptr);
    timePara->retCode = SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_ERR;
    EXPECT_EQ(strcpy_s(timePara->networkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    ret = ProcessTimeSyncComplete(timePara);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test07
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test07, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplInitPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplDeinitPacked).WillRepeatedly(Return());
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    EXPECT_CALL(timeSyncOtherMock, LnnNotifyTimeSyncResult).WillRepeatedly(Return());
    StartTimeSyncReqMsgPara startPara;
    startPara.accuracy = HIGH_ACCURACY;
    startPara.period = LONG_PERIOD;
    startPara.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startPara.targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&startPara);
    ASSERT_TRUE(info != nullptr);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListAdd(&g_timeSyncCtrl.reqList, &info->node);
    StartTimeSyncReqMsgPara *msgPara = (StartTimeSyncReqMsgPara *)SoftBusMalloc(sizeof(StartTimeSyncReqMsgPara));
    ASSERT_NE(msgPara, nullptr);
    EXPECT_EQ(strcpy_s(msgPara->targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    ret = ProcessStartTimeSyncRequest(msgPara);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyTimeSyncResult(info, 1, SOFTBUS_NETWORK_TIME_SYNC_INTERFERENCE);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test08
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test08, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplInitPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplDeinitPacked).WillRepeatedly(Return());
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara startPara;
    startPara.accuracy = LOW_ACCURACY;
    startPara.period = LONG_PERIOD;
    startPara.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startPara.targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE2_NETWORK_ID), EOK);
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&startPara);
    ASSERT_TRUE(info != nullptr);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListAdd(&g_timeSyncCtrl.reqList, &info->node);
    TimeSyncCompleteMsgPara *timePara = (TimeSyncCompleteMsgPara *)SoftBusMalloc(sizeof(TimeSyncCompleteMsgPara));
    ASSERT_NE(timePara, nullptr);
    EXPECT_EQ(strcpy_s(timePara->networkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    ret = ProcessTimeSyncComplete(timePara);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    StopTimeSyncReqMsgPara *msgPara = (StopTimeSyncReqMsgPara *)SoftBusMalloc(sizeof(StopTimeSyncReqMsgPara));
    ASSERT_NE(msgPara, nullptr);
    EXPECT_EQ(strcpy_s(msgPara->targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE2_NETWORK_ID), EOK);
    ret = ProcessStopTimeSyncRequest(msgPara);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitTimeSync();
}

/*
 * @tc.name: LnnTimeSyncManager_Test9
 * @tc.desc: lnn time sync manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTimeSyncTest, LnnTimeSyncManager_Test9, TestSize.Level1)
{
    NiceMock<TimeSyncOtherDepsInterfaceMock> timeSyncOtherMock;
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplInitPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(timeSyncOtherMock, LnnTimeSyncImplDeinitPacked).WillRepeatedly(Return());
    EXPECT_CALL(timeSyncOtherMock, GetLooper).WillRepeatedly(Return(&g_Looper));
    StartTimeSyncReqMsgPara startPara;
    startPara.accuracy = HIGH_ACCURACY;
    startPara.period = LONG_PERIOD;
    startPara.pid = TEST_PID;
    EXPECT_EQ(strcpy_s(startPara.targetNetworkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    TimeSyncReqInfo *info = CreateTimeSyncReqInfo(&startPara);
    ASSERT_TRUE(info != nullptr);
    int32_t ret = LnnInitTimeSync();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListAdd(&g_timeSyncCtrl.reqList, &info->node);
    TimeSyncCompleteMsgPara *timePara = (TimeSyncCompleteMsgPara *)SoftBusMalloc(sizeof(TimeSyncCompleteMsgPara));
    ASSERT_NE(timePara, nullptr);
    timePara->retCode = SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_TIMEOUT;
    EXPECT_EQ(strcpy_s(timePara->networkId, NETWORK_ID_BUF_LEN, TEST_NODE1_NETWORK_ID), EOK);
    ret = ProcessTimeSyncComplete(timePara);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitTimeSync();
}
} // namespace OHOS
