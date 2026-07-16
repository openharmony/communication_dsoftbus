/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "disc_event_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "softbus_server_frame.h"
#include "trans_channel_manager.c"
#include "trans_lane_manager.c"
#include "trans_manager_mock.h"
#include "trans_session_service.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define TRANS_TEST_PID 4700
#define TEST_PROXY_CHANNEL_ID 1026
#define TEST_TDC_CHANNEL_ID 2048
#define TEST_BUF_LEN 1024

#define TEST_LANE_ID 123456789
#define TEST_NOTIFY_CHANNEL_ID 1111
#define TEST_NEGATIVE_CHANNEL_ID (-1111)
#define TEST_CONN_CHANNEL_ID 111
#define TEST_CLOSE_CHANNEL_ID_01 112
#define TEST_CLOSE_CHANNEL_ID_02 113
#define TEST_CLOSE_CHANNEL_ID_03 114
#define TEST_CLOSE_CHANNEL_ID_04 115
#define TEST_INVALID_CHANNEL_TYPE 222
#define TEST_INVALID_CHANNEL_TYPE_LARGE 8888
#define TEST_APP_TYPE 333
#define TEST_QUALITY 444
#define TEST_SESSION_NAME_LEN 2
#define TEST_CALLING_TOKEN_ID 2
#define TEST_BUF_LEN_12 12
#define TEST_BUF_LEN_28 28
#define TEST_BUF_LEN_9 9
#define TEST_BUF_LEN_8 8
#define TEST_BUF_LEN_5 5
#define TEST_BUF_LEN_4 4
#define TEST_CHANNEL_TYPE_OFFSET 4
#define TEST_USER_ID 123
#define TEST_TOKEN_ID 987654321
#define TEST_QOS_COUNT 12

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";

static SessionAttribute g_sessionAttr[] = {
    {.dataType = TYPE_MESSAGE},
    {.dataType = TYPE_BYTES},
    {.dataType = TYPE_FILE},
    {.dataType = TYPE_STREAM},
    {.dataType = LANE_T_BUTT},
};

static void AddInt32ToBuffer(int32_t value, uint8_t *testBuffer, int32_t &bufferOffset)
{
    if (memcpy_s(testBuffer + bufferOffset, sizeof(int32_t), &value, sizeof(int32_t)) != EOK) {
        return;
    }
    bufferOffset += sizeof(int32_t);
}

static void AddUint64ToBuffer(uint64_t value, uint8_t *testBuffer, int32_t &bufferOffset)
{
    if (memcpy_s(testBuffer + bufferOffset, sizeof(uint64_t), &value, sizeof(uint64_t)) != EOK) {
        return;
    }
    bufferOffset += sizeof(uint64_t);
}

static void AddStringToBuffer(const char *str, uint8_t *testBuffer, int32_t &bufferOffset)
{
    uint32_t len = strlen(str);
    if (memcpy_s(testBuffer + bufferOffset, sizeof(uint32_t), &len, sizeof(uint32_t)) != EOK) {
        return;
    }
    bufferOffset += sizeof(uint32_t);
    if (memcpy_s(testBuffer + bufferOffset, len, str, len) != EOK) {
        return;
    }
    bufferOffset += len;
}

class TransChannelManagerTest : public testing::Test {
public:
    TransChannelManagerTest()
    {}
    ~TransChannelManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransChannelManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
}

void TransChannelManagerTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
}

/*
 * @tc.name: TransChannelInit001
 * @tc.desc: test GetServerIsInit returns false before init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransChannelInit001, TestSize.Level1)
{
    bool ret = false;
    ret = GetServerIsInit();
    EXPECT_EQ(false, ret);
    TransServerDeinit();
    ret = GetServerIsInit();
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: GetAppInfo001
 * @tc.desc: test TransOpenChannel with TransCommonGetAppInfo error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAppInfo001, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];

    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillRepeatedly(Return(SOFTBUS_MEM_ERR));

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannel001
 * @tc.desc: test TransOpenChannel with null param or null transInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel001, TestSize.Level1)
{
    SessionParam param;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    int32_t tmp = 0;
    param.attr = &g_sessionAttr[tmp];
    TransInfo transInfo;
    (void)memset_s(&transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));

    int32_t ret = TransOpenChannel(nullptr, &transInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOpenChannel(&param, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOpenChannel002
 * @tc.desc: test TransOpenChannel with isQosLane true and TransAsyncGetLaneInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel002, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = true;

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);

    g_socketChannelList = CreateSoftBusList();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransAsyncGetLaneInfo).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = nullptr;
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannel003
 * @tc.desc: test TransOpenChannel with isQosLane false and TransGetConnectOptByConnInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel003, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = false;

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = 1;
    transInfo->channelType = 1;

    g_socketChannelList = CreateSoftBusList();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetLaneInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetConnectOptByConnInfo).WillOnce(Return(SOFTBUS_TRANS_GET_CONN_OPT_FAILED));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CONN_OPT_FAILED, ret);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = nullptr;
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannel004
 * @tc.desc: test TransOpenChannel with isQosLane true and async lane success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel004, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = true;

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);

    g_socketChannelList = CreateSoftBusList();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransAsyncGetLaneInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = nullptr;
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannel005
 * @tc.desc: test TransOpenChannel with isQosLane false and TransGetLaneInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel005, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = false;

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = 1;
    transInfo->channelType = 1;

    g_socketChannelList = CreateSoftBusList();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetLaneInfo).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = nullptr;
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannel006
 * @tc.desc: test TransOpenChannel with enableMultipath true and async lane success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel006, TestSize.Level1)
{
    SessionParam *param = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = true;
    param->enableMultipath = true;

    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);

    g_socketChannelList = CreateSoftBusList();
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransAsyncGetLaneInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = nullptr;
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: TransOpenChannelSecond001
 * @tc.desc: test TransOpenChannelSecond with invalid channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannelSecond001, TestSize.Level1)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = SOFTBUS_OK;
    ret = TransOpenChannelSecond(channelId, laneId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOpenChannelSecond002
 * @tc.desc: test TransOpenChannelSecond with socket list no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannelSecond002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t laneId = TEST_LANE_ID;
    int32_t ret = SOFTBUS_OK;
    ret = TransOpenChannelSecond(channelId, laneId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransOpenChannelSecond003
 * @tc.desc: test TransOpenChannelSecond with TransCommonGetAppInfo error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannelSecond003, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    int32_t sessionId = 1;
    int32_t channelId = 1;
    int32_t laneId = TEST_LANE_ID;

    int32_t ret = TransSocketLaneMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr;
    attr.dataType = TYPE_FILE;
    SessionParam addParam = {
        .sessionName = "testSessionName",
        .peerSessionName = "testPeerSessionName",
        .peerDeviceId = "testPeerDeviceId",
        .groupId = "testGroupId",
        .attr = &attr,
    };
    ret = TransAddSocketChannelInfoMultipath(
        "testSessionName", sessionId, channelId, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAddSessionParamBySessionId("testSessionName", sessionId, &addParam);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH));
    ret = TransOpenChannelSecond(channelId, laneId);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransSocketLaneMgrDeinit();
}

/*
 * @tc.name: TransOpenChannelSecond004
 * @tc.desc: test TransOpenChannelSecond with TransUpdateSocketChannelInfo error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannelSecond004, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    int32_t sessionId = 1;
    int32_t channelId = 1;
    int32_t laneId = TEST_LANE_ID;

    int32_t ret = TransSocketLaneMgrInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionAttribute attr;
    attr.dataType = TYPE_FILE;
    SessionParam addParam = {
        .sessionName = "testSessionName",
        .peerSessionName = "testPeerSessionName",
        .peerDeviceId = "testPeerDeviceId",
        .groupId = "testGroupId",
        .attr = &attr,
    };
    ret = TransAddSocketChannelInfoMultipath(
        "testSessionName", sessionId, channelId, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddSessionParamBySessionId("testSessionName", sessionId, &addParam);
    ASSERT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, TransCommonGetAppInfo).WillOnce(Return(SOFTBUS_OK));
    ret = TransOpenChannelSecond(channelId, laneId);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransSocketLaneMgrDeinit();
}

/*
 * @tc.name: TransOpenAuthChannel001
 * @tc.desc: test TransOpenAuthChannel with null sessionName or null connOpt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenAuthChannel001, TestSize.Level1)
{
    const char *sessionName = TEST_PKG_NAME;
    ConnectOption *connOpt = reinterpret_cast<ConnectOption *>(SoftBusCalloc(sizeof(ConnectOption)));
    ASSERT_TRUE(connOpt != nullptr);
    ConnectParam param;
    (void)memset_s(&param, sizeof(ConnectParam), 0, sizeof(ConnectParam));

    int32_t ret = TransOpenAuthChannel(nullptr, connOpt, nullptr, &param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransOpenAuthChannel(sessionName, nullptr, nullptr, &param);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(connOpt);
}

/*
 * @tc.name: MergeStatsInterval001
 * @tc.desc: test MergeStatsInterval with costTime stats (zero result)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, MergeStatsInterval001, TestSize.Level1)
{
    StreamSendStats *src = reinterpret_cast<StreamSendStats *>(SoftBusCalloc(sizeof(StreamSendStats)));
    ASSERT_TRUE(src != nullptr);

    FrameSendStats *dest = reinterpret_cast<FrameSendStats *>(SoftBusCalloc(sizeof(FrameSendStats)));
    ASSERT_TRUE(dest != nullptr);

    uint32_t *srcCostCnt = reinterpret_cast<uint32_t *>(src->costTimeStatsCnt);
    uint32_t *destCostCnt = dest->costTimeStatsCnt;

    destCostCnt[FRAME_COST_TIME_MEDIUM] = MergeStatsInterval(srcCostCnt, FRAME_COST_LT30MS, FRAME_COST_LT100MS);
    EXPECT_EQ(0, static_cast<int32_t>(destCostCnt[FRAME_COST_TIME_MEDIUM]));

    SoftBusFree(src);
    SoftBusFree(dest);
}

/*
 * @tc.name: MergeStatsInterval002
 * @tc.desc: test MergeStatsInterval with bitRate stats (zero result)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, MergeStatsInterval002, TestSize.Level1)
{
    StreamSendStats *src = reinterpret_cast<StreamSendStats *>(SoftBusCalloc(sizeof(StreamSendStats)));
    ASSERT_TRUE(src != nullptr);

    FrameSendStats *dest = reinterpret_cast<FrameSendStats *>(SoftBusCalloc(sizeof(FrameSendStats)));
    ASSERT_TRUE(dest != nullptr);

    uint32_t *srcBitRate = reinterpret_cast<uint32_t *>(src->sendBitRateStatsCnt);
    uint32_t *destBitRate = dest->sendBitRateStatsCnt;

    destBitRate[FRAME_BIT_RATE_MEDIUM] = MergeStatsInterval(srcBitRate, FRAME_BIT_RATE_LT30M, FRAME_BIT_RATE_LT6M);
    EXPECT_EQ(0, static_cast<int32_t>(destBitRate[FRAME_BIT_RATE_MEDIUM]));
    TRANS_LOGI(TRANS_TEST, "destBitRate[FRAME_BIT_RATE_MEDIUM]=%{public}d",
        destBitRate[FRAME_BIT_RATE_MEDIUM]);

    SoftBusFree(src);
    SoftBusFree(dest);
}

/*
 * @tc.name: ConvertStreamStats001
 * @tc.desc: test ConvertStreamStats with valid src and dest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, ConvertStreamStats001, TestSize.Level1)
{
    StreamSendStats *src = reinterpret_cast<StreamSendStats *>(SoftBusCalloc(sizeof(StreamSendStats)));
    ASSERT_TRUE(src != nullptr);

    FrameSendStats *dest = reinterpret_cast<FrameSendStats *>(SoftBusCalloc(sizeof(FrameSendStats)));
    ASSERT_TRUE(dest != nullptr);

    ConvertStreamStats(src, dest);
    EXPECT_NE(nullptr, dest);

    SoftBusFree(src);
    SoftBusFree(dest);
}

/*
 * @tc.name: TransRippleStats001
 * @tc.desc: test TransRippleStats with valid data and get lane handle fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRippleStats001, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    TrafficStats *trafficStats = reinterpret_cast<TrafficStats *>(SoftBusCalloc(sizeof(TrafficStats)));
    ASSERT_TRUE(trafficStats != nullptr);

    int32_t ret = TransRippleStats(channelId, channelType, trafficStats);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(trafficStats);
}

/*
 * @tc.name: TransRippleStats002
 * @tc.desc: test TransRippleStats with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRippleStats002, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    int32_t ret = SOFTBUS_OK;
    ret = TransRippleStats(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransStreamStats001
 * @tc.desc: test TransStreamStats with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransStreamStats001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    int32_t ret = SOFTBUS_OK;
    ret = TransStreamStats(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransStreamStats002
 * @tc.desc: test TransStreamStats after lane mgr deinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransStreamStats002, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    StreamSendStats *data = reinterpret_cast<StreamSendStats *>(SoftBusCalloc(sizeof(StreamSendStats)));
    ASSERT_TRUE(data != nullptr);

    TransLaneMgrDeinit();
    int32_t ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(data);
}

/*
 * @tc.name: TransNotifyAuthSuccess001
 * @tc.desc: test TransNotifyAuthSuccess with CHANNEL_TYPE_UDP (invalid type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransNotifyAuthSuccess001, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_UDP;
    int32_t ret = SOFTBUS_OK;
    ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/*
 * @tc.name: TransNotifyAuthSuccess002
 * @tc.desc: test TransNotifyAuthSuccess with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransNotifyAuthSuccess002, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = SOFTBUS_OK;
    ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransNotifyAuthSuccess003
 * @tc.desc: test TransNotifyAuthSuccess with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransNotifyAuthSuccess003, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransProxyGetConnOptionByChanId).WillOnce(Return(SOFTBUS_OK));
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    int32_t ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNELID_CONVERT_ADDR_FAILED, ret);
}

/*
 * @tc.name: TransRequestQos001
 * @tc.desc: test TransRequestQos with invalid channelId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRequestQos001, TestSize.Level1)
{
    int32_t channelId = TEST_NEGATIVE_CHANNEL_ID;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    int32_t appType = TEST_APP_TYPE;
    int32_t quality = TEST_QUALITY;

    int32_t ret = TransRequestQos(channelId, channelType, appType, quality);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransCloseChannel001
 * @tc.desc: test TransCloseChannel with invalid channel type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannel001, TestSize.Level1)
{
    int32_t channelId = TEST_CLOSE_CHANNEL_ID_01;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    int32_t ret = SOFTBUS_OK;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/*
 * @tc.name: TransCloseChannel002
 * @tc.desc: test TransCloseChannel with CHANNEL_TYPE_UDP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannel002, TestSize.Level1)
{
    int32_t channelId = TEST_CLOSE_CHANNEL_ID_02;
    int32_t channelType = CHANNEL_TYPE_UDP;
    int32_t ret = SOFTBUS_OK;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransCloseChannel003
 * @tc.desc: test TransCloseChannel with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannel003, TestSize.Level1)
{
    int32_t channelId = TEST_CLOSE_CHANNEL_ID_03;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = SOFTBUS_OK;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: TransCloseChannel004
 * @tc.desc: test TransCloseChannel with CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannel004, TestSize.Level1)
{
    int32_t channelId = TEST_CLOSE_CHANNEL_ID_04;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t ret = SOFTBUS_OK;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSendMsg001
 * @tc.desc: test TransSendMsg with CHANNEL_TYPE_AUTH and null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSendMsg001, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    void *data = nullptr;
    uint32_t len = 0;
    int32_t msgType = 0;

    int32_t ret = TransSendMsg(channelId, channelType, data, len, msgType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransSendMsg002
 * @tc.desc: test TransSendMsg with CHANNEL_TYPE_UDP (invalid type, default branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSendMsg002, TestSize.Level1)
{
    int32_t channelId = TEST_NOTIFY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_UDP;
    void *data = nullptr;
    uint32_t len = 0;
    int32_t msgType = 0;

    int32_t ret = TransSendMsg(channelId, channelType, data, len, msgType);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);
}

/*
 * @tc.name: TransSendMsg003
 * @tc.desc: test TransSendMsg with CHANNEL_TYPE_PROXY and null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSendMsg003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    void *data = nullptr;
    uint32_t len = 0;
    int32_t msgType = 1;
    int32_t ret = TransSendMsg(channelId, channelType, data, len, msgType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyDeathCallback001
 * @tc.desc: test TransProxyDeathCallback with null pkgName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProxyDeathCallback001, TestSize.Level1)
{
    int32_t pid = 1;
    EXPECT_NO_FATAL_FAILURE(TransProxyDeathCallback(nullptr, pid));
    char pkgName[] = "testPackage";
    int32_t newPid = 0;
    EXPECT_NO_FATAL_FAILURE(TransChannelDeathCallback(pkgName, newPid));
}

/*
 * @tc.name: TransGetNameByChanId001
 * @tc.desc: test TransGetNameByChanId with null info, null pkgName, or null sessionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId001, TestSize.Level1)
{
    TransInfo *info = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(info != nullptr);
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = TEST_SESSION_NAME_LEN;

    int32_t ret = TransGetNameByChanId(nullptr, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, nullptr, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, pkgName, nullptr, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
}

/*
 * @tc.name: TransGetNameByChanId002
 * @tc.desc: test TransGetNameByChanId with invalid channel type (8888)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId002, TestSize.Level1)
{
    TransInfo *info = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(info != nullptr);
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = TEST_SESSION_NAME_LEN;

    info->channelType = TEST_INVALID_CHANNEL_TYPE_LARGE;
    int32_t ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
}

/*
 * @tc.name: TransGetNameByChanId003
 * @tc.desc: test TransGetNameByChanId with CHANNEL_TYPE_UDP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId003, TestSize.Level1)
{
    TransInfo *info = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(info != nullptr);
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = TEST_SESSION_NAME_LEN;

    info->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    SoftBusFree(info);
}

/*
 * @tc.name: TransGetNameByChanId004
 * @tc.desc: test TransGetNameByChanId with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId004, TestSize.Level1)
{
    TransInfo *info = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(info != nullptr);
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = TEST_SESSION_NAME_LEN;

    info->channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
}

/*
 * @tc.name: TransGetNameByChanId005
 * @tc.desc: test TransGetNameByChanId with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId005, TestSize.Level1)
{
    TransInfo *info = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(info != nullptr);
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = TEST_SESSION_NAME_LEN;

    info->channelType = CHANNEL_TYPE_PROXY;
    int32_t ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(info);
}

/*
 * @tc.name: TransGetAppInfoByChanId001
 * @tc.desc: test TransGetAppInfoByChanId with null appInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;
    int32_t ret = SOFTBUS_OK;
    ret = TransGetAppInfoByChanId(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetAppInfoByChanId002
 * @tc.desc: test TransGetAppInfoByChanId with invalid channel type (222)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    int32_t channelId = 1;
    int32_t channelType = TEST_INVALID_CHANNEL_TYPE;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransGetAppInfoByChanId003
 * @tc.desc: test TransGetAppInfoByChanId with CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransGetAppInfoByChanId004
 * @tc.desc: test TransGetAppInfoByChanId with CHANNEL_TYPE_UDP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId004, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_UDP;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransGetAppInfoByChanId005
 * @tc.desc: test TransGetAppInfoByChanId with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId005, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_AUTH;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransGetAppInfoByChanId006
 * @tc.desc: test TransGetAppInfoByChanId with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId006, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_PROXY;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransGetConnByChanId001
 * @tc.desc: test TransGetConnByChanId with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId001, TestSize.Level1)
{
    int32_t channelId = TEST_CONN_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    int32_t connId = -1;

    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransGetConnByChanId002
 * @tc.desc: test TransGetConnByChanId with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId002, TestSize.Level1)
{
    int32_t channelId = TEST_CONN_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t connId = -1;

    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransGetConnByChanId003
 * @tc.desc: test TransGetConnByChanId with CHANNEL_TYPE_BUTT (invalid type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId003, TestSize.Level1)
{
    int32_t channelId = TEST_CONN_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    int32_t connId = -1;

    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/*
 * @tc.name: TransGetConnByChanId004
 * @tc.desc: test TransGetConnByChanId with CHANNEL_TYPE_AUTH and channelId 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t connId = 1;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GenerateProxyChannelId001
 * @tc.desc: test GenerateProxyChannelId returns expected channel id (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateProxyChannelId001, TestSize.Level1)
{
    SoftBusMutexInit(&g_myIdLock, nullptr);
    int32_t channelId = GenerateProxyChannelId();
    EXPECT_EQ(TEST_PROXY_CHANNEL_ID, channelId);
    ReleaseProxyChannelId(channelId);
    SoftBusMutexDestroy(&g_myIdLock);
}

/*
 * @tc.name: GenerateTdcChannelId001
 * @tc.desc: test GenerateTdcChannelId returns expected channel id (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateTdcChannelId001, TestSize.Level1)
{
    int32_t ret = SoftBusMutexInit(&g_myIdLock, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = GenerateTdcChannelId();
    EXPECT_EQ(TEST_TDC_CHANNEL_ID, channelId);
    SoftBusMutexDestroy(&g_myIdLock);
}

/*
 * @tc.name: GenerateTdcChannelId002
 * @tc.desc: test GenerateTdcChannelId when g_allocTdcChannelId reaches max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateTdcChannelId002, TestSize.Level1)
{
    int32_t tdcChannel = g_allocTdcChannelId;
    g_allocTdcChannelId = MAX_TDC_CHANNEL_ID;
    int32_t ret = SoftBusMutexInit(&g_myIdLock, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = GenerateTdcChannelId();
    EXPECT_EQ(MAX_TDC_CHANNEL_ID, channelId);
    g_allocTdcChannelId = tdcChannel;
    SoftBusMutexDestroy(&g_myIdLock);
}

/*
 * @tc.name: GenerateProxyChannelId002
 * @tc.desc: test GenerateProxyChannelId when g_channelIdCount reaches max
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateProxyChannelId002, TestSize.Level1)
{
    int32_t proxyChannel = g_channelIdCount;
    g_channelIdCount = MAX_PROXY_CHANNEL_ID_COUNT;
    int32_t ret = SoftBusMutexInit(&g_myIdLock, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = GenerateProxyChannelId();
    EXPECT_EQ(INVALID_CHANNEL_ID, channelId);
    g_channelIdCount = proxyChannel;
    SoftBusMutexDestroy(&g_myIdLock);
}

/*
 * @tc.name: IsLaneModuleError001
 * @tc.desc: test IsLaneModuleError with SOFTBUS_LANE_DETECT_FAIL (true) and SOFTBUS_CONN_FAIL (false)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, IsLaneModuleError001, TestSize.Level1)
{
    int32_t errcode = SOFTBUS_LANE_DETECT_FAIL;
    bool ret = IsLaneModuleError(errcode);
    EXPECT_EQ(true, ret);
    errcode = SOFTBUS_CONN_FAIL;
    ret = IsLaneModuleError(errcode);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: TransSetFirstTokenInfo001
 * @tc.desc: test TransSetFirstTokenInfo with first token not set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetFirstTokenInfo001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->tokenName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    appInfo->callingTokenId = TEST_CALLING_TOKEN_ID;
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransAclGetFirstTokenID).WillOnce(Return(TOKENID_NOT_SET));
    TransSetFirstTokenInfo(appInfo, &extra);
    EXPECT_NE(nullptr, appInfo);
    TransFreeAppInfo(appInfo);
}

/*
 * @tc.name: TransReleaseUdpResources001
 * @tc.desc: test TransReleaseUdpResources with valid channelId (success) and TransChannelResultLoopMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReleaseUdpResources001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransReleaseUdpResources(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusMessage *msg = nullptr;
    EXPECT_NO_FATAL_FAILURE(TransChannelResultLoopMsgHandler(msg));
}

/*
 * @tc.name: TransCloseChannelWithStatistics001
 * @tc.desc: test TransCloseChannelWithStatistics with valid params (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannelWithStatistics001, TestSize.Level1)
{
    const char *data = "test";
    uint32_t len = strlen(data);
    int32_t channelId = 1;
    int32_t channelType = 1;
    int32_t ret = TransCloseChannelWithStatistics(channelId, channelType, 1, static_cast<const void *>(data), len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetAuthAppInfo001
 * @tc.desc: test GetAuthAppInfo with all mock calls success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo001, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransCommonGetLocalConfig).WillOnce(Return(SOFTBUS_OK));
    AppInfo *appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_NE(nullptr, appInfo);
}

/*
 * @tc.name: GetAuthAppInfo002
 * @tc.desc: test GetAuthAppInfo with TransGetUidAndPid fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo002, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_NO_INIT));
    AppInfo *appInfo = nullptr;
    appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_EQ(nullptr, appInfo);
}

/*
 * @tc.name: GetAuthAppInfo003
 * @tc.desc: test GetAuthAppInfo with LnnGetLocalStrInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo003, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    AppInfo *appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_EQ(nullptr, appInfo);
}

/*
 * @tc.name: GetAuthAppInfo004
 * @tc.desc: test GetAuthAppInfo with TransGetPkgNameBySessionName fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo004, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_TRANS_SESSION_NAME_NO_EXIST));
    AppInfo *appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_EQ(nullptr, appInfo);
}

/*
 * @tc.name: GetAuthAppInfo005
 * @tc.desc: test GetAuthAppInfo with TransCommonGetLocalConfig fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo005, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransCommonGetLocalConfig).WillOnce(Return(SOFTBUS_GET_CONFIG_VAL_ERR));
    AppInfo *appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_EQ(nullptr, appInfo);
}

/*
 * @tc.name: TransGetAndComparePid001
 * @tc.desc: test TransGetAndComparePid with CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAndComparePid001, TestSize.Level1)
{
    pid_t pid = TRANS_TEST_PID;
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t ret = TransGetAndComparePid(pid, channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
}

/*
 * @tc.name: TransGetAndComparePid002
 * @tc.desc: test TransGetAndComparePid with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAndComparePid002, TestSize.Level1)
{
    pid_t pid = TRANS_TEST_PID;
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransGetAndComparePid(pid, channelId, channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransPrivilegeCloseChannel001
 * @tc.desc: test TransPrivilegeCloseChannel with null peerNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransPrivilegeCloseChannel001, TestSize.Level1)
{
    uint64_t tokenId = 1;
    int32_t pid = 1;
    int32_t ret = SOFTBUS_OK;
    ret = TransPrivilegeCloseChannel(tokenId, pid, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransPrivilegeCloseChannel002
 * @tc.desc: test TransPrivilegeCloseChannel with valid peerNetworkId (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransPrivilegeCloseChannel002, TestSize.Level1)
{
    uint64_t tokenId = 1;
    int32_t pid = 1;
    const char *deviceId = "ASDS123124";
    int32_t ret = TransPrivilegeCloseChannel(tokenId, pid, deviceId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PrivilegeCloseListAddItem001
 * @tc.desc: test PrivilegeCloseListAddItem with null list or null pkgName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, PrivilegeCloseListAddItem001, TestSize.Level1)
{
    int32_t pid = 0;
    ListNode *list = nullptr;
    int32_t ret = SOFTBUS_OK;
    ret = PrivilegeCloseListAddItem(list, pid, g_pkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: PrivilegeCloseListAddItem002
 * @tc.desc: test PrivilegeCloseListAddItem with valid params (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, PrivilegeCloseListAddItem002, TestSize.Level1)
{
    int32_t pid = 0;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    int32_t ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, g_pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PrivilegeCloseChannelInfo *pos = nullptr;
    PrivilegeCloseChannelInfo *tmp = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &privilegeCloseList, PrivilegeCloseChannelInfo, node) {
        ListDelete(&(pos->node));
        SoftBusFree(pos);
    }
}

/*
 * @tc.name: PrivilegeCloseListAddItem003
 * @tc.desc: test PrivilegeCloseListAddItem with duplicate item (dedup)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, PrivilegeCloseListAddItem003, TestSize.Level1)
{
    int32_t pid = 0;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    int32_t ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, g_pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, g_pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PrivilegeCloseChannelInfo *pos = nullptr;
    PrivilegeCloseChannelInfo *tmp = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &privilegeCloseList, PrivilegeCloseChannelInfo, node) {
        ListDelete(&(pos->node));
        SoftBusFree(pos);
    }
}

/*
 * @tc.name: GetChannelInfoFromBuf001
 * @tc.desc: test GetChannelInfoFromBuf with len=12 (accessInfo read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetChannelInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    info.channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetChannelInfoFromBuf002
 * @tc.desc: test GetChannelInfoFromBuf with len=8 (openResult read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetChannelInfoFromBuf002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_8;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    info.channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetChannelInfoFromBuf003
 * @tc.desc: test GetChannelInfoFromBuf with len=4 (channelType read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetChannelInfoFromBuf003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_4;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    info.channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetChannelInfoFromBuf004
 * @tc.desc: test GetChannelInfoFromBuf with len=1 (channelId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetChannelInfoFromBuf004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = 1;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    info.channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetUdpChannelInfoFromBuf001
 * @tc.desc: test GetUdpChannelInfoFromBuf with len=28 (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    int32_t udpPort = 0;
    uint32_t len = TEST_BUF_LEN_28;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int32_t ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetUdpChannelInfoFromBuf002
 * @tc.desc: test GetUdpChannelInfoFromBuf with len=12 (udpPort read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    int32_t udpPort = 0;
    uint32_t len = TEST_BUF_LEN_12;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int32_t ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetUdpChannelInfoFromBuf003
 * @tc.desc: test GetUdpChannelInfoFromBuf with len=8 (openResult read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    int32_t udpPort = 0;
    uint32_t len = TEST_BUF_LEN_8;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int32_t ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetUdpChannelInfoFromBuf004
 * @tc.desc: test GetUdpChannelInfoFromBuf with len=4 (channelType read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    int32_t udpPort = 0;
    uint32_t len = TEST_BUF_LEN_4;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int32_t ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetUdpChannelInfoFromBuf005
 * @tc.desc: test GetUdpChannelInfoFromBuf with len=1 (channelId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf005, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    int32_t udpPort = 0;
    uint32_t len = 1;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int32_t ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetLimitChangeInfoFromBuf001
 * @tc.desc: test GetLimitChangeInfoFromBuf with len=9 (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetLimitChangeInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_9] = {0};
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limit = 0;
    uint32_t len = TEST_BUF_LEN_9;

    int32_t ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetLimitChangeInfoFromBuf002
 * @tc.desc: test GetLimitChangeInfoFromBuf with len=5 (limitChangeResult read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetLimitChangeInfoFromBuf002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_9] = {0};
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limit = 0;
    uint32_t len = TEST_BUF_LEN_5;

    int32_t ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetLimitChangeInfoFromBuf003
 * @tc.desc: test GetLimitChangeInfoFromBuf with len=4 (tos read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetLimitChangeInfoFromBuf003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_9] = {0};
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limit = 0;
    uint32_t len = TEST_BUF_LEN_4;

    int32_t ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetLimitChangeInfoFromBuf004
 * @tc.desc: test GetLimitChangeInfoFromBuf with len=1 (channelId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetLimitChangeInfoFromBuf004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_9] = {0};
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limit = 0;
    uint32_t len = 1;

    int32_t ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo001
 * @tc.desc: test TransReportChannelOpenedInfo with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = TEST_BUF_LEN_28;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_PROXY;
    int32_t ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo002
 * @tc.desc: test TransReportChannelOpenedInfo with CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = TEST_BUF_LEN_28;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_TCP_DIRECT;
    int32_t ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo003
 * @tc.desc: test TransReportChannelOpenedInfo with CHANNEL_TYPE_UDP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = TEST_BUF_LEN_28;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_UDP;
    int32_t ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo004
 * @tc.desc: test TransReportChannelOpenedInfo with CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = TEST_BUF_LEN_28;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_AUTH;
    int32_t ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo005
 * @tc.desc: test TransReportChannelOpenedInfo with CHANNEL_TYPE_BUTT (invalid type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo005, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = TEST_BUF_LEN_28;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_BUTT;
    int32_t ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/*
 * @tc.name: TransReportChannelOpenedInfo006
 * @tc.desc: test TransReportChannelOpenedInfo with invalid data length (len=1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo006, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_28] = {0};
    uint32_t len = 1;
    int32_t ret = SOFTBUS_OK;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportLimitChangeInfo001
 * @tc.desc: test TransReportLimitChangeInfo with valid len=9 and invalid len=1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportLimitChangeInfo001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_9] = {0};
    pid_t callingPid = static_cast<pid_t>(TRANS_TEST_PID);
    int32_t len = TEST_BUF_LEN_9;
    EXPECT_NO_FATAL_FAILURE(TransReportLimitChangeInfo(buf, len, callingPid));
}

/*
 * @tc.name: GetCollabCheckResultFromBuf001
 * @tc.desc: test GetCollabCheckResultFromBuf with len=12 (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetCollabCheckResultFromBuf001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t len = TEST_BUF_LEN_12;

    int32_t ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetCollabCheckResultFromBuf002
 * @tc.desc: test GetCollabCheckResultFromBuf with len=8 (checkResult read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetCollabCheckResultFromBuf002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t len = TEST_BUF_LEN_8;

    int32_t ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetCollabCheckResultFromBuf003
 * @tc.desc: test GetCollabCheckResultFromBuf with len=4 (channelType read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetCollabCheckResultFromBuf003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t len = TEST_BUF_LEN_4;

    int32_t ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: GetCollabCheckResultFromBuf004
 * @tc.desc: test GetCollabCheckResultFromBuf with len=1 (channelId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetCollabCheckResultFromBuf004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t len = 1;

    int32_t ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: TransReportCheckCollabInfo001
 * @tc.desc: test TransReportCheckCollabInfo with CHANNEL_TYPE_PROXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t len = TEST_BUF_LEN_12;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_PROXY;
    int32_t ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportCheckCollabInfo002
 * @tc.desc: test TransReportCheckCollabInfo with CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t len = TEST_BUF_LEN_12;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_TCP_DIRECT;
    int32_t ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportCheckCollabInfo003
 * @tc.desc: test TransReportCheckCollabInfo with CHANNEL_TYPE_UDP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t len = TEST_BUF_LEN_12;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_UDP;
    int32_t ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransReportCheckCollabInfo004
 * @tc.desc: test TransReportCheckCollabInfo with CHANNEL_TYPE_BUTT (invalid type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t len = TEST_BUF_LEN_12;
    buf[TEST_CHANNEL_TYPE_OFFSET] = CHANNEL_TYPE_BUTT;
    int32_t ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/*
 * @tc.name: TransReportCheckCollabInfo005
 * @tc.desc: test TransReportCheckCollabInfo with invalid data length (len=1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo005, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    int32_t len = 1;
    int32_t ret = SOFTBUS_OK;
    ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProcessInnerEvent001
 * @tc.desc: test TransProcessInnerEvent with null buf
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent001, TestSize.Level1)
{
    uint32_t len = TEST_BUF_LEN_12;
    int32_t eventType = EVENT_TYPE_CHANNEL_OPENED;
    int32_t ret = SOFTBUS_OK;
    ret = TransProcessInnerEvent(eventType, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProcessInnerEvent002
 * @tc.desc: test TransProcessInnerEvent with EVENT_TYPE_BUTT (invalid event type)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent002, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    int32_t eventType = EVENT_TYPE_BUTT;

    int32_t ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_EQ(SOFTBUS_TRANS_MSG_INVALID_EVENT_TYPE, ret);
}

/*
 * @tc.name: TransProcessInnerEvent003
 * @tc.desc: test TransProcessInnerEvent with EVENT_TYPE_TRANS_LIMIT_CHANGE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent003, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    int32_t eventType = EVENT_TYPE_TRANS_LIMIT_CHANGE;

    int32_t ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProcessInnerEvent004
 * @tc.desc: test TransProcessInnerEvent with EVENT_TYPE_COLLAB_CHECK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent004, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    int32_t eventType = EVENT_TYPE_COLLAB_CHECK;

    int32_t ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProcessInnerEvent005
 * @tc.desc: test TransProcessInnerEvent with EVENT_TYPE_SET_ACCESS_INFO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent005, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    int32_t eventType = EVENT_TYPE_SET_ACCESS_INFO;

    int32_t ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransDisableIdleCheck001
 * @tc.desc: test TransDisableIdleCheck with valid buf and len
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransDisableIdleCheck001, TestSize.Level1)
{
    uint8_t buf[TEST_BUF_LEN_12] = {0};
    uint32_t len = TEST_BUF_LEN_12;
    int32_t ret = SOFTBUS_OK;
    ret = TransDisableIdleCheck(buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransSetAccessInfo001
 * @tc.desc: test TransSetAccessInfo without session server (SOFTBUS_NO_INIT)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo001, TestSize.Level1)
{
    int32_t expectedUserId = TEST_USER_ID;
    uint64_t expectedTokenId = TEST_TOKEN_ID;
    const char *expectedSessionName = "test_session";
    const char *expectedExtraInfo = "extra_info_data";
    const char *expectedBusinessVer = "v1.2.3";
    uint8_t testBuffer[TEST_BUF_LEN] = {0};
    int32_t bufferOffset = 0;
    pid_t callingPid = static_cast<pid_t>(TRANS_TEST_PID);

    AddInt32ToBuffer(expectedUserId, testBuffer, bufferOffset);
    AddUint64ToBuffer(expectedTokenId, testBuffer, bufferOffset);
    AddStringToBuffer(expectedSessionName, testBuffer, bufferOffset);
    AddStringToBuffer(expectedExtraInfo, testBuffer, bufferOffset);
    AddStringToBuffer(expectedBusinessVer, testBuffer, bufferOffset);

    int32_t ret = TransSetAccessInfo(testBuffer, TEST_BUF_LEN, callingPid);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransSetAccessInfo002
 * @tc.desc: test TransSetAccessInfo with session server added (success)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo002, TestSize.Level1)
{
    int32_t expectedUserId = TEST_USER_ID;
    uint64_t expectedTokenId = TEST_TOKEN_ID;
    const char *expectedSessionName = "test_session";
    const char *expectedExtraInfo = "extra_info_data";
    const char *expectedBusinessVer = "v1.2.3";
    uint8_t testBuffer[TEST_BUF_LEN] = {0};
    int32_t bufferOffset = 0;
    pid_t callingPid = static_cast<pid_t>(TRANS_TEST_PID);

    AddInt32ToBuffer(expectedUserId, testBuffer, bufferOffset);
    AddUint64ToBuffer(expectedTokenId, testBuffer, bufferOffset);
    AddStringToBuffer(expectedSessionName, testBuffer, bufferOffset);
    AddStringToBuffer(expectedExtraInfo, testBuffer, bufferOffset);
    AddStringToBuffer(expectedBusinessVer, testBuffer, bufferOffset);

    char sessionName[] = "test_session";
    SessionServer *newNode = reinterpret_cast<SessionServer *>(SoftBusCalloc(sizeof(SessionServer)));
    ASSERT_TRUE(newNode != nullptr);
    (void)strcpy_s(newNode->sessionName, sizeof(sessionName), sessionName);
    newNode->pid = callingPid;

    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetAccessInfo(testBuffer, TEST_BUF_LEN, callingPid);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/*
 * @tc.name: TransSetAccessInfo003
 * @tc.desc: test TransSetAccessInfo with len=1 (userId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo003, TestSize.Level1)
{
    uint8_t shortBuf[1] = {0};
    pid_t callingPid = static_cast<pid_t>(TRANS_TEST_PID);
    int32_t ret = SOFTBUS_OK;
    ret = TransSetAccessInfo(shortBuf, 1, callingPid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransSetAccessInfo004
 * @tc.desc: test TransSetAccessInfo with len=5 (tokenId read fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo004, TestSize.Level1)
{
    uint8_t buf[sizeof(int32_t) + 1] = {0};
    pid_t callingPid = static_cast<pid_t>(TRANS_TEST_PID);
    int32_t ret = SOFTBUS_OK;
    ret = TransSetAccessInfo(buf, sizeof(buf), callingPid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransAsyncChannelOpenTaskManager001
 * @tc.desc: test TransAsyncChannelOpenTaskManager with CHANNEL_TYPE_PROXY and CHANNEL_TYPE_TCP_DIRECT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransAsyncChannelOpenTaskManager001, TestSize.Level1)
{
    int32_t channelId = TEST_PROXY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_PROXY;
    EXPECT_NO_FATAL_FAILURE(TransAsyncChannelOpenTaskManager(channelId, channelType));
    channelType = CHANNEL_TYPE_TCP_DIRECT;
    EXPECT_NO_FATAL_FAILURE(TransAsyncChannelOpenTaskManager(channelId, channelType));
}

/*
 * @tc.name: TransAsyncChannelOpenTaskManager002
 * @tc.desc: test TransAsyncChannelOpenTaskManager with CHANNEL_TYPE_UDP, CHANNEL_TYPE_AUTH and CHANNEL_TYPE_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransAsyncChannelOpenTaskManager002, TestSize.Level1)
{
    int32_t channelId = TEST_PROXY_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_UDP;
    EXPECT_NO_FATAL_FAILURE(TransAsyncChannelOpenTaskManager(channelId, channelType));
    channelType = CHANNEL_TYPE_AUTH;
    EXPECT_NO_FATAL_FAILURE(TransAsyncChannelOpenTaskManager(channelId, channelType));
    channelType = CHANNEL_TYPE_BUTT;
    EXPECT_NO_FATAL_FAILURE(TransAsyncChannelOpenTaskManager(channelId, channelType));
}

/*
 * @tc.name: TransSetQosInfo001
 * @tc.desc: test TransSetQosInfo with qosCount=12
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetQosInfo001, TestSize.Level1)
{
    QosTV qosTv;
    TransEventExtra extra;
    uint32_t qosCount = TEST_QOS_COUNT;
    (void)memset_s(&qosTv, sizeof(QosTV), 0, sizeof(QosTV));
    EXPECT_NO_FATAL_FAILURE(TransSetQosInfo(&qosTv, qosCount, &extra));
}

/*
 * @tc.name: CheckAuthChannelIsExit001
 * @tc.desc: test CheckAuthChannelIsExit with null connInfo and CONNECT_TCP type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, CheckAuthChannelIsExit001, TestSize.Level1)
{
    ConnectOption *connInfo = nullptr;
    int32_t ret = CheckAuthChannelIsExit(connInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnectOption tcpConnInfo = {
        .type = CONNECT_TCP
    };
    ret = CheckAuthChannelIsExit(&tcpConnInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CheckAuthChannelIsExit002
 * @tc.desc: test CheckAuthChannelIsExit with CONNECT_BR type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, CheckAuthChannelIsExit002, TestSize.Level1)
{
    ConnectOption connInfo = {
        .type = CONNECT_BR
    };
    int32_t ret = CheckAuthChannelIsExit(&connInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: CheckAuthChannelIsExit003
 * @tc.desc: test CheckAuthChannelIsExit with CONNECT_BLE type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, CheckAuthChannelIsExit003, TestSize.Level1)
{
    ConnectOption connInfo = {
        .type = CONNECT_BLE
    };
    int32_t ret = CheckAuthChannelIsExit(&connInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: CheckAuthChannelIsExit004
 * @tc.desc: test CheckAuthChannelIsExit with CONNECT_HML type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, CheckAuthChannelIsExit004, TestSize.Level1)
{
    ConnectOption connInfo = {
        .type = CONNECT_HML
    };
    int32_t ret = CheckAuthChannelIsExit(&connInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NOT_MATCH);
}
} // namespace OHOS
