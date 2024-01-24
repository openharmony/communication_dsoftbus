/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "trans_channel_manager.h"
#include "trans_lane_manager.h"
#include "trans_channel_callback.h"
#include "softbus_def.h"
#include "softbus_server_frame.h"

#include "trans_lane_pending_ctl.c"
#include "trans_channel_callback.c"
#include "trans_channel_manager.c"
#include "trans_log.h"
#include "trans_session_service.h"
#include "lnn_lane_qos.h"
#include "softbus_trans_def.h"

using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)

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
{}

void TransChannelManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransChannelInit001
 * @tc.desc: TransChannelInit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransChannelInit001, TestSize.Level1)
{
    InitSoftBusServer();
    bool ret = GetServerIsInit();
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: TransChannelDeinit001
 * @tc.desc: TransChannelDeinit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransChannelDeinit001, TestSize.Level1)
{
    TransServerDeinit();
    bool ret = GetServerIsInit();
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: CopyAppInfoFromSessionParam001
 * @tc.desc: CopyAppInfoFromSessionParam, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, CopyAppInfoFromSessionParam001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    SessionParam *sessionParam = (SessionParam *)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    (void)memcpy_s(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, "test", DEVICE_ID_SIZE_MAX);

    int32_t ret = CopyAppInfoFromSessionParam(appInfo, sessionParam);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    SoftBusFree(appInfo);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: GetAppInfo001
 * @tc.desc: TransOpenChannel
 * @tc.desc: GetAppInfo, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAppInfo001, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    (void)memset_s(param, sizeof(SessionParam), 0, sizeof(SessionParam));

    int tmp = 0;
    param->attr = &g_sessionAttr[tmp];

    TransInfo *transInfo = (TransInfo *)SoftBusMalloc(sizeof(TransInfo));
    ASSERT_TRUE(transInfo != nullptr);
    (void)memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));

    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    tmp++;
    param->attr = &g_sessionAttr[tmp];
    ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    tmp++;
    param->attr = &g_sessionAttr[tmp];
    ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    tmp++;
    param->attr = &g_sessionAttr[tmp];
    ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    SoftBusFree(param);
    SoftBusFree(transInfo);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransGetChannelType001
 * @tc.desc: TransGetChannelType, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetChannelType001, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    memset_s(param, sizeof(SessionParam), 0, sizeof(SessionParam));

    int tmp = 0;
    param->attr = &g_sessionAttr[tmp];

    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusMalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);
    memset_s(connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));

    TransInfo *transInfo = (TransInfo *)SoftBusMalloc(sizeof(TransInfo));
    ASSERT_TRUE(transInfo != nullptr);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));

    transInfo->channelType = TransGetChannelType(NULL, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_BUTT, transInfo->channelType);

    connInfo->type = LANE_BR;
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, transInfo->channelType);

    connInfo->type = LANE_P2P;
    tmp = 2;
    param->attr = &g_sessionAttr[tmp];
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, transInfo->channelType);

    tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    connInfo->type = LANE_BR;
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, transInfo->channelType);
    connInfo->type = LANE_P2P;

    tmp = 1;
    param->attr = &g_sessionAttr[tmp];
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    EXPECT_EQ(CHANNEL_TYPE_TCP_DIRECT, transInfo->channelType);

    SoftBusFree(param);
    SoftBusFree(connInfo);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransOpenChannelProc001
 * @tc.desc: TransOpenChannelProc, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannelProc001, TestSize.Level1)
{
    ConnectOption *connOpt = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != nullptr);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t channelId = 1;

    int ret = TransOpenChannelProc(CHANNEL_TYPE_BUTT, appInfo, connOpt, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransOpenChannelProc(CHANNEL_TYPE_UDP, appInfo, connOpt, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransOpenChannelProc(CHANNEL_TYPE_PROXY, appInfo, connOpt, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = TransOpenChannelProc(CHANNEL_TYPE_TCP_DIRECT, appInfo, connOpt, &channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    SoftBusFree(connOpt);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: GetAuthAppInfo001
 * @tc.desc: GetAuthAppInfo, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    const char *mySessionName = TEST_PKG_NAME;

    int32_t ret = TransSessionMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo = GetAuthAppInfo(mySessionName);

    EXPECT_TRUE(appInfo == NULL);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransOpenAuthChannel001
 * @tc.desc: TransOpenAuthChannel001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenAuthChannel001, TestSize.Level1)
{
    const char *sessionName = TEST_PKG_NAME;
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connOpt != nullptr);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    int32_t ret = TransOpenAuthChannel(NULL, NULL, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenAuthChannel(sessionName, NULL, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenAuthChannel(NULL, connOpt, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    connOpt->type = CONNECT_TCP;
    ret = TransOpenAuthChannel(sessionName, connOpt, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    connOpt->type = CONNECT_BR;
    ret = TransOpenAuthChannel(sessionName, connOpt, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    connOpt->type = CONNECT_P2P;
    ret = TransOpenAuthChannel(sessionName, connOpt, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    SoftBusFree(connOpt);
}

/**
 * @tc.name: MergeStatsInterval001
 * @tc.desc: MergeStatsInterval001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, MergeStatsInterval001, TestSize.Level1)
{
    StreamSendStats *src = (StreamSendStats *)SoftBusMalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(src != nullptr);
    memset_s(src, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    FrameSendStats *dest = (FrameSendStats *)SoftBusMalloc(sizeof(FrameSendStats));
    ASSERT_TRUE(dest != nullptr);
    memset_s(dest, sizeof(FrameSendStats), 0, sizeof(FrameSendStats));

    uint32_t *srcCostCnt = (uint32_t *)(src->costTimeStatsCnt);
    uint32_t *srcBitRate = (uint32_t *)(src->sendBitRateStatsCnt);
    uint32_t *destCostCnt = dest->costTimeStatsCnt;
    uint32_t *destBitRate = dest->sendBitRateStatsCnt;

    destCostCnt[FRAME_COST_TIME_MEDIUM] = MergeStatsInterval(srcCostCnt, FRAME_COST_LT30MS, FRAME_COST_LT100MS);
    EXPECT_EQ(0, (int)destCostCnt[FRAME_COST_TIME_MEDIUM]);

    destBitRate[FRAME_BIT_RATE_MEDIUM] = MergeStatsInterval(srcBitRate, FRAME_BIT_RATE_LT30M, FRAME_BIT_RATE_LT6M);
    EXPECT_EQ(0, (int)destBitRate[FRAME_BIT_RATE_MEDIUM]);
    TRANS_LOGI(TRANS_TEST, "destBitRate[FRAME_BIT_RATE_MEDIUM]=%{public}d",
        destBitRate[FRAME_BIT_RATE_MEDIUM]);
    ConvertStreamStats(src, dest);

    SoftBusFree(src);
    SoftBusFree(dest);
}

/**
 * @tc.name: TransRippleStats001
 * @tc.name: TransStreamStats, use the wrong parameter.
 * @tc.desc: TransRippleStats001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRippleStats001, TestSize.Level1)
{
    int32_t channelId = 1111;
    int32_t channelType = 222;
    StreamSendStats *data = (StreamSendStats *)SoftBusMalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(data != nullptr);
    memset_s(data, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    TrafficStats *trafficStats = (TrafficStats *)SoftBusMalloc(sizeof(TrafficStats));
    ASSERT_TRUE(trafficStats != nullptr);
    memset_s(trafficStats, sizeof(TrafficStats), 0, sizeof(TrafficStats));

    int32_t ret = TransRippleStats(channelId, channelType, trafficStats);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransRippleStats(channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = -1;
    ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransStreamStats(channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransLaneMgrDeinit();
    ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    if (data != NULL) {
        SoftBusFree(data);
    }
}

/**
 * @tc.name: TransNotifyAuthSuccess001
 * @tc.desc: TransNotifyAuthSuccess, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransNotifyAuthSuccess001, TestSize.Level1)
{
    int32_t channelId = 1111;
    int32_t channelType = CHANNEL_TYPE_UDP;

    int32_t ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransRequestQos001
 * @tc.desc: TransRequestQos001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRequestQos001, TestSize.Level1)
{
    int32_t channelId = -1111;
    int32_t channelType = 222;
    int32_t appType = 333;
    int32_t quality = 444;

    int32_t ret = TransRequestQos(channelId, channelType, appType, quality);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCloseChannel001
 * @tc.desc: TransCloseChannel001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannel001, TestSize.Level1)
{
    int32_t channelId = 111;
    int32_t channelType = 222;

    channelId++;
    int32_t ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelId++;
    channelType = CHANNEL_TYPE_UDP;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelId++;
    channelType = CHANNEL_TYPE_AUTH;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);

    channelId++;
    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransSendMsg001
 * @tc.desc: TransSendMsg, use the wrong parameter.
 * @tc.desc: TransChannelDeathCallback, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSendMsg001, TestSize.Level1)
{
    int32_t channelId = 1111;
    int32_t channelType = 222;
    void *data = nullptr;
    uint32_t len = 0;
    int32_t msgType = 0;

    channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransSendMsg(channelId, channelType, data, len, msgType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_UDP;
    ret = TransSendMsg(channelId, channelType, data, len, msgType);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNEL_TYPE_INVALID, ret);

    int32_t pid = 1;

    TransProxyDeathCallback(NULL, pid);
    TransChannelDeathCallback(NULL, pid);
}

/**
 * @tc.name: TransGetNameByChanId001
 * @tc.desc: TransGetNameByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId001, TestSize.Level1)
{
    TransInfo *info = (TransInfo *)SoftBusMalloc(sizeof(TransInfo));
    ASSERT_TRUE(info != nullptr);
    memset_s(info, sizeof(TransInfo), 0, sizeof(TransInfo));
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";

    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = 2;

    int32_t ret = TransGetNameByChanId(NULL, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, NULL, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, pkgName, NULL, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = 8888;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = CHANNEL_TYPE_UDP;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    info->channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    if (info != NULL) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: TransGetAppInfoByChanId001
 * @tc.desc: TransGetAppInfoByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t channelId = 111;
    int32_t channelType = 222;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransGetAppInfoByChanId(channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_UDP;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: TransGetConnByChanId001
 * @tc.desc: TransGetConnByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId001, TestSize.Level1)
{
    int32_t channelId = 111;
    int32_t channelType = 222;
    int32_t connId = -1;

    channelType = CHANNEL_TYPE_PROXY + 1;
    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: FindConfigType001
 * @tc.desc: FindConfigType001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, FindConfigType001, TestSize.Level1)
{
    int32_t channelType = 0;
    int32_t businessType = 0;

    int32_t ret = FindConfigType(channelType, businessType);
    EXPECT_EQ(SOFTBUS_CONFIG_TYPE_MAX, ret);

    channelType = CHANNEL_TYPE_AUTH;
    businessType = BUSINESS_TYPE_BYTE;
    ret = FindConfigType(channelType, businessType);
    EXPECT_EQ(SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH, ret);
}

/**
 * @tc.name: TransGetLocalConfig001
 * @tc.desc: TransGetLocalConfig001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetLocalConfig001, TestSize.Level1)
{
    int32_t channelType = 0;
    int32_t businessType = 0;
    uint32_t len = 0;

    int32_t ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_AUTH;
    businessType = BUSINESS_TYPE_BYTE;
    ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // OHOS
