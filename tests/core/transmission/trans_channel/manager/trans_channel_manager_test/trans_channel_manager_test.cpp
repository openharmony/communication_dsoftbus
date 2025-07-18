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

/**
 * @tc.name: TransChannelInit001
 * @tc.desc: TransChannelInit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransChannelInit001, TestSize.Level1)
{
    bool ret = GetServerIsInit();
    EXPECT_EQ(false, ret);
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
    EXPECT_EQ(false, ret);
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
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    (void)memset_s(param, sizeof(SessionParam), 0, sizeof(SessionParam));
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];

    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransCommonGetAppInfo).WillRepeatedly(Return(SOFTBUS_MEM_ERR));

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_TRUE(transInfo != nullptr);
    (void)memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    int32_t ret = TransOpenChannel(param, transInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    SoftBusFree(param);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransOpenChannel002
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given null parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel002, TestSize.Level1)
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

    int32_t ret = TransOpenAuthChannel(nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenAuthChannel(sessionName, nullptr, nullptr, nullptr);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ConnectParam param;
    (void)memset_s(&param, sizeof(ConnectParam), 0, sizeof(ConnectParam));
    TransManagerInterfaceMock mock;
    connOpt->type = CONNECT_TCP;
    ret = TransOpenAuthChannel(sessionName, connOpt, nullptr, &param);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    connOpt->type = CONNECT_BR;
    ret = TransOpenAuthChannel(sessionName, connOpt, nullptr, &param);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    connOpt->type = CONNECT_BLE;
    ret = TransOpenAuthChannel(sessionName, connOpt, nullptr, &param);
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
    StreamSendStats *src = (StreamSendStats *)SoftBusCalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(src != nullptr);
    memset_s(src, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    FrameSendStats *dest = (FrameSendStats *)SoftBusCalloc(sizeof(FrameSendStats));
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
    StreamSendStats *data = (StreamSendStats *)SoftBusCalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(data != nullptr);
    memset_s(data, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    TrafficStats *trafficStats = (TrafficStats *)SoftBusCalloc(sizeof(TrafficStats));
    ASSERT_TRUE(trafficStats != nullptr);
    memset_s(trafficStats, sizeof(TrafficStats), 0, sizeof(TrafficStats));

    int32_t ret = TransRippleStats(channelId, channelType, trafficStats);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransRippleStats(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = -1;
    ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransStreamStats(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransLaneMgrDeinit();
    ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    if (data != nullptr) {
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
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransNotifyAuthSuccess(channelId, channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
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
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
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
    int32_t ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);

    channelId++;
    channelType = CHANNEL_TYPE_UDP;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    channelId++;
    channelType = CHANNEL_TYPE_AUTH;
    ret = TransCloseChannel(nullptr, channelId, channelType);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);

    channelId++;
    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransCloseChannel(nullptr, channelId, channelType);
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

    TransProxyDeathCallback(nullptr, pid);
    TransChannelDeathCallback(nullptr, pid);
}

/**
 * @tc.name: TransGetNameByChanId001
 * @tc.desc: TransGetNameByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId001, TestSize.Level1)
{
    TransInfo *info = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_TRUE(info != nullptr);
    memset_s(info, sizeof(TransInfo), 0, sizeof(TransInfo));
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";

    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = 2;

    int32_t ret = TransGetNameByChanId(nullptr, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, nullptr, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, pkgName, nullptr, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = 8888;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = CHANNEL_TYPE_UDP;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    info->channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = CHANNEL_TYPE_PROXY;
    ret = TransGetNameByChanId(info, pkgName, sessionName, pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    if (info != nullptr) {
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
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t channelId = 1;
    int32_t channelType = 222;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
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

    channelType = CHANNEL_TYPE_PROXY;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: TransGetConnByChanId Test
 * @tc.desc: TransGetConnByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId001, TestSize.Level1)
{
    int32_t channelId = 111;
    int32_t channelType = 222;
    int32_t connId = -1;

    channelType = CHANNEL_TYPE_PROXY;
    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_BUTT;
    ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
}

/**
 * @tc.name: TransGetConnByChanId Test
 * @tc.desc: TransGetConnByChanId002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t connId = 1;
    int32_t channelType = CHANNEL_TYPE_AUTH;
    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GenerateProxyChannelId and ReleaseProxyChannelId test
 * @tc.desc: GenerateProxyChannelId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateProxyChannelId001, TestSize.Level1)
{
    SoftBusMutexInit(&g_myIdLock, nullptr);
    int32_t channelId = GenerateProxyChannelId();
    EXPECT_EQ(TEST_PROXY_CHANNEL_ID, channelId);
    channelId = GenerateTdcChannelId();
    EXPECT_EQ(TEST_TDC_CHANNEL_ID, channelId);
    ReleaseProxyChannelId(channelId);
    SoftBusMutexDestroy(&g_myIdLock);
}

/**
 * @tc.name: IsLaneModuleError test
 * @tc.desc: IsLaneModuleError001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, IsLaneModuleError001, TestSize.Level1)
{
    bool ret = IsLaneModuleError(SOFTBUS_LANE_DETECT_FAIL);
    EXPECT_EQ(true, ret);
    ret = IsLaneModuleError(SOFTBUS_CONN_FAIL);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: TransSetFirstTokenInfo test
 * @tc.desc: TransSetFirstTokenInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetFirstTokenInfo001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->tokenName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    appInfo->callingTokenId = 2;
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransAclGetFirstTokenID).WillOnce(Return(TOKENID_NOT_SET));
    TransSetFirstTokenInfo(appInfo, &extra);
    EXPECT_NE(nullptr, appInfo);
    TransFreeAppInfo(appInfo);
}

/**
 * @tc.name: TransNotifyAuthSuccess test
 * @tc.desc: TransNotifyAuthSuccess002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransNotifyAuthSuccess002, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransProxyGetConnOptionByChanId).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransNotifyAuthSuccess(1, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_TRANS_CHANNELID_CONVERT_ADDR_FAILED, ret);
}

/**
 * @tc.name: TransReleaseUdpResources test
 * @tc.desc: TransReleaseUdpResources001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReleaseUdpResources001, TestSize.Level1)
{
    int32_t ret = TransReleaseUdpResources(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCloseChannelWithStatistics test
 * @tc.desc: TransCloseChannelWithStatistics001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransCloseChannelWithStatistics001, TestSize.Level1)
{
    const char *data = "test";
    int32_t ret = TransCloseChannelWithStatistics(1, 1, 1, static_cast<const void *>(data), strlen(data));
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransSendMsg test
 * @tc.desc: TransSendMsg002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSendMsg002, TestSize.Level1)
{
    int32_t ret = TransSendMsg(1, CHANNEL_TYPE_PROXY, nullptr, 0, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransOpenChannel test
 * @tc.desc: TransOpenChannel003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel003, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = true;

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
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

/**
 * @tc.name: TransOpenChannel test
 * @tc.desc: TransOpenChannel004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel004, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = false;

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
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

/**
 * @tc.name: TransOpenChannel test
 * @tc.desc: TransOpenChannel005
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel005, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = true;

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
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

/**
 * @tc.name: TransOpenChannel test
 * @tc.desc: TransOpenChannel006
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel006, TestSize.Level1)
{
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(param != nullptr);
    param->sessionName = TEST_SESSION_NAME;
    param->sessionId = 1;
    int32_t tmp = 0;
    param->attr = &g_sessionAttr[tmp];
    param->isQosLane = false;

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
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

/**
 * @tc.name: GetAuthAppInfo Test
 * @tc.desc: GetAuthAppInfo001
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

/**
 * @tc.name: GetAuthAppInfo Test
 * @tc.desc: GetAuthAppInfo002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetAuthAppInfo002, TestSize.Level1)
{
    TransManagerInterfaceMock mock;
    EXPECT_CALL(mock, TransGetUidAndPid).WillOnce(Return(SOFTBUS_NO_INIT));
    AppInfo *appInfo = GetAuthAppInfo(g_sessionName);
    EXPECT_EQ(nullptr, appInfo);
}

/**
 * @tc.name: GetAuthAppInfo Test
 * @tc.desc: GetAuthAppInfo003
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

/**
 * @tc.name: GetAuthAppInfo Test
 * @tc.desc: GetAuthAppInfo004
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

/**
 * @tc.name: GetAuthAppInfo Test
 * @tc.desc: GetAuthAppInfo005
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

/**
 * @tc.name: TransGetAndComparePid Test
 * @tc.desc: TransGetAndComparePid001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAndComparePid001, TestSize.Level1)
{
    int32_t ret = TransGetAndComparePid(TRANS_TEST_PID, 1, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_ID, ret);
    ret = TransGetAndComparePid(TRANS_TEST_PID, 1, CHANNEL_TYPE_AUTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransPrivilegeCloseChannel001
 * @tc.desc: TransPrivilegeCloseChannel Test
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransPrivilegeCloseChannel001, TestSize.Level1)
{
    uint64_t tokenId = 1;
    int32_t pid = 1;
    int32_t ret = TransPrivilegeCloseChannel(tokenId, pid, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *deviceId = "ASDS123124";
    ret = TransPrivilegeCloseChannel(tokenId, pid, deviceId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: PrivilegeCloseListAddItem Test
 * @tc.desc: PrivilegeCloseListAddItem001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, PrivilegeCloseListAddItem001, TestSize.Level1)
{
    int32_t pid = 0;
    ListNode privilegeCloseList;
    ListInit(&privilegeCloseList);
    int32_t ret = PrivilegeCloseListAddItem(nullptr, pid, g_pkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PrivilegeCloseListAddItem(&privilegeCloseList, pid, g_pkgName);
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

/**
 * @tc.name: GetChannelInfoFromBuf Test
 * @tc.desc: GetChannelInfoFromBuf001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetChannelInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[12] = {0};
    uint32_t len = 12;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    info.channelType = CHANNEL_TYPE_AUTH;
    int ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 8;
    ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 4;
    ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 1;
    ret = GetChannelInfoFromBuf(buf, len, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: GetUdpChannelInfoFromBuf Test
 * @tc.desc: GetUdpChannelInfoFromBuf001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetUdpChannelInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[28] = {0};
    int32_t udpPort = 0;
    uint32_t len = 28;
    OpenChannelResult info = {0};
    AccessInfo accessInfo = {0};
    int ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    len = 12;
    ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 8;
    ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 4;
    ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 1;
    ret = GetUdpChannelInfoFromBuf(buf, len, &udpPort, &info, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: GetLimitChangeInfoFromBuf Test
 * @tc.desc: GetLimitChangeInfoFromBuf001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetLimitChangeInfoFromBuf001, TestSize.Level1)
{
    uint8_t buf[9] = {0};
    int32_t channelId = 0;
    uint8_t tos = 0;
    int32_t limit = 0;
    uint32_t len = 9;

    int ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    len = 5;
    ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 4;
    ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 1;
    ret = GetLimitChangeInfoFromBuf(buf, &channelId, &tos, &limit, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: TransReportChannelOpenedInfo Test
 * @tc.desc: TransReportChannelOpenedInfo001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportChannelOpenedInfo001, TestSize.Level1)
{
    uint8_t buf[28] = {0};
    uint32_t len = 28;

    buf[4] = CHANNEL_TYPE_PROXY;
    int ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_UDP;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_AUTH;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_BUTT;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);

    len = 1;
    ret = TransReportChannelOpenedInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransReportLimitChangeInfo Test
 * @tc.desc: TransReportLimitChangeInfo001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportLimitChangeInfo001, TestSize.Level1)
{
    uint8_t buf[9] = {0};
    int32_t len = 9;

    EXPECT_NO_FATAL_FAILURE(TransReportLimitChangeInfo(buf, len, TRANS_TEST_PID));
    len = 1;
    EXPECT_NO_FATAL_FAILURE(TransReportLimitChangeInfo(buf, len, TRANS_TEST_PID));
}

/**
 * @tc.name: GetCollabCheckResultFromBuf Test
 * @tc.desc: GetCollabCheckResultFromBuf001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GetCollabCheckResultFromBuf001, TestSize.Level1)
{
    uint8_t buf[12] = {0};
    int32_t channelId = 0;
    int32_t channelType = 0;
    int32_t checkResult = 0;
    int32_t len = 12;

    int ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    len = 8;
    ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 4;
    ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = 1;
    ret = GetCollabCheckResultFromBuf(buf, &channelId, &channelType, &checkResult, len);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: TransReportCheckCollabInfo Test
 * @tc.desc: TransReportCheckCollabInfo001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransReportCheckCollabInfo001, TestSize.Level1)
{
    uint8_t buf[12] = {0};
    int32_t len = 12;

    buf[4] = CHANNEL_TYPE_PROXY;
    int ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_UDP;
    ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);

    buf[4] = CHANNEL_TYPE_BUTT;
    ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);

    len = 1;
    ret = TransReportCheckCollabInfo(buf, len, TRANS_TEST_PID);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransProcessInnerEvent Test
 * @tc.desc: TransProcessInnerEvent001
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransProcessInnerEvent001, TestSize.Level1)
{
    uint8_t buf[12] = {0};
    int32_t len = 12;
    int32_t eventType = EVENT_TYPE_CHANNEL_OPENED;

    int ret = TransProcessInnerEvent(eventType, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    eventType = EVENT_TYPE_BUTT;
    ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_EQ(SOFTBUS_TRANS_MSG_INVALID_EVENT_TYPE, ret);

    eventType = EVENT_TYPE_TRANS_LIMIT_CHANGE;
    ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    eventType = EVENT_TYPE_COLLAB_CHECK;
    ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    eventType = EVENT_TYPE_SET_ACCESS_INFO;
    ret = TransProcessInnerEvent(eventType, buf, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GenerateChannelId test
 * @tc.desc: GenerateChannelId001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, GenerateChannelId001, TestSize.Level1)
{
    int32_t channelId;
    int32_t tdcChannel = g_allocTdcChannelId;
    g_allocTdcChannelId = MAX_TDC_CHANNEL_ID;
    int32_t ret = SoftBusMutexInit(&g_myIdLock, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    channelId = GenerateTdcChannelId();
    EXPECT_EQ(MAX_TDC_CHANNEL_ID, channelId);
    g_allocTdcChannelId = tdcChannel;

    int32_t proxyChannel = g_channelIdCount;
    g_channelIdCount = MAX_PROXY_CHANNEL_ID_COUNT;
    channelId = GenerateProxyChannelId();
    EXPECT_EQ(INVALID_CHANNEL_ID, channelId);
    g_channelIdCount = proxyChannel;
    SoftBusMutexDestroy(&g_myIdLock);
}

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

/**
 * @tc.name: TransSetAccessInfo test
 * @tc.desc: TransSetAccessInfo001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo001, TestSize.Level1)
{
    int32_t expectedUserId = 123;
    uint64_t expectedTokenId = 987654321;
    const char *expectedSessionName = "test_session";
    const char *expectedExtraInfo = "extra_info_data";
    const char *expectedBusinessVer = "v1.2.3";
    uint8_t testBuffer[TEST_BUF_LEN] = {0};
    int32_t bufferOffset = 0;
    pid_t callingPid = (pid_t)TRANS_TEST_PID;
 
    AddInt32ToBuffer(expectedUserId, testBuffer, bufferOffset);
    AddUint64ToBuffer(expectedTokenId, testBuffer, bufferOffset);
    AddStringToBuffer(expectedSessionName, testBuffer, bufferOffset);
    AddStringToBuffer(expectedExtraInfo, testBuffer, bufferOffset);
    AddStringToBuffer(expectedBusinessVer, testBuffer, bufferOffset);

    int32_t ret = TransSetAccessInfo(testBuffer, TEST_BUF_LEN, callingPid);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    char sessionName[] = "test_session";
    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    ASSERT_TRUE(newNode != nullptr);
    strcpy_s(newNode->sessionName, sizeof(sessionName), sessionName);
    newNode->pid = callingPid;

    ret = TransSessionMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSessionServerAddItem(newNode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetAccessInfo(testBuffer, TEST_BUF_LEN, callingPid);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSessionServerDelItem(sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSessionMgrDeinit();
}

/**
 * @tc.name: TransSetAccessInfo test
 * @tc.desc: TransSetAccessInfo002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransSetAccessInfo002, TestSize.Level1)
{
    uint8_t shortBuf[1] = {0};
    pid_t callingPid = (pid_t)TRANS_TEST_PID;
    int32_t ret = TransSetAccessInfo(shortBuf, 1, callingPid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);

    uint8_t buf[sizeof(int32_t) + 1] = {0};
    ret = TransSetAccessInfo(buf, sizeof(buf), callingPid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}
} // OHOS