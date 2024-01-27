/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "softbus_app_info.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_server_frame.h"
#include "trans_log.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "client_trans_session_service.h"
#include "softbus_access_token_test.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_SOCKET_PORT 60000
#define TEST_CHANNEL_ID  12345

#define INVALID_EVENT_ID (-1)
#define INVALID_PID (-1)

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";

class TransUdpNegotiationTest : public testing::Test {
public:
    TransUdpNegotiationTest()
    {}
    ~TransUdpNegotiationTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static int OnSessionOpened(int sessionId, int result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d", sessionId);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, sessionId=%{public}d", sessionId);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, sessionId=%{public}d", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

void TransUdpNegotiationTest::SetUpTestCase(void)
{
    InitSoftBusServer();
    SetAceessTokenPermission("dsoftbusTransTest");
}

void TransUdpNegotiationTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransUdpNegotiationTest01
 * @tc.desc: Transmission open channel with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest01, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ConnectOption *connOpt = (ConnectOption*)SoftBusMalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t channelId = 0;
    int32_t ret = TransOpenUdpChannel(NULL, connOpt, &channelId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransOpenUdpChannel(appInfo, NULL, &channelId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = TransOpenUdpChannel(appInfo, connOpt, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    SoftBusFree(appInfo);
    SoftBusFree(connOpt);
}
/**
 * @tc.name: TransUdpNegotiationTest02
 * @tc.desc: Transmission open channel with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest02, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ConnectOption *connOpt = (ConnectOption*)SoftBusMalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt->socketOption.port = TEST_SOCKET_PORT;
    connOpt->type = CONNECT_TYPE_MAX;
    int32_t channelId = 0;
    int32_t ret = TransOpenUdpChannel(appInfo, connOpt, &channelId);
    EXPECT_NE(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
    SoftBusFree(connOpt);
}

/**
 * @tc.name: TransUdpNegotiationTest03
 * @tc.desc: Transmission open channel with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest03, TestSize.Level1)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    ConnectOption *connOpt = (ConnectOption*)SoftBusMalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt->type = CONNECT_TCP;
    connOpt->socketOption.port = TEST_SOCKET_PORT;
    int32_t channelId = 0;
    ret = TransOpenUdpChannel(appInfo, connOpt, &channelId);
    EXPECT_NE(ret,  SOFTBUS_OK);
    ret = TransDelUdpChannel(TEST_CHANNEL_ID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
    SoftBusFree(connOpt);
}

/**
 * @tc.name: TransUdpNegotiationTest04
 * @tc.desc: Transmission open channel with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest04, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    ConnectOption *connOpt = (ConnectOption*)SoftBusMalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    memset_s(connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt->type = CONNECT_TCP;
    connOpt->socketOption.port = TEST_SOCKET_PORT;
    int32_t channelId = 0;
    int32_t ret = TransOpenUdpChannel(appInfo, connOpt, &channelId);
    EXPECT_NE(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
    SoftBusFree(connOpt);
}

/**
 * @tc.name: TransUdpNegotiationTest05
 * @tc.desc: Transmission close channel with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest05, TestSize.Level1)
{
    int32_t ret = TransCloseUdpChannel(TEST_CHANNEL_ID);
    EXPECT_NE(ret,  SOFTBUS_OK);
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransCloseUdpChannel(TEST_CHANNEL_ID);
    EXPECT_NE(ret,  SOFTBUS_OK);
    ret = TransDelUdpChannel(TEST_CHANNEL_ID);
    EXPECT_NE(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegotiationTest06
 * @tc.desc: Transmission notify udp channel closed with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest06, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    appInfo->myData.pid = INVALID_PID;
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = NotifyUdpChannelClosed(appInfo);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationTest07
 * @tc.desc: Transmission notify udp channel open failed with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest07, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                       g_sessionName);
    EXPECT_EQ(res, EOK);
    int32_t ret = NotifyUdpChannelOpenFailed(appInfo, SOFTBUS_TRANS_INVALID_SESSION_NAME);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationTest08
 * @tc.desc: Transmission notify udp channel open failed with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest08, TestSize.Level1)
{
    int res = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(res, SOFTBUS_OK);
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                   g_sessionName);
    EXPECT_EQ(res, EOK);
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = NotifyUdpChannelOpenFailed(appInfo, SOFTBUS_ERR);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    RemoveSessionServer(g_pkgName, g_sessionName);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationTest09
 * @tc.desc: Transmission notify udp qos event with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest09, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                       g_sessionName);
    EXPECT_EQ(res, EOK);
    int32_t ret = NotifyUdpQosEvent(appInfo, INVALID_EVENT_ID, 0, NULL);
    EXPECT_NE(ret,  SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationTest10
 * @tc.desc: Transmission notify udp qos event with wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest10, TestSize.Level1)
{
    int res = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(res, SOFTBUS_OK);
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                   g_sessionName);
    EXPECT_EQ(res, EOK);
    int32_t ret = NotifyUdpQosEvent(appInfo, INVALID_EVENT_ID, 0, NULL);
    EXPECT_NE(ret,  SOFTBUS_OK);
    RemoveSessionServer(g_pkgName, g_sessionName);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationTest11
 * @tc.desc: Transmission release udp channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest11, TestSize.Level1)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDelUdpChannel(TEST_CHANNEL_ID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ReleaseUdpChannelId(TEST_CHANNEL_ID);
}

/**
 * @tc.name: TransUdpNegotiationTest12
 * @tc.desc: Transmission udp death callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest12, TestSize.Level1)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int res = strcpy_s(newChannel->info.myData.pkgName, sizeof(newChannel->info.myData.pkgName),
                       g_pkgName);
    newChannel->info.myData.pid = INVALID_PID;
    EXPECT_EQ(res, EOK);
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransUdpDeathCallback(g_pkgName, INVALID_PID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}
}