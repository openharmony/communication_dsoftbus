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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "disc_event_manager.h"
#include "lnn_lane_interface.h"
#include "message_handler.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "trans_session_service.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"

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

void TransUdpNegotiationTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
    SetAccessTokenPermission("dsoftbusTransTest");
}

void TransUdpNegotiationTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
}

/**
 * @tc.name: TransUdpNegotiationTest01
 * @tc.desc: Transmission open channel with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransUdpNegotiationTest01, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
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
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    appInfo->linkType = LANE_BLE;
    strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName);
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
    connOpt->type = CONNECT_TYPE_MAX;
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    ConnectOption *connOpt = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    EXPECT_TRUE(connOpt != NULL);
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
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    int32_t res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    appInfo->myData.pid = INVALID_PID;
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = NotifyUdpChannelClosed(appInfo, MESSAGE_TYPE_NOMAL);
    EXPECT_EQ(ret,  SOFTBUS_IPC_ERR);
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
    AppInfo* appInfo = nullptr;
    int32_t ret = NotifyUdpChannelOpenFailed(appInfo, SOFTBUS_TRANS_INVALID_SESSION_NAME);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    int32_t res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                       g_sessionName);
    EXPECT_EQ(res, EOK);
    ret = NotifyUdpChannelOpenFailed(appInfo, SOFTBUS_TRANS_INVALID_SESSION_NAME);
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    int32_t res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
                   g_sessionName);
    EXPECT_EQ(res, EOK);
    appInfo->myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = NotifyUdpChannelOpenFailed(appInfo, SOFTBUS_MEM_ERR);
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    int32_t res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
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
    AppInfo* appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    int32_t res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName),
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
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
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
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t res = strcpy_s(newChannel->info.myData.pkgName, sizeof(newChannel->info.myData.pkgName),
                       g_pkgName);
    newChannel->info.myData.pid = INVALID_PID;
    EXPECT_EQ(res, EOK);
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransUdpDeathCallback(g_pkgName, INVALID_PID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = TransUdpChannelMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransDealUdpCheckCollabResult001
 * @tc.desc: Check collab result, invalid channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransDealUdpCheckCollabResult001, TestSize.Level1)
{
    int32_t checkResult = SOFTBUS_OK;
    int32_t ret = TransDealUdpCheckCollabResult(TEST_CHANNEL_ID, checkResult);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND);
}

/**
 * @tc.name: TransDealUdpCheckCollabResult002
 * @tc.desc: Check collab result, check result is ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransDealUdpCheckCollabResult002, TestSize.Level1)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t res = strcpy_s(newChannel->info.myData.pkgName, sizeof(newChannel->info.myData.pkgName),
                       g_pkgName);
    newChannel->info.myData.pid = INVALID_PID;
    EXPECT_EQ(res, EOK);
    int32_t checkResult = SOFTBUS_OK;
    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealUdpCheckCollabResult(TEST_CHANNEL_ID, checkResult);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ReleaseUdpChannelId(TEST_CHANNEL_ID);
}

/**
 * @tc.name: TransDealUdpCheckCollabResult003
 * @tc.desc: Check collab result, check result is err.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationTest, TransDealUdpCheckCollabResult003, TestSize.Level1)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    EXPECT_TRUE(newChannel != NULL);
    newChannel->seq = 1;
    newChannel->info.myData.channelId = TEST_CHANNEL_ID;
    int32_t ret = strcpy_s(newChannel->info.myData.pkgName, sizeof(newChannel->info.myData.pkgName), g_pkgName);
    newChannel->info.myData.pid = INVALID_PID;
    EXPECT_EQ(ret, EOK);
    int32_t checkResult = SOFTBUS_COND_INIT_FAILED;
    ret = TransAddUdpChannel(newChannel);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransDealUdpCheckCollabResult(TEST_CHANNEL_ID, checkResult);
    EXPECT_EQ(ret, SOFTBUS_COND_INIT_FAILED);

    ReleaseUdpChannelId(TEST_CHANNEL_ID);
}
}