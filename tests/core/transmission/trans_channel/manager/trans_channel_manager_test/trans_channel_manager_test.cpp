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
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "trans_channel_manager.h"
#include "trans_lane_manager.h"
#include "trans_channel_callback.h"
#include "softbus_def.h"
#include "softbus_server_frame.h"

#include "trans_lane_pending_ctl.c"
#include "trans_channel_callback.c"
#include "trans_session_service.h"

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
 * @tc.name: TransOpenChannel001
 * @tc.desc: TransOpenChannel001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransOpenChannel001, TestSize.Level1)
{
    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));

    int32_t ret = TransOpenSession(param, transInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransSessionMgrInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionServer *sessionServer = (SessionServer*)SoftBusMalloc(sizeof(SessionServer));
    memset_s(sessionServer, sizeof(SessionServer), 0, sizeof(SessionServer));
    ret = strcpy_s(sessionServer->sessionName, sizeof(sessionServer->sessionName), g_sessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(sessionServer->pkgName, sizeof(sessionServer->pkgName), g_pkgName);
    EXPECT_EQ(ret, EOK);
    sessionServer->pid = TRANS_TEST_INVALID_PID;
    ret = TransSessionServerAddItem(sessionServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDelItemByPackageName(g_pkgName, TRANS_TEST_INVALID_PID);
    TransSessionMgrDeinit();
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

    int32_t ret = TransOpenAuthChannel(NULL, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenAuthChannel(sessionName, NULL);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);
    ret = TransOpenAuthChannel(NULL, connOpt);
    EXPECT_EQ(INVALID_CHANNEL_ID, ret);

    if (connOpt != NULL) {
        SoftBusFree(connOpt);
    }
}

/**
 * @tc.name: TransRippleStats001
 * @tc.desc: TransRippleStats001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRippleStats001, TestSize.Level1)
{
    int32_t channelId = 1111111;
    int32_t channelType = 222222;
    StreamSendStats *data = (StreamSendStats*)SoftBusMalloc(sizeof(StreamSendStats));
    memset_s(data, sizeof(StreamSendStats), 0, sizeof(StreamSendStats));

    int32_t ret = TransRippleStats(channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = -1;
    ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    if (data != NULL) {
        SoftBusFree(data);
    }
}

/**
 * @tc.name: TransRequestQos001
 * @tc.desc: TransRequestQos001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransRequestQos001, TestSize.Level1)
{
    int32_t channelId = 1111111;
    int32_t channelType = 222222;
    int32_t appType = 3333;
    int32_t quality = 444444444;

    channelId = -1;
    int32_t ret = TransRequestQos(channelId, channelType, appType, quality);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    channelId = 1111111;

    quality = 444444444;
    ret = TransRequestQos(channelId, channelType, appType, quality);
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
    int32_t channelId = 1111111;
    int32_t channelType = 222222;

    int32_t ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    channelType = CHANNEL_TYPE_PROXY;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID, ret);

    channelType = CHANNEL_TYPE_UDP;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransCloseChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransGetNameByChanId001
 * @tc.desc: TransGetNameByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetNameByChanId001, TestSize.Level1)
{
    TransInfo *info = (TransInfo*)SoftBusMalloc(sizeof(TransInfo));
    memset_s(info, sizeof(TransInfo), 0, sizeof(TransInfo));
    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";

    uint16_t pkgLen = 1;
    uint16_t sessionNameLen = 2;

    int32_t ret = TransGetNameByChanId(NULL, pkgName, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, NULL, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransGetNameByChanId(info, pkgName, NULL,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = 8888;
    ret = TransGetNameByChanId(info, pkgName, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info->channelType = CHANNEL_TYPE_PROXY;
    ret = TransGetNameByChanId(info, pkgName, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    info->channelType = CHANNEL_TYPE_UDP;
    ret = TransGetNameByChanId(info, pkgName, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    info->channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetNameByChanId(info, pkgName, sessionName,
    pkgLen, sessionNameLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransGetAppInfoByChanId001
 * @tc.desc: TransGetAppInfoByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetAppInfoByChanId001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t channelId = 1111111;
    int32_t channelType = 222222;

    int32_t ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransGetAppInfoByChanId(channelId, channelType, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_PROXY;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    channelType = CHANNEL_TYPE_UDP;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    channelType = CHANNEL_TYPE_AUTH;
    ret = TransGetAppInfoByChanId(channelId, channelType, appInfo);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransGetConnByChanId001
 * @tc.desc: TransGetConnByChanId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerTest, TransGetConnByChanId001, TestSize.Level1)
{
    int32_t channelId = 1111111;
    int32_t channelType = 222222;
    int32_t connId = -1;

    channelType = CHANNEL_TYPE_PROXY + 1;
    int32_t ret = TransGetConnByChanId(channelId, channelType, &connId);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // OHOS
