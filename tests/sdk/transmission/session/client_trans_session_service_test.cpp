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

#include <gtest/gtest.h>
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_trans_def.h"
#include "softbus_app_info.h"
#include "softbus_server_frame.h"
#include "softbus_adapter_mem.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "softbus_config_type.h"
#include "trans_log.h"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_CHANNEL_ID 12345
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_STATE 1

#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define TRANS_TEST_INVALID_QUALITY (-1)
#define TRANS_TEST_INVALID_CHANNEL_ID (-1)
#define TRANS_TEST_INVALID_SESSION_ID (-1)

#define MAX_SESSION_SERVER_NUM 32

using namespace testing::ext;

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_groupid = "TEST_GROUP_ID";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};
class TransClientSessionServiceTest : public testing::Test {
public:
    TransClientSessionServiceTest()
    {}
    ~TransClientSessionServiceTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionServiceTest::SetUpTestCase(void)
{
    InitSoftBusServer();
}

void TransClientSessionServiceTest::TearDownTestCase(void)
{
}

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

static SessionInfo *GenerateSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo*)SoftBusMalloc(sizeof(SessionInfo));
    EXPECT_TRUE(session != NULL);
    memset_s(session, sizeof(SessionInfo), 0, sizeof(SessionInfo));

    int ret = strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName);
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId);
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId);
    EXPECT_EQ(ret, EOK);

    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->isEnable = false;
    session->routeType = ROUTE_TYPE_ALL;
    session->info.flag = TYPE_BYTES;
    session->isEncrypt = true;
    session->algorithm = TRANS_TEST_ALGORITHM;
    session->fileEncrypt = TRANS_TEST_FILE_ENCRYPT;
    session->crc = TRANS_TEST_CRC;

    return session;
}
static void GenerateCommParam(SessionParam *sessionParam)
{
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupid;
    sessionParam->attr = &g_sessionAttr;
}

/**
 * @tc.name: TransClientSessionServiceTest01
 * @tc.desc: Transmission sdk session service qos report and open session synchronize with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest01, TestSize.Level1)
{
    int32_t ret = QosReport(TRANS_TEST_SESSION_ID, APP_TYPE_AUTH, TRANS_TEST_INVALID_QUALITY);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = QosReport(TRANS_TEST_SESSION_ID, APP_TYPE_AUTH, QOS_IMPROVE);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = OpenSessionSync(NULL, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = OpenSessionSync(g_sessionName, NULL, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = OpenSessionSync(g_sessionName, g_sessionName, NULL, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = OpenSessionSync(g_sessionName, g_sessionName, g_networkId, NULL, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = OpenSessionSync(g_sessionName, g_sessionName, g_networkId, g_groupid, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = OpenSessionSync(g_sessionName, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionServiceTest02
 * @tc.desc: Transmission sdk session service qos report.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest02, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    session->isServer = true;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = QosReport(sessionId, APP_TYPE_AUTH, QOS_IMPROVE);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = QosReport(sessionId, APP_TYPE_AUTH, QOS_IMPROVE);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionServiceTest03
 * @tc.desc: Transmission sdk session service open session synchronize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest03, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isEnabled = false;
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = OpenSessionSync(g_sessionName, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenSessionSync(g_sessionName, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

}
