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
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "softbus_app_info.h"
#include "softbus_server_frame.h"
#include "softbus_adapter_mem.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_session_service.h"
#include "softbus_config_type.h"
#include "trans_log.h"
#include "softbus_feature_config.h"
#include "softbus_conn_interface.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "trans_session_service.h"

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
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
}

void TransClientSessionServiceTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
}

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d", sessionId);
}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, sessionId=%{public}d", sessionId);
}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, sessionId=%{public}d", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

static void TestGenerateCommParam(SessionParam *sessionParam)
{
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupid;
    sessionParam->attr = &g_sessionAttr;
}

static SessionInfo *TestGenerateSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo*)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        return NULL;
    }

    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK) {
        SoftBusFree(session);
        return NULL;
    }

    session->sessionId = TRANS_TEST_SESSION_ID;
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->enableStatus = ENABLE_STATUS_INIT;
    session->routeType = ROUTE_TYPE_ALL;
    session->info.flag = TYPE_BYTES;
    session->isEncrypt = true;
    session->algorithm = TRANS_TEST_ALGORITHM;
    session->fileEncrypt = TRANS_TEST_FILE_ENCRYPT;
    session->crc = TRANS_TEST_CRC;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
    return session;
}

static int32_t AddSessionServerAndSession(const char *sessionName, int32_t channelType, bool isServer)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    if (sessionParam == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }

    TestGenerateCommParam(sessionParam);
    sessionParam->sessionName = sessionName;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, sessionName, &g_sessionlistener);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(sessionParam);
        return ret;
    }

    SessionInfo *session = TestGenerateSession(sessionParam);
    if (session == NULL) {
        SoftBusFree(sessionParam);
        return SOFTBUS_MALLOC_ERR;
    }

    session->channelType = (ChannelType)channelType;
    session->isServer = isServer;
    ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        SoftBusFree(sessionParam);
        return ret;
    }

    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, channelType, &sessionId, isClosing);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        SoftBusFree(sessionParam);
        return ret;
    }

    SoftBusFree(sessionParam);
    return sessionId;
}

static void DeleteSessionServerAndSession(const char *sessionName, int32_t sessionId)
{
    (void)ClientDeleteSession(sessionId);
    (void)ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, sessionName);
}

static SessionInfo *GenerateSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo*)SoftBusMalloc(sizeof(SessionInfo));
    EXPECT_TRUE(session != NULL);
    memset_s(session, sizeof(SessionInfo), 0, sizeof(SessionInfo));

    int32_t ret = strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName);
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId);
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId);
    EXPECT_EQ(ret, EOK);

    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->enableStatus = ENABLE_STATUS_INIT;
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
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED);
    ret = OpenSessionSync(NULL, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_INVALID_SESSION_NAME);
    ret = OpenSessionSync(g_sessionName, NULL, g_networkId, g_groupid, &g_sessionAttr);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_INVALID_SESSION_NAME);
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
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
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
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = QosReport(sessionId, APP_TYPE_AUTH, QOS_IMPROVE);
    EXPECT_EQ(ret,  SOFTBUS_ACCESS_TOKEN_DENIED);
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
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
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
    EXPECT_EQ(ret, SOFTBUS_ACCESS_TOKEN_DENIED);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionServiceTest04
 * @tc.desc: Transmission sdk session service get session option with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest04, TestSize.Level1)
{
    uint32_t optionValue = 0;
    int32_t ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_BUTT,
                               &optionValue, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           NULL, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           &optionValue, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           &optionValue, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    ret = GetSessionOption(sessionId, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           &optionValue, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionServiceTest05
 * @tc.desc: Transmission sdk session service get peer device Id with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest05, TestSize.Level1)
{
    char networkId[DEVICE_ID_SIZE_MAX] = {0};
    int32_t ret = GetPeerDeviceId(TRANS_TEST_INVALID_SESSION_ID, networkId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerDeviceId(TRANS_TEST_SESSION_ID, NULL, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerDeviceId(TRANS_TEST_SESSION_ID, networkId, SESSION_NAME_SIZE_MAX + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerDeviceId(TRANS_TEST_SESSION_ID, networkId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_BUTT, false);
    ASSERT_GT(sessionId, 0);
    ret = GetPeerDeviceId(sessionId, networkId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = strcmp(g_deviceId, networkId);
    EXPECT_EQ(ret, EOK);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionServiceTest06
 * @tc.desc: Transmission sdk session service get peer session name with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest06, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = GetPeerSessionName(TRANS_TEST_INVALID_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerSessionName(TRANS_TEST_SESSION_ID, NULL, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerSessionName(TRANS_TEST_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerSessionName(TRANS_TEST_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_BUTT, false);
    ASSERT_GT(sessionId, 0);
    ret = GetPeerSessionName(sessionId, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = strcmp(g_sessionName, sessionName);
    EXPECT_EQ(ret, EOK);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionServiceTest04
 * @tc.desc: Transmission sdk session set action addr bind.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionServiceTest, TransClientSessionServiceTest07, TestSize.Level1)
{
    SessionEnableStatus isSessionEnabled = ENABLE_STATUS_INIT;
    int32_t sessionId = 1;
    auto *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_NE(sessionParam, nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);

    int32_t ret = TransClientInit();
    ASSERT_EQ(ret,  SOFTBUS_OK);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddSession(sessionParam, &sessionId, &isSessionEnabled);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ClientSetActionIdBySessionId(sessionId, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t actionId = 1024;
    ret = ClientSetActionIdBySessionId(sessionId, actionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t actionIdRet = 0;
    ret = ClientGetSessionIntegerDataById(sessionId, &actionIdRet, KEY_ACTION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(actionIdRet, actionId);

    ret = ClientDeleteSession(sessionId);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ClientGetSessionIntegerDataById(sessionId, &actionIdRet, KEY_ACTION_ID);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = ClientSetActionIdBySessionId(sessionId, actionId);
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}
}