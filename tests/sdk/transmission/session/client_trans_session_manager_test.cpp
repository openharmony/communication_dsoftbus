/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "device_auth.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_server_frame.h"
#include "softbus_trans_def.h"
#include "trans_log.h"
#include "trans_session_service.h"
#include <gtest/gtest.h>

#define TRANS_TEST_SESSION_ID         10
#define TRANS_TEST_PID                0
#define TRANS_TEST_UID                0
#define TRANS_TEST_INVALID_PID        (-1)
#define TRANS_TEST_INVALID_UID        (-1)
#define TRANS_TEST_CHANNEL_ID         1000
#define TRANS_TEST_INVALID_CHANNEL_ID (-1)
#define TRANS_TEST_INVALID_SESSION_ID (-1)
#define TRANS_TEST_FILE_ENCRYPT       10
#define TRANS_TEST_ALGORITHM          1
#define TRANS_TEST_CRC                1
#define TRANS_TEST_STATE              1
#define TRANS_TEST_MAX_WAIT_TIMEOUT   9000
#define TRANS_TEST_DEF_WAIT_TIMEOUT   30000

using namespace testing::ext;

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};
class TransClientSessionManagerTest : public testing::Test {
public:
    TransClientSessionManagerTest() { }
    ~TransClientSessionManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void TransClientSessionManagerTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    InitDeviceAuthService();
    BusCenterServerInit();
    TransServerInit();
}

void TransClientSessionManagerTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
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

static SessionInfo *GenerateSession(const SessionParam *param)
{
    SessionInfo *session = reinterpret_cast<SessionInfo *>(SoftBusCalloc(sizeof(SessionInfo)));
    if (session == nullptr) {
        return nullptr;
    }

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
    session->isAsync = param->isAsync;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
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

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

/*
 * @tc.name: ClientAddSessionInvalidParamTest001
 * @tc.desc: test ClientAddSession with null param and no comm param returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(nullptr, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: ClientAddSessionNoServerTest001
 * @tc.desc: test ClientAddSession with valid param but no session server
 *           returns SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionNoServerTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionServerTest001
 * @tc.desc: test ClientAddSessionServer with null timestamp returns SOFTBUS_INVALID_PARAM
 *           and valid params returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionServerTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientAddNewSessionNoServerTest001
 * @tc.desc: test ClientAddNewSession without session server returns SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddNewSessionNoServerTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    int32_t ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: ClientAddNewSessionTest001
 * @tc.desc: test ClientAddNewSession with session server returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddNewSessionTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddAuthSessionTest001
 * @tc.desc: test ClientAddAuthSession returns SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED without session server
 *           and SOFTBUS_OK with session server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddAuthSessionTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientDeleteSessionNotFoundTest001
 * @tc.desc: test ClientDeleteSession with non-existent session returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDeleteSessionNotFoundTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
/*
 * @tc.name: ClientDeleteSessionTest001
 * @tc.desc: test ClientDeleteSession with valid sessions returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDeleteSessionTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t newSessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(newSessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionTest001
 * @tc.desc: test ClientAddSession with valid params returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionServerOutOfRangeTest001
 * @tc.desc: test ClientAddSessionServer exceeds max number returns SOFTBUS_INVALID_NUM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionServerOutOfRangeTest001, TestSize.Level1)
{
    int32_t ret = 0;
    uint64_t timestamp = 0;
    for (int32_t i = 0; i < MAX_SESSION_SERVER_NUMBER; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = { 0 };
        char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = sprintf_s(pkgName, PKG_NAME_SIZE_MAX, "%s%d", g_pkgName, i);
        EXPECT_GT(ret, 0);
        ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, pkgName, sessionNme, &g_sessionlistener, &timestamp);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_NUM);
    for (int32_t i = 0; i < MAX_SESSION_SERVER_NUMBER; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = { 0 };
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, sessionNme);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
}

/*
 * @tc.name: SetMaxIdleTimeBySocketTest001
 * @tc.desc: test SetMaxIdleTimeBySocket returns SOFTBUS_NOT_IMPLEMENT for valid session id
 *           and SOFTBUS_INVALID_PARAM for invalid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, SetMaxIdleTimeBySocketTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    uint32_t optValueValid = 10000;
    ret = SetMaxIdleTimeBySocket(sessionId, optValueValid);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = SetMaxIdleTimeBySocket(0, optValueValid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: GetMaxIdleTimeBySocketInvalidParamTest001
 * @tc.desc: test GetMaxIdleTimeBySocket with invalid session ID and null pointer returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxIdleTimeBySocketInvalidParamTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    uint32_t getValue = 0;
    ret = GetMaxIdleTimeBySocket(0, &getValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMaxIdleTimeBySocket(sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: GetMaxIdleTimeBySocketTest001
 * @tc.desc: test GetMaxIdleTimeBySocket with valid session ID returns SOFTBUS_NOT_IMPLEMENT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxIdleTimeBySocketTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    uint32_t getValue = 0;
    ret = GetMaxIdleTimeBySocket(sessionId, &getValue);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionOutOfMaxTest001
 * @tc.desc: test ClientAddSession exceeds max session count returns SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionOutOfMaxTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    for (int32_t i = 0; i < MAX_SESSION_ID; ++i) {
        char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
        ret = sprintf_s(sessionName, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        sessionParam->peerSessionName = sessionName;
        ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    sessionParam->peerSessionName = g_sessionName;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionRepeatedTest001
 * @tc.desc: test ClientAddSession with repeated session returns SOFTBUS_TRANS_SESSION_REPEATED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionRepeatedTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    int32_t newSessionId = 0;
    ret = ClientAddSession(sessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_REPEATED);
    EXPECT_EQ(sessionId, newSessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientAddSessionFailedTest001
 * @tc.desc: test ClientAddSession with wrong device ID returns SOFTBUS_TRANS_SESSION_CREATE_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionFailedTest001, TestSize.Level1)
{
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    char longDeviceId[] = { "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF" };
    sessionParam->peerDeviceId = longDeviceId;
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_CREATE_FAILED);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionDataByIdInvalidParamTest001
 * @tc.desc: test ClientGetSessionDataById with invalid session ID returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionDataByIdInvalidParamTest001, TestSize.Level1)
{
    char data[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = ClientGetSessionDataById(TRANS_TEST_INVALID_SESSION_ID, data,
        SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionDataById(TRANS_TEST_INVALID_SESSION_ID, data, SESSION_NAME_SIZE_MAX, KEY_PEER_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionDataById(TRANS_TEST_INVALID_SESSION_ID, data, SESSION_NAME_SIZE_MAX, KEY_PEER_DEVICE_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
/*
 * @tc.name: ClientGetSessionDataByIdValidKeyTest001
 * @tc.desc: test ClientGetSessionDataById with valid key types returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionDataByIdValidKeyTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char data[SESSION_NAME_SIZE_MAX] = { 0 };
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, SESSION_NAME_SIZE_MAX, KEY_PEER_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, DEVICE_ID_SIZE_MAX, KEY_PEER_DEVICE_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, PKG_NAME_SIZE_MAX, KEY_PKG_NAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: ClientGetSessionDataByIdPeerPidTest001
 * @tc.desc: test ClientGetSessionDataById with KEY_PEER_PID returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionDataByIdPeerPidTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char data[SESSION_NAME_SIZE_MAX] = { 0 };
    ret = ClientGetSessionDataById(sessionId, data, PKG_NAME_SIZE_MAX, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionIntegerDataByIdNotFoundTest001
 * @tc.desc: test ClientGetSessionIntegerDataById returns SOFTBUS_INVALID_PARAM for invalid session id or null data,
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIntegerDataByIdNotFoundTest001, TestSize.Level1)
{
    int32_t data = 0;
    int32_t ret = ClientGetSessionIntegerDataById(TRANS_TEST_INVALID_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, nullptr, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}
/*
 * @tc.name: ClientGetSessionIntegerDataByIdValidKeyTest001
 * @tc.desc: test ClientGetSessionIntegerDataById with valid key types returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIntegerDataByIdValidKeyTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t data = 0;
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_IS_SERVER);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PEER_UID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: ClientGetSessionIntegerDataByIdPkgNameTest001
 * @tc.desc: test ClientGetSessionIntegerDataById with KEY_PKG_NAME returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIntegerDataByIdPkgNameTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t data = 0;
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PKG_NAME);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetChannelBySessionIdInvalidParamTest001
 * @tc.desc: test ClientGetChannelBySessionId with invalid session ID returns SOFTBUS_TRANS_INVALID_SESSION_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelBySessionIdInvalidParamTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t type = 0;
    SessionEnableStatus enableStatus = ENABLE_STATUS_INIT;
    int32_t ret = ClientGetChannelBySessionId(TRANS_TEST_INVALID_SESSION_ID, &channelId, &type, &enableStatus);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
}

/*
 * @tc.name: ClientSetChannelBySessionIdNotFoundTest001
 * @tc.desc: test ClientSetChannelBySessionId with non-existent session returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetChannelBySessionIdNotFoundTest001, TestSize.Level1)
{
    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(transInfo);
}
/*
 * @tc.name: ClientSetChannelBySessionIdTest001
 * @tc.desc: test ClientSetChannelBySessionId with valid session returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetChannelBySessionIdTest001, TestSize.Level1)
{
    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetChannelBySessionId(sessionId, transInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(transInfo);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetChannelBusinessTypeBySessionIdNotFoundTest001
 * @tc.desc: test ClientGetChannelBusinessTypeBySessionId with non-existent session
 *           returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelBusinessTypeBySessionIdNotFoundTest001, TestSize.Level1)
{
    int32_t businessType = 0;
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_SESSION_ID, &businessType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetEncryptByChannelIdNotFoundTest001
 * @tc.desc: test GetEncryptByChannelId with non-existent channel returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetEncryptByChannelIdNotFoundTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t data = 0;
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
/*
 * @tc.name: GetEncryptByChannelIdTest001
 * @tc.desc: test GetEncryptByChannelId with existing channel returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetEncryptByChannelIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t data = 0;
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(data);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: GetEncryptByChannelIdWrongTypeTest001
 * @tc.desc: test GetEncryptByChannelId with wrong channel type returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetEncryptByChannelIdWrongTypeTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t data = 0;
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionIdByChannelIdNotFoundTest001
 * @tc.desc: test ClientGetSessionIdByChannelId with non-existent channel returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIdByChannelIdNotFoundTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
/*
 * @tc.name: ClientGetSessionIdByChannelIdTest001
 * @tc.desc: test ClientGetSessionIdByChannelId with existing channel returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIdByChannelIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientEnableSessionByChannelIdNotFoundTest001
 * @tc.desc: test ClientEnableSessionByChannelId with non-existent channel
 *           returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientEnableSessionByChannelIdNotFoundTest001, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    ret = ClientEnableSessionByChannelId(channel, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}
/*
 * @tc.name: ClientEnableSessionByChannelIdMemErrTest001
 * @tc.desc: test ClientEnableSessionByChannelId with missing peerDeviceId returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientEnableSessionByChannelIdMemErrTest001, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channel->channelId = 0;
    channel->channelType = CHANNEL_TYPE_AUTH;
    int32_t sessionId = 0;
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t newSessionId = 0;
    ret = ClientEnableSessionByChannelId(channel, &newSessionId);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}
/*
 * @tc.name: ClientEnableSessionByChannelIdTest001
 * @tc.desc: test ClientEnableSessionByChannelId with valid channel returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientEnableSessionByChannelIdTest001, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channel->channelId = 0;
    channel->channelType = CHANNEL_TYPE_AUTH;
    int32_t sessionId = 0;
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char peerDeviceId[DEVICE_ID_SIZE_MAX] = { 0 };
    ret = strcpy_s(peerDeviceId, DEVICE_ID_SIZE_MAX, g_deviceId);
    EXPECT_EQ(ret, EOK);
    channel->peerDeviceId = peerDeviceId;
    int32_t newSessionId = 0;
    ret = ClientEnableSessionByChannelId(channel, &newSessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(sessionId, newSessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientGetSessionCallbackByIdTest001
 * @tc.desc: test ClientGetSessionCallbackById returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 *           and SOFTBUS_OK with matching callbacks for valid session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackByIdTest001, TestSize.Level1)
{
    ISessionListener sessionlistener = { 0 };
    int32_t ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionCallbackById(sessionId, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(sessionlistener.OnSessionOpened, OnSessionOpened);
    EXPECT_EQ(sessionlistener.OnSessionClosed, OnSessionClosed);
    EXPECT_EQ(sessionlistener.OnMessageReceived, OnMessageReceived);
    EXPECT_EQ(sessionlistener.OnBytesReceived, OnBytesReceived);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionCallbackByNameTest001
 * @tc.desc: test ClientGetSessionCallbackByName returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent name
 *           and SOFTBUS_OK with matching callbacks for valid name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackByNameTest001, TestSize.Level1)
{
    ISessionListener sessionlistener = { 0 };
    int32_t ret = ClientGetSessionCallbackByName(g_sessionName, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char secondPkgName[] = { "dms1" };
    char secondSessionName[] = { "ohos.distributedschedule.dms.test1" };
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, secondPkgName,
        secondSessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionCallbackByName(secondSessionName, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(sessionlistener.OnSessionOpened, OnSessionOpened);
    EXPECT_EQ(sessionlistener.OnSessionClosed, OnSessionClosed);
    EXPECT_EQ(sessionlistener.OnMessageReceived, OnMessageReceived);
    EXPECT_EQ(sessionlistener.OnBytesReceived, OnBytesReceived);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, secondSessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientGetSessionSideTest001
 * @tc.desc: test ClientGetSessionSide returns error for non-existent session and IS_CLIENT for valid sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionSideTest001, TestSize.Level1)
{
    int32_t ret = ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_NE(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char secondSessionName[] = { "ohos.distributedschedule.dms.test1" };
    char secondGroupId[] = { "TEST_GROUP_ID1" };
    char secondDeviceId[] = { "ABCDEF00ABCDEF00ABCDEF00A" };
    sessionParam->groupId = secondGroupId;
    sessionParam->peerSessionName = secondSessionName;
    sessionParam->peerDeviceId = secondDeviceId;
    int32_t newSessionId = 0;
    ret = ClientAddSession(sessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionSide(sessionId);
    EXPECT_EQ(ret, IS_CLIENT);
    ret = ClientGetSessionSide(newSessionId);
    EXPECT_EQ(ret, IS_CLIENT);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(newSessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGrantPermissionInvalidParamTest001
 * @tc.desc: test ClientGrantPermission returns SOFTBUS_INVALID_PARAM for invalid uid, pid, or null sessionName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGrantPermissionInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = ClientGrantPermission(TRANS_TEST_INVALID_UID, TRANS_TEST_PID, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGrantPermission(TRANS_TEST_UID, TRANS_TEST_INVALID_PID, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGrantPermission(TRANS_TEST_UID, TRANS_TEST_PID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
/*
 * @tc.name: ClientRemovePermissionInvalidParamTest001
 * @tc.desc: test ClientRemovePermission returns SOFTBUS_INVALID_PARAM for null sessionName
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientRemovePermissionInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = ClientRemovePermission(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientRemovePermission(g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED);
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientGetFileConfigInfoByIdNotFoundTest001
 * @tc.desc: test ClientGetFileConfigInfoById with non-existent session returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetFileConfigInfoByIdNotFoundTest001, TestSize.Level1)
{
    int32_t fileEncrypt = 0;
    int32_t algorithm = 0;
    int32_t crc = 0;
    int32_t ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}
/*
 * @tc.name: ClientGetFileConfigInfoByIdTest001
 * @tc.desc: test ClientGetFileConfigInfoById with valid session returns SOFTBUS_OK and correct config values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetFileConfigInfoByIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t fileEncrypt = 0;
    int32_t algorithm = 0;
    int32_t crc = 0;
    ret = ClientGetFileConfigInfoById(sessionId, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(TRANS_TEST_FILE_ENCRYPT, fileEncrypt);
    EXPECT_EQ(TRANS_TEST_ALGORITHM, algorithm);
    EXPECT_EQ(TRANS_TEST_CRC, crc);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ReCreateSessionServerToServerNullTest001
 * @tc.desc: test ReCreateSessionServerToServer with null param returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ReCreateSessionServerToServerNullTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ReCreateSessionServerToServer(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
/*
 * @tc.name: ReCreateSessionServerToServerTest001
 * @tc.desc: test ReCreateSessionServerToServer with valid session server list returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ReCreateSessionServerToServerTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListNode sessionServerList;
    ListInit(&sessionServerList);
    ret = ReCreateSessionServerToServer(&sessionServerList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionServerInfo *infoNode = nullptr;
    SessionServerInfo *infoNodeNext = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, &(sessionServerList), SessionServerInfo, node) {
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }
}

/*
 * @tc.name: ClientTransOnLinkDownTest001
 * @tc.desc: test ClientTransOnLinkDown closes session by device ID and ROUTE_TYPE_ALL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnLinkDownTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientTransOnLinkDown(g_deviceId, ROUTE_TYPE_ALL);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientCleanAllSessionWhenServerDeathTest001
 * @tc.desc: test ClientCleanAllSessionWhenServerDeath processes empty and
 *           non-empty session server lists without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCleanAllSessionWhenServerDeathTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListNode sessionServerList;
    ListInit(&sessionServerList);
    ClientCleanAllSessionWhenServerDeath(&sessionServerList);
    SessionServerInfo *infoNode = nullptr;
    SessionServerInfo *infoNodeNext = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, &(sessionServerList), SessionServerInfo, node) {
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientCleanAllSessionWhenServerDeath(&sessionServerList);
    infoNode = nullptr;
    infoNodeNext = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, &(sessionServerList), SessionServerInfo, node) {
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: PermissionStateChangeTest001
 * @tc.desc: test PermissionStateChange updates permission state without crash for existing session server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, PermissionStateChangeTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    PermissionStateChange(g_pkgName, TRANS_TEST_STATE);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransOnLinkDownSpecificRouteTest001
 * @tc.desc: test ClientTransOnLinkDown with WIFI_STA route type only closes matching sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnLinkDownSpecificRouteTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sessionParam->peerDeviceId = g_networkId;
    SessionInfo *p2pSession = GenerateSession(sessionParam);
    ASSERT_TRUE(p2pSession != nullptr);
    p2pSession->channelId = TRANS_TEST_CHANNEL_ID + 1;
    p2pSession->channelType = CHANNEL_TYPE_UDP;
    p2pSession->routeType = WIFI_P2P;
    ret = ClientAddNewSession(g_sessionName, p2pSession);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientTransOnLinkDown(g_networkId, WIFI_STA);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID + 1, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientTransOnLinkDownAllRouteTest001
 * @tc.desc: test ClientTransOnLinkDown with ROUTE_TYPE_ALL closes all sessions for network ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnLinkDownAllRouteTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    sessionParam->peerDeviceId = g_networkId;
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    session->routeType = WIFI_P2P;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientTransOnLinkDown(g_networkId, ROUTE_TYPE_ALL);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientTransOnLinkDownByDeviceIdTest001
 * @tc.desc: test ClientTransOnLinkDown with device ID and ROUTE_TYPE_ALL closes sessions for device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnLinkDownByDeviceIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClientTransOnLinkDown(g_deviceId, ROUTE_TYPE_ALL);
    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionIsAsyncBySessionIdTest001
 * @tc.desc: test ClientGetSessionIsAsyncBySessionId returns correct isAsync status for async and non-async sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIsAsyncBySessionIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    sessionParam->isAsync = true;
    SessionInfo *asyncSession = GenerateSession(sessionParam);
    ASSERT_TRUE(asyncSession != nullptr);
    ret = ClientAddNewSession(g_sessionName, asyncSession);
    EXPECT_EQ(ret, SOFTBUS_OK);
    asyncSession->sessionId = 2;
    bool isAsync = false;
    ClientGetSessionIsAsyncBySessionId(2, &isAsync);
    EXPECT_EQ(isAsync, true);
    ClientGetSessionIsAsyncBySessionId(1, &isAsync);
    EXPECT_EQ(isAsync, false);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: SetSessionIsAsyncByIdTest001
 * @tc.desc: test SetSessionIsAsyncById sets isAsync status and ClientGetSessionIsAsyncBySessionId verifies it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, SetSessionIsAsyncByIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    bool isAsync = false;
    ClientGetSessionIsAsyncBySessionId(1, &isAsync);
    EXPECT_EQ(isAsync, false);
    SetSessionIsAsyncById(1, true);
    ClientGetSessionIsAsyncBySessionId(1, &isAsync);
    EXPECT_EQ(isAsync, true);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientTransSetChannelInfoTest001
 * @tc.desc: test ClientTransSetChannelInfo returns SOFTBUS_OK when setting channel info for existing session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransSetChannelInfoTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 11, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetChannelBySessionIdAfterSetTest001
 * @tc.desc: test ClientGetChannelBySessionId returns correct channel info after ClientTransSetChannelInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelBySessionIdAfterSetTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 11, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    ClientGetChannelBySessionId(1, &channelId, &channelType, nullptr);
    EXPECT_EQ(channelId, 11);
    EXPECT_EQ(channelType, CHANNEL_TYPE_TCP_DIRECT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: GetSocketLifecycleAndSessionNameBySessionIdTest001
 * @tc.desc: test GetSocketLifecycleAndSessionNameBySessionId returns SOFTBUS_OK and correct lifecycle state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetSocketLifecycleAndSessionNameBySessionIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 11, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char sessionName[SESSION_NAME_SIZE_MAX];
    SocketLifecycleData lifecycle;
    ret = GetSocketLifecycleAndSessionNameBySessionId(1, sessionName, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(lifecycle.sessionState, SESSION_STATE_OPENED);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: SetSessionStateBySessionIdTest001
 * @tc.desc: test SetSessionStateBySessionId returns SOFTBUS_OK for valid session,
 *           SOFTBUS_TRANS_INVALID_SESSION_ID for invalid session id,
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, SetSessionStateBySessionIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 11, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionStateBySessionId(1, SESSION_STATE_CANCELLING, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = SetSessionStateBySessionId(-1, SESSION_STATE_CANCELLING, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = SetSessionStateBySessionId(TRANS_TEST_CHANNEL_ID, SESSION_STATE_CANCELLING, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetChannelOsTypeBySessionIdTest001
 * @tc.desc: test ClientGetChannelOsTypeBySessionId returns SOFTBUS_OK for valid session,
 *           SOFTBUS_INVALID_PARAM for invalid session id or null output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelOsTypeBySessionIdTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName,
        g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session->sessionId = 1;
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 11, CHANNEL_TYPE_TCP_DIRECT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t osType = 0;
    ret = ClientGetChannelOsTypeBySessionId(1, &osType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetChannelOsTypeBySessionId(-1, &osType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelOsTypeBySessionId(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}
/*
 * @tc.name: ClientTransOnPrivilegeCloseTest001
 * @tc.desc: test ClientTransOnPrivilegeClose does not crash with valid network ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnPrivilegeCloseTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(ClientTransOnPrivilegeClose(g_networkId));
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetLowLatencyBySocketErrorTest001
 * @tc.desc: test ClientSetLowLatencyBySocket returns SOFTBUS_INVALID_PARAM for invalid socket ids
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetLowLatencyBySocketErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientSetLowLatencyBySocket(0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetLowLatencyBySocket(-1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetLowLatencyBySocket(1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetLowLatencyBySocketTest001
 * @tc.desc: test ClientSetLowLatencyBySocket returns SOFTBUS_OK when session exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetLowLatencyBySocketTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 1;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetLowLatencyBySocket(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientCancelEncryptionInvalidParamTest001
 * @tc.desc: test ClientCancelEncryption returns SOFTBUS_INVALID_PARAM for invalid socket id or invalid link type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCancelEncryptionInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = ClientCancelEncryption(0, LINK_TYPE_WIRED);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientCancelEncryption(-1, LINK_TYPE_WIRED);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientCancelEncryption(1, LINK_TYPE_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientCancelEncryption(1, LINK_MEDIUM_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientCancelEncryptionSessionNotFoundTest001
 * @tc.desc: test ClientCancelEncryption returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCancelEncryptionSessionNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientCancelEncryption(1, LINK_TYPE_WIRED);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientCancelEncryptionTest001
 * @tc.desc: test ClientCancelEncryption returns SOFTBUS_OK with valid session for WIRED and WIFI link types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCancelEncryptionTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    int32_t sessionId = 1;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientCancelEncryption(sessionId, LINK_TYPE_WIRED);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientCancelEncryption(sessionId, LINK_TYPE_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientCancelEncryptionFileTypeTest001
 * @tc.desc: test ClientCancelEncryption returns SOFTBUS_OK with TYPE_FILE data type session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCancelEncryptionFileTypeTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    g_sessionAttr.dataType = TYPE_FILE;
    GenerateCommParam(sessionParam);
    int32_t sessionId = 1;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientCancelEncryption(sessionId, LINK_TYPE_WIRED);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    g_sessionAttr.dataType = TYPE_BYTES;
    TransClientDeinit();
}

/*
 * @tc.name: GetMaxBufferLenBySocketInvalidParamTest001
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_INVALID_PARAM for invalid socket id or null output pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketInvalidParamTest001, TestSize.Level1)
{
    uint32_t maxBufferLen = 0;
    int32_t ret = GetMaxBufferLenBySocket(0, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMaxBufferLenBySocket(-1, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t initRet = TransClientInit();
    EXPECT_EQ(initRet, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_BYTE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}
/*
 * @tc.name: GetMaxBufferLenBySocketSessionNotFoundTest001
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketSessionNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxBufferLen = 0;
    ret = GetMaxBufferLenBySocket(9999, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: GetMaxBufferLenBySocketByteTest001
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_OK with BUSINESS_TYPE_BYTE session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketByteTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_BYTE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxBufferLen = 0;
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: GetMaxBufferLenBySocketMessageTest001
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_OK with BUSINESS_TYPE_MESSAGE session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketMessageTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_MESSAGE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxBufferLen = 0;
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: GetMaxBufferLenBySocketUnsupportedTypeTest001
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_TRANS_FUNC_NOT_SUPPORT for file and stream business types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketUnsupportedTypeTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_FILE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxBufferLen = 0;
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_STREAM;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}
/*
 * @tc.name: GetMaxBufferLenBySocketUnsupportedTypeTest002
 * @tc.desc: test GetMaxBufferLenBySocket returns SOFTBUS_TRANS_FUNC_NOT_SUPPORT for d2d and not-care business types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetMaxBufferLenBySocketUnsupportedTypeTest002, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_D2D_MESSAGE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxBufferLen = 0;
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sessionInfo = GenerateSession(sessionParam);
    sessionInfo->businessType = BUSINESS_TYPE_D2D_VOICE;
    ret = ClientAddNewSession(g_sessionName, sessionInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMaxBufferLenBySocket(sessionInfo->sessionId, &maxBufferLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(sessionInfo->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: CheckChannelIsReserveByChannelIdInvalidParamTest001
 * @tc.desc: test CheckChannelIsReserveByChannelId returns SOFTBUS_INVALID_PARAM for invalid ids or null output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, CheckChannelIsReserveByChannelIdInvalidParamTest001, TestSize.Level1)
{
    int32_t sessionId = INVALID_SESSION_ID;
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t ret = CheckChannelIsReserveByChannelId(sessionId, TRANS_TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckChannelIsReserveByChannelId(TRANS_TEST_SESSION_ID, channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckChannelIsReserveByChannelId(TRANS_TEST_SESSION_ID, TRANS_TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IsMultiPathSessionInvalidParamTest001
 * @tc.desc: test IsMultiPathSession returns false for null sessionName or null multipathSessionId pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, IsMultiPathSessionInvalidParamTest001, TestSize.Level1)
{
    int32_t multipathSessionId = 0;
    bool ret = IsMultiPathSession(nullptr, &multipathSessionId);
    EXPECT_FALSE(ret);
    ret = IsMultiPathSession(g_sessionName, nullptr);
    EXPECT_FALSE(ret);
}
} // namespace OHOS
