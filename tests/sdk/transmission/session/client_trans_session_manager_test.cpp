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
#include "trans_log.h"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_INVALID_PID (-1)
#define TRANS_TEST_INVALID_UID (-1)
#define TRANS_TEST_CHANNEL_ID 1000
#define TRANS_TEST_INVALID_CHANNEL_ID (-1)
#define TRANS_TEST_INVALID_SESSION_ID (-1)
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_STATE 1

#define MAX_SESSION_SERVER_NUM 32

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
    TransClientSessionManagerTest()
    {}
    ~TransClientSessionManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionManagerTest::SetUpTestCase(void)
{
    InitSoftBusServer();
}

void TransClientSessionManagerTest::TearDownTestCase(void)
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

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

/**
 * @tc.name: TransClientSessionManagerTest01
 * @tc.desc: Transmission sdk session manager add session with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest01, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isEnabled = false;
    ret = ClientAddSession(NULL, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest02
 * @tc.desc: Transmission sdk session manager add new session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest02, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    int32_t ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest03
 * @tc.desc: Transmission sdk session manager add new auth session with invalid and valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest03, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, SESSION_NAME_SIZE_MAX + 2, 'A', SESSION_NAME_SIZE_MAX + 1);
    int32_t ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest04
 * @tc.desc: Transmission sdk session manager delete session with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest04, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSession(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest05
 * @tc.desc: Transmission sdk session manager add session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest05, TestSize.Level1)
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
    EXPECT_GT(sessionId, 0);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest06
 * @tc.desc: Transmission sdk session manager add session server out of range.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest06, TestSize.Level1)
{
    int32_t ret = 0;
    for (int i = 0; i < MAX_SESSION_SERVER_NUMBER; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = {0};
        char pkgName[PKG_NAME_SIZE_MAX] = {0};
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = sprintf_s(pkgName, PKG_NAME_SIZE_MAX, "%s%d", g_pkgName, i);
        EXPECT_GT(ret, 0);
        ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, pkgName, sessionNme, &g_sessionlistener);
        EXPECT_EQ(ret,  SOFTBUS_OK);
    }
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_NUM);
    for (int i = 0; i < MAX_SESSION_SERVER_NUMBER; ++i) {
        char sessionNme[SESSION_NAME_SIZE_MAX] = {0};
        ret = sprintf_s(sessionNme, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        EXPECT_GT(ret, 0);
        ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, sessionNme);
        EXPECT_EQ(ret,  SOFTBUS_OK);
    }
}

/**
 * @tc.name: TransClientAddSessionOutOfMaxTest01
 * @tc.desc: Transmission sdk session manager add session out of maxmum.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientAddSessionOutOfMaxTest01, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isEnabled = false;
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    GenerateCommParam(sessionParam);
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret,  SOFTBUS_OK);

    for (int i = 0; i < MAX_SESSION_ID; ++i) {
        char sessionName[SESSION_NAME_SIZE_MAX] = {0};
        ret = sprintf_s(sessionName, SESSION_NAME_SIZE_MAX, "%s%d", g_sessionName, i);
        ASSERT_GT(ret, 0);
        sessionParam->peerSessionName = (const char*)sessionName;
        ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
        EXPECT_EQ(ret,  SOFTBUS_OK);
    }

    sessionParam->peerSessionName = g_sessionName;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest07
 * @tc.desc: Transmission sdk session manager add session with existed session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest07, TestSize.Level1)
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
    EXPECT_GT(sessionId, 0);
    int32_t newSessionId = 0;
    ret = ClientAddSession(sessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_REPEATED);
    EXPECT_EQ(sessionId,  newSessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest08
 * @tc.desc: Transmission sdk session manager add session with wrong session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest08, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isEnabled = false;
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    char deviceId[] = {"ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF"};
    sessionParam->peerDeviceId = deviceId;
    int32_t ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_CREATE_FAILED);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest09
 * @tc.desc: Transmission sdk session manager delete session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest09, TestSize.Level1)
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
    char sessionName[] = {"ohos.distributedschedule.dms.test1"};
    char groupId[] = {"TEST_GROUP_ID1"};
    char deviceId[] = {"ABCDEF00ABCDEF00ABCDEF00A"};
    SessionAttribute sessionAttr = {
        .dataType = TYPE_FILE,
    };
    SessionParam *newSessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(newSessionParam != NULL);
    memset_s(newSessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    newSessionParam->attr = &sessionAttr;
    newSessionParam->groupId = groupId;
    newSessionParam->peerDeviceId = deviceId;
    newSessionParam->peerSessionName = sessionName;
    newSessionParam->sessionName = g_sessionName;
    int32_t newSessionId = 0;
    ret = ClientAddSession(newSessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSession(newSessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
    SoftBusFree(newSessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest10
 * @tc.desc: Transmission sdk session manager get session data by session id with invalid and valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest10, TestSize.Level1)
{
    char data[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = ClientGetSessionDataById(TRANS_TEST_INVALID_SESSION_ID, data,
                                           SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    bool isEnabled = false;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, SESSION_NAME_SIZE_MAX, KEY_PEER_SESSION_NAME);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, DEVICE_ID_SIZE_MAX, KEY_PEER_DEVICE_ID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    memset_s(data, sizeof(data), 0, sizeof(data));
    ret = ClientGetSessionDataById(sessionId, data, PKG_NAME_SIZE_MAX, KEY_PKG_NAME);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionDataById(sessionId, data, PKG_NAME_SIZE_MAX, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest11
 * @tc.desc: Transmission sdk session manager get session Integer data by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest11, TestSize.Level1)
{
    int data = 0;
    int32_t ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
}

/**
 * @tc.name: TransClientSessionManagerTest12
 * @tc.desc: Transmission sdk session manager get session Integer data by session id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest12, TestSize.Level1)
{
    int data = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    bool isEnabled = false;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_IS_SERVER);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PEER_UID);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIntegerDataById(sessionId, &data, KEY_PKG_NAME);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest13
 * @tc.desc: Transmission sdk session manager get channel id by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest13, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t type = 0;
    bool isEnable = false;
    int32_t ret = ClientGetChannelBySessionId(TRANS_TEST_INVALID_SESSION_ID, &channelId, &type, &isEnable);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransClientSessionManagerTest14
 * @tc.desc: Transmission sdk session manager set channel id by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest14, TestSize.Level1)
{
    TransInfo *transInfo = (TransInfo*)SoftBusMalloc(sizeof(TransInfo));
    EXPECT_TRUE(transInfo != NULL);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransClientSessionManagerTest15
 * @tc.desc: Transmission sdk session manager set channel id by session id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest15, TestSize.Level1)
{
    TransInfo *transInfo = (TransInfo*)SoftBusMalloc(sizeof(TransInfo));
    EXPECT_TRUE(transInfo != NULL);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    int32_t sessionId = 0;
    bool isEnabled = false;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientSetChannelBySessionId(sessionId, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(transInfo);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest16
 * @tc.desc: Transmission sdk session manager get channel business type by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest16, TestSize.Level1)
{
    int32_t businessType = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_SESSION_ID, &businessType);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest17
 * @tc.desc: Transmission sdk session manager get encrypt by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest17, TestSize.Level1)
{
    int data = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_TRUE(data);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &data);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest18
 * @tc.desc: Transmission sdk session manager get session id by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest18, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest19
 * @tc.desc: Transmission sdk session manager get enable session id by channel id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest19, TestSize.Level1)
{
    ChannelInfo *channel = (ChannelInfo*)SoftBusMalloc(sizeof(ChannelInfo));
    EXPECT_TRUE(channel != NULL);
    memset_s(channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    ret = ClientEnableSessionByChannelId(channel, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    channel->channelId = 0;
    channel->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t newSessionId = 0;
    ret = ClientEnableSessionByChannelId(channel, &newSessionId);
    EXPECT_EQ(ret,  SOFTBUS_MEM_ERR);
    char deviceId[DEVICE_ID_SIZE_MAX] = {0};
    ret = strcpy_s(deviceId, DEVICE_ID_SIZE_MAX, g_deviceId);
    EXPECT_EQ(ret,  EOK);
    channel->peerDeviceId = deviceId;
    ret = ClientEnableSessionByChannelId(channel, &newSessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_EQ(sessionId,  newSessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(channel);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest20
 * @tc.desc: Transmission sdk session manager get enable session callback by session id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest20, TestSize.Level1)
{
    ISessionListener sessionlistener = {0};
    int32_t ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isEnabled = false;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionCallbackById(sessionId, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_EQ(sessionlistener.OnSessionOpened,  OnSessionOpened);
    EXPECT_EQ(sessionlistener.OnSessionClosed,  OnSessionClosed);
    EXPECT_EQ(sessionlistener.OnMessageReceived, OnMessageReceived);
    EXPECT_EQ(sessionlistener.OnBytesReceived, OnBytesReceived);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest21
 * @tc.desc: Transmission sdk session manager get enable session callback by session name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest21, TestSize.Level1)
{
    ISessionListener sessionlistener = {0};
    int32_t ret = ClientGetSessionCallbackByName(g_sessionName, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    char pkgName[] = {"dms1"};
    char sessionName[] = {"ohos.distributedschedule.dms.test1"};
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, pkgName, sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionCallbackByName(sessionName, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_EQ(sessionlistener.OnSessionOpened,  OnSessionOpened);
    EXPECT_EQ(sessionlistener.OnSessionClosed,  OnSessionClosed);
    EXPECT_EQ(sessionlistener.OnMessageReceived, OnMessageReceived);
    EXPECT_EQ(sessionlistener.OnBytesReceived, OnBytesReceived);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest22
 * @tc.desc: Transmission sdk session manager get session side by session id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest22, TestSize.Level1)
{
    int32_t ret = ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_NE(ret,  SOFTBUS_OK);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    bool isEnabled = false;
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    char sessionName[] = {"ohos.distributedschedule.dms.test1"};
    char groupId[] = {"TEST_GROUP_ID1"};
    char deviceId[] = {"ABCDEF00ABCDEF00ABCDEF00A"};
    sessionParam->groupId = groupId;
    sessionParam->peerSessionName = sessionName;
    sessionParam->peerDeviceId = deviceId;
    int32_t newSessionId = 0;
    ret = ClientAddSession(sessionParam, &newSessionId, &isEnabled);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionSide(sessionId);
    EXPECT_EQ(ret,  IS_CLIENT);
    ret = ClientGetSessionSide(newSessionId);
    EXPECT_EQ(ret,  IS_CLIENT);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(newSessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest23
 * @tc.desc: Transmission sdk session manager grant permission and remove permission with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest23, TestSize.Level1)
{
    int32_t ret = ClientGrantPermission(TRANS_TEST_INVALID_UID, TRANS_TEST_PID, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientGrantPermission(TRANS_TEST_UID, TRANS_TEST_INVALID_PID, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientGrantPermission(TRANS_TEST_UID, TRANS_TEST_PID, NULL);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = ClientRemovePermission(NULL);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
}

/**
 * @tc.name: TransClientSessionManagerTest24
 * @tc.desc: Transmission sdk session manager get file config by session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest24, TestSize.Level1)
{
    int32_t fileEncrypt = 0;
    int32_t algorithm = 0;
    int32_t crc = 0;
    int32_t ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret,  SOFTBUS_NOT_FIND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    int32_t sessionId = 0;
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientGetFileConfigInfoById(sessionId, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    EXPECT_EQ(TRANS_TEST_FILE_ENCRYPT, fileEncrypt);
    EXPECT_EQ(TRANS_TEST_ALGORITHM, algorithm);
    EXPECT_EQ(TRANS_TEST_CRC, crc);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest25
 * @tc.desc: Transmission sdk session manager recreate session server to server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest25, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ReCreateSessionServerToServer();
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest26
 * @tc.desc: Transmission sdk session manager clear list on link down.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest26, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ClientTransOnLinkDown(g_deviceId, ROUTE_TYPE_ALL);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest27
 * @tc.desc: Transmission sdk session manager clear all session when server death.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest27, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ClientCleanAllSessionWhenServerDeath();
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ClientCleanAllSessionWhenServerDeath();
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionManagerTest28
 * @tc.desc: Transmission sdk session manager permission state change.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest28, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    PermissionStateChange(g_pkgName, TRANS_TEST_STATE);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionDestroyTest01
 * @tc.desc: Transmission sdk session manager destroy session by network id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionDestroyTest01, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_UDP;
    session->routeType = WIFI_STA;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    sessionParam->peerDeviceId = g_networkId;
    SessionInfo *newSession = GenerateSession(sessionParam);
    ASSERT_TRUE(newSession != NULL);
    newSession->channelId = TRANS_TEST_CHANNEL_ID + 1;
    newSession->channelType = CHANNEL_TYPE_UDP;
    newSession->routeType = WIFI_P2P;
    ret = ClientAddNewSession(g_sessionName, newSession);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ClientTransOnLinkDown(g_networkId, WIFI_STA);
    int32_t sessionId = 0;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID + 1, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(sessionId, 0);
    ClientTransOnLinkDown(g_networkId, ROUTE_TYPE_ALL);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID + 1, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ClientTransOnLinkDown(g_deviceId, ROUTE_TYPE_ALL);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest29
 * @tc.desc: Transmission sdk session manager add and delete server with invalid parameters no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest29, TestSize.Level1)
{
    TransClientDeinit();
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, NULL, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_UNKNOWN, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientDeleteSession(TRANS_TEST_INVALID_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ClientDeleteSession(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}


/**
 * @tc.name: TransClientSessionManagerTest30
 * @tc.desc: Transmission sdk session manager add new auth session with invalid parameters no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest30, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientAddAuthSession(NULL, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest31
 * @tc.desc: Transmission sdk session manager add new session no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest31, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    int32_t ret = ClientAddNewSession(g_sessionName, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionManagerTest32
 * @tc.desc: Transmission sdk session manager get session Integer data by session id no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest32, TestSize.Level1)
{
    int data = 0;
    int32_t ret = ClientGetSessionIntegerDataById(TRANS_TEST_INVALID_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, NULL, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest33
 * @tc.desc: Transmission sdk session manager set channel id by session id with invalid parameters no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest33, TestSize.Level1)
{
    TransInfo *transInfo = (TransInfo*)SoftBusMalloc(sizeof(TransInfo));
    EXPECT_TRUE(transInfo != NULL);
    memset_s(transInfo, sizeof(TransInfo), 0, sizeof(TransInfo));
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = ClientSetChannelBySessionId(TRANS_TEST_INVALID_SESSION_ID, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    transInfo->channelId = TRANS_TEST_INVALID_CHANNEL_ID;
    ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: TransClientSessionManagerTest34
 * @tc.desc: Transmission sdk session manager get channel business type by session id no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest34, TestSize.Level1)
{
    int32_t businessType = 0;
    int32_t ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_INVALID_SESSION_ID, &businessType);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_SESSION_ID, &businessType);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest35
 * @tc.desc: Transmission sdk session manager get encrypt by channel id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest35, TestSize.Level1)
{
    int data = 0;
    int32_t ret = GetEncryptByChannelId(TRANS_TEST_INVALID_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest36
 * @tc.desc: Transmission sdk session manager get session id by channel id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest36, TestSize.Level1)
{
    int sessionId = 0;
    int32_t ret = ClientGetSessionIdByChannelId(TRANS_TEST_INVALID_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    char data[SESSION_NAME_SIZE_MAX] = {0};
    ret = ClientGetSessionDataById(TRANS_TEST_SESSION_ID, data, SESSION_NAME_SIZE_MAX, KEY_PEER_SESSION_NAME);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest37
 * @tc.desc: Transmission sdk session manager get enable session id by channel id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest37, TestSize.Level1)
{
    ChannelInfo *channel = (ChannelInfo*)SoftBusMalloc(sizeof(ChannelInfo));
    EXPECT_TRUE(channel != NULL);
    memset_s(channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t sessionId = 0;
    int32_t ret = ClientEnableSessionByChannelId(NULL, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientEnableSessionByChannelId(channel, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientEnableSessionByChannelId(channel, &sessionId);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransClientSessionManagerTest38
 * @tc.desc: Transmission sdk session manager get enable session callback by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest38, TestSize.Level1)
{
    ISessionListener sessionlistener = {0};
    int32_t ret = ClientGetSessionCallbackById(TRANS_TEST_INVALID_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest39
 * @tc.desc: Transmission sdk session manager get enable session callback by session name with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest39, TestSize.Level1)
{
    ISessionListener sessionlistener = {0};
    int32_t ret = ClientGetSessionCallbackByName(NULL, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackByName(g_sessionName, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackByName(g_sessionName, &sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest40
 * @tc.desc: Transmission sdk session manager get side by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest40, TestSize.Level1)
{
    int32_t ret = ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest41
 * @tc.desc: Transmission sdk session manager get file config by session id with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest41, TestSize.Level1)
{
    int32_t fileEncrypt = 0;
    int32_t algorithm = 0;
    int32_t crc = 0;
    int32_t ret = ClientGetFileConfigInfoById(TRANS_TEST_INVALID_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, NULL, &algorithm, &crc);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, NULL, &crc);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, NULL);
    EXPECT_EQ(ret,  SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ret = CheckPermissionState(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret,  SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/**
 * @tc.name: TransClientSessionManagerTest42
 * @tc.desc: Transmission sdk session manager operate no initialize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransClientSessionManagerTest42, TestSize.Level1)
{
    int32_t ret = ReCreateSessionServerToServer();
    EXPECT_EQ(ret,  SOFTBUS_ERR);
    ClientTransOnLinkDown(NULL, ROUTE_TYPE_ALL);
    ClientTransOnLinkDown(g_networkId, ROUTE_TYPE_ALL);
    ClientCleanAllSessionWhenServerDeath();
    PermissionStateChange(g_pkgName, 0);
}
}