/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#define MAX_SESSION_SERVER_NUM        32
#define USER_SWITCH_OFFSET            10
#define BLOCK_MODE_OFFSET             12

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

static int32_t CheckCollabRelation(const CollabInfo *sourceInfo, const CollabInfo *sinkInfo)
{
    TRANS_LOGI(TRANS_TEST, "call check collab relation func");
    return SOFTBUS_OK;
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

static IFeatureAbilityRelationChecker g_relationChecker = {
    .CheckCollabRelation = CheckCollabRelation,
};

/*
 * @tc.name: ClientAddSessionServerErrorTest001
 * @tc.desc: test ClientAddSessionServer returns SOFTBUS_INVALID_PARAM for null pkgName
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSessionServerErrorTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, nullptr, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientDeleteSessionServerErrorTest001
 * @tc.desc: test ClientDeleteSessionServer returns SOFTBUS_INVALID_PARAM for SEC_TYPE_UNKNOWN
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDeleteSessionServerErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientDeleteSessionServer(SEC_TYPE_UNKNOWN, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientDeleteSessionErrorTest001
 * @tc.desc: test ClientDeleteSession returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDeleteSessionErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientDeleteSession(TRANS_TEST_INVALID_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    TransClientDeinit();
    ret = ClientDeleteSession(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientAddAuthSessionErrorTest001
 * @tc.desc: test ClientAddAuthSession returns SOFTBUS_INVALID_PARAM for null sessionName
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddAuthSessionErrorTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientAddAuthSession(nullptr, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientAddAuthSession(g_sessionName, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientAddNewSessionErrorTest001
 * @tc.desc: test ClientAddNewSession returns SOFTBUS_INVALID_PARAM for null session
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddNewSessionErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientAddNewSession(g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: ClientGetSessionIntegerDataByIdErrorTest001
 * @tc.desc: test ClientGetSessionIntegerDataById returns SOFTBUS_INVALID_PARAM for invalid session id or null data
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIntegerDataByIdErrorTest001, TestSize.Level1)
{
    int32_t data = 0;
    int32_t ret = ClientGetSessionIntegerDataById(TRANS_TEST_INVALID_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, nullptr, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, &data, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionIntegerDataById(TRANS_TEST_SESSION_ID, &data, KEY_PEER_UID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientSetChannelBySessionIdInvalidParamTest001
 * @tc.desc: test ClientSetChannelBySessionId returns SOFTBUS_INVALID_PARAM for invalid session id or channel id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetChannelBySessionIdInvalidParamTest001, TestSize.Level1)
{
    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = ClientSetChannelBySessionId(TRANS_TEST_INVALID_SESSION_ID, transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    transInfo->channelId = TRANS_TEST_INVALID_CHANNEL_ID;
    ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: ClientSetChannelBySessionIdNoInitTest001
 * @tc.desc: test ClientSetChannelBySessionId returns SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetChannelBySessionIdNoInitTest001, TestSize.Level1)
{
    TransClientDeinit();
    TransInfo *transInfo = reinterpret_cast<TransInfo *>(SoftBusCalloc(sizeof(TransInfo)));
    ASSERT_TRUE(transInfo != nullptr);
    transInfo->channelId = TRANS_TEST_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_UDP;
    int32_t ret = ClientSetChannelBySessionId(TRANS_TEST_SESSION_ID, transInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(transInfo);
}

/*
 * @tc.name: ClientGetChannelBusinessTypeBySessionIdErrorTest001
 * @tc.desc: test ClientGetChannelBusinessTypeBySessionId returns SOFTBUS_INVALID_PARAM for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelBusinessTypeBySessionIdErrorTest001, TestSize.Level1)
{
    int32_t businessType = 0;
    int32_t ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_INVALID_SESSION_ID, &businessType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetChannelBusinessTypeBySessionId(TRANS_TEST_SESSION_ID, &businessType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: GetEncryptByChannelIdErrorTest001
 * @tc.desc: test GetEncryptByChannelId returns SOFTBUS_INVALID_PARAM for invalid channel id or null data
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetEncryptByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t data = 0;
    int32_t ret = GetEncryptByChannelId(TRANS_TEST_INVALID_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = GetEncryptByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetSessionIdByChannelIdErrorTest001
 * @tc.desc: test ClientGetSessionIdByChannelId returns SOFTBUS_INVALID_PARAM for invalid channel id or null sessionId
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIdByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isClosing = false;
    int32_t ret = ClientGetSessionIdByChannelId(TRANS_TEST_INVALID_CHANNEL_ID,
        CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, nullptr, isClosing);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetSessionDataByIdNoInitTest001
 * @tc.desc: test ClientGetSessionDataById returns SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 *           for various key types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionDataByIdNoInitTest001, TestSize.Level1)
{
    TransClientDeinit();
    char data[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = ClientGetSessionDataById(TRANS_TEST_SESSION_ID, data, SESSION_NAME_SIZE_MAX, KEY_PEER_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionDataById(TRANS_TEST_SESSION_ID, data, SESSION_NAME_SIZE_MAX, KEY_PEER_PID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionDataById(0, data, SESSION_NAME_SIZE_MAX, KEY_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientEnableSessionByChannelIdErrorTest001
 * @tc.desc: test ClientEnableSessionByChannelId returns SOFTBUS_INVALID_PARAM for null channel or sessionId
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientEnableSessionByChannelIdErrorTest001, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t sessionId = 0;
    int32_t ret = ClientEnableSessionByChannelId(nullptr, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientEnableSessionByChannelId(channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientEnableSessionByChannelId(channel, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientGetSessionCallbackByIdErrorTest001
 * @tc.desc: test ClientGetSessionCallbackById returns SOFTBUS_INVALID_PARAM for invalid session id or null listener
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackByIdErrorTest001, TestSize.Level1)
{
    ISessionListener sessionlistener = { 0 };
    int32_t ret = ClientGetSessionCallbackById(TRANS_TEST_INVALID_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetSessionCallbackById(TRANS_TEST_SESSION_ID, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetSessionCallbackByNameErrorTest001
 * @tc.desc: test ClientGetSessionCallbackByName returns SOFTBUS_INVALID_PARAM for null name or listener
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackByNameErrorTest001, TestSize.Level1)
{
    ISessionListener sessionlistener = { 0 };
    int32_t ret = ClientGetSessionCallbackByName(nullptr, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackByName(g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetSessionCallbackByName(g_sessionName, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionCallbackByName(g_pkgName, &sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetSessionSideNoInitTest001
 * @tc.desc: test ClientGetSessionSide returns SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionSideNoInitTest001, TestSize.Level1)
{
    TransClientDeinit();
    int32_t ret = ClientGetSessionSide(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetFileConfigInfoByIdErrorTest001
 * @tc.desc: test ClientGetFileConfigInfoById returns SOFTBUS_INVALID_PARAM for null output pointers
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetFileConfigInfoByIdErrorTest001, TestSize.Level1)
{
    int32_t fileEncrypt = 0;
    int32_t algorithm = 0;
    int32_t crc = 0;
    int32_t ret = ClientGetFileConfigInfoById(TRANS_TEST_INVALID_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, nullptr, &algorithm, &crc);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, nullptr, &crc);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetFileConfigInfoById(TRANS_TEST_SESSION_ID, &fileEncrypt, &algorithm, &crc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: CheckPermissionStateNoInitTest001
 * @tc.desc: test CheckPermissionState returns SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 *           for various session ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, CheckPermissionStateNoInitTest001, TestSize.Level1)
{
    TransClientDeinit();
    int32_t ret = CheckPermissionState(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = CheckPermissionState(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ReCreateSessionServerToServerTest001
 * @tc.desc: test ReCreateSessionServerToServer returns SOFTBUS_OK with empty list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ReCreateSessionServerToServerTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListNode sessionServerList;
    ListInit(&sessionServerList);
    ret = ReCreateSessionServerToServer(&sessionServerList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}
/*
 * @tc.name: ClientTransOnLinkDownNoSessionTest001
 * @tc.desc: test ClientTransOnLinkDown does not crash with null and valid network IDs when no session server added
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnLinkDownNoSessionTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(ClientTransOnLinkDown(nullptr, ROUTE_TYPE_ALL));
    EXPECT_NO_FATAL_FAILURE(ClientTransOnLinkDown(g_networkId, ROUTE_TYPE_ALL));
    TransClientDeinit();
}

/*
 * @tc.name: ClientCleanAllSessionWhenServerDeathTest001
 * @tc.desc: test ClientCleanAllSessionWhenServerDeath does not crash with empty and non-empty session server lists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientCleanAllSessionWhenServerDeathTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListNode sessionServerList;
    ListInit(&sessionServerList);
    EXPECT_NO_FATAL_FAILURE(ClientCleanAllSessionWhenServerDeath(&sessionServerList));
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(ClientCleanAllSessionWhenServerDeath(&sessionServerList));
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}
/*
 * @tc.name: PermissionStateChangeTest001
 * @tc.desc: test PermissionStateChange does not crash with valid pkgName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, PermissionStateChangeTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(PermissionStateChange(g_pkgName, 0));
    TransClientDeinit();
}
/*
 * @tc.name: ClientRawStreamEncryptDefOptGetErrorTest001
 * @tc.desc: test ClientRawStreamEncryptDefOptGet returns SOFTBUS_INVALID_PARAM for null pointers
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientRawStreamEncryptDefOptGetErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientRawStreamEncryptDefOptGet(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientRawStreamEncryptDefOptGet(g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    bool isEncrypt = false;
    ret = ClientRawStreamEncryptDefOptGet(nullptr, &isEncrypt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientRawStreamEncryptDefOptGet(g_sessionName, &isEncrypt);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientRawStreamEncryptOptGetErrorTest001
 * @tc.desc: test ClientRawStreamEncryptOptGet returns SOFTBUS_INVALID_PARAM for invalid channel id or null isEncrypt
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientRawStreamEncryptOptGetErrorTest001, TestSize.Level1)
{
    bool isEncrypt = false;
    int32_t ret = ClientRawStreamEncryptOptGet(
        TRANS_TEST_SESSION_ID, TRANS_TEST_INVALID_CHANNEL_ID, CHANNEL_TYPE_UDP, &isEncrypt);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientRawStreamEncryptOptGet(TRANS_TEST_SESSION_ID, TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientRawStreamEncryptOptGet(TRANS_TEST_SESSION_ID, TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &isEncrypt);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: SetSessionIsAsyncByIdErrorTest001
 * @tc.desc: test SetSessionIsAsyncById returns SOFTBUS_INVALID_PARAM for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, SetSessionIsAsyncByIdErrorTest001, TestSize.Level1)
{
    int32_t ret = SetSessionIsAsyncById(-1, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = SetSessionIsAsyncById(1, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientTransSetChannelInfoErrorTest001
 * @tc.desc: test ClientTransSetChannelInfo returns SOFTBUS_INVALID_PARAM for null sessionName
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransSetChannelInfoErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientTransSetChannelInfo(nullptr, 1, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientTransSetChannelInfo(g_sessionName, 1, 1, CHANNEL_TYPE_AUTH);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetSessionIsAsyncBySessionIdErrorTest001
 * @tc.desc: test ClientGetSessionIsAsyncBySessionId returns SOFTBUS_INVALID_PARAM for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIsAsyncBySessionIdErrorTest001, TestSize.Level1)
{
    bool isAsync = false;
    int32_t ret = ClientGetSessionIsAsyncBySessionId(-1, &isAsync);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetSessionIsAsyncBySessionId(1, &isAsync);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientHandleBindWaitTimerErrorTest001
 * @tc.desc: test ClientHandleBindWaitTimer returns SOFTBUS_INVALID_PARAM for
 *           invalid session id or invalid timer action
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientHandleBindWaitTimerErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientHandleBindWaitTimer(-1, 0, TIMER_ACTION_STOP);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t maxWaitTime = 0;
    ret = ClientHandleBindWaitTimer(TRANS_TEST_SESSION_ID, maxWaitTime, TIMER_ACTION_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientHandleBindWaitTimer(1, 0, TIMER_ACTION_STOP);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: GetQosValueTest001
 * @tc.desc: test GetQosValue returns SOFTBUS_OK and correct value when QoS type matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetQosValueTest001, TestSize.Level1)
{
    QosTV qos[] = {
        { .qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = TRANS_TEST_MAX_WAIT_TIMEOUT },
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = 0                           },
    };
    int32_t maxWaitTimeout = 0;
    int32_t ret = GetQosValue(
        qos, sizeof(qos) / sizeof(qos[0]), QOS_TYPE_MAX_WAIT_TIMEOUT, &maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(maxWaitTimeout, TRANS_TEST_MAX_WAIT_TIMEOUT);
}

/*
 * @tc.name: GetQosValueTest002
 * @tc.desc: test GetQosValue returns default value when QoS type is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetQosValueTest002, TestSize.Level1)
{
    QosTV qos[] = {
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = 0 },
    };
    int32_t maxWaitTimeout = 0;
    int32_t ret = GetQosValue(
        qos, sizeof(qos) / sizeof(qos[0]), QOS_TYPE_MAX_WAIT_TIMEOUT, &maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
    ret = GetQosValue(nullptr, 0, QOS_TYPE_MAX_WAIT_TIMEOUT, &maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
}

/*
 * @tc.name: GetQosValueTest003
 * @tc.desc: test GetQosValue returns SOFTBUS_INVALID_PARAM for null qos with non-zero count and null value pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetQosValueTest003, TestSize.Level1)
{
    int32_t maxWaitTimeout = 0;
    int32_t ret = GetQosValue(nullptr, 1, QOS_TYPE_MAX_WAIT_TIMEOUT, &maxWaitTimeout, TRANS_TEST_DEF_WAIT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetQosValue(nullptr, 2, QOS_TYPE_MAX_WAIT_TIMEOUT, nullptr, TRANS_TEST_DEF_WAIT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientWaitSyncBindErrorTest001
 * @tc.desc: test ClientWaitSyncBind returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientWaitSyncBindErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientWaitSyncBind(-1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    TransClientDeinit();
    ret = ClientWaitSyncBind(1);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientSignalSyncBindErrorTest001
 * @tc.desc: test ClientSignalSyncBind returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid session id
 *           and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSignalSyncBindErrorTest001, TestSize.Level1)
{
    int32_t ret = ClientSignalSyncBind(-1, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    TransClientDeinit();
    ret = ClientSignalSyncBind(1, 0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientTransOnSwitchTest001
 * @tc.desc: test ClientTransOnSwitch does not crash when called with positive, zero, and negative offsets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransOnSwitchTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ClientTransOnSwitch(USER_SWITCH_OFFSET));
    EXPECT_NO_FATAL_FAILURE(ClientTransOnSwitch(BLOCK_MODE_OFFSET));
    EXPECT_NO_FATAL_FAILURE(ClientTransOnSwitch(0));
    EXPECT_NO_FATAL_FAILURE(ClientTransOnSwitch(-1));
    EXPECT_NO_FATAL_FAILURE(ClientTransOnSwitch(TRANS_TEST_SESSION_ID));
}

/*
 * @tc.name: ClientRegisterRelationCheckerTest001
 * @tc.desc: test ClientRegisterRelationChecker returns SOFTBUS_INVALID_PARAM for null checker
 *           and SOFTBUS_OK with valid checker, and DestroyRelationChecker cleans up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientRegisterRelationCheckerTest001, TestSize.Level1)
{
    int32_t ret = ClientRegisterRelationChecker(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientRegisterRelationChecker(&g_relationChecker);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DestroyRelationChecker());
}

/*
 * @tc.name: ClientTransCheckCollabRelationInvalidParamTest001
 * @tc.desc: test ClientTransCheckCollabRelation returns SOFTBUS_INVALID_PARAM when sourceInfo or sinkInfo is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransCheckCollabRelationInvalidParamTest001, TestSize.Level1)
{
    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    int32_t ret = ClientTransCheckCollabRelation(nullptr, &sinkInfo, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    ret = ClientTransCheckCollabRelation(&sourceInfo, nullptr, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientTransCheckCollabRelationNoInitTest001
 * @tc.desc: test ClientTransCheckCollabRelation returns SOFTBUS_NO_INIT when relation checker is not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransCheckCollabRelationNoInitTest001, TestSize.Level1)
{
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    int32_t ret = ClientTransCheckCollabRelation(&sourceInfo, &sinkInfo, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: ClientTransCheckCollabRelationTest001
 * @tc.desc: test ClientTransCheckCollabRelation returns SOFTBUS_OK when relation checker is registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientTransCheckCollabRelationTest001, TestSize.Level1)
{
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    int32_t ret = ClientRegisterRelationChecker(&g_relationChecker);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransCheckCollabRelation(&sourceInfo, &sinkInfo, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DestroyRelationChecker());
}

/*
 * @tc.name: DataSeqInfoListAddItemTest001
 * @tc.desc: test DataSeqInfoListAddItem returns SOFTBUS_OK with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, DataSeqInfoListAddItemTest001, TestSize.Level1)
{
    TransDataSeqInfoListInit();
    int32_t channelId = 1;
    uint32_t dataSeq = 1;
    int32_t socketId = 1;
    int32_t ret = DataSeqInfoListAddItem(dataSeq, channelId, socketId, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataSeqInfoListDeinit();
}

/*
 * @tc.name: DeleteDataSeqInfoListTest001
 * @tc.desc: test DeleteDataSeqInfoList returns SOFTBUS_OK after adding an item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, DeleteDataSeqInfoListTest001, TestSize.Level1)
{
    TransDataSeqInfoListInit();
    int32_t channelId = 1;
    uint32_t dataSeq = 1;
    int32_t socketId = 1;
    DataSeqInfoListAddItem(dataSeq, channelId, socketId, 0);
    int32_t ret = DeleteDataSeqInfoList(dataSeq, channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataSeqInfoListDeinit();
}

/*
 * @tc.name: TryDeleteEmptySessionServerInvalidParamTest001
 * @tc.desc: test TryDeleteEmptySessionServer returns SOFTBUS_INVALID_PARAM when pkgName or sessionName is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TryDeleteEmptySessionServerInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TryDeleteEmptySessionServer(nullptr, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TryDeleteEmptySessionServer(g_pkgName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TryDeleteEmptySessionServer(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SocketServerStateUpdateTest001
 * @tc.desc: test SocketServerStateUpdate does not crash with null and valid session names
 *           and updates session server state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, SocketServerStateUpdateTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(SocketServerStateUpdate(nullptr));
    EXPECT_NO_FATAL_FAILURE(SocketServerStateUpdate(g_sessionName));
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(SocketServerStateUpdate(g_sessionName));
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetStatusClosingBySocketInvalidParamTest001
 * @tc.desc: test ClientSetStatusClosingBySocket returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid socket id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetStatusClosingBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t socketId = SOFTBUS_TRANS_INVALID_SESSION_ID;
    ret = ClientSetStatusClosingBySocket(socketId, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetStatusClosingBySocketSessionNotFoundTest001
 * @tc.desc: test ClientSetStatusClosingBySocket returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetStatusClosingBySocketSessionNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetStatusClosingBySocket(TRANS_TEST_SESSION_ID, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetStatusClosingReserveBySocketInvalidParamTest001
 * @tc.desc: test ClientSetStatusClosingReserveBySocket returns SOFTBUS_TRANS_INVALID_SESSION_ID
 *           for invalid and zero socket ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetStatusClosingReserveBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetStatusClosingReserveBySocket(-1, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientSetStatusClosingReserveBySocket(0, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientSetStatusClosingReserveBySocket(-1, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetEnableMultipathBySocketInvalidParamTest001
 * @tc.desc: test ClientSetEnableMultipathBySocket returns SOFTBUS_TRANS_INVALID_SESSION_ID
 *           for invalid and zero socket ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetEnableMultipathBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetEnableMultipathBySocket(-1, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientSetEnableMultipathBySocket(0, true);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientSetEnableMultipathBySocket(-1, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    TransClientDeinit();
}

/*
 * @tc.name: GetSupportTlvAndNeedAckByIdInvalidParamTest001
 * @tc.desc: test GetSupportTlvAndNeedAckById returns SOFTBUS_INVALID_PARAM when output parameters are nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, GetSupportTlvAndNeedAckByIdInvalidParamTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_UDP, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSupportTlvAndNeedAckById(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetSessionStateByChannelIdErrorTest001
 * @tc.desc: test ClientGetSessionStateByChannelId returns SOFTBUS_INVALID_PARAM for null output
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionStateByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = TRANS_TEST_INVALID_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = ClientGetSessionStateByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = TRANS_TEST_CHANNEL_ID;
    ret = ClientGetSessionStateByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SessionState sessionState;
    ret = ClientGetSessionStateByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, &sessionState);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetSessionStateByChannelIdTest001
 * @tc.desc: test ClientGetSessionStateByChannelId returns SOFTBUS_OK when session exists with matching channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionStateByChannelIdTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->sessionId = TRANS_TEST_SESSION_ID;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionState sessionState;
    ret = ClientGetSessionStateByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionState);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetRouteTypeByChannelIdErrorTest001
 * @tc.desc: test ClientGetRouteTypeByChannelId returns SOFTBUS_INVALID_PARAM for null routeType output
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetRouteTypeByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = TRANS_TEST_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = ClientGetRouteTypeByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t routeType = 0;
    ret = ClientGetRouteTypeByChannelId(channelId, channelType, &routeType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetRouteTypeByChannelIdTest001
 * @tc.desc: test ClientGetRouteTypeByChannelId returns SOFTBUS_OK when session exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetRouteTypeByChannelIdTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->sessionId = TRANS_TEST_SESSION_ID;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t routeType = 0;
    ret = ClientGetRouteTypeByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &routeType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientAddSocketServerInvalidParamTest001
 * @tc.desc: test ClientAddSocketServer returns SOFTBUS_INVALID_PARAM when
 *           pkgName, sessionName or timestamp is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSocketServerInvalidParamTest001, TestSize.Level1)
{
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSocketServer(SEC_TYPE_PLAINTEXT, nullptr, g_sessionName, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSocketServer(SEC_TYPE_PLAINTEXT, g_pkgName, nullptr, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSocketServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientAddSocketSessionInvalidParamTest001
 * @tc.desc: test ClientAddSocketSession returns SOFTBUS_INVALID_PARAM for null sessionParam and null output pointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientAddSocketSessionInvalidParamTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientAddSocketSession(nullptr, true, &sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSocketSession(nullptr, true, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSocketSession(nullptr, false, &sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientIpcOpenSessionInvalidParamTest001
 * @tc.desc: test ClientIpcOpenSession returns SOFTBUS_INVALID_PARAM when qosInfo is nullptr or session id is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientIpcOpenSessionInvalidParamTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    uint32_t qosCount = 0;
    int32_t ret = ClientIpcOpenSession(sessionId, nullptr, qosCount, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    sessionId = TRANS_TEST_INVALID_SESSION_ID;
    ret = ClientIpcOpenSession(sessionId, nullptr, qosCount, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientSetSocketStateErrorTest001
 * @tc.desc: test ClientSetSocketState returns SOFTBUS_INVALID_PARAM for invalid session id
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetSocketStateErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint32_t maxIdleTimeout = 0;
    ret = ClientSetSocketState(TRANS_TEST_INVALID_SESSION_ID, maxIdleTimeout, SESSION_ROLE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetSocketState(TRANS_TEST_SESSION_ID, maxIdleTimeout, SESSION_ROLE_CLIENT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientDfsIpcOpenSessionErrorTest001
 * @tc.desc: test ClientDfsIpcOpenSession returns SOFTBUS_INVALID_PARAM for invalid session id or null transInfo
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDfsIpcOpenSessionErrorTest001, TestSize.Level1)
{
    TransInfo transInfo;
    int32_t ret = ClientDfsIpcOpenSession(TRANS_TEST_INVALID_SESSION_ID, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDfsIpcOpenSession(TRANS_TEST_SESSION_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDfsIpcOpenSession(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientDfsIpcOpenSessionSessionNotFoundTest001
 * @tc.desc: test ClientDfsIpcOpenSession returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientDfsIpcOpenSessionSessionNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->sessionId = TRANS_TEST_SESSION_ID;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransInfo transInfo;
    ret = ClientDfsIpcOpenSession(TRANS_TEST_SESSION_ID, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetSessionCallbackAdapterByNameInvalidParamTest001
 * @tc.desc: test ClientGetSessionCallbackAdapterByName returns SOFTBUS_INVALID_PARAM when name or adapter is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackAdapterByNameInvalidParamTest001, TestSize.Level1)
{
    SessionListenerAdapter callbackAdapter;
    int32_t ret = ClientGetSessionCallbackAdapterByName(nullptr, &callbackAdapter);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackAdapterByName(g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetSessionCallbackAdapterByIdErrorTest001
 * @tc.desc: test ClientGetSessionCallbackAdapterById returns SOFTBUS_INVALID_PARAM for invalid session id
 *           or null adapter and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionCallbackAdapterByIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    bool isServer = true;
    SessionListenerAdapter callbackAdapter;
    ret = ClientGetSessionCallbackAdapterById(TRANS_TEST_INVALID_SESSION_ID, &callbackAdapter, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackAdapterById(TRANS_TEST_SESSION_ID, nullptr, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionCallbackAdapterById(TRANS_TEST_SESSION_ID, &callbackAdapter, &isServer);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetPeerSocketInfoByIdInvalidParamTest001
 * @tc.desc: test ClientGetPeerSocketInfoById returns SOFTBUS_INVALID_PARAM for invalid session id
 *           or null peerSocketInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetPeerSocketInfoByIdInvalidParamTest001, TestSize.Level1)
{
    PeerSocketInfo peerSocketInfo;
    int32_t ret = ClientGetPeerSocketInfoById(TRANS_TEST_INVALID_SESSION_ID, &peerSocketInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetPeerSocketInfoById(TRANS_TEST_SESSION_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetPeerSocketInfoByIdSessionNotFoundTest001
 * @tc.desc: test ClientGetPeerSocketInfoById returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session does not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetPeerSocketInfoByIdSessionNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->sessionId = TRANS_TEST_SESSION_ID;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    PeerSocketInfo peerSocketInfo;
    ret = ClientGetPeerSocketInfoById(TRANS_TEST_SESSION_ID, &peerSocketInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientResetIdleTimeoutByIdErrorTest001
 * @tc.desc: test ClientResetIdleTimeoutById returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid session id
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientResetIdleTimeoutByIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientResetIdleTimeoutById(TRANS_TEST_INVALID_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientResetIdleTimeoutById(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientResetIdleTimeoutById(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetSessionNameByChannelIdErrorTest001
 * @tc.desc: test ClientGetSessionNameByChannelId returns SOFTBUS_INVALID_PARAM for invalid channel, null buffer,
 *           or zero length, and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionNameByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t len = sizeof(g_sessionName);
    char sessionName[] = { "ohos.distributedschedule.dms.test" };
    ret = ClientGetSessionNameByChannelId(TRANS_TEST_INVALID_CHANNEL_ID,
        CHANNEL_TYPE_TCP_DIRECT, sessionName, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionNameByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionNameByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, sessionName, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionNameByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, sessionName, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetSessionNameByChannelIdTest001
 * @tc.desc: test ClientGetSessionNameByChannelId does not return SOFTBUS_INVALID_PARAM when session exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionNameByChannelIdTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->sessionId = TRANS_TEST_SESSION_ID;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t len = sizeof(g_sessionName);
    char sessionName[] = { "ohos.distributedschedule.dms.test" };
    ret = ClientGetSessionNameByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, sessionName, len);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetChannelBusinessTypeByChannelIdErrorTest001
 * @tc.desc: test ClientGetChannelBusinessTypeByChannelId returns SOFTBUS_INVALID_PARAM
 *           for invalid channel id or null output and SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetChannelBusinessTypeByChannelIdErrorTest001, TestSize.Level1)
{
    int32_t businessType = 0;
    int32_t ret = ClientGetChannelBusinessTypeByChannelId(TRANS_TEST_INVALID_CHANNEL_ID, &businessType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelBusinessTypeByChannelId(TRANS_TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
    ret = ClientGetChannelBusinessTypeByChannelId(TRANS_TEST_CHANNEL_ID, &businessType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: ClientGetMultipathInvalidParamTest001
 * @tc.desc: test ClientGetMultipath returns SOFTBUS_INVALID_PARAM for zero or invalid socket id with null output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetMultipathInvalidParamTest001, TestSize.Level1)
{
    int32_t socket = 1;
    int32_t ret = ClientGetMultipath(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetMultipath(socket, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    bool enableMultipath = false;
    ret = ClientGetMultipath(0, &enableMultipath);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientSetMultipathInvalidParamTest001
 * @tc.desc: test ClientSetMultipath returns SOFTBUS_INVALID_PARAM for invalid socket id with both enable states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetMultipathInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = ClientSetMultipath(-1, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetMultipath(-1, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetMultipath(0, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetenableMultipathBySocketInvalidParamTest001
 * @tc.desc: test ClientGetenableMultipathBySocket returns SOFTBUS_TRANS_INVALID_SESSION_ID
 *           for invalid and zero socket ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetenableMultipathBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t socket = -1;
    bool enableMultipath = false;
    ret = ClientGetenableMultipathBySocket(socket, &enableMultipath);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientGetenableMultipathBySocket(0, &enableMultipath);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientGetenableMultipathBySocket(socket, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetDataTypeBySocketInvalidParamTest001
 * @tc.desc: test ClientGetDataTypeBySocket returns SOFTBUS_TRANS_INVALID_SESSION_ID for invalid socket id
 *           with null and valid output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetDataTypeBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t socket = -1;
    ret = ClientGetDataTypeBySocket(socket, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t dataType = 0;
    ret = ClientGetDataTypeBySocket(socket, &dataType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientGetDataTypeBySocket(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransClientDeinit();
}

/*
 * @tc.name: ClientGetSessionIdByChannelIdReserveInvalidParamTest001
 * @tc.desc: test ClientGetSessionIdByChannelIdReserve returns SOFTBUS_INVALID_PARAM for invalid channel id
 *           or null sessionId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIdByChannelIdReserveInvalidParamTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isClosing = false;
    int32_t ret = ClientGetSessionIdByChannelIdReserve(TRANS_TEST_INVALID_CHANNEL_ID,
        CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIdByChannelIdReserve(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, nullptr, isClosing);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetSessionIdByChannelIdReserveNoInitTest001
 * @tc.desc: test ClientGetSessionIdByChannelIdReserve returns
 *           SOFTBUS_TRANS_SESSION_SERVER_NOINIT when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientGetSessionIdByChannelIdReserveNoInitTest001, TestSize.Level1)
{
    TransClientDeinit();
    int32_t sessionId = 0;
    bool isClosingReserve = false;
    int32_t ret = ClientGetSessionIdByChannelIdReserve(TRANS_TEST_CHANNEL_ID,
        CHANNEL_TYPE_UDP, &sessionId, isClosingReserve);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = ClientGetSessionIdByChannelIdReserve(TRANS_TEST_CHANNEL_ID,
        CHANNEL_TYPE_TCP_DIRECT, &sessionId, isClosingReserve);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
}

/*
 * @tc.name: UpdateMultiPathSessionInfoInvalidParamTest001
 * @tc.desc: test UpdateMultiPathSessionInfo returns SOFTBUS_INVALID_PARAM for null output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, UpdateMultiPathSessionInfoInvalidParamTest001, TestSize.Level1)
{
    int32_t sessionId = INVALID_SESSION_ID;
    int32_t ret = UpdateMultiPathSessionInfo(sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    sessionId = TRANS_TEST_SESSION_ID;
    ret = UpdateMultiPathSessionInfo(sessionId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientSetKeyTypeBySocketInvalidParamTest001
 * @tc.desc: test ClientSetKeyTypeBySocket returns SOFTBUS_INVALID_PARAM for
 *           invalid socket id or invalid keyType range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetKeyTypeBySocketInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = ClientSetKeyTypeBySocket(0, KEY_TYPE_NORMAL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetKeyTypeBySocket(-1, KEY_TYPE_NORMAL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetKeyTypeBySocket(1, -1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetKeyTypeBySocket(1, KEY_TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransGetKeyTypeBySocketIdErrorTest001
 * @tc.desc: test TransGetKeyTypeBySocketId returns SOFTBUS_INVALID_PARAM for null keyType output
 *           and SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND for non-existent session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransGetKeyTypeBySocketIdErrorTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransGetKeyTypeBySocketId(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    int32_t keyTypeOut = 0;
    ret = TransGetKeyTypeBySocketId(0, &keyTypeOut);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetKeyTypeBySocketNoEnableTest001
 * @tc.desc: test ClientSetKeyTypeBySocket returns SOFTBUS_TRANS_SESSION_NO_ENABLE when role is SERVER
 *           or sessionState is not INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetKeyTypeBySocketNoEnableTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->role = SESSION_ROLE_SERVER;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetKeyTypeBySocket(session->sessionId, KEY_TYPE_NORMAL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NO_ENABLE);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetKeyTypeBySocketNoEnableTest002
 * @tc.desc: test ClientSetKeyTypeBySocket returns SOFTBUS_TRANS_SESSION_NO_ENABLE when role is SERVER
 *           or sessionState is not INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetKeyTypeBySocketNoEnableTest002, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->role = SESSION_ROLE_CLIENT;
    session->lifecycle.sessionState = SESSION_STATE_OPENED;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetKeyTypeBySocket(session->sessionId, KEY_TYPE_NORMAL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NO_ENABLE);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetKeyTypeBySocketAuthChannelTest001
 * @tc.desc: test ClientSetKeyTypeBySocket returns
 *           SOFTBUS_TRANS_FUNC_NOT_SUPPORT when channelType is CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetKeyTypeBySocketAuthChannelTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_AUTH;
    session->role = SESSION_ROLE_CLIENT;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetKeyTypeBySocket(session->sessionId, KEY_TYPE_NORMAL);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: ClientSetKeyTypeBySocketSuccessTest001
 * @tc.desc: test ClientSetKeyTypeBySocket returns SOFTBUS_OK when role is CLIENT and sessionState is INIT
 *           and channelType is not AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, ClientSetKeyTypeBySocketSuccessTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->role = SESSION_ROLE_CLIENT;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientSetKeyTypeBySocket(session->sessionId, KEY_TYPE_META);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: TransGetKeyTypeBySocketIdEnableStatusNotSuccessTest001
 * @tc.desc: test TransGetKeyTypeBySocketId returns SOFTBUS_TRANS_SESSION_NO_ENABLE
 *           when enableStatus is not ENABLE_STATUS_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransGetKeyTypeBySocketIdEnableStatusNotSuccessTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->enableStatus = ENABLE_STATUS_INIT;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t keyTypeOut = 0;
    ret = TransGetKeyTypeBySocketId(session->sessionId, &keyTypeOut);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_NO_ENABLE);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: TransGetKeyTypeBySocketIdAuthChannelTest001
 * @tc.desc: test TransGetKeyTypeBySocketId returns
 *           SOFTBUS_TRANS_FUNC_NOT_SUPPORT when channelType is CHANNEL_TYPE_AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransGetKeyTypeBySocketIdAuthChannelTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_AUTH;
    session->enableStatus = ENABLE_STATUS_SUCCESS;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t keyTypeOut = 0;
    ret = TransGetKeyTypeBySocketId(session->sessionId, &keyTypeOut);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}

/*
 * @tc.name: TransGetKeyTypeBySocketIdSuccessTest001
 * @tc.desc: test TransGetKeyTypeBySocketId returns SOFTBUS_OK and correct keyType
 *           when enableStatus is SUCCESS and channelType is not AUTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionManagerTest, TransGetKeyTypeBySocketIdSuccessTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = reinterpret_cast<SessionParam *>(SoftBusCalloc(sizeof(SessionParam)));
    ASSERT_TRUE(sessionParam != nullptr);
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelId = TRANS_TEST_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_PROXY;
    session->enableStatus = ENABLE_STATUS_SUCCESS;
    session->keyType = KEY_TYPE_META;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t keyTypeOut = 0;
    ret = TransGetKeyTypeBySocketId(session->sessionId, &keyTypeOut);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(keyTypeOut, KEY_TYPE_META);
    ret = ClientDeleteSession(session->sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    TransClientDeinit();
}
} // namespace OHOS
