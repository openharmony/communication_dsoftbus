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
#include "client_trans_session_callback.h"
#include "client_trans_session_callback.c"
#include "softbus_config_type.h"
#include "trans_log.h"
#include "softbus_feature_config.h"
#include "softbus_conn_interface.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "session_ipc_adapter.h"
#include "session_set_timer.h"
#include "trans_session_service.h"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_CHANNEL_ID 1000
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_EVENT_ID 1
#define TRANS_TEST_TV_COUNT 1
#define TRANS_TEST_AUTH_DATA "test auth message data"
#define DFX_TIMERS_S 15

#define TRANS_TEST_INVALID_CHANNEL_ID (-1)

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
class TransClientSessionCallbackTest : public testing::Test {
public:
    TransClientSessionCallbackTest()
    {}
    ~TransClientSessionCallbackTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionCallbackTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    int32_t ret = TransClientInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
}

void TransClientSessionCallbackTest::TearDownTestCase(void)
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

static void OnStreamReceived(int32_t sessionId, const StreamData *data,
                             const StreamData *ext, const StreamFrameInfo *param)
{
    TRANS_LOGI(TRANS_TEST, "session stream received, sessionId=%{public}d", sessionId);
}

static void OnQosEvent(int32_t sessionId, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    TRANS_LOGI(TRANS_TEST, "session Qos event emit, sessionId=%{public}d", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
};

static void OnFile(int32_t socketId, FileEvent *event)
{
    TRANS_LOGI(TRANS_TEST, "session on file event, sessionId=%{public}d", socketId);
}

static void OnShutDown(int32_t socketId, ShutdownReason reason)
{
    TRANS_LOGI(TRANS_TEST, "session shutdown, socketId=%{public}d", socketId);
}

static void OnBindSucc(int32_t socketId, PeerSocketInfo info)
{
    TRANS_LOGI(TRANS_TEST, "session on bind, socketId=%{public}d", socketId);
}

static bool OnNegotiate(int32_t socketId, PeerSocketInfo info)
{
    TRANS_LOGI(TRANS_TEST, "session on bind, socketId=%{public}d", socketId);
    return true;
}

static ISocketListener g_socketlistener = {
    .OnBind = OnBindSucc,
    .OnShutdown = OnShutDown,
    .OnFile = OnFile,
    .OnNegotiate = OnNegotiate,
};

static ISocketListener g_testSocketlistener = {
    .OnBind = nullptr,
    .OnShutdown = OnShutDown,
    .OnFile = OnFile,
    .OnNegotiate = nullptr,
};

static void TestGenerateCommParam(SessionParam *sessionParam)
{
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupid;
    sessionParam->attr = &g_sessionAttr;
}

static int32_t TestGenerateChannInfo(ChannelInfo *channel)
{
    char *sessionName = (char*)SoftBusCalloc(SESSION_NAME_SIZE_MAX * sizeof(char));
    char *deviceId = (char*)SoftBusCalloc(DEVICE_ID_SIZE_MAX * sizeof(char));
    char *groupId = (char*)SoftBusCalloc(GROUP_ID_SIZE_MAX * sizeof(char));

    if (sessionName == NULL || deviceId == NULL || groupId == NULL ||
        strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, g_sessionName) != EOK ||
        strcpy_s(deviceId, SESSION_NAME_SIZE_MAX, g_deviceId) != EOK ||
        strcpy_s(groupId, SESSION_NAME_SIZE_MAX, g_groupid) != EOK) {
        SoftBusFree(sessionName);
        SoftBusFree(deviceId);
        SoftBusFree(groupId);
        return SOFTBUS_STRCPY_ERR;
    }

    channel->peerSessionName = sessionName;
    channel->peerDeviceId = deviceId;
    channel->groupId = groupId;
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->channelType = CHANNEL_TYPE_BUTT;
    channel->peerPid = TRANS_TEST_PID;
    channel->peerUid = TRANS_TEST_UID;
    channel->isServer = false;
    channel->businessType = BUSINESS_TYPE_BUTT;
    channel->routeType = ROUTE_TYPE_ALL;
    channel->encrypt = TRANS_TEST_FILE_ENCRYPT;
    channel->algorithm = TRANS_TEST_ALGORITHM;
    channel->crc = TRANS_TEST_CRC;

    return SOFTBUS_OK;
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

    return session;
}

static void RelesseChannInfo(ChannelInfo *channel)
{
    if (channel != NULL) {
        if (channel->peerSessionName != NULL) {
            SoftBusFree(channel->peerSessionName);
        }
        if (channel->peerDeviceId != NULL) {
            SoftBusFree(channel->peerDeviceId);
        }
        if (channel->groupId != NULL) {
            SoftBusFree(channel->groupId);
        }
        SoftBusFree(channel);
    }
    channel = NULL;
}

/**
 * @tc.name: TransClientSessionCallbackTest01
 * @tc.desc: Transmission sdk session callback accept session as server with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest01, TestSize.Level1)
{
    int32_t sessionId = 0;
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ChannelInfo *channel = (ChannelInfo*)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != NULL);
    ret = TestGenerateChannInfo(channel);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AcceptSessionAsServer(g_sessionName, channel, TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "com.huawei.devicegroupmanage";
    ret = AcceptSessionAsServer(sessionName, channel, TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    SoftBusFree(channel->groupId);
    channel->groupId = NULL;
    ret = AcceptSessionAsServer(g_sessionName, channel, TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RelesseChannInfo(channel);
}

/**
 * @tc.name: TransClientSessionCallbackTest02
 * @tc.desc: Transmission sdk session callback get session callback by channe id with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest02, TestSize.Level1)
{
    int32_t sessionId = 0;
    ISessionListener listener = {0};
    int32_t ret = GetSessionCallbackByChannelId(TRANS_TEST_INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT,
                                                &sessionId, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionCallbackByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, NULL, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionCallbackByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionCallbackByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId, &listener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = GetSessionCallbackByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest03
 * @tc.desc: Transmission sdk session callback on session opened with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest03, TestSize.Level1)
{
    ISessionListener sessionlistener = {
        .OnSessionOpened = NULL,
        .OnSessionClosed = OnSessionClosed,
        .OnBytesReceived = OnBytesReceived,
        .OnMessageReceived = OnMessageReceived,
    };
    ChannelInfo *channel = (ChannelInfo*)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != NULL);
    int32_t ret = TestGenerateChannInfo(channel);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnSessionOpened(NULL, channel, TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnSessionOpened(g_sessionName, NULL, TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnSessionOpened(g_sessionName, channel, TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnSessionOpened(g_sessionName, channel, TYPE_BUTT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_ON_SESSION_OPENED_FAILED);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RelesseChannInfo(channel);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest04
 * @tc.desc: Transmission sdk session callback on session opened with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest04, TestSize.Level1)
{
    ChannelInfo *channel = (ChannelInfo*)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != NULL);
    int32_t ret = TestGenerateChannInfo(channel);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    channel->channelType = TYPE_BUTT;
    ret = TransOnSessionOpened(g_sessionName, channel, TYPE_BYTES);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    channel->isServer = true;
    ret = TransOnSessionOpened(g_sessionName, channel, TYPE_BYTES);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransOnSessionOpenFailed(TRANS_TEST_CHANNEL_ID, TYPE_BYTES, SOFTBUS_NO_INIT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RelesseChannInfo(channel);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest05
 * @tc.desc: Transmission sdk session callback on session closed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest05, TestSize.Level1)
{
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnSessionClosed(INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = TransOnSessionClosed(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest06
 * @tc.desc: Transmission sdk session callback process receive file data with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest06, TestSize.Level1)
{
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = ProcessReceivedFileData(TRANS_TEST_SESSION_ID, TRANS_TEST_CHANNEL_ID, TRANS_TEST_AUTH_DATA,
                                          strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ProcessReceivedFileData(sessionId, TRANS_TEST_CHANNEL_ID, TRANS_TEST_AUTH_DATA,
                                  strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest07
 * @tc.desc: Transmission sdk session callback on data received with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest07, TestSize.Level1)
{
    int32_t ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, TRANS_TEST_AUTH_DATA,
                                      strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_PROXY;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_BYTES);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_PROXY, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_MESSAGE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest08
 * @tc.desc: Transmission sdk session callback on stream received with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest08, TestSize.Level1)
{
    StreamData data = {0};
    StreamData ext = {0};
    StreamFrameInfo param = {0};
    int32_t ret = TransOnOnStreamRecevied(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &data, &ext, &param);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnOnStreamRecevied(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &data, &ext, &param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest09
 * @tc.desc: Transmission sdk session callback on stream received no callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest09, TestSize.Level1)
{
    StreamData data = {0};
    StreamData ext = {0};
    StreamFrameInfo param = {0};
    ISessionListener sessionlistener = {
        .OnSessionOpened = OnSessionOpened,
        .OnSessionClosed = OnSessionClosed,
        .OnBytesReceived = OnBytesReceived,
        .OnMessageReceived = OnMessageReceived,
        .OnStreamReceived = NULL,
    };
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnOnStreamRecevied(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &data, &ext, &param);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest10
 * @tc.desc: Transmission sdk session callback on qos with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest10, TestSize.Level1)
{
    QosTv *tvList = (QosTv*)SoftBusCalloc(sizeof(QosTv));
    ASSERT_TRUE(tvList != NULL);
    int32_t ret = TransOnQosEvent(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, TRANS_TEST_EVENT_ID,
                                  TRANS_TEST_TV_COUNT, tvList);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnQosEvent(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, TRANS_TEST_EVENT_ID, TRANS_TEST_TV_COUNT, tvList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    SoftBusFree(tvList);
}

/**
 * @tc.name: TransClientSessionCallbackTest11
 * @tc.desc: Transmission sdk session callback on qos no callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest11, TestSize.Level1)
{
    QosTv *tvList = (QosTv*)SoftBusCalloc(sizeof(QosTv));
    ASSERT_TRUE(tvList != NULL);
    ISessionListener sessionlistener = {
        .OnSessionOpened = OnSessionOpened,
        .OnSessionClosed = OnSessionClosed,
        .OnBytesReceived = OnBytesReceived,
        .OnMessageReceived = OnMessageReceived,
        .OnStreamReceived = OnStreamReceived,
        .OnQosEvent = NULL,
    };
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnQosEvent(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, TRANS_TEST_EVENT_ID, TRANS_TEST_TV_COUNT, tvList);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
    SoftBusFree(tvList);
}

/**
 * @tc.name: TransClientSessionCallbackTest12
 * @tc.desc: Transmission sdk session callback on session open failed with no callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest12, TestSize.Level1)
{
    ISessionListener sessionlistener = {
        .OnSessionOpened = NULL,
        .OnSessionClosed = OnSessionClosed,
        .OnBytesReceived = OnBytesReceived,
        .OnMessageReceived = OnMessageReceived,
        .OnStreamReceived = OnStreamReceived,
        .OnQosEvent = OnQosEvent,
    };
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnSessionOpenFailed(TRANS_TEST_CHANNEL_ID, TYPE_BYTES, SOFTBUS_NO_INIT);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest13
 * @tc.desc: Transmission sdk session callback on data received with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest13, TestSize.Level1)
{
    int32_t ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, TRANS_TEST_AUTH_DATA,
                                      strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_UDP;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_ALLFILE_SENT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_CRC_CHECK_FRAME);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_RESULT_FRAME);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_ACK_REQUEST_SENT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), TRANS_SESSION_FILE_ACK_RESPONSE_SENT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnDataReceived(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, TRANS_TEST_AUTH_DATA,
                              strlen(TRANS_TEST_AUTH_DATA), (SessionPktType)(TRANS_SESSION_FILE_ACK_RESPONSE_SENT + 1));
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_TYPE);

    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest14
 * @tc.desc: HandleAsyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest14, TestSize.Level1)
{
    SocketLifecycleData lifecycle;
    lifecycle.bindErrCode = 0;
    int32_t ret = HandleAsyncBindSuccess(1, NULL, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransClientSessionCallbackTest15
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest15, TestSize.Level1)
{
    SocketLifecycleData lifecycle;
    lifecycle.sessionState = SESSION_STATE_CANCELLING;
    lifecycle.bindErrCode = SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT;
    int32_t ret = HandleSyncBindSuccess(1, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_OK);

    lifecycle.sessionState = SESSION_STATE_INIT;
    ret = HandleSyncBindSuccess(1, &lifecycle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransClientSessionCallbackTest16
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest16, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    int32_t sessionId;
    SessionListenerAdapter sessionCallback;
    bool isServer = true;
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);

    int32_t ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = TRANS_TEST_CHANNEL_ID;
    ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, nullptr, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, nullptr, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = GetSocketCallbackAdapterByChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest17
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest17, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    int32_t sessionId;
    SessionListenerAdapter sessionCallback;
    bool isServer = true;
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->isClosing = true;

    int32_t ret = GetSocketCallbackAdapterByUdpChannelId(channelId,
        channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = TRANS_TEST_CHANNEL_ID;
    ret = GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, nullptr, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, &sessionId, nullptr, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, &sessionId, &sessionCallback, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = GetSocketCallbackAdapterByUdpChannelId(channelId, channelType, &sessionId, &sessionCallback, &isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest18
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest18, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    int32_t socketId = TRANS_TEST_SESSION_ID;

    int32_t ret = TransOnBindSuccess(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnBindSuccess(socketId, &g_testSocketlistener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnBindSuccess(socketId, &g_socketlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnBindSuccess(socketId, &g_socketlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest19
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest19, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    int32_t socketId = TRANS_TEST_SESSION_ID;

    int32_t ret = TransOnNegotiate(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransOnNegotiate(socketId, &g_testSocketlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransOnNegotiate(socketId, &g_socketlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransOnNegotiate(socketId, &g_socketlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = HandleServerOnNegotiate(socketId, &g_socketlistener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest20
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest20, TestSize.Level1)
{
    int32_t socketId = TRANS_TEST_SESSION_ID;
    bool isServer = true;
    SessionListenerAdapter sessionCallback;
    memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));

    int32_t ret = HandleCacheQosEvent(socketId, sessionCallback, isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isServer = false;
    ret = HandleCacheQosEvent(socketId, sessionCallback, isServer);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = HandleOnBindSuccess(socketId, sessionCallback, isServer);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: TransClientSessionCallbackTest21
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest21, TestSize.Level1)
{
    int32_t channelId = TRANS_TEST_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;

    int32_t ret = ClientTransOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: TransClientSessionCallbackTest22
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest22, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    bool isSocket =  true;

    int32_t ret = ClientTransIfChannelForSocket(nullptr, &isSocket);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransIfChannelForSocket(g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransIfChannelForSocket(g_sessionName, &isSocket);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransIfChannelForSocket(g_sessionName, &isSocket);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionCallbackTest23
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, TransClientSessionCallbackTest23, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    int32_t channelId = TRANS_TEST_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_BUTT;
    QoSEvent event = QOS_NOT_SATISFIED;
    QosTV qos;
    uint32_t count = 0;

    int32_t ret = ClientTransOnQos(channelId, channelType, event, nullptr, count);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransOnQos(channelId, channelType, event, &qos, count);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);

    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransOnQos(channelId, channelType, event, &qos, count);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: SetTimerTest001
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, SetTimerTest001, TestSize.Level1)
{
    int32_t ret = SetTimer(nullptr, DFX_TIMERS_S);
    EXPECT_EQ(ret, INVALID);

    ret = SetTimer("OnChannelOpened", DFX_TIMERS_S);
    EXPECT_NE(ret, INVALID);
    CancelTimer(INVALID);
    CancelTimer(DFX_TIMERS_S);
}

/**
 * @tc.name: SoftBusGetSelfTokenIdTest001
 * @tc.desc: HandleSyncBindSuccess not found session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionCallbackTest, SoftBusGetSelfTokenIdTest001, TestSize.Level1)
{
    int32_t ret = SoftBusGetSelfTokenId(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SoftBusGetCallingFullTokenId(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SoftBusGetCallingTokenId(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t tokenId = 1;
    ret = SoftBusGetCallingTokenId(&tokenId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}