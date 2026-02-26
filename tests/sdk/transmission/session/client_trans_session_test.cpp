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

#include <securec.h>

#include <gtest/gtest.h>
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "softbus_json_utils.h"
#include "softbus_app_info.h"
#include "softbus_server_frame.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_session_service.c"
#include "client_trans_session_manager.c"
#include "client_trans_socket_manager.c"
#include "softbus_access_token_test.h"
#include "softbus_common.h"
#include "token_setproc.h"
#include "trans_log.h"
#include "softbus_feature_config.h"
#include "softbus_conn_interface.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "trans_session_service.h"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_CHANNEL_ID 1000
#define TRANS_TEST_DEVICE_TYPE_ID 3
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_AUTH_DATA "test auth message data"
#define TRANS_TEST_CONN_IP "192.168.8.1"
#define TRANS_TEST_BR_MAC "11:22:33:44:55:66"
#define TRANS_TEST_AUTH_PORT 60000
#define TRANS_TEST_ADDR_INFO_NUM 2
#define TRANS_TEST_MAX_LENGTH 1024
#define TRANS_TEST_INVALID_SESSION_ID (-1)
#define TRANS_TEST_INVALID_VALUE_SIZE 8
#define HAP_TOKENID 123456
#define NATIVE_TOKENID 134341184
using namespace testing::ext;

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_sessionKey = "www.test.com";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_groupId = "TEST_GROUP_ID";
const char *g_deviceName = "rk3568test";
const char *g_rootDir = "/data";
const char *NEW_SESSION_NAME = "ohos.test.distributedschedule.dms.test";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};
class TransClientSessionTest : public testing::Test {
public:
    TransClientSessionTest()
    {}
    ~TransClientSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransClientSessionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    SetAccessTokenPermission("dsoftbusTransTest");
    int32_t ret = TransClientInit();
    ASSERT_EQ(ret,  SOFTBUS_OK);
}

void TransClientSessionTest::TearDownTestCase(void)
{
    ConnServerDeinit();
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

static int32_t OnSessionOpenedErr(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sessionId=%{public}d", sessionId);
    return SOFTBUS_NOT_FIND;
}

static int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    TRANS_LOGI(TRANS_TEST, "receive file start, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static int32_t OnReceiveFileProcess(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    TRANS_LOGI(TRANS_TEST, "receive file process, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{
    TRANS_LOGI(TRANS_TEST, "receive file finished, sessionId=%{public}d", sessionId);
}

void OnFileTransError(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "file transmission error, sessionId=%{public}d", sessionId);
}

int32_t OnSendFileProcess(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    TRANS_LOGI(TRANS_TEST, "send file process, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    TRANS_LOGI(TRANS_TEST, "send file finished, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
    .OnStreamReceived = OnStreamReceived,
    .OnQosEvent = OnQosEvent,
};

static IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileProcess = OnReceiveFileProcess,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnFileTransError = OnFileTransError
};

static IFileSendListener g_fileSendListener = {
    .OnSendFileProcess = OnSendFileProcess,
    .OnSendFileFinished = OnSendFileFinished,
    .OnFileTransError = OnFileTransError
};

static void TestGenerateCommParam(SessionParam *sessionParam)
{
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = &g_sessionAttr;
}

static SessionInfo *TestGenerateSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo*)SoftBusCalloc(sizeof(SessionInfo));
    if (session == nullptr) {
        return nullptr;
    }

    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK) {
        SoftBusFree(session);
        return nullptr;
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
    if (sessionParam == nullptr) {
        return SOFTBUS_MALLOC_ERR;
    }

    TestGenerateCommParam(sessionParam);
    sessionParam->sessionName = sessionName;
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, sessionName, &g_sessionlistener, &timestamp);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    SessionInfo *session = TestGenerateSession(sessionParam);
    if (session == nullptr) {
        return SOFTBUS_MALLOC_ERR;
    }

    session->channelType = (ChannelType)channelType;
    session->isServer = isServer;
    ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    int32_t sessionId = 0;
    bool isClosing = false;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, channelType, &sessionId, isClosing);
    if (ret != SOFTBUS_OK) {
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

/*
 * @tc.name: TransClientSessionTest01
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service open session with existed session callback success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest01, TestSize.Level1)
{
    bool isEnabled = false;
    int32_t ret = OpenSessionWithExistSession(TRANS_TEST_SESSION_ID, isEnabled);
    EXPECT_EQ(ret, TRANS_TEST_SESSION_ID);
    isEnabled = true;
    ret = OpenSessionWithExistSession(TRANS_TEST_SESSION_ID, isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OpenSessionWithExistSession(session->sessionId, isEnabled);
    EXPECT_EQ(ret, session->sessionId);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest02
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service open session with existed session callback error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest02, TestSize.Level1)
{
    bool isEnabled = false;
    ISessionListener sessionlistener = {
        .OnSessionOpened = OnSessionOpenedErr,
        .OnSessionClosed = OnSessionClosed,
        .OnBytesReceived = OnBytesReceived,
        .OnMessageReceived = OnMessageReceived,
        .OnStreamReceived = OnStreamReceived,
        .OnQosEvent = OnQosEvent,
    };
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener, &timestamp);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    isEnabled = true;
    ret = OpenSessionWithExistSession(session->sessionId, isEnabled);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest03
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service creat session server with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest03, TestSize.Level0)
{
    const char *pkgName = "package.test";
    int32_t ret = CreateSessionServer(pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientSessionTest04
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service remove session server with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest04, TestSize.Level0)
{
    int32_t ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_PID_ERROR);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientSessionTest05
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service open session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest05, TestSize.Level0)
{
    int32_t sessionId = 0;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupId, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupId, &g_sessionAttr);
    EXPECT_EQ(ret, sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientSessionTest06
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service convert address string with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest06, TestSize.Level1)
{
    ConnectionAddr *addrInfo = (ConnectionAddr*)SoftBusMalloc(sizeof(ConnectionAddr));
    ASSERT_TRUE(addrInfo != nullptr);
    int32_t ret = ConvertAddrStr(TRANS_TEST_AUTH_DATA, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON *msg = cJSON_CreateObject();
    bool res = AddStringToJsonObject(msg, "ETH_IP", TRANS_TEST_CONN_IP);
    ASSERT_TRUE(res);
    res = AddNumberToJsonObject(msg, "ETH_PORT", TRANS_TEST_AUTH_PORT);
    ASSERT_TRUE(res);
    char *data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "WIFI_IP", TRANS_TEST_CONN_IP);
    ASSERT_TRUE(res);
    res = AddNumberToJsonObject(msg, "WIFI_PORT", TRANS_TEST_AUTH_PORT);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "BR_MAC", TRANS_TEST_BR_MAC);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "BLE_MAC", TRANS_TEST_BR_MAC);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    SoftBusFree(addrInfo);
}

/*
 * @tc.name: TransClientSessionTest07
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service is valid addrInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest07, TestSize.Level1)
{
    ConnectionAddr addrInfoArr[TRANS_TEST_ADDR_INFO_NUM] = {
        {.type = CONNECTION_ADDR_MAX},
        {.type = CONNECTION_ADDR_MAX}
    };
    int32_t ret = IsValidAddrInfoArr(addrInfoArr, TRANS_TEST_ADDR_INFO_NUM);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: TransClientSessionTest08
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service open auth session with different
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest08, TestSize.Level0)
{
    ConnectionAddr addrInfoArr[TRANS_TEST_ADDR_INFO_NUM] = {
        {.type = CONNECTION_ADDR_MAX},
        {.type = CONNECTION_ADDR_MAX}
    };
    cJSON *msg = cJSON_CreateObject();
    bool res = AddStringToJsonObject(msg, "BLE_MAC", TRANS_TEST_BR_MAC);
    ASSERT_TRUE(res);
    char *data = cJSON_PrintUnformatted(msg);
    int32_t ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = CreateSessionServer(g_pkgName, NEW_SESSION_NAME, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    ret = ClientDeleteSession(ret);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "WIFI_IP", TRANS_TEST_CONN_IP);
    ASSERT_TRUE(res);
    res = AddNumberToJsonObject(msg, "WIFI_PORT", TRANS_TEST_AUTH_PORT);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = OpenAuthSession(NEW_SESSION_NAME, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = ClientDeleteSession(ret);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, NEW_SESSION_NAME);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    cJSON_free(data);
    cJSON_Delete(msg);
}

/*
 * @tc.name: TransClientSessionTest09
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service notify auth success with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest09, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isClosing = false;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NotifyAuthSuccess(sessionId);
    ret = ClientDeleteSession(sessionId);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->isServer = true;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyAuthSuccess(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest10
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service check whether session is opened
 *           with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest10, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isClosing = false;
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->enableStatus = ENABLE_STATUS_SUCCESS;
    ret = CheckSessionIsOpened(TRANS_TEST_CHANNEL_ID, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckSessionIsOpened(sessionId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest11
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service close session with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest11, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isClosing = false;
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    CloseSession(TRANS_TEST_INVALID_SESSION_ID);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelType = CHANNEL_TYPE_UDP;
    CloseSession(TRANS_TEST_SESSION_ID);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != nullptr);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_AUTH, &sessionId, isClosing);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest12
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get my session name with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest12, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = GetMySessionName(TRANS_TEST_INVALID_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMySessionName(TRANS_TEST_SESSION_ID, nullptr, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMySessionName(TRANS_TEST_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransClientSessionTest13
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get peer session name with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest13, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = GetPeerSessionName(TRANS_TEST_INVALID_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerSessionName(TRANS_TEST_SESSION_ID, nullptr, SESSION_NAME_SIZE_MAX);
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

/*
 * @tc.name: TransClientSessionTest14
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get peer device Id with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest14, TestSize.Level1)
{
    char networkId[DEVICE_ID_SIZE_MAX] = {0};
    int32_t ret = GetPeerDeviceId(TRANS_TEST_INVALID_SESSION_ID, networkId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetPeerDeviceId(TRANS_TEST_SESSION_ID, nullptr, DEVICE_ID_SIZE_MAX);
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

/*
 * @tc.name: TransClientSessionTest15
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service judge session server or client
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest15, TestSize.Level1)
{
    int32_t ret =  ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, -1);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_BUTT, false);
    ASSERT_GT(sessionId, 0);
    ret =  GetSessionSide(sessionId);
    EXPECT_EQ(ret, IS_CLIENT);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
    sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_BUTT, true);
    ASSERT_GT(sessionId, 0);
    ret =  GetSessionSide(sessionId);
    EXPECT_EQ(ret, IS_SERVER);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest16
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service set file receive listener with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest16, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, SESSION_NAME_SIZE_MAX + 2, 'A', SESSION_NAME_SIZE_MAX + 1);
    char pkgName[PKG_NAME_SIZE_MAX + 2] = {0};
    memset_s(pkgName, PKG_NAME_SIZE_MAX + 2, 'B', PKG_NAME_SIZE_MAX + 1);
    char rootDir[FILE_RECV_ROOT_DIR_SIZE_MAX + 2] = {0};
    memset_s(rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX + 2, 'C', FILE_RECV_ROOT_DIR_SIZE_MAX + 1);
    int32_t ret = SetFileReceiveListener(pkgName, g_sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, nullptr, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, &g_fileRecvListener, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientSessionTest17
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service set file send listener with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest17, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, SESSION_NAME_SIZE_MAX + 2, 'A', SESSION_NAME_SIZE_MAX + 1);
    char pkgName[PKG_NAME_SIZE_MAX + 2] = {0};
    memset_s(pkgName, PKG_NAME_SIZE_MAX + 2, 'B', PKG_NAME_SIZE_MAX + 1);
    char rootDir[FILE_RECV_ROOT_DIR_SIZE_MAX + 2] = {0};
    memset_s(rootDir, FILE_RECV_ROOT_DIR_SIZE_MAX + 2, 'C', FILE_RECV_ROOT_DIR_SIZE_MAX + 1);
    int32_t ret = SetFileSendListener(pkgName, g_sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, g_sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, g_sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientSessionTest18
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service judge whether session is DFS with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest18, TestSize.Level1)
{
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_BUTT, false);
    ASSERT_GT(sessionId, 0);
    int32_t channelId = 0;
    int32_t ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
    const char *dfsSessionName = "DistributedFileService";
    sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_BUTT, false);
    ASSERT_GT(sessionId, 0);
    ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    EXPECT_EQ(channelId, TRANS_TEST_CHANNEL_ID);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
    sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(channelId, TRANS_TEST_CHANNEL_ID);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest19
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get session key with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest19, TestSize.Level1)
{
    const char *dfsSessionName = "DistributedFileService";
    int32_t sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    char sessionKey[SESSION_KEY_LEN] = {0};
    int32_t ret = GetSessionKey(sessionId, sessionKey, SESSION_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest20
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get session handle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest20, TestSize.Level1)
{
    const char *dfsSessionName = "DistributedFileService";
    int32_t sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    int32_t handle = 0;
    int32_t ret = GetSessionHandle(sessionId, &handle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest21
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service disable session listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest21, TestSize.Level1)
{
    const char *dfsSessionName = "DistributedFileService";
    int32_t sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    int32_t ret = DisableSessionListener(sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest22
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service read max send bytes size
 *           with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest22, TestSize.Level1)
{
    uint32_t value = 0;
    int32_t ret = ReadMaxSendBytesSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT,
                                   &value, TRANS_TEST_INVALID_VALUE_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadMaxSendBytesSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, nullptr, TRANS_TEST_INVALID_VALUE_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadMaxSendBytesSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &value, sizeof(value));
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/*
 * @tc.name: TransClientSessionTest23
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service read max send message size
 *           with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest23, TestSize.Level1)
{
    uint32_t value = 0;
    int32_t ret = ReadMaxSendMessageSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT,
                                     &value, TRANS_TEST_INVALID_VALUE_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadMaxSendMessageSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &value, sizeof(value));
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);
    ret = ReadMaxSendMessageSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, nullptr, sizeof(value));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransClientSessionTest24
 * @tc.desc: test TransClientSession
 *           Transmission sdk session service get session option
 *           with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest24, TestSize.Level1)
{
    uint32_t optionValue = 0;
    int32_t ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_BUTT,
                               &optionValue, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           nullptr, sizeof(optionValue));
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

/*
 * @tc.name: TransClientSessionTest25
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager lnn offline process with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest25, TestSize.Level1)
{
    ClientTransLnnOfflineProc(nullptr);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);

    NodeBasicInfo info;
    memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    int32_t ret = strcpy_s(info.networkId, sizeof(info.networkId), g_networkId);
    ASSERT_EQ(ret, EOK);
    ret = strcpy_s(info.deviceName, sizeof(info.deviceName), g_deviceName);
    ASSERT_EQ(ret, EOK);
    info.deviceTypeId = TRANS_TEST_DEVICE_TYPE_ID;
    ClientTransLnnOfflineProc(&info);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest26
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager judge session whether session is available
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest26, TestSize.Level1)
{
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    DestroyClientSessionServer(nullptr, nullptr);
    bool res = SessionIdIsAvailable(sessionId);
    EXPECT_FALSE(res);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest27
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get new session server with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest27, TestSize.Level1)
{
    ClientSessionServer *server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, g_pkgName, &g_sessionlistener);
    ASSERT_TRUE(server != nullptr);
    ListNode destroyList;
    DestroyAllClientSession(nullptr, &destroyList);
    DestroyAllClientSession(server, nullptr);
    DestroyAllClientSession(server, &destroyList);
    SoftBusFree(server);
    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, sizeof(sessionName), 'A', SESSION_NAME_SIZE_MAX + 1);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, sessionName, g_pkgName, &g_sessionlistener);
    EXPECT_TRUE(server == nullptr);
    char pkgName[PKG_NAME_SIZE_MAX + 2] = {0};
    memset_s(pkgName, sizeof(pkgName), 'B', PKG_NAME_SIZE_MAX + 1);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, pkgName, &g_sessionlistener);
    EXPECT_TRUE(server == nullptr);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, nullptr, pkgName, &g_sessionlistener);
    EXPECT_TRUE(server == nullptr);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, nullptr, &g_sessionlistener);
    EXPECT_TRUE(server == nullptr);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, pkgName, nullptr);
    EXPECT_TRUE(server == nullptr);
}

/*
 * @tc.name: TransClientSessionTest28
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager judge whether parameter is valid with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest28, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);

    bool res = IsValidSessionParam(nullptr);
    EXPECT_FALSE(res);
    res = IsValidSessionParam(sessionParam);
    EXPECT_FALSE(res);
    sessionParam->sessionName = g_sessionName;
    res = IsValidSessionParam(sessionParam);
    EXPECT_FALSE(res);
    sessionParam->peerSessionName = g_sessionName;
    res = IsValidSessionParam(sessionParam);
    EXPECT_FALSE(res);
    sessionParam->peerDeviceId = g_deviceId;
    res = IsValidSessionParam(sessionParam);
    EXPECT_FALSE(res);
    sessionParam->groupId = g_groupId;
    res = IsValidSessionParam(sessionParam);
    EXPECT_FALSE(res);
    sessionParam->attr = (const SessionAttribute*)&g_sessionAttr;
    res = IsValidSessionParam(sessionParam);
    EXPECT_TRUE(res);

    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest29
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager create new session with different parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest29, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);

    TestGenerateCommParam(sessionParam);
    SessionInfo *session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session != nullptr);
    SoftBusFree(session);

    session = CreateNewSession(nullptr);
    EXPECT_TRUE(session == nullptr);

    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, sizeof(sessionName), 'A', SESSION_NAME_SIZE_MAX + 1);
    sessionParam->peerSessionName = (const char*)sessionName;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == nullptr);

    char deviceId[DEVICE_ID_SIZE_MAX + 2] = {0};
    memset_s(deviceId, sizeof(deviceId), 'B', DEVICE_ID_SIZE_MAX + 1);
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = (const char*)deviceId;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == nullptr);

    char groupId[GROUP_ID_SIZE_MAX + 2] = {0};
    memset_s(groupId, sizeof(groupId), 'C', GROUP_ID_SIZE_MAX + 1);
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = (const char*)groupId;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == nullptr);

    SoftBusFree(sessionParam);
}

/*
 * @tc.name: TransClientSessionTest30
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest30, TestSize.Level1)
{
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);

    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);

    SessionInfo *session = GetExistSession(sessionParam);
    ASSERT_TRUE(session != nullptr);

    int32_t ret = strcmp(session->info.peerSessionName, sessionParam->peerSessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcmp(session->info.peerDeviceId, sessionParam->peerDeviceId);
    EXPECT_EQ(ret, EOK);
    ret = strcmp(session->info.groupId, sessionParam->groupId);
    EXPECT_EQ(ret, EOK);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/*
 * @tc.name: TransClientSessionTest31
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest31, TestSize.Level1)
{
    SessionInfo *sessionNode = (SessionInfo*)SoftBusCalloc(sizeof(SessionInfo));
    ASSERT_TRUE(sessionNode != nullptr);
    ClientSessionServer *SessionServer = GetNewSessionServer(SEC_TYPE_PLAINTEXT,
        g_sessionName, g_pkgName, &g_sessionlistener);
    ASSERT_TRUE(SessionServer != nullptr);
    sessionNode->sessionId = TRANS_TEST_SESSION_ID;
    sessionNode->channelId = TRANS_TEST_CHANNEL_ID;
    sessionNode->channelType = CHANNEL_TYPE_BUTT;
    sessionNode->isAsync = true;
    sessionNode->lifecycle.condIsWaiting = true;
    SessionServer->listener.isSocketListener = true;

    DestroySessionInfo *destroyInfo = CreateDestroySessionNode(nullptr, SessionServer, NOT_MULTIPATH);
    EXPECT_TRUE(destroyInfo == nullptr);
    destroyInfo = CreateDestroySessionNode(sessionNode, nullptr, NOT_MULTIPATH);
    EXPECT_TRUE(destroyInfo == nullptr);
    destroyInfo = CreateDestroySessionNode(sessionNode, SessionServer, NOT_MULTIPATH);
    ASSERT_TRUE(destroyInfo != nullptr);
    ClientDestroySession(nullptr, SHUTDOWN_REASON_USER_SWICTH);
    SoftBusFree(destroyInfo);
    SoftBusFree(sessionNode);
    SoftBusFree(SessionServer);
}

/*
 * @tc.name: TransClientSessionTest32
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest32, TestSize.Level1)
{
    SessionInfo *sessionNode = CreateNonEncryptSessionInfo(nullptr);
    EXPECT_TRUE(sessionNode == nullptr);
    char sessionName[SESSION_NAME_SIZE_MAX + TRANS_TEST_ADDR_INFO_NUM] = {0};
    memset_s(sessionName, sizeof(sessionName), 'A', SESSION_NAME_SIZE_MAX + 1);
    sessionNode = CreateNonEncryptSessionInfo(sessionName);
    EXPECT_TRUE(sessionNode == nullptr);
}

/*
 * @tc.name: TransClientSessionTest33
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest33, TestSize.Level1)
{
    int32_t channelId = TRANS_TEST_CHANNEL_ID;
    char myIp[IP_LEN] = {0};
    memcpy_s(myIp, IP_LEN, TRANS_TEST_CONN_IP, IP_LEN);
    int32_t ipLen = IP_LEN;
    int32_t ret = ClientTransGetTdcIp(channelId, myIp, ipLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    ret = ClientTransGetUdpIp(channelId, myIp, ipLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND);
}

/*
 * @tc.name: TransClientSessionTest34
 * @tc.desc: test ClientTransCheckHmlIp
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest34, TestSize.Level1)
{
    char myIp[IP_LEN] = {0};
    memcpy_s(myIp, IP_LEN, TRANS_TEST_CONN_IP, IP_LEN);
    bool ret = ClientTransCheckHmlIp(myIp);
    EXPECT_FALSE(ret);
    memcpy_s(myIp, IP_LEN, TRANS_TEST_BR_MAC, IP_LEN);
    ret = ClientTransCheckHmlIp(myIp);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: TransClientSessionTest35
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest35, TestSize.Level1)
{
    const char *sessionName = "ohos.distributedschedule.dms.test";
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);
    SessionInfo *info = TestGenerateSession(sessionParam);
    ASSERT_TRUE(info != nullptr);
    int32_t connType = TRANS_CONN_HML;
    int32_t routeType = WIFI_P2P_REUSE;
    bool ret = ClientTransCheckNeedDel(sessionName, info, routeType, connType);
    EXPECT_FALSE(ret);
    routeType = ROUTE_TYPE_ALL;
    info->channelType = CHANNEL_TYPE_UDP;
    ret = ClientTransCheckNeedDel(sessionName, info, routeType, connType);
    EXPECT_FALSE(ret);
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = ClientTransCheckNeedDel(sessionName, info, routeType, connType);
    EXPECT_FALSE(ret);
    info->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientTransCheckNeedDel(sessionName, info, routeType, connType);
    EXPECT_TRUE(ret);
    info->channelType = CHANNEL_TYPE_BUTT;
    ret = ClientTransCheckNeedDel(sessionName, info, routeType, connType);
    EXPECT_FALSE(ret);
    SoftBusFree(sessionParam);
    SoftBusFree(info);
}

/*
 * @tc.name: TransClientSessionTest36
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest36, TestSize.Level1)
{
    ClientSessionServer server;
    char networkId[DEVICE_ID_SIZE_MAX] = {0};
    ASSERT_TRUE(networkId != NULL);
    int32_t type = 1;
    ListNode destroyList;
    DestroyClientSessionByNetworkId(nullptr, networkId, type, &destroyList);
    DestroyClientSessionByNetworkId(&server, nullptr, type, &destroyList);
    DestroyClientSessionByNetworkId(&server, networkId, type, nullptr);
    SessionServerInfo *info = CreateSessionServerInfoNode(nullptr);
    ASSERT_TRUE(info == nullptr);
}

/*
 * @tc.name: TransClientSessionTest37
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest37, TestSize.Level1)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    memset_s(sessionName, SESSION_NAME_SIZE_MAX, 'A', SESSION_NAME_SIZE_MAX - 1);
    SoftBusSecType type = SEC_TYPE_PLAINTEXT;
    ClientSessionServer *server = GetNewSocketServer(type, nullptr, pkgName);
    ASSERT_TRUE(server == nullptr);
    server = GetNewSocketServer(type, sessionName, nullptr);
    ASSERT_TRUE(server == nullptr);
    bool ret = IsDistributedDataSession(nullptr);
    EXPECT_FALSE(ret);
    ret = IsDistributedDataSession(sessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: TransClientSessionTest38
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest38, TestSize.Level1)
{
    SessionInfo sessionInfo;
    sessionInfo.info.flag = COMMON_VIDEO_STREAM;
    sessionInfo.isEncyptedRawStream = true;
    int dataType = RAW_STREAM;
    bool isEncyptedRawStream = true;
    bool ret = IsDifferentDataType(nullptr, dataType, isEncyptedRawStream);
    EXPECT_FALSE(ret);
    ret = IsDifferentDataType(&sessionInfo, dataType, isEncyptedRawStream);
    EXPECT_TRUE(ret);
    sessionInfo.info.flag = RAW_STREAM;
    ret = IsDifferentDataType(&sessionInfo, dataType, isEncyptedRawStream);
    EXPECT_FALSE(ret);
    dataType = COMMON_VIDEO_STREAM;
    sessionInfo.info.flag = COMMON_VIDEO_STREAM;
    ret = IsDifferentDataType(&sessionInfo, dataType, isEncyptedRawStream);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: TransClientSessionTest39
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest39, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);
    SessionInfo *info = CreateNewSocketSession(nullptr);
    ASSERT_TRUE(info == nullptr);
    info = CreateNewSocketSession(sessionParam);
    ASSERT_TRUE(info != nullptr);
    SoftBusFree(sessionParam);
    SoftBusFree(info);
}

/*
 * @tc.name: TransClientSessionTest40
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest40, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);
    SessionInfo *info = TestGenerateSession(sessionParam);
    ASSERT_TRUE(info != nullptr);
    ClientSessionServer serverNode;
    SessionAttribute tmpAttr;
    int32_t ret = CheckBindSocketInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckBindSocketInfo(info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info->info.flag = 0;
    ret = CheckBindSocketInfo(info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    info->info.flag = TYPE_BUTT;
    ret = CheckBindSocketInfo(info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    FillSessionParam(nullptr, &tmpAttr, &serverNode, info);
    FillSessionParam(sessionParam, nullptr, &serverNode, info);
    FillSessionParam(sessionParam, &tmpAttr, nullptr, info);
    FillSessionParam(sessionParam, &tmpAttr, &serverNode, nullptr);
    SoftBusFree(sessionParam);
    SoftBusFree(info);
}

/*
 * @tc.name: TransClientSessionTest41
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest41, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);
    SessionInfo *info = TestGenerateSession(sessionParam);
    ASSERT_TRUE(info != nullptr);
    ClientSessionServer serverNode;
    int32_t socket = 1;
    int32_t retOut = 0;
    int32_t socketId[5] = {0};
    uint32_t capacity = 1;
    uint32_t num = 1;
    ClientConvertRetVal(socket, &retOut);
    ClientConvertRetVal(socket, nullptr);
    bool ret = CleanUpTimeoutAuthSession(socket);
    ASSERT_FALSE(ret);
    ClientCheckWaitTimeOut(nullptr, info, socketId, capacity, &num);
    ClientCheckWaitTimeOut(&serverNode, nullptr, socketId, capacity, &num);
    ClientCheckWaitTimeOut(&serverNode, info, nullptr, capacity, &num);
    ClientCheckWaitTimeOut(&serverNode, info, socketId, capacity, nullptr);
    ClientCheckWaitTimeOut(&serverNode, info, socketId, capacity, &num);
    ClientCleanUpWaitTimeoutSocket(nullptr, num);
    ClientCleanUpWaitTimeoutSocket(socketId, num);
    SoftBusFree(sessionParam);
    SoftBusFree(info);
}

/*
 * @tc.name: TransClientSessionTest42
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest42, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientDeleteSocketSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != nullptr);
    TestGenerateCommParam(sessionParam);
    SessionInfo *info = TestGenerateSession(sessionParam);
    ASSERT_TRUE(info != nullptr);
    ClientSessionServer serverNode;
    SessionAttribute tmpAttr;
    ListNode destroyList;
    FillDfsSocketParam(nullptr, &tmpAttr, &serverNode, info);
    FillDfsSocketParam(sessionParam, nullptr, &serverNode, info);
    FillDfsSocketParam(sessionParam, &tmpAttr, nullptr, info);
    FillDfsSocketParam(sessionParam, &tmpAttr, &serverNode, nullptr);
    FillDfsSocketParam(sessionParam, &tmpAttr, &serverNode, info);
    ClientUpdateIdleTimeout(nullptr, info, &destroyList);
    ClientUpdateIdleTimeout(&serverNode, nullptr, &destroyList);
    ClientUpdateIdleTimeout(&serverNode, info, nullptr);
    PrivilegeDestroyAllClientSession(nullptr, &destroyList, g_networkId);
    PrivilegeDestroyAllClientSession(&serverNode, nullptr, g_networkId);
    PrivilegeDestroyAllClientSession(&serverNode, &destroyList, nullptr);
    SoftBusFree(sessionParam);
    SoftBusFree(info);
}

/*
 * @tc.name: TransClientSessionTest43
 * @tc.desc: test TransClientSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest43, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientDeletePagingSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    sessionId = 1;
    ret = ClientDeletePagingSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: TransClientSessionTest44
 * @tc.desc: test ClientDeletePagingSession
 *           Transmission sdk session manager get exist session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest44, TestSize.Level1)
{
    int32_t sessionId = 0;
    int32_t ret = ClientDeletePagingSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    sessionId = 1;
    ret = ClientDeletePagingSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: ReadSessionLinkTypeTest45
 * @tc.desc: test ReadSessionLinkType
 *           given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ReadSessionLinkTypeTest45, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t type = 1;
    uint32_t value = 0;
    uint32_t valueSize = 1;
    int32_t ret = ReadSessionLinkType(channelId, type, nullptr, valueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadSessionLinkType(channelId, type, &value, valueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    valueSize = sizeof(uint32_t);
    ret = ReadSessionLinkType(channelId, type, &value, valueSize);
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/*
 * @tc.name: RemoveAppIdFromSessionNameTest46
 * @tc.desc: test RemoveAppIdFromSessionName
 *           given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, RemoveAppIdFromSessionNameTest46, TestSize.Level1)
{
    const char *testSessionName = "testSessionName";
    char testNewSessionName[] = "testNewSessionName";
    int32_t length = 1;
    bool ret = RemoveAppIdFromSessionName(nullptr, testNewSessionName, length);
    EXPECT_FALSE(ret);
    ret = RemoveAppIdFromSessionName(testSessionName, nullptr, length);
    EXPECT_FALSE(ret);
    ret = RemoveAppIdFromSessionName(testSessionName, testNewSessionName, length);
    EXPECT_FALSE(ret);
    int32_t res = CreateSocket(nullptr, testNewSessionName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);
    ret = CreateSocket(testSessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, res);
}

/*
 * @tc.name: CreateSessionAttributeBySocketInfoTest47
 * @tc.desc: Verify given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.desc: Verify given different datatype should return tmpAttr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, CreateSessionAttributeBySocketInfoTest47, TestSize.Level1)
{
    SocketInfo info;
    bool isEncryptedRawStream;
    SessionAttribute *ret = CreateSessionAttributeBySocketInfoTrans(nullptr, &isEncryptedRawStream);
    EXPECT_TRUE(ret == nullptr);
    ret = CreateSessionAttributeBySocketInfoTrans(&info, nullptr);
    EXPECT_TRUE(ret == nullptr);
    info.dataType = DATA_TYPE_MESSAGE;
    ret = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret != nullptr);
    SoftBusFree(ret);
    info.dataType = DATA_TYPE_BYTES;
    SessionAttribute *ret1 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret1 != nullptr);
    SoftBusFree(ret1);
    info.dataType = DATA_TYPE_FILE;
    SessionAttribute *ret2 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret2 != nullptr);
    SoftBusFree(ret2);
    info.dataType = DATA_TYPE_RAW_STREAM;
    SessionAttribute *ret3 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret3 != nullptr);
    SoftBusFree(ret3);
    info.dataType = DATA_TYPE_RAW_STREAM_ENCRYPED;
    SessionAttribute *ret4 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret4 != nullptr);
    SoftBusFree(ret4);
    info.dataType = DATA_TYPE_VIDEO_STREAM;
    SessionAttribute *ret5 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret5 != nullptr);
    SoftBusFree(ret5);
    info.dataType = DATA_TYPE_AUDIO_STREAM;
    SessionAttribute *ret6 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret6 != nullptr);
    SoftBusFree(ret6);
    info.dataType = DATA_TYPE_SLICE_STREAM;
    SessionAttribute *ret7 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret7 != nullptr);
    SoftBusFree(ret7);
    info.dataType = DATA_TYPE_BUTT;
    SessionAttribute *ret8 = CreateSessionAttributeBySocketInfoTrans(&info, &isEncryptedRawStream);
    EXPECT_TRUE(ret8 != nullptr);
    SoftBusFree(ret8);
}

/*
 * @tc.name: ClientAddSocketTest48
 * @tc.desc: test ClientAddSocket
 *           Verify given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientAddSocketTest48, TestSize.Level1)
{
    SocketInfo info;
    int32_t sessionId = 1;
    SessionEnableStatus enableStatus = ENABLE_STATUS_SUCCESS;
    int32_t ret = ClientAddSocket(nullptr, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientAddSocket(&info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    bool res = IsContainServiceBySocket(-1);
    EXPECT_FALSE(res);
    ret = ClientSetEnableStatusBySocket(-1, enableStatus);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
}

/*
 * @tc.name: ClientGetSessionIsD2DByChannelIdTest49
 * @tc.desc: test ClientGetSessionIsD2DByChannelId
 *           given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientGetSessionIsD2DByChannelIdTest49, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = 1;
    bool isD2D = true;
    int32_t ret = ClientGetSessionIsD2DByChannelId(channelId, channelType, &isD2D);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIsD2DByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = 1;
    ret = ClientGetSessionIsD2DByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionIsD2DByChannelId(channelId, channelType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetIsAsyncAndTokenTypeBySessionIdTest50
 * @tc.desc: test GetIsAsyncAndTokenTypeBySessionId
 *           given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, GetIsAsyncAndTokenTypeBySessionIdTest50, TestSize.Level1)
{
    int32_t sessionId = -1;
    bool isAsync = false;
    int32_t tokenType = 1;
    int32_t ret = GetIsAsyncAndTokenTypeBySessionId(sessionId, &isAsync, &tokenType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    sessionId = 1;
    ret = GetIsAsyncAndTokenTypeBySessionId(sessionId, nullptr, &tokenType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetIsAsyncAndTokenTypeBySessionId(sessionId, &isAsync, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientGetChannelIdAndTypeBySocketIdTest51
 * @tc.desc: test ClientGetChannelIdAndTypeBySocketId
 *           given invalid param should return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientGetChannelIdAndTypeBySocketIdTest51, TestSize.Level1)
{
    int32_t socketId = 1;
    int32_t type = 1;
    int32_t channelId = 1;
    char *socketName = (char *)SoftBusCalloc(sizeof(SessionInfo));
    int32_t ret = ClientGetChannelIdAndTypeBySocketId(socketId, nullptr, &channelId, socketName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelIdAndTypeBySocketId(socketId, &type, nullptr, socketName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelIdAndTypeBySocketId(socketId, &type, &channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetChannelIdAndTypeBySocketId(socketId, &type, &channelId, socketName);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: SessionTypeConvertTest52
 * @tc.desc: test SessionTypeConvert
 *           given different BusinessType return different SessionType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, SessionTypeConvertTest52, TestSize.Level1)
{
    BusinessType type = BUSINESS_TYPE_BYTE;
    SessionType ret = SessionTypeConvert(type);
    EXPECT_EQ(ret, TYPE_BYTES);
    type = BUSINESS_TYPE_FILE;
    ret = SessionTypeConvert(type);
    EXPECT_EQ(ret, TYPE_FILE);
    type = BUSINESS_TYPE_D2D_MESSAGE;
    ret = SessionTypeConvert(type);
    EXPECT_EQ(ret, TYPE_D2D_MESSAGE);
    type = BUSINESS_TYPE_D2D_VOICE;
    ret = SessionTypeConvert(type);
    EXPECT_EQ(ret, TYPE_D2D_VOICE);
    type = BUSINESS_TYPE_BUTT;
    ret = SessionTypeConvert(type);
    EXPECT_EQ(ret, TYPE_MESSAGE);
}

/*
 * @tc.name: ClientForkSocketByIdTest53
 * @tc.desc: test ClientForkSocketById
 *           given invalid param return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientForkSocketByIdTest53, TestSize.Level1)
{
    int32_t socketId = 1;
    BusinessType type = BUSINESS_TYPE_FILE;
    int32_t newSocketId = 0;
    int32_t ret = ClientForkSocketById(socketId, type, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientForkSocketById(socketId, type, &newSocketId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: ClientGetServiceSocketInfoByIdTest54
 * @tc.desc: test ClientGetServiceSocketInfoById
 *           given invalid param return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientGetServiceSocketInfoByIdTest54, TestSize.Level1)
{
    int32_t socketId = 0;
    ServiceSocketInfo socketInfo;
    int32_t ret = ClientGetServiceSocketInfoById(socketId, &socketInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetSessionInitInfoById(socketId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);
    socketId = 1;
    ret = ClientGetServiceSocketInfoById(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetServiceSocketInfoById(socketId, &socketInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = SetSessionInitInfoById(socketId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/*
 * @tc.name: ClientGetServiceSocketInfoByIdTest55
 * @tc.desc: test ClientGetServiceSocketInfoById
 *           given invalid param return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, ClientGetServiceSocketInfoByIdTest55, TestSize.Level1)
{
    int32_t socketId = -1;
    bool isD2D = true;
    int32_t sessionType = 1;
    TransFlowInfo flowInfo;
    int32_t ret = ClientCheckIsD2DBySessionId(socketId, &isD2D);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionTypeBySocket(socketId, &sessionType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetFLTos(socketId, &flowInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    socketId = 1;
    ret = ClientCheckIsD2DBySessionId(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientGetSessionTypeBySocket(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientSetFLTos(socketId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientCheckIsD2DBySessionId(socketId, &isD2D);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientGetSessionTypeBySocket(socketId, &sessionType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    ret = ClientSetFLTos(socketId, &flowInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
}

/**
 * @tc.name: PrintCollabInfo001
 * @tc.desc: test PrintCollabInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, PrintCollabInfo001, TestSize.Level1)
{
    CollabInfo info = {
        .pid = 11380,
        .userId = 12345,
        .tokenId = TRANS_TEST_MAX_LENGTH
    };
    memset_s(info.deviceId, DEVICE_ID_LEN_MAX, 0, DEVICE_ID_LEN_MAX);
    memset_s(info.accountId, ACCOUNT_UID_LEN_MAX, 0, ACCOUNT_UID_LEN_MAX);
    (void)strcpy_s(info.deviceId, DEVICE_ID_LEN_MAX, "device-12345");
    (void)strcpy_s(info.accountId, ACCOUNT_UID_LEN_MAX, "account-67890");

    EXPECT_NO_FATAL_FAILURE(PrintCollabInfo(&info, nullptr));
    EXPECT_NO_FATAL_FAILURE(PrintCollabInfo(nullptr, "source"));
    EXPECT_NO_FATAL_FAILURE(PrintCollabInfo(&info, "sourece"));
}

/**
 * @tc.name: PrintAnonymizedString001
 * @tc.desc: test PrintAnonymizedString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, PrintAnonymizedString001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(PrintAnonymizedString(nullptr, "deviceId", "sink"));
}
}