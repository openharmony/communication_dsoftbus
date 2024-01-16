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
#include "softbus_json_utils.h"
#include "softbus_app_info.h"
#include "softbus_server_frame.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_session_service.c"
#include "client_trans_session_manager.c"
#include "softbus_access_token_test.h"
#include "softbus_common.h"
#include "trans_log.h"

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

using namespace testing::ext;

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_sessionKey = "www.huaweitest.com";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_groupId = "TEST_GROUP_ID";
const char *g_deviceName = "rk3568test";
const char *g_rootDir = "/data";
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
    InitSoftBusServer();
    SetAceessTokenPermission("dsoftbusTransTest");
    int32_t ret = TransClientInit();
    ASSERT_EQ(ret,  SOFTBUS_OK);
}

void TransClientSessionTest::TearDownTestCase(void)
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

static void OnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    TRANS_LOGI(TRANS_TEST, "session stream received, sessionId=%{public}d", sessionId);
}

static void OnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    TRANS_LOGI(TRANS_TEST, "session Qos event emit, sessionId=%{public}d", sessionId);
}

static int OnSessionOpenedErr(int sessionId, int result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sessionId=%{public}d", sessionId);
    return SOFTBUS_ERR;
}

static int OnReceiveFileStarted(int sessionId, const char *files, int fileCnt)
{
    TRANS_LOGI(TRANS_TEST, "receive file start, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static int OnReceiveFileProcess(int sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    TRANS_LOGI(TRANS_TEST, "receive file process, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnReceiveFileFinished(int sessionId, const char *files, int fileCnt)
{
    TRANS_LOGI(TRANS_TEST, "receive file finished, sessionId=%{public}d", sessionId);
}

void OnFileTransError(int sessionId)
{
    TRANS_LOGI(TRANS_TEST, "file transmission error, sessionId=%{public}d", sessionId);
}

int OnSendFileProcess(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    TRANS_LOGI(TRANS_TEST, "send file process, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

int OnSendFileFinished(int sessionId, const char *firstFile)
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
    session->isEnable = false;
    session->routeType = ROUTE_TYPE_ALL;
    session->info.flag = TYPE_BYTES;
    session->isEncrypt = true;
    session->algorithm = TRANS_TEST_ALGORITHM;
    session->fileEncrypt = TRANS_TEST_FILE_ENCRYPT;
    session->crc = TRANS_TEST_CRC;

    return session;
}

static int32_t AddSessionServerAndSession(const char *sessionName, int32_t channelType, bool isServer)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    if (sessionParam == NULL) {
        return SOFTBUS_ERR;
    }

    TestGenerateCommParam(sessionParam);
    sessionParam->sessionName = sessionName;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, sessionName, &g_sessionlistener);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    SessionInfo *session = TestGenerateSession(sessionParam);
    if (session == NULL) {
        return SOFTBUS_ERR;
    }

    session->channelType = (ChannelType)channelType;
    session->isServer = isServer;
    ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    int32_t sessionId = 0;
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, channelType, &sessionId);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    SoftBusFree(sessionParam);
    return sessionId;
}

static void DeleteSessionServerAndSession(const char *sessionName, int32_t sessionId)
{
    (void)ClientDeleteSession(sessionId);
    (void)ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, sessionName);
}

/**
 * @tc.name: TransClientSessionTest01
 * @tc.desc: Transmission sdk session service open session with existed session callback success.
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
    EXPECT_EQ(ret, INVALID_SESSION_ID);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OpenSessionWithExistSession(session->sessionId, isEnabled);
    EXPECT_EQ(ret, session->sessionId);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest02
 * @tc.desc: Transmission sdk session service open session with existed session callback error.
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
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    isEnabled = true;
    ret = OpenSessionWithExistSession(session->sessionId, isEnabled);
    EXPECT_EQ(ret, INVALID_SESSION_ID);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest03
 * @tc.desc: Transmission sdk session service creat session server with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest03, TestSize.Level1)
{
    const char *pkgName = "package.test";
    int ret = CreateSessionServer(pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionTest04
 * @tc.desc: Transmission sdk session service remove session server with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest04, TestSize.Level1)
{
    int ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionTest05
 * @tc.desc: Transmission sdk session service open session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest05, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isEnabled = false;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupId, &g_sessionAttr);
    EXPECT_EQ(ret, -1);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
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

/**
 * @tc.name: TransClientSessionTest06
 * @tc.desc: Transmission sdk session service convert address string with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest06, TestSize.Level1)
{
    ConnectionAddr *addrInfo = (ConnectionAddr*)SoftBusMalloc(sizeof(ConnectionAddr));
    ASSERT_TRUE(addrInfo != NULL);
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

/**
 * @tc.name: TransClientSessionTest07
 * @tc.desc: Transmission sdk session service is valid addrInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest07, TestSize.Level1)
{
    ConnectionAddr addrInfoArr[TRANS_TEST_ADDR_INFO_NUM] = {
        {.type = CONNECTION_ADDR_MAX},
        {.type = CONNECTION_ADDR_MAX}
    };
    int ret = IsValidAddrInfoArr(addrInfoArr, TRANS_TEST_ADDR_INFO_NUM);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: TransClientSessionTest08
 * @tc.desc: Transmission sdk session service open auth session with different.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest08, TestSize.Level1)
{
    ConnectionAddr addrInfoArr[TRANS_TEST_ADDR_INFO_NUM] = {
        {.type = CONNECTION_ADDR_MAX},
        {.type = CONNECTION_ADDR_MAX}
    };
    cJSON *msg = cJSON_CreateObject();
    bool res = AddStringToJsonObject(msg, "BLE_MAC", TRANS_TEST_BR_MAC);
    ASSERT_TRUE(res);
    char *data = cJSON_PrintUnformatted(msg);
    int ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
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
    ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, INVALID_SESSION_ID);
    ret = ClientDeleteSession(ret);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransClientSessionTest09
 * @tc.desc: Transmission sdk session service notify auth success with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest09, TestSize.Level1)
{
    int32_t sessionId = 0;
    bool isEnabled = false;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NotifyAuthSuccess(sessionId);
    ret = ClientDeleteSession(sessionId);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->isServer = true;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyAuthSuccess(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest10
 * @tc.desc: Transmission sdk session service check whether session is opened with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest10, TestSize.Level1)
{
    int32_t sessionId = 0;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->isEnable = true;
    ret = CheckSessionIsOpened(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckSessionIsOpened(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest11
 * @tc.desc: Transmission sdk session service close session with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest11, TestSize.Level1)
{
    int32_t sessionId = 0;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    CloseSession(TRANS_TEST_INVALID_SESSION_ID);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    TestGenerateCommParam(sessionParam);
    SessionInfo *session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_UDP;
    CloseSession(TRANS_TEST_SESSION_ID);
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    session = TestGenerateSession(sessionParam);
    ASSERT_TRUE(session != NULL);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_AUTH, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest12
 * @tc.desc: Transmission sdk session service get my session name with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest12, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int ret = GetMySessionName(TRANS_TEST_INVALID_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMySessionName(TRANS_TEST_SESSION_ID, NULL, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetMySessionName(TRANS_TEST_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX + 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransClientSessionTest13
 * @tc.desc: Transmission sdk session service get peer session name with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest13, TestSize.Level1)
{
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int ret = GetPeerSessionName(TRANS_TEST_INVALID_SESSION_ID, sessionName, SESSION_NAME_SIZE_MAX);
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
 * @tc.name: TransClientSessionTest14
 * @tc.desc: Transmission sdk session service get peer device Id with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest14, TestSize.Level1)
{
    char networkId[DEVICE_ID_SIZE_MAX] = {0};
    int ret = GetPeerDeviceId(TRANS_TEST_INVALID_SESSION_ID, networkId, DEVICE_ID_SIZE_MAX);
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
 * @tc.name: TransClientSessionTest15
 * @tc.desc: Transmission sdk session service judge session server or client.
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

/**
 * @tc.name: TransClientSessionTest16
 * @tc.desc: Transmission sdk session service set file receive listener with different parameters.
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
    int ret = SetFileReceiveListener(pkgName, g_sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, NULL, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, &g_fileRecvListener, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileReceiveListener(g_pkgName, g_sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionTest17
 * @tc.desc: Transmission sdk session service set file send listener with different parameters.
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
    int ret = SetFileSendListener(pkgName, g_sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, g_sessionName, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SetFileSendListener(g_pkgName, g_sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionTest18
 * @tc.desc: Transmission sdk session service judge whether session is DFS with different parameters.
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

/**
 * @tc.name: TransClientSessionTest19
 * @tc.desc: Transmission sdk session service get session key with different parameters.
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
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest20
 * @tc.desc: Transmission sdk session service get session handle.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest20, TestSize.Level1)
{
    const char *dfsSessionName = "DistributedFileService";
    int32_t sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    int handle = 0;
    int32_t ret = GetSessionHandle(sessionId, &handle);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest21
 * @tc.desc: Transmission sdk session service disable session listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest21, TestSize.Level1)
{
    const char *dfsSessionName = "DistributedFileService";
    int32_t sessionId = AddSessionServerAndSession(dfsSessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    int32_t ret = DisableSessionListener(sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DeleteSessionServerAndSession(dfsSessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest22
 * @tc.desc: Transmission sdk session service read max send bytes size with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest22, TestSize.Level1)
{
    uint32_t value = 0;
    int ret = ReadMaxSendBytesSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT,
                                   &value, TRANS_TEST_INVALID_VALUE_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadMaxSendBytesSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &value, sizeof(value));
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/**
 * @tc.name: TransClientSessionTest23
 * @tc.desc: Transmission sdk session service read max send message size with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest23, TestSize.Level1)
{
    uint32_t value = 0;
    int ret = ReadMaxSendMessageSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT,
                                     &value, TRANS_TEST_INVALID_VALUE_SIZE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ReadMaxSendMessageSize(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &value, sizeof(value));
    EXPECT_EQ(ret, SOFTBUS_GET_CONFIG_VAL_ERR);
}

/**
 * @tc.name: TransClientSessionTest24
 * @tc.desc: Transmission sdk session service get session option with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest24, TestSize.Level1)
{
    uint32_t optionValue = 0;
    int ret = GetSessionOption(TRANS_TEST_SESSION_ID, SESSION_OPTION_BUTT,
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
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    ret = GetSessionOption(sessionId, SESSION_OPTION_MAX_SENDBYTES_SIZE,
                           &optionValue, sizeof(optionValue));
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest25
 * @tc.desc: Transmission sdk session manager lnn offline process with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest25, TestSize.Level1)
{
    ClientTransLnnOfflineProc(NULL);
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);

    NodeBasicInfo info;
    memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    int ret = strcpy_s(info.networkId, sizeof(info.networkId), g_networkId);
    ASSERT_EQ(ret, EOK);
    ret = strcpy_s(info.deviceName, sizeof(info.deviceName), g_deviceName);
    ASSERT_EQ(ret, EOK);
    info.deviceTypeId = TRANS_TEST_DEVICE_TYPE_ID;
    ClientTransLnnOfflineProc(&info);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest26
 * @tc.desc: Transmission sdk session manager judge session whether session is available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest26, TestSize.Level1)
{
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);
    DestroyClientSessionServer(NULL, NULL);
    bool res = SessionIdIsAvailable(sessionId);
    EXPECT_FALSE(res);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}

/**
 * @tc.name: TransClientSessionTest27
 * @tc.desc: Transmission sdk session manager get new session server with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest27, TestSize.Level1)
{
    ClientSessionServer *server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, g_pkgName, &g_sessionlistener);
    ASSERT_TRUE(server != NULL);
    SoftBusFree(server);
    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, sizeof(sessionName), 'A', SESSION_NAME_SIZE_MAX + 1);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, sessionName, g_pkgName, &g_sessionlistener);
    EXPECT_TRUE(server == NULL);
    char pkgName[PKG_NAME_SIZE_MAX + 2] = {0};
    memset_s(pkgName, sizeof(pkgName), 'B', PKG_NAME_SIZE_MAX + 1);
    server = GetNewSessionServer(SEC_TYPE_PLAINTEXT, g_sessionName, pkgName, &g_sessionlistener);
    EXPECT_TRUE(server == NULL);
}

/**
 * @tc.name: TransClientSessionTest28
 * @tc.desc: Transmission sdk session manager judge whether parameter is valid with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest28, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);

    bool res = IsValidSessionParam(NULL);
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

/**
 * @tc.name: TransClientSessionTest29
 * @tc.desc: Transmission sdk session manager create new session with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest29, TestSize.Level1)
{
    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);

    TestGenerateCommParam(sessionParam);
    SessionInfo *session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session != NULL);
    SoftBusFree(session);

    char sessionName[SESSION_NAME_SIZE_MAX + 2] = {0};
    memset_s(sessionName, sizeof(sessionName), 'A', SESSION_NAME_SIZE_MAX + 1);
    sessionParam->peerSessionName = (const char*)sessionName;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == NULL);

    char deviceId[DEVICE_ID_SIZE_MAX + 2] = {0};
    memset_s(deviceId, sizeof(deviceId), 'B', DEVICE_ID_SIZE_MAX + 1);
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = (const char*)deviceId;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == NULL);

    char groupId[GROUP_ID_SIZE_MAX + 2] = {0};
    memset_s(groupId, sizeof(groupId), 'C', GROUP_ID_SIZE_MAX + 1);
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = (const char*)groupId;
    session = CreateNewSession(sessionParam);
    EXPECT_TRUE(session == NULL);

    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest30
 * @tc.desc: Transmission sdk session manager get exist session.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest30, TestSize.Level1)
{
    int32_t sessionId = AddSessionServerAndSession(g_sessionName, CHANNEL_TYPE_TCP_DIRECT, false);
    ASSERT_GT(sessionId, 0);

    SessionParam *sessionParam = (SessionParam*)SoftBusCalloc(sizeof(SessionParam));
    ASSERT_TRUE(sessionParam != NULL);
    TestGenerateCommParam(sessionParam);

    SessionInfo *session = GetExistSession(sessionParam);
    ASSERT_TRUE(session != NULL);

    int ret = strcmp(session->info.peerSessionName, sessionParam->peerSessionName);
    EXPECT_EQ(ret, EOK);
    ret = strcmp(session->info.peerDeviceId, sessionParam->peerDeviceId);
    EXPECT_EQ(ret, EOK);
    ret = strcmp(session->info.groupId, sessionParam->groupId);
    EXPECT_EQ(ret, EOK);

    DeleteSessionServerAndSession(g_sessionName, sessionId);
}
}