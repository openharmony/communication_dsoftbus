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
#include "softbus_log.h"
#include "softbus_trans_def.h"
#include "softbus_json_utils.h"
#include "softbus_app_info.h"
#include "softbus_server_frame.h"
#include "softbus_adapter_mem.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_session_service.c"
#include "softbus_access_token_test.h"
#include "softbus_common.h"

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_PID 0
#define TRANS_TEST_UID 0
#define TRANS_TEST_CHANNEL_ID 1000
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_STATE 1
#define TRANS_TEST_EVENT_ID 1
#define TRANS_TEST_TV_COUNT 1
#define TRANS_TEST_AUTH_DATA "test auth message data"
#define TRANS_TEST_CONN_IP "192.168.8.1"
#define TRANS_TEST_BR_MAC "11:22:33:44:55:66"
#define TRANS_TEST_AUTH_PORT 60000
#define TRANS_TEST_ADDR_INFO_NUM 2

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
const char *g_sessionKey = "www.huaweitest.com";
const char *g_networkId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_groupId = "TEST_GROUP_ID";
const char *g_rootDir = "/data/local/test";
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
    EXPECT_EQ(ret,  SOFTBUS_OK);
}

void TransClientSessionTest::TearDownTestCase(void)
{
}

static int OnSessionOpened(int sessionId, int result)
{
    LOG_INFO("session opened,sesison id = %d\r\n", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int sessionId)
{
    LOG_INFO("session closed, session id = %d\r\n", sessionId);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("session bytes received, session id = %d\r\n", sessionId);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("session msg received, session id = %d\r\n", sessionId);
}

static void OnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    LOG_INFO("session stream received, session id = %d\r\n", sessionId);
}

static void OnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    LOG_INFO("session Qos event emit, session id = %d\r\n", sessionId);
}

static int OnSessionOpenedErr(int sessionId, int result)
{
    LOG_INFO("session opened,sesison id = %d\r\n", sessionId);
    return SOFTBUS_ERR;
}

static int OnReceiveFileStarted(int sessionId, const char *files, int fileCnt)
{
    LOG_INFO("receive file start,sesison id = %d\r\n", sessionId);
    return SOFTBUS_OK;
}

static int OnReceiveFileProcess(int sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    LOG_INFO("receive file process,sesison id = %d\r\n", sessionId);
    return SOFTBUS_OK;
}

static void OnReceiveFileFinished(int sessionId, const char *files, int fileCnt)
{
    LOG_INFO("receive file finished,sesison id = %d\r\n", sessionId);
}

void OnFileTransError(int sessionId)
{
    LOG_INFO("file transmission error,sesison id = %d\r\n", sessionId);
}

int OnSendFileProcess(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    LOG_INFO("send file process,sesison id = %d\r\n", sessionId);
    return SOFTBUS_OK;
}

int OnSendFileFinished(int sessionId, const char *firstFile)
{
    LOG_INFO("send file finished,sesison id = %d\r\n", sessionId);
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

static void GenerateCommParam(SessionParam *sessionParam)
{
    sessionParam->sessionName = g_sessionName;
    sessionParam->peerSessionName = g_sessionName;
    sessionParam->peerDeviceId = g_deviceId;
    sessionParam->groupId = g_groupId;
    sessionParam->attr = &g_sessionAttr;
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

/**
 * @tc.name: TransClientSessionTest01
 * @tc.desc: Transmission sdk session service open session with existed session callback success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest01, TestSize.Level1)
{
    bool isEnabled = false;
    int32_t ret = OpenSessionWithExistSession(TRANS_TEST_SESSION_ID , isEnabled);
    EXPECT_EQ(ret, TRANS_TEST_SESSION_ID);
    isEnabled = true;
    ret = OpenSessionWithExistSession(TRANS_TEST_SESSION_ID , isEnabled);
    EXPECT_EQ(ret, TRANS_TEST_SESSION_ID);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenSessionWithExistSession(session->sessionId , isEnabled);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isEnabled = true;
    ret = OpenSessionWithExistSession(session->sessionId , isEnabled);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupId, &g_sessionAttr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_TRUE(addrInfo != NULL);
    int32_t ret = ConvertAddrStr(TRANS_TEST_AUTH_DATA, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON *msg = cJSON_CreateObject();
    bool res = AddStringToJsonObject(msg, "ETH_IP", TRANS_TEST_CONN_IP);
    EXPECT_TRUE(res);
    res = AddNumberToJsonObject(msg, "ETH_PORT", TRANS_TEST_AUTH_PORT);
    EXPECT_TRUE(res);
    char *data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "WIFI_IP", TRANS_TEST_CONN_IP);
    EXPECT_TRUE(res);
    res = AddNumberToJsonObject(msg, "WIFI_PORT", TRANS_TEST_AUTH_PORT);
    EXPECT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "BR_MAC", TRANS_TEST_BR_MAC);
    EXPECT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = ConvertAddrStr(data, addrInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "BLE_MAC", TRANS_TEST_BR_MAC);
    EXPECT_TRUE(res);
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
    EXPECT_EQ(ret, SOFTBUS_ERR);
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
    EXPECT_TRUE(res);
    char *data = cJSON_PrintUnformatted(msg);
    int ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = OpenAuthSession(g_sessionName, addrInfoArr, TRANS_TEST_ADDR_INFO_NUM, data);
    EXPECT_EQ(ret, INVALID_SESSION_ID);
    ret = ClientDeleteSession(ret);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    cJSON_free(data);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    res = AddStringToJsonObject(msg, "WIFI_IP", TRANS_TEST_CONN_IP);
    EXPECT_TRUE(res);
    res = AddNumberToJsonObject(msg, "WIFI_PORT", TRANS_TEST_AUTH_PORT);
    EXPECT_TRUE(res);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnabled);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyAuthSuccess(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionInfo *session = GenerateSession(sessionParam);
    session->isServer = true;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
 * @tc.desc: Transmission sdk session service notify auth success with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest10, TestSize.Level1)
{
    int32_t sessionId = 0;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->isEnable = true;
    ret = CheckSessionIsOpened(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(TRANS_TEST_INVALID_SESSION_ID);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_UDP;
    CloseSession(TRANS_TEST_SESSION_ID);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_UDP, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CloseSession(sessionId);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    int32_t sessionId = 0;
    bool isEnable = false;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnable);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetPeerSessionName(sessionId, sessionName, SESSION_NAME_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = strcmp(g_sessionName, sessionName);
    EXPECT_EQ(ret, EOK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
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
    int32_t sessionId = 0;
    bool isEnable = false;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnable);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetPeerDeviceId(sessionId, networkId, DEVICE_ID_SIZE_MAX);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = strcmp(g_deviceId, networkId);
    EXPECT_EQ(ret, EOK);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest15
 * @tc.desc: Transmission sdk session service judge session server or client.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest15, TestSize.Level1)
{
    int32_t sessionId = 0;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret =  ClientGetSessionSide(TRANS_TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    SessionInfo *session = GenerateSession(sessionParam);
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret =  ClientGetSessionSide(sessionId);
    EXPECT_EQ(ret, IS_CLIENT);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    session = GenerateSession(sessionParam);
    session->isServer = true;
    ret = ClientAddNewSession(g_sessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_BUTT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret =  ClientGetSessionSide(sessionId);
    EXPECT_EQ(ret, IS_SERVER);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(sessionParam);
}

/**
 * @tc.name: TransClientSessionTest16
 * @tc.desc: Transmission sdk session service set file recieve listener with different parameters.
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
    int32_t sessionId = 0;
    bool isEnable = false;
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    ret = ClientAddSession(sessionParam, &sessionId, &isEnable);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 0;
    ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *dfsSessionName = "DistributedFileService";
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, dfsSessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    sessionParam->sessionName = dfsSessionName;
    ret = ClientAddSession(sessionParam, &sessionId, &isEnable);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FUNC_NOT_SUPPORT);
    EXPECT_EQ(channelId, TRANS_TEST_INVALID_CHANNEL_ID);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = ClientAddNewSession(dfsSessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = IsValidDFSSession(sessionId, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(channelId, TRANS_TEST_CHANNEL_ID);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, dfsSessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransClientSessionTest19
 * @tc.desc: Transmission sdk session service get session key with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionTest, TransClientSessionTest19, TestSize.Level1)
{
    int32_t sessionId = 0;
    SessionParam *sessionParam = (SessionParam*)SoftBusMalloc(sizeof(SessionParam));
    EXPECT_TRUE(sessionParam != NULL);
    memset_s(sessionParam, sizeof(SessionParam), 0, sizeof(SessionParam));
    GenerateCommParam(sessionParam);
    const char *dfsSessionName = "DistributedFileService";
    int32_t ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, dfsSessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    sessionParam->sessionName = dfsSessionName;
    SessionInfo *session = GenerateSession(sessionParam);
    session->channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = ClientAddNewSession(dfsSessionName, session);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientGetSessionIdByChannelId(TRANS_TEST_CHANNEL_ID, CHANNEL_TYPE_TCP_DIRECT, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    char sessionKey[SESSION_KEY_LEN] = {0};
    ret = GetSessionKey(sessionId, sessionKey, SESSION_KEY_LEN);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = ClientDeleteSession(sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientDeleteSessionServer(SEC_TYPE_PLAINTEXT, dfsSessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}