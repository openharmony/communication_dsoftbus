/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 
#include <arpa/inet.h>
#include <unistd.h>
#include <securec.h>

#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "lnn_local_net_ledger.h"
#include "session.h"
#include "softbus_base_listener.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_message_open_channel.h"
#include "softbus_protocol_def.h"
#include "softbus_server_frame.h"
#include "softbus_socket.h"
#include "trans_channel_callback.c"
#include "trans_channel_manager.h"
#include "trans_tcp_direct_manager.c"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_wifi.h"
#include "softbus_tcp_socket.h"
#include "softbus_feature_config.h"
#include "softbus_conn_interface.h"
#include "bus_center_manager.h"
#include "trans_session_service.h"
#include "disc_event_manager.h"
#include "softbus_conn_ble_direct.h"
#include "message_handler.h"

using namespace testing::ext;

namespace OHOS {
#define TEST_TRANS_UDID "1234567"
#define TEST_AUTH_ID 1
#define AUTH_TRANS_DATA_LEN 32
#define DC_MSG_PACKET_HEAD_SIZE_LEN 24
#define MODULE_P2P_LISTEN 16
#define MSG_FLAG_REQUEST 0
#define TEST_SOCKET_PORT 6000
#define TEST_SOCKET_ADDR "192.168.8.119"
#define TEST_SOCKET_INVALID_PORT (-1)

#define TEST_RECV_DATA "receive data"
#define TEST_JSON "{errcode:1}"
#define TEST_MESSAGE "testMessage"
#define TEST_NETWORK_ID "peer networkId"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

#define TRANS_TEST_CONN_ID 1000
#define TRANS_TEST_REQUEST_ID 1000
#define TRANS_TEST_AUTH_SEQ 1000
#define TRANS_TEST_CHCANNEL_ID 1000
#define TRANS_TEST_FD 1000

static const char *g_sessionKey = "www.test.com";
static const char *g_uuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *g_udid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static SessionConn *g_conn = NULL;

class TransServerTcpDirectTest : public testing::Test {
public:
    TransServerTcpDirectTest()
    {}
    ~TransServerTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TestAddTestSessionConn(void)
{
    g_conn = CreateNewSessinConn(DIRECT_CHANNEL_CLIENT, false);
    g_conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    if (g_conn == NULL) {
        printf("create session conn failed.\n");
        return;
    }
    g_conn->channelId = 1;
    g_conn->authHandle.authId = 1;
    g_conn->serverSide = false;
    if (TransTdcAddSessionConn(g_conn) != SOFTBUS_OK) {
        printf("add session conn failed.\n");
    }
}

void TestDelSessionConn(void)
{
    int32_t channelId = 1;
    TransDelSessionConnById(channelId);
    if (g_conn != nullptr) {
        SoftBusFree(g_conn);
    }
}

void TransServerTcpDirectTest::SetUpTestCase(void)
{
    int32_t ret = LnnInitLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
    CreatSessionConnList();
    ret = AuthCommonInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TestAddTestSessionConn();
}

void TransServerTcpDirectTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
    AuthCommonDeinit();
    TransTcpDirectDeinit();
    LnnDeinitLocalLedger();
}

static int32_t TestAddAuthManager(int64_t authSeq, const char *sessionKeyStr, bool isServer)
{
    if (sessionKeyStr == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }

    AuthSessionInfo *info = (AuthSessionInfo*)SoftBusCalloc(sizeof(AuthSessionInfo));
    if (info == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }

    info->requestId = TRANS_TEST_REQUEST_ID;
    info->connId = TRANS_TEST_CONN_ID;
    info->isServer = isServer;
    info->version = SOFTBUS_NEW_V1;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    if (strcpy_s(info->udid, sizeof(info->udid), g_udid) != EOK ||
        strcpy_s(info->uuid, sizeof(info->uuid), g_uuid) != EOK ||
        strcpy_s(info->connInfo.info.ipInfo.ip, sizeof(info->connInfo.info.ipInfo.ip), TEST_SOCKET_ADDR) != EOK) {
        SoftBusFree(info);
        return SOFTBUS_STRCPY_ERR;
    }

    SessionKey *sessionKey = (SessionKey*)SoftBusCalloc(sizeof(SessionKey));
    if (sessionKey ==  NULL) {
        SoftBusFree(info);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(sessionKey->value, sizeof(sessionKey->value), sessionKeyStr, strlen(sessionKeyStr))) {
        SoftBusFree(info);
        SoftBusFree(sessionKey);
        return SOFTBUS_MEM_ERR;
    }
    sessionKey->len = strlen(sessionKeyStr);

    int32_t ret = AuthManagerSetSessionKey(authSeq, info, sessionKey, false, false);
    SoftBusFree(info);
    return ret;
}

static void TestDelAuthManager(int64_t authId)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
    }
}

static int32_t TestAddSessionConn(bool isServerSide)
{
    SessionConn *session = CreateNewSessinConn(DIRECT_CHANNEL_CLIENT, isServerSide);
    if (session == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }

    session->channelId = TRANS_TEST_CHCANNEL_ID;
    session->authHandle.authId = TRANS_TEST_AUTH_SEQ;
    session->appInfo.fd = TRANS_TEST_FD;

    int32_t ret = TransTdcAddSessionConn(session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        return ret;
    }

    return SOFTBUS_OK;
}

static void TestDelSessionConnNode(int32_t channelId)
{
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: GetCipherFlagByAuthId001
 * @tc.desc: GetCipherFlagByAuthId, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, GetCipherFlagByAuthId001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 0, .type = AUTH_LINK_TYPE_WIFI };
    uint32_t flag = 0;
    bool isAuthServer = false;
    bool isLegacyOs = false;

    int32_t ret = GetCipherFlagByAuthId(authHandle, &flag, &isAuthServer, isLegacyOs);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: GetCipherFlagByAuthId002
 * @tc.desc: GetCipherFlagByAuthId, transmission tcp direct listener get cipher flag by auth id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, GetCipherFlagByAuthId002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = TRANS_TEST_AUTH_SEQ, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = TestAddAuthManager(TRANS_TEST_AUTH_SEQ, g_sessionKey, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    uint32_t flag = 0;
    bool isAuthServer = false;
    bool isLegacyOs = false;

    ret = GetCipherFlagByAuthId(authHandle, &flag, &isAuthServer, isLegacyOs);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    EXPECT_FALSE(isAuthServer);
    TestDelAuthManager(TRANS_TEST_AUTH_SEQ);
}

/**
 * @tc.name: StartVerifySession001
 * @tc.desc: StartVerifySession, start verify session, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, StartVerifySession001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo *info = (AuthSessionInfo *)SoftBusMalloc(sizeof(AuthSessionInfo));
    ASSERT_TRUE(info != nullptr);

    SessionKey sessionKey;
    info->connInfo.type = AUTH_LINK_TYPE_WIFI;
    int32_t ret = AuthManagerSetSessionKey(authSeq, info, &sessionKey, false, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(info);
}

/**
 * @tc.name: StartVerifySession002
 * @tc.desc: StartVerifySession, transmission tcp direct listener start verify session with different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, StartVerifySession002, TestSize.Level1)
{
    static SessionConn *tmpSessionConn = NULL;
    tmpSessionConn = CreateNewSessinConn(DIRECT_CHANNEL_CLIENT, false);
    if (tmpSessionConn == NULL) {
        printf("create session conn failed.\n");
        return;
    }
    tmpSessionConn->channelId = 1;
    tmpSessionConn->authHandle.authId = 1;
    tmpSessionConn->serverSide = false;
    if (TransTdcAddSessionConn(tmpSessionConn) != SOFTBUS_OK) {
        printf("add session conn failed.\n");
    }

    static const char *tmpSessionKeyTest = "www.test.com";

    int32_t ret = TestAddAuthManager(tmpSessionConn->authHandle.authId, tmpSessionKeyTest, false);
    ASSERT_EQ(ret, SOFTBUS_OK);

    TestDelAuthManager(tmpSessionConn->authHandle.authId);
}

/**
 * @tc.name: TdcOnDataEvent001
 * @tc.desc: TdcOnDataEvent, transmission tcp direct listener Tdc on data event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TdcOnDataEvent001, TestSize.Level1)
{
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = TEST_SOCKET_PORT,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    int32_t ret = strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_SOCKET_ADDR);
    ASSERT_EQ(ret, EOK);

    ret = TestAddSessionConn(true);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TestAddSessionConn(true);
    ASSERT_EQ(ret, SOFTBUS_OK);

    TestDelSessionConnNode(TRANS_TEST_CHCANNEL_ID);

    ret = TestAddSessionConn(true);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TdcOnDataEvent002
 * @tc.desc: TdcOnDataEvent, transmission tcp direct listener Tdc on data event.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TdcOnDataEvent002, TestSize.Level1)
{
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = TEST_SOCKET_PORT,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    int32_t ret = strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_SOCKET_ADDR);
    ASSERT_EQ(ret, EOK);

    ret = TestAddSessionConn(false);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcStartSessionListener001
 * @tc.desc: TransTdcStartSessionListener, extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransTdcStartSessionListener001, TestSize.Level1)
{
    LocalListenerInfo *info = (LocalListenerInfo *)SoftBusMalloc(sizeof(LocalListenerInfo));
    ASSERT_TRUE(info != nullptr);

    info->type = CONNECT_TCP;
    (void)memset_s(info->socketOption.addr, sizeof(info->socketOption.addr), 0, sizeof(info->socketOption.addr));
    info->socketOption.port = TEST_SOCKET_PORT;
    info->socketOption.moduleId = DIRECT_CHANNEL_SERVER_WIFI;
    info->socketOption.protocol = LNN_PROTOCOL_IP;
    int32_t ret = TransTdcStartSessionListener(UNUSE_BUTT, info);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_BIND_ERR);

    (void)strcpy_s(info->socketOption.addr, strlen(TEST_SOCKET_ADDR) + 1, TEST_SOCKET_ADDR);
    info->socketOption.port = TEST_SOCKET_INVALID_PORT;
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    (void)memset_s(info->socketOption.addr, sizeof(info->socketOption.addr), 0, sizeof(info->socketOption.addr));
    info->socketOption.port = TEST_SOCKET_INVALID_PORT;
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcStopSessionListener001
 * @tc.desc: TransTdcStopSessionListener, extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransTdcStopSessionListener001, TestSize.Level1)
{
    int32_t ret = TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_WIFI);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * trans_tcp_direct_wifi.c
 * @tc.name: OpenTcpDirectChannel001
 * @tc.desc: OpenTcpDirectChannel, extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, OpenTcpDirectChannel001, TestSize.Level1)
{
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    (void)memset_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr),
        0, sizeof(connInfo.socketOption.addr));
    connInfo.socketOption.port = TEST_SOCKET_PORT;
    connInfo.socketOption.moduleId = MODULE_MESSAGE_SERVICE;
    connInfo.socketOption.protocol = LNN_PROTOCOL_IP;
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_SOCKET_ADDR) != EOK) {
        return;
    }
    int32_t channelId = 0;

    int32_t ret = OpenTcpDirectChannel(&appInfo, &connInfo, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED);
}

/**
 * trans_tcp_direct_message.c
 * @tc.name: PackBytes001
 * @tc.desc: PackBytes, validate packaging with error parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, PackBytes001, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    AuthHandle authHandle = { .authId = 1, .type = 1};
    int32_t ret = SetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcPostBytes001
 * @tc.desc: TransTdcPostBytes, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransTdcPostBytes001, TestSize.Level1)
{
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t channelId = 0;

    int32_t ret = TransTdcPostBytes(channelId, NULL, bytes);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcPostBytes(channelId, &packetHead, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    packetHead.dataLen = 0;
    ret = TransTdcPostBytes(channelId, &packetHead, bytes);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: ProcessReceivedData001
 * @tc.desc: ProcessReceivedData, The process of receiving data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, ProcessReceivedData001, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    int32_t fd = 1;

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * trans_tcp_direct_sessionconn.c
 * @tc.name: GetAuthHandleByChanId001
 * @tc.desc: GetAuthHandleByChanId, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, GetAuthHandleByChanId001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t ret = GetAppInfoById(g_conn->channelId, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    ret = GetAuthHandleByChanId(g_conn->channelId, &authHandle);
    EXPECT_EQ(authHandle.authId, TEST_AUTH_ID);

    ret = SetAuthHandleByChanId(g_conn->channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * trans_tcp_direct_p2p.c
 * @tc.name: SendAuthData001
 * @tc.desc: SendAuthData, sending authentication data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, SendAuthData001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 0;
    const char *data = TEST_MESSAGE;
    int32_t ret = SendAuthData(authHandle, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, seq, data);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: OpenAuthConn001
 * @tc.desc: OpenAuthConn, improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, OpenAuthConn001, TestSize.Level1)
{
    const char* uuid = TEST_TRANS_UDID;
    uint32_t reqId = 1;
    ConnectType type = CONNECT_HML;

    int32_t ret = OpenAuthConn(uuid, reqId, false, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    type = CONNECT_P2P;
    ret = OpenAuthConn(uuid, reqId, false, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    type = CONNECT_TCP;
    ret = OpenAuthConn(uuid, reqId, false, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
}

/**
 * @tc.name: TransTdcStopSessionProc001
 * @tc.desc: TransTdcStopSessionProc, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransTdcStopSessionProc001, TestSize.Level1)
{
    int32_t channelId = 1;
    SessionConn *conn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));

    conn->channelId = 1;
    conn->serverSide = false;
    conn->appInfo.fd = 0;
    conn->timeout = HANDSHAKE_TIMEOUT;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;

    TransTdcTimerProc();
    TransTdcStopSessionProc(AUTH);

    int32_t ret = TestAddSessionConn(false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    TransTdcTimerProc();
    NotifyTdcChannelTimeOut(nullptr);
    NotifyTdcChannelStopProc(nullptr);
    TransTdcStopSessionProc(AUTH);

    TransDelSessionConnById(channelId);
    SoftBusFree(conn);
}

/**
 * @tc.name: TransUpdateAppInfo001
 * @tc.desc: TransUpdateAppInfo, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransUpdateAppInfo001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ConnectOption *connInfo = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    connInfo->type = CONNECT_TCP;
    connInfo->socketOption.port = TEST_SOCKET_PORT;
    connInfo->socketOption.moduleId = MODULE_MESSAGE_SERVICE;
    connInfo->socketOption.protocol = LNN_PROTOCOL_NIP;
    (void)strcpy_s(connInfo->socketOption.addr, sizeof(connInfo->socketOption.addr), TEST_SOCKET_ADDR);
    (void)strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), TEST_SOCKET_ADDR);

    int32_t ret = TransUpdateAppInfo(appInfo, connInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: TransOpenDirectChannel001
 * @tc.desc: TransOpenDirectChannel, extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransOpenDirectChannel001, TestSize.Level1)
{
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    (void)memset_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr),
        0, sizeof(connInfo.socketOption.addr));
    connInfo.socketOption.port = TEST_SOCKET_PORT;
    connInfo.socketOption.moduleId = MODULE_MESSAGE_SERVICE;
    connInfo.socketOption.protocol = LNN_PROTOCOL_IP;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), TEST_SOCKET_ADDR) != EOK) {
        return;
    }
    int32_t fd = 1;

    int32_t ret = TransOpenDirectChannel(NULL, &connInfo, &fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOpenDirectChannel(&appInfo, NULL, &fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, &fd);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED);
}

/**
 * softbus_message_open_channel.c
 * @tc.name: UnpackReplyErrCode001
 * @tc.desc: UnpackReplyErrCode, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, UnpackReplyErrCode001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_MEM_ERR;
    int32_t ret = UnpackReplyErrCode(NULL, &errCode);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackReplyErrCode(NULL, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    std::string str = TEST_JSON;
    cJSON *msg = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(msg, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(msg);

    std::string errDesc = TEST_JSON;
    str = PackError(errCode, errDesc.c_str());
    cJSON *json = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(json, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/**
 * trans_channel_callback.c
 * @tc.name: TransServerOnChannelOpenFailed001
 * @tc.desc: TransServerOnChannelOpenFailed, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransServerOnChannelOpenFailed001, TestSize.Level1)
{
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = 0;
    int32_t channelId = -1;
    int32_t channelType = 0;
    int32_t errCode = -1;
    int32_t ret = TransServerOnChannelOpenFailed(pkgName, pid, channelId, channelType, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransServerOnChannelOpenFailed(NULL, pid, channelId, channelType, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * trans_lane_pending_ctl.c
 * @tc.name: TransGetAuthTypeByNetWorkId001
 * @tc.desc: TransGetAuthTypeByNetWorkId, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransServerTcpDirectTest, TransGetAuthTypeByNetWorkId001, TestSize.Level1)
{
    std::string networkId = TEST_NETWORK_ID;
    bool ret = TransGetAuthTypeByNetWorkId(networkId.c_str());
    EXPECT_NE(true, ret);

    SessionConn *node = static_cast<SessionConn *>(SoftBusCalloc(sizeof(SessionConn)));
    EXPECT_NE(nullptr, node);
    OnSessionOpenFailProc(node, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
    SoftBusFree(node);
}
} // namespace OHOS
