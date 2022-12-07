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

#include "auth_manager.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "auth_interface.h"
#include "cJSON.h"
#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"

#include "trans_channel_callback.c"
#include "trans_channel_manager.h"
#include "trans_tcp_direct_listener.c"
#include "trans_tcp_direct_manager.c"
#include "trans_tcp_direct_message.c"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_wifi.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_TRANS_UDID "1234567"
#define TRANS_SEQ_STEP 2
#define AUTH_TRANS_DATA_LEN 32
#define DEVICE_ID_SIZE_MAX_LEN 65
#define DC_MSG_PACKET_HEAD_SIZE_LEN 24
#define MODULE_P2P_LISTEN 16
#define MSG_FLAG_REQUEST 0
#define TEST_SOCKET_PORT 6000
#define TEST_SOCKET_ADDR "192.168.8.119"
#define TEST_SOCKET_INVALID_PORT (-1)

#define TEST_RECV_DATA "receive data"
#define TEST_JSON "{errcode:1}"
#define TEST_MESSAGE "testMessage"
#define TEST_NETWORK_ID "testNetworkId"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

static SessionConn *g_conn = NULL;

class ServerTransTcpDirectTest : public testing::Test {
public:
    ServerTransTcpDirectTest()
    {}
    ~ServerTransTcpDirectTest()
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
    if (g_conn == NULL) {
        printf("create session conn failed.\n");
        return;
    }
    g_conn->channelId = 1;
    g_conn->authId = 1;
    g_conn->serverSide = false;
    if (TransTdcAddSessionConn(g_conn) != SOFTBUS_OK) {
        printf("add session conn failed.\n");
    }
}

void TestDelSessionConn(void)
{
    int32_t channelId = 1;
    TransDelSessionConnById(channelId);
}

void ServerTransTcpDirectTest::SetUpTestCase(void)
{
    int32_t ret = AuthCommonInit();
    EXPECT_TRUE(SOFTBUS_OK == ret);

    IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransTcpDirectInit(cb);
    EXPECT_TRUE(SOFTBUS_OK == ret);

    TestAddTestSessionConn();
}

void ServerTransTcpDirectTest::TearDownTestCase(void)
{
    AuthCommonDeinit();
    TransTcpDirectDeinit();

    TestDelSessionConn();
}

/**
 * @tc.name: StartSessionListenerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, StartSessionListenerTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    LocalListenerInfo info;
    info.type = CONNECT_TCP;
    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = TEST_SOCKET_PORT;
    info.socketOption.moduleId = DIRECT_CHANNEL_SERVER_WIFI;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    ret = TransTdcStartSessionListener(UNUSE_BUTT, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    (void)strcpy_s(info.socketOption.addr, strlen(TEST_SOCKET_ADDR) + 1, TEST_SOCKET_ADDR);
    info.socketOption.port = TEST_SOCKET_INVALID_PORT;
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = TEST_SOCKET_INVALID_PORT;
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: StoptSessionListenerTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, StoptSessionListenerTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_WIFI);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenTcpDirectChannelTest001
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OpenTcpDirectChannelTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;

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

    ret = TransOpenDirectChannel(NULL, &connInfo, &fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(&appInfo, NULL, &fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, &fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenTcpDirectChannelTest002
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OpenTcpDirectChannelTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
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
    ret = OpenTcpDirectChannel(&appInfo, &connInfo, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcPostBytesTest001
 * @tc.desc: TransTdcPostBytesTest, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, TransTdcPostBytesTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t channelId = 0;

    ret = TransTdcPostBytes(channelId, NULL, bytes);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcPostBytes(channelId, &packetHead, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    packetHead.dataLen = 0;
    ret = TransTdcPostBytes(channelId, &packetHead, bytes);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest001
 * @tc.desc: GetCipherFlagByAuthId, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, GetCipherFlagByAuthIdTest001, TestSize.Level1)
{
    int64_t authId = 0;
    uint32_t flag = 0;
    bool isAuthServer = false;

    int32_t ret = GetCipherFlagByAuthId(authId, &flag, &isAuthServer);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: SessionConnListTest001
 * @tc.desc: SessionConnListTest001, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, SessionConnListTest001, TestSize.Level1)
{
    AppInfo appInfo;
    int32_t authId = AUTH_INVALID_ID;
    
    int32_t ret = GetAppInfoById(g_conn->channelId, &appInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    authId = GetAuthIdByChanId(g_conn->channelId);
    EXPECT_TRUE(authId != AUTH_INVALID_ID);

    ret = SetAuthIdByChanId(g_conn->channelId, AUTH_INVALID_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    authId = GetAuthIdByChanId(g_conn->channelId);
    EXPECT_TRUE(authId == AUTH_INVALID_ID);
}

/**
 * @tc.name: StartVerifySessionTest001
 * @tc.desc: start verify session, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, StartVerifySessionTest001, TestSize.Level1)
{
    int64_t authSeq = 0;
    AuthSessionInfo info;
    SessionKey sessionKey;

    int32_t ret = StartVerifySession(g_conn);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = AuthManagerSetSessionKey(authSeq, &info, &sessionKey);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = StartVerifySession(g_conn);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: PackBytesTest001
 * @tc.desc: validate packaging with error parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, PackBytesTest001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    const char *data = TEST_MESSAGE;
    const char *bytes = TEST_MESSAGE;
    int32_t channelId = g_conn->channelId;
    TdcPacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.module = MODULE_SESSION;
    packetHead.seq = 0;
    packetHead.flags = FLAG_REQUEST;
    packetHead.dataLen = strlen(bytes);
    char buffer[DC_MSG_PACKET_HEAD_SIZE_LEN] = {0};

    ret = PackBytes(channelId, data, &packetHead, buffer, DC_MSG_PACKET_HEAD_SIZE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = SetAuthIdByChanId(channelId, 1);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = PackBytes(channelId, data, &packetHead, buffer, DC_MSG_PACKET_HEAD_SIZE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = PackBytes(-1, data, &packetHead, buffer, DC_MSG_PACKET_HEAD_SIZE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenAuthConnTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
 
HWTEST_F(ServerTransTcpDirectTest, OpenAuthConnTest001, TestSize.Level1)
{
    const char* uuid = TEST_TRANS_UDID;
    uint32_t reqId = 1;

    int32_t ret = OpenAuthConn(uuid, reqId, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}
/**
 * @tc.name: OpenDataBusReplyTest002
 * @tc.desc: Open the data channel for reply with error parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OpenDataBusReplyTest002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = g_conn->channelId;
    uint64_t seq = 0;
    int32_t errCode = SOFTBUS_ERR;
    char *msg = PackError(errCode, TEST_MESSAGE);
    cJSON *reply = cJSON_Parse(msg);

    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenDataBusReply(0, seq, reply);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusRequestErrorTest003
 * @tc.desc: open dsofutbus data erro request with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OpenDataBusRequestErrorTest003, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 0;
    uint64_t seq = 0;
    int32_t errCode = 0;
    uint32_t flags = 0;
    ret = OpenDataBusRequestError(channelId, seq, NULL, errCode, flags);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetUuidByChanIdTest004
 * @tc.desc: get uuid by channelId with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, GetUuidByChanIdTest004, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    int32_t channelId = 0;
    uint32_t len = 0;
    ret = GetUuidByChanId(channelId, NULL, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = GetUuidByChanId(g_conn->channelId, NULL, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OpenDataBusRequestTest005
 * @tc.desc: OpenDataBusRequestTest005, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OpenDataBusRequestTest005, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    uint32_t flags = 0;
    uint64_t seq = 0;
    ret = OpenDataBusRequest(0, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenDataBusRequest(g_conn->channelId, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: ProcessMessageTest006
 * @tc.desc: ProcessMessageTest006, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, ProcessMessageTest006, TestSize.Level1)
{
    int32_t channelId = 0;
    uint32_t flags = 0;
    uint64_t seq = 0;
    int32_t ret = ProcessMessage(channelId, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelId = g_conn->channelId;
    ret = ProcessMessage(channelId, flags, seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ProcessMessage(channelId, flags, seq, TEST_MESSAGE);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest007
 * @tc.desc: GetAuthIdByChannelInfoTest007, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, GetAuthIdByChannelInfoTest007, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    uint64_t seq = 0;
    uint32_t cipherFlag = 0;
    int32_t ret = GetAuthIdByChannelInfo(channelId, seq, cipherFlag);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: DecryptMessageTest008
 * @tc.desc: DecryptMessageTest008, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, DecryptMessageTest008, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    uint8_t* outData = nullptr;
    uint32_t dataLen = DC_MSG_PACKET_HEAD_SIZE_LEN;
    const char *bytes = TEST_MESSAGE;
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t ret = DecryptMessage(channelId, &packetHead, NULL, &outData, &dataLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: ProcessReceivedDataTest009
 * @tc.desc: The process of receiving data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, ProcessReceivedDataTest009, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    int32_t fd = 1;

    int32_t ret = ProcessReceivedData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = ProcessReceivedData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: SendAuthDataTest001
 * @tc.desc: sending authentication data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, SendAuthDataTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = 0;
    const char *data = TEST_MESSAGE;
    int32_t ret = SendAuthData(authId, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, seq, data);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: OnAuthDataRecvTest002
 * @tc.desc: receiving authentication data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OnAuthDataRecvTest002, TestSize.Level1)
{
    int64_t authId = 0;
    AuthTransData dataInfo;
    (void)memset_s(&dataInfo, sizeof(AuthTransData), 0, sizeof(AuthTransData));
    dataInfo.len = 1;
    dataInfo.data = NULL;

    OnAuthDataRecv(authId, NULL);
    OnAuthDataRecv(authId, &dataInfo);

    dataInfo.data = (const uint8_t *)TEST_RECV_DATA;
    OnAuthDataRecv(authId, &dataInfo);

    dataInfo.len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authId, &dataInfo);
}

/**
 * @tc.name: TransDelSessionConnByIdTest001
 * @tc.desc: delete the session by channelId, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, TransDelSessionConnByIdTest001, TestSize.Level1)
{
    int32_t channelId = g_conn->channelId;
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnSessionOpenFailProcTest001
 * @tc.desc: delete the session by channelId, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, OnSessionOpenFailProcTest001, TestSize.Level1)
{
    SessionConn sessionConn = {
        .channelId = 1,
    };
    OnSessionOpenFailProc(&sessionConn, SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
}

/**
 * @tc.name: UnpackReplyErrCodeTest001
 * @tc.desc: UnpackReplyErrCodeTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, UnpackReplyErrCodeTest001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_ERR;
    int32_t ret = UnpackReplyErrCode(NULL, &errCode);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackReplyErrCode(NULL, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);

    string str = TEST_JSON;
    cJSON *msg = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(msg, NULL);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(msg);

    string errDesc = TEST_JSON;
    str = PackError(SOFTBUS_ERR, errDesc.c_str());
    cJSON *json = cJSON_Parse(str.c_str());
    ret = UnpackReplyErrCode(json, &errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: TransServerOnChannelOpenFailedTest001
 * @tc.desc: TransServerOnChannelOpenFailedTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, TransServerOnChannelOpenFailedTest001, TestSize.Level1)
{
    const char *pkgName = TEST_PKG_NAME;
    int32_t ret = TransServerOnChannelOpenFailed(pkgName, -1, 0, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransServerOnChannelOpenFailed(NULL, -1, 0, SOFTBUS_ERR);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransGetAuthTypeByNetWorkIdTest001
 * @tc.desc: TransGetAuthTypeByNetWorkIdTest001, with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerTransTcpDirectTest, TransGetAuthTypeByNetWorkIdTest001, TestSize.Level1)
{
    string networkId = TEST_NETWORK_ID;
    bool ret = TransGetAuthTypeByNetWorkId(networkId.c_str());
    EXPECT_NE(true, ret);
}

} // namespace OHOS
