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
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <securec.h>
#include "auth_interface.h"
#include "gtest/gtest.h"
#include "trans_auth_message.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_sessionconn.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"

using namespace testing::ext;

namespace OHOS {

#define EOK 0
#define INVALID_VALUE (-1)
#define AUTH_TRANS_DATA_LEN 32
#define PKG_NAME_SIZE_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 65

static const char *g_addr = "192.168.8.119";
static const char *g_ip = "192.168.8.1";
static int32_t g_port = 6000;
static const char *g_sessionName = "com.test.trans.auth.demo";
static const char *g_pkgName = "dms";
static const char *g_udid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
class TransTcpDirectP2pTest : public testing::Test {
public:
    TransTcpDirectP2pTest()
    {}
    ~TransTcpDirectP2pTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectP2pTest::SetUpTestCase(void)
{
}

void TransTcpDirectP2pTest::TearDownTestCase(void)
{
}

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }
    
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = 1;
    conn->authId = 1;
    conn->requestId = 1;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.routeType = WIFI_P2P;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    return conn;
}

string TestGetMsgPack()
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        cJSON_Delete(msg);
        return nullptr;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        cJSON_Delete(msg);
        return nullptr;
    }
    
    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = 1;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName)+1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    if (TransAuthChannelMsgPack(msg, appInfo) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        return nullptr;
    }
    string data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    return data;
}
/**
 * @tc.name: StartNewP2pListenerTest001
 * @tc.desc: StartNewP2pListener, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartNewP2pListenerTest001, TestSize.Level1)
{
    int32_t ret = StartNewP2pListener(nullptr, &g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = StartNewP2pListener(g_ip, &g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: NotifyP2pSessionConnClearTest001
 * @tc.desc: NotifyP2pSessionConnClear, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, NotifyP2pSessionConnClearTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    ListNode *sessionConnList = (ListNode*)SoftBusMalloc(sizeof(ListNode));
    ASSERT_NE(sessionConnList, nullptr);

    NotifyP2pSessionConnClear(NULL);

    ClearP2pSessionConn();
    int32_t ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    ret = TransTdcAddSessionConn(conn);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ClearP2pSessionConn();
    TransDelSessionConnById(channelId);

    SoftBusFree(sessionConnList);
}

/**
 * @tc.name: StartP2pListenerTest001
 * @tc.desc: StartP2pListener, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartP2pListenerTest001, TestSize.Level1)
{
    StopP2pSessionListener();
    int32_t ret = StartP2pListener(nullptr, &g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = StartP2pListener(g_ip, &g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = StartP2pListener(g_ip, &g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    StopP2pSessionListener();
}

/**
 * @tc.name: OnChannelOpenFailTest001
 * @tc.desc: OnChannelOpenFail, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnChannelOpenFailTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    OnChannelOpenFail(channelId, errCode);
    int32_t ret = AuthInit();
    ASSERT_EQ(ret, SOFTBUS_AUTH_INIT_FAIL);

    AuthDeinit();
}

/**
 * @tc.name: VerifyP2pTest001
 * @tc.desc: VerifyP2p, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, VerifyP2pTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = 1;
    int32_t ret = VerifyP2p(authId, nullptr, 0, seq);
    ASSERT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    ret = VerifyP2p(authId, g_ip, g_port, seq);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: OnAuthConnOpenedTest001
 * @tc.desc: OnAuthConnOpened, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthConnOpenedTest001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int64_t authId = 1;
    int32_t channelId = 1;
    OnAuthConnOpened(requestId, authId);

    int32_t ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    ret = TransTdcAddSessionConn(conn);
    ASSERT_EQ(ret, SOFTBUS_OK);

    OnAuthConnOpened(requestId, authId);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnAuthConnOpenFailedTest001
 * @tc.desc: OnAuthConnOpenFailed, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthConnOpenFailedTest001, TestSize.Level1)
{
    uint32_t requestId = 1;
        int32_t channelId = 1;
    int32_t reason = SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    OnAuthConnOpenFailed(requestId, reason);

    int32_t ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    ret = TransTdcAddSessionConn(conn);
    ASSERT_EQ(ret, SOFTBUS_OK);

    OnAuthConnOpenFailed(requestId, reason);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OpenAuthConnTest001
 * @tc.desc: OpenAuthConn, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OpenAuthConnTest001, TestSize.Level1)
{
    int32_t reqId = 1;
    int32_t ret = OpenAuthConn(nullptr, reqId, true);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = OpenAuthConn(nullptr, reqId, false);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = OpenAuthConn(g_udid, reqId, true);
    EXPECT_EQ(ret, SOFTBUS_ERR);

}

/**
 * @tc.name: OnVerifyP2pRequestTest001
 * @tc.desc: OnVerifyP2pRequest, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pRequestTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = 1;
    int32_t code = CODE_VERIFY_P2P;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "OnVerifyP2pRequest unpack fail";
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);
    SendVerifyP2pFailRsp(authId, seq, code, errCode, nullptr);

    SendVerifyP2pFailRsp(authId, seq, code, errCode, errDesc);
    int32_t ret = OnVerifyP2pRequest(authId, seq, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OnVerifyP2pRequest(authId, seq, json);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    OnAuthChannelClose(authId);
}

/**
 * @tc.name: ConnectTcpDirectPeerTest004
 * @tc.desc: ConnectTcpDirectPeer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ConnectTcpDirectPeerTest001, TestSize.Level1)
{
    int32_t ret = ConnectTcpDirectPeer(nullptr, g_port);
    EXPECT_EQ(ret, INVALID_VALUE);

    ret = ConnectTcpDirectPeer(g_addr, g_port);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: OnVerifyP2pReplyTest001
 * @tc.desc: OnVerifyP2pReply, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pReplyTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = 1;
    int32_t channelId = 1;
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);

    int32_t ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    ret = TransTdcAddSessionConn(conn);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = OnVerifyP2pReply(authId, seq, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    seq = INVALID_VALUE;
    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnAuthDataRecvTest001
 * @tc.desc: OnAuthDataRecv, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecvTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = 1;
    int32_t flags = MSG_FLAG_REQUEST;
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    int32_t ret = OnVerifyP2pRequest(authId, seq, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    OnAuthMsgProc(authId, flags, seq, nullptr);

    flags = MES_FLAG_REPLY;
    OnAuthMsgProc(authId, flags, seq, nullptr);

    OnAuthDataRecv(authId, nullptr);
    OnAuthDataRecv(authId, data);

    SoftBusFree(data);
}
}