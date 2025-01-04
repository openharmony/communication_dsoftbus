/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_sessionconn.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_CHANNEL_ID 1027
#define EOK 0
#define INVALID_VALUE (-1)
#define AUTH_TRANS_DATA_LEN 32
#define PKG_NAME_SIZE_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 65
#define MY_IP "192.168.2.1"
#define HML_ADDR "172.30.2.1"
#define NOAMAL_SEQ 123
#define NORMAL_FD 151
#define MY_PORT 6000

static const char *g_addr = "192.168.8.119";
static const char *g_ip = "192.168.8.1";
static const char *g_localIp = "127.0.0.1";
static int32_t g_port = 6000;
static const char *g_sessionName = "com.test.trans.auth.demo";
static const char *g_pkgName = "dms";
static const char *g_udid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *g_uuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static IServerChannelCallBack g_testChannelCallBack;
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
    int32_t ret = InitBaseListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    conn->authHandle.authId = 1;
    conn->requestId = 1;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.routeType = WIFI_P2P;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName) + 1));
    (void)memcpy_s(conn->appInfo.myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName) + 1));
    return conn;
}

static int32_t TestTransServerOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    TRANS_LOGE(TRANS_QOS, "TransServerOnChannelOpened");
    return SOFTBUS_OK;
}

static int32_t TestTransServerOnChannelClosed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t messageType)
{
    TRANS_LOGE(TRANS_QOS, "TransServerOnChannelClosed");
    return SOFTBUS_OK;
}

static int32_t TestTransServerOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    TRANS_LOGE(TRANS_QOS, "TransServerOnChannelOpenFailed");
    return SOFTBUS_OK;
}

static int32_t TestTransServerOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData *receiveData)
{
    TRANS_LOGE(TRANS_QOS, "TransServerOnChannelOpenFailed");
    return SOFTBUS_OK;
}

static int32_t TestTransServerOnQosEvent(const char *pkgName, const QosParam *param)
{
    TRANS_LOGE(TRANS_QOS, "TransServerOnChannelOpenFailed");
    return SOFTBUS_OK;
}

static int32_t TestTransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    TRANS_LOGE(TRANS_QOS, "TransGetPkgNameBySessionName");
    return SOFTBUS_OK;
}

static int32_t TestTransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    TRANS_LOGE(TRANS_QOS, "TransGetUidAndPid");
    return SOFTBUS_OK;
}

IServerChannelCallBack *TestTransServerGetChannelCb(void)
{
    g_testChannelCallBack.OnChannelOpened = TestTransServerOnChannelOpened;
    g_testChannelCallBack.OnChannelClosed = TestTransServerOnChannelClosed;
    g_testChannelCallBack.OnChannelOpenFailed = TestTransServerOnChannelOpenFailed;
    g_testChannelCallBack.OnDataReceived = TestTransServerOnMsgReceived;
    g_testChannelCallBack.OnQosEvent = TestTransServerOnQosEvent;
    g_testChannelCallBack.GetPkgNameBySessionName = TestTransGetPkgNameBySessionName;
    g_testChannelCallBack.GetUidAndPidBySessionName = TestTransGetUidAndPid;
    return &g_testChannelCallBack;
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
    appInfo->peerData.port = g_port;
    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName) + 1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName) + 1));
    (void)memcpy_s(appInfo->myData.addr, IP_LEN, g_addr, (strlen(g_addr) + 1));
    if (TransAuthChannelMsgPack(msg, appInfo) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        SoftBusFree(appInfo);
        return nullptr;
    }
    string data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
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
    CreateP2pListenerList();
    int32_t ret = StartNewP2pListener(nullptr, &g_port);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);

    ret = StartNewP2pListener(g_ip, &g_port);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ret = StartNewP2pListener(g_localIp, &g_port);
    EXPECT_EQ(ret, SOFTBUS_OK);
    StopP2pSessionListener();
}

/**
 * @tc.name: NotifyP2pSessionConnClearTest001
 * @tc.desc: NotifyP2pSessionConnClear, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, NotifyP2pSessionConnClearTest001, TestSize.Level1)
{
    IServerChannelCallBack *testCallBack = TestTransServerGetChannelCb();
    ASSERT_NE(testCallBack, nullptr);
    int32_t ret = TransTdcSetCallBack(testCallBack);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 1;
    // will free in ClearP2pSessionConn
    ListNode *sessionConnList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    ASSERT_NE(sessionConnList, nullptr);
    NotifyP2pSessionConnClear(NULL);
    ClearP2pSessionConn();
    ListNode *testsessionConnList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    ASSERT_NE(testsessionConnList, nullptr);
    ret = CreatSessionConnList();
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    ret = TransTdcAddSessionConn(conn);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ClearP2pSessionConn();
    TransDelSessionConnById(channelId);

    SoftBusFree(sessionConnList);
    SoftBusFree(testsessionConnList);
}

/**
 * @tc.name: P2pDirectChannelInitTest001
 * @tc.desc: P2pDirectChannelInit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, P2pDirectChannelInitTest001, TestSize.Level1)
{
    CheckAndAddPeerDeviceInfo(g_uuid);
    int32_t ret = CreateP2pListenerList();
    CheckAndAddPeerDeviceInfo(g_uuid);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    int32_t ret = StartP2pListener(nullptr, &g_port, g_uuid);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = StartP2pListener(g_ip, &g_port, g_uuid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ret = StartP2pListener(g_ip, &g_port, g_uuid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ret = StartP2pListener(g_localIp, &g_port, g_uuid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    OnChannelOpenFail(channelId, errCode);

    StopP2pSessionListener();
}

/**
 * @tc.name: VerifyP2pTest001
 * @tc.desc: VerifyP2p, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, VerifyP2pTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    int32_t ret = VerifyP2p(authHandle, nullptr, nullptr, 0, seq);
    ASSERT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    int32_t port = MY_PORT;
    ret = VerifyP2p(authHandle, g_ip, nullptr, port, seq);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
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
    ConnectType type = CONNECT_TCP;

    int32_t ret = OpenAuthConn(nullptr, reqId, true, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    ret = OpenAuthConn(nullptr, reqId, false, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    ret = OpenAuthConn(g_udid, reqId, true, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
}

/**
 * @tc.name: OnVerifyP2pRequestTest001
 * @tc.desc: OnVerifyP2pRequest, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pRequestTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    int32_t code = CODE_VERIFY_P2P;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "OnVerifyP2pRequest unpack fail";
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);
    SendVerifyP2pFailRsp(authHandle, seq, code, errCode, nullptr, true);

    SendVerifyP2pFailRsp(authHandle, seq, code, errCode, errDesc, true);
    int32_t ret = OnVerifyP2pRequest(authHandle, seq, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OnVerifyP2pRequest(authHandle, seq, json, true);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    OnAuthChannelClose(authHandle);
}

/**
 * @tc.name: ConnectTcpDirectPeerTest004
 * @tc.desc: ConnectTcpDirectPeer, use the wrong parameter.sss
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ConnectTcpDirectPeerTest001, TestSize.Level1)
{
    int32_t ret = ConnectTcpDirectPeer(g_addr, g_port, g_ip);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: OnAuthDataRecvTest001
 * @tc.desc: OnAuthDataRecv, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecvTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    int32_t flags = MSG_FLAG_REQUEST;
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    int32_t ret = OnVerifyP2pRequest(authHandle, seq, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    OnAuthMsgProc(authHandle, flags, seq, nullptr);

    flags = MES_FLAG_REPLY;
    OnAuthMsgProc(authHandle, flags, seq, nullptr);

    OnAuthDataRecv(authHandle, nullptr);
    OnAuthDataRecv(authHandle, data);

    SoftBusFree(data);
}

/**
 * @tc.name: OpenAuthConntest002
 * @tc.desc: OpenAuthConntest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OpenAuthConntest002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return ;
    }
    int32_t ret;
    int32_t reason = 1;
    uint32_t requestId = 1;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    bool isMeta = 1;
    ConnectType type = CONNECT_TCP;

    (void)memcpy_s(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, "test", DEVICE_ID_SIZE_MAX);
    OnAuthConnOpenFailed(requestId, reason);
    OnAuthConnOpened(requestId, authHandle);
    ret = OpenAuthConn(appInfo->peerData.deviceId, requestId, isMeta, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/**
 * @tc.name: SendVerifyP2pRsp003
 * @tc.desc: SendVerifyP2pRsp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, SendVerifyP2pRsp003, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret;
    int32_t errCode = SOFTBUS_NO_INIT;
    int64_t seq = 1;
    bool isAuthLink = true;
    bool notAuthLink = false;
    SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, errCode, "pack reply failed", isAuthLink);
    SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, errCode, "pack reply failed", notAuthLink);

    ret = SendVerifyP2pRsp(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, "pack reply failed", isAuthLink);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = SendVerifyP2pRsp(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, "pack reply failed", notAuthLink);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID);
}

/**
 * @tc.name: OpenNewAuthConn004
 * @tc.desc: OpenNewAuthConn.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OpenNewAuthConn004, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return ;
    }
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        SoftBusFree(appInfo);
        appInfo = nullptr;
        return ;
    }
    int32_t ret;
    int32_t newChannelId = 1;
    ConnectType type = CONNECT_P2P;

    (void)memcpy_s(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, "test", DEVICE_ID_SIZE_MAX);
    ret = OpenNewAuthConn(appInfo, conn, newChannelId, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
    SoftBusFree(conn);
    conn = nullptr;
}

/**
 * @tc.name: StartVerifyP2pInfo005
 * @tc.desc: StartVerifyP2pInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartVerifyP2pInfo005, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return ;
    }
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        SoftBusFree(appInfo);
        appInfo = nullptr;
        return ;
    }
    int32_t ret;
    ConnectType type = CONNECT_P2P;

    conn->authHandle.authId = AUTH_INVALID_ID;
    ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    conn->authHandle.authId = 1;
    ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    SoftBusFree(appInfo);
    appInfo = nullptr;
    SoftBusFree(conn);
    conn = nullptr;
}

/**
 * @tc.name: StartNewHmlListenerTest001
 * @tc.desc: StartNewHmlListener, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartNewHmlListenerTest001, TestSize.Level1)
{
    ListenerModule moduleType = UNUSE_BUTT;
    int32_t ret = StartNewHmlListener(nullptr, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);

    ret = StartNewHmlListener(g_ip, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ret = StartNewHmlListener(g_localIp, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/**
 * @tc.name: StartHmlListenerTest001
 * @tc.desc: StartHmlListener, ListenerList not init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest001, TestSize.Level1)
{
    int32_t ret = StartHmlListener(g_ip, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: StartHmlListenerTest002
 * @tc.desc: StartHmlListener, ListenerList is init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest002, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_ip, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ListenerModule moduleType = GetModuleByHmlIp(g_ip);
    EXPECT_EQ(moduleType, UNUSE_BUTT);

    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        DelHmlListenerByMoudle((ListenerModule)i);
    }
}

/**
 * @tc.name: StartHmlListenerTest003
 * @tc.desc: StartHmlListener, ListenerList is init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest003, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_ip, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/**
 * @tc.name: StartHmlListenerTest004
 * @tc.desc: StartHmlListener, try listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest004, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_localIp, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_localIp, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/**
 * @tc.name: StartVerifyP2pInfoTest001
 * @tc.desc: StartVerifyP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartVerifyP2pInfoTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_NE(appInfo, NULL);

    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == NULL) {
        SoftBusFree(appInfo);
        appInfo = nullptr;
    }
    EXPECT_NE(conn, NULL);
    ConnectType type = CONNECT_P2P;

    int32_t ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    SoftBusFree(appInfo);
    appInfo = nullptr;
    SoftBusFree(conn);
    conn = nullptr;
}

/**
 * @tc.name: OnP2pVerifyChannelClosedTest001
 * @tc.desc: OnP2pVerifyChannelClosed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnP2pVerifyChannelClosedTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    OnP2pVerifyChannelClosed(channelId);
    EXPECT_TRUE(1);
}

/**
 * @tc.name: AddP2pOrHmlTriggerTest001
 * @tc.desc: AddP2pOrHmlTrigger, use hml addr, not found hml ip.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, AddP2pOrHmlTriggerTest001, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t fd = NORMAL_FD;
    const char *myAddr = HML_ADDR;
    int32_t seq = NOAMAL_SEQ;
    ret = AddP2pOrHmlTrigger(fd, myAddr, seq);
    EXPECT_EQ(SOFTBUS_TRANS_ADD_HML_TRIGGER_FAILED, ret);
}

/**
 * @tc.name: AddP2pOrHmlTriggerTest002
 * @tc.desc: AddP2pOrHmlTrigger, not use hml addr, enter AddTrigger return fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, AddP2pOrHmlTriggerTest002, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t fd = NORMAL_FD;
    const char *myAddr = MY_IP;
    int32_t seq = NOAMAL_SEQ;
    ret = AddP2pOrHmlTrigger(fd, myAddr, seq);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/**
 * @tc.name: TransProxyGetAuthIdByUuidTest001
 * @tc.desc: TransProxyGetAuthIdByUuid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, TransProxyGetAuthIdByUuidTest001, TestSize.Level1)
{
    SessionConn *conn = reinterpret_cast<SessionConn *>(SoftBusCalloc(sizeof(SessionConn)));
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransProxyGetAuthIdByUuid(conn);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);
    SoftBusFree(conn);
}

/**
 * @tc.name: StopP2pListenerByRemoteUuidTest001
 * @tc.desc: StopP2pListenerByRemoteUuid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StopP2pListenerByRemoteUuidTest001, TestSize.Level1)
{
    StopP2pListenerByRemoteUuid(nullptr);
    StopP2pListenerByRemoteUuid(g_uuid);
    int32_t ret = CreateP2pListenerList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    StopP2pListenerByRemoteUuid(g_uuid);
    CheckAndAddPeerDeviceInfo(g_uuid);
    StopP2pListenerByRemoteUuid(g_uuid);
}

/**
 * @tc.name: ClearHmlListenerByUuidTest001
 * @tc.desc: ClearHmlListenerByUuid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ClearHmlListenerByUuidTest001, TestSize.Level1)
{
    ClearHmlListenerByUuid(nullptr);
    ClearHmlListenerByUuid(g_uuid);
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartHmlListener(g_ip, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);
    ClearHmlListenerByUuid(g_uuid);
    ret = StartHmlListener(g_localIp, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClearHmlListenerByUuid(g_uuid);
    AnonymizeIp(g_ip, (char *)g_ip, g_port);
    OutputAnonymizeIpAddress(g_ip, g_ip);
}

/**
 * @tc.name: OnAuthConnOpenedTest001
 * @tc.desc: OnAuthConnOpened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthConnOpenedTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    conn->requestId = requestId;
    conn->channelId = channelId;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_MAX };
    OnAuthConnOpened(requestId, authHandle);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnAuthConnOpenedTest002
 * @tc.desc: OnAuthConnOpened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthConnOpenedTest002, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    conn->requestId = requestId;
    conn->channelId = channelId;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_BR };
    // fail auto free conn
    OnAuthConnOpened(requestId, authHandle);
}

/**
 * @tc.name: OnAuthConnOpenFailedTest001
 * @tc.desc: OnAuthConnOpenFailed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthConnOpenFailedTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    conn->requestId = requestId;
    conn->channelId = channelId;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    // fail auto free conn
    OnAuthConnOpenFailed(requestId, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
}

/**
 * @tc.name: PackAndSendVerifyP2pRspTest001
 * @tc.desc: PackAndSendVerifyP2pRsp.ip is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, PackAndSendVerifyP2pRspTest001, TestSize.Level1)
{
    int32_t seq = 0;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_MAX };
    int32_t ret = PackAndSendVerifyP2pRsp(nullptr, g_port, seq, true, authHandle);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
 * @tc.name: PackAndSendVerifyP2pRspTest002
 * @tc.desc: PackAndSendVerifyP2pRsp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, PackAndSendVerifyP2pRspTest002, TestSize.Level1)
{
    int64_t seq = 0;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_MAX };
    int32_t ret = PackAndSendVerifyP2pRsp(g_ip, g_port, seq, true, authHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackAndSendVerifyP2pRsp(g_ip, g_port, seq, false, authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/**
 * @tc.name: TransGetRemoteUuidByAuthHandleTest001
 * @tc.desc: TransGetRemoteUuidByAuthHandle.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, TransGetRemoteUuidByAuthHandleTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_BLE };
    int32_t ret = TransGetRemoteUuidByAuthHandle(authHandle, (char *)g_uuid);
    EXPECT_NE(SOFTBUS_OK, ret);
    authHandle.type = AUTH_INVALID_ID;
    ret = TransGetRemoteUuidByAuthHandle(authHandle, (char *)g_uuid);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnVerifyP2pRequestTest002
 * @tc.desc: OnVerifyP2pRequest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pRequestTest002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_BLE };
    int64_t seq = 0;
    char *data = VerifyP2pPack(g_ip, g_port, g_ip);
    ASSERT_TRUE(data != nullptr);
    int32_t len = strlen(data);
    cJSON *json = cJSON_ParseWithLength((const char *)(data), len);
    if (json == nullptr) {
        cJSON_free(data);
        ASSERT_TRUE(false);
    }

    int32_t ret = OnVerifyP2pRequest(authHandle, seq, json, true);
    EXPECT_EQ(SOFTBUS_TRANS_GET_P2P_INFO_FAILED, ret);
    cJSON_Delete(json);
    cJSON_free(data);
}

/**
 * @tc.name: OnP2pVerifyMsgReceivedTest001
 * @tc.desc: OnP2pVerifyMsgReceived.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnP2pVerifyMsgReceivedTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    char *data = VerifyP2pPack(g_ip, g_port, g_ip);
    ASSERT_TRUE(data != nullptr);
    int32_t len = strlen(data);
    OnP2pVerifyMsgReceived(channelId, data, len);
    cJSON_free(data);
}

/**
 * @tc.name: AddHmlTriggerTest001
 * @tc.desc: AddHmlTrigger.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, AddHmlTriggerTest001, TestSize.Level1)
{
    int32_t fd = 1;
    int64_t seq = 1;
    int32_t ret = StartHmlListener(g_localIp, &g_port, g_udid);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddHmlTrigger(fd, g_ip, seq);
    EXPECT_NE(SOFTBUS_OK, ret);
    ClearHmlListenerByUuid(g_uuid);
}

/**
 * @tc.name: OnVerifyP2pReplyTest001
 * @tc.desc: OnVerifyP2pReply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pReplyTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    int64_t req = 1234;
    conn->requestId = requestId;
    conn->channelId = channelId;
    conn->req = req;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int64_t authId = 1234;
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);
    ret = OnVerifyP2pReply(authId, req, json);
    EXPECT_NE(ret, SOFTBUS_OK);
    cJSON_Delete(json);
    TransDelSessionConnById(channelId);
}
}
