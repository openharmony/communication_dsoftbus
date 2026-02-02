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

#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <securec.h>
#include <unistd.h>

#include "auth_interface.h"
#include "dsoftbus_enhance_interface.h"
#include "g_enhance_lnn_func.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "trans_auth_message.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_common_mock.h"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_sessionconn.h"

using namespace testing;
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
static const char *g_hmlAddr = "172.30.1.2";
static const char *g_ip = "192.168.8.1";
static const char *g_localIp = "127.0.0.1";
static int32_t g_port = 6000;
static const char *g_sessionName = "com.test.trans.auth.demo";
static const char *g_pkgName = "dms";
static const char *g_udid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *g_uuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *g_peerUuid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF01";
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
    if (msg == nullptr) {
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

/*
 * @tc.name: StartNewP2pListenerTest001
 * @tc.desc: test StartNewP2pListener
 *           use the wrong parameter
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

/*
 * @tc.name: NotifyP2pSessionConnClearTest001
 * @tc.desc: test NotifyP2pSessionConnClear
 *           use the wrong parameter
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
    NotifyP2pSessionConnClear(nullptr);
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

/*
 * @tc.name: P2pDirectChannelInitTest001
 * @tc.desc: test P2pDirectChannelInit
 *           use the wrong parameter
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

/*
 * @tc.name: StartP2pListenerTest001
 * @tc.desc: test StartP2pListener
 *           use the wrong parameter
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

/*
 * @tc.name: VerifyP2pTest001
 * @tc.desc: test VerifyP2p
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, VerifyP2pTest001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaPostTransData = AuthMetaPostTransData;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    VerifyP2pInfo info;
    info.myIp = nullptr;
    info.peerIp = nullptr;
    info.myPort = 0;
    info.protocol = LNN_PROTOCOL_IP;
    int32_t ret = VerifyP2p(authHandle, seq, &info);
    ASSERT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillOnce(Return(SOFTBUS_LOCK_ERR));
    int32_t port = MY_PORT;
    info.myIp = g_ip;
    info.myPort = port;
    ret = VerifyP2p(authHandle, seq, &info);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: OpenAuthConnTest001
 * @tc.desc: test OpenAuthConn
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OpenAuthConnTest001, TestSize.Level1)
{
    int32_t reqId = 1;
    ConnectType type = CONNECT_TCP;
    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = OpenAuthConn(nullptr, reqId, true, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    ret = OpenAuthConn(nullptr, reqId, false, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    ret = OpenAuthConn(g_udid, reqId, true, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
}

/*
 * @tc.name: OnVerifyP2pRequestTest001
 * @tc.desc: test OnVerifyP2pRequest
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pRequestTest001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaPostTransData = AuthMetaPostTransData;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = 1;
    int32_t code = CODE_VERIFY_P2P;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "OnVerifyP2pRequest unpack fail";
    string msg = TestGetMsgPack();
    cJSON *json = cJSON_Parse(msg.c_str());
    EXPECT_TRUE(json != nullptr);
    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillRepeatedly(Return(SOFTBUS_OK));
    SendVerifyP2pFailRsp(authHandle, seq, code, errCode, nullptr, true);

    SendVerifyP2pFailRsp(authHandle, seq, code, errCode, errDesc, true);
    int32_t ret = OnVerifyP2pRequest(authHandle, seq, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OnVerifyP2pRequest(authHandle, seq, json, true);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    OnAuthChannelClose(authHandle);
}

/*
 * @tc.name: ConnectSocketDirectPeerTest004
 * @tc.desc: test ConnectSocketDirectPeer
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ConnectSocketDirectPeerTest001, TestSize.Level1)
{
    int32_t ret = ConnectSocketDirectPeer(g_addr, g_port, g_ip, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnAuthDataRecvTest001
 * @tc.desc: test OnAuthDataRecv
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecvTest001, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaPostTransData = AuthMetaPostTransData;
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
    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = OnVerifyP2pRequest(authHandle, seq, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    OnAuthMsgProc(authHandle, flags, seq, nullptr);

    flags = MES_FLAG_REPLY;
    OnAuthMsgProc(authHandle, flags, seq, nullptr);

    OnAuthDataRecv(authHandle, nullptr);
    OnAuthDataRecv(authHandle, data);

    SoftBusFree(data);
}

/*
 * @tc.name: OpenAuthConntest002
 * @tc.desc: Testing the scenario where authentication connection fails
 *           during direct P2P communication over TCP
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

/*
 * @tc.name: SendVerifyP2pRsp003
 * @tc.desc: Test the function of sending and verifying P2P responses in direct TCP P2P communication
 *           including handing both successful and failed scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, SendVerifyP2pRsp003, TestSize.Level1)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaPostTransData = AuthMetaPostTransData;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret;
    int32_t errCode = SOFTBUS_NO_INIT;
    int64_t seq = 1;
    bool isAuthLink = true;
    bool notAuthLink = false;
    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillOnce(Return(SOFTBUS_OK));
    SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, errCode, "pack reply failed", isAuthLink);
    SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, errCode, "pack reply failed", notAuthLink);

    EXPECT_CALL(TransTcpDirectP2pMock, AuthMetaPostTransData).WillOnce(Return(SOFTBUS_LOCK_ERR));
    ret = SendVerifyP2pRsp(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, "pack reply failed", isAuthLink);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, errCode, "pack reply failed", notAuthLink);
    ret = SendVerifyP2pRsp(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, "pack reply failed", notAuthLink);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID);
}

/*
 * @tc.name: OpenNewAuthConn004
 * @tc.desc: Test whether opening a new authenticated connection fails
 *           under specific conditions
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
    ConnectType type = CONNECT_P2P;

    ret = OpenNewAuthConn(appInfo, nullptr, type);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    (void)memcpy_s(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, "test", DEVICE_ID_SIZE_MAX);
    ret = OpenNewAuthConn(appInfo, conn, type);
    EXPECT_EQ(ret, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
    SoftBusFree(conn);
    conn = nullptr;
}

/*
 * @tc.name: StartVerifyP2pInfo005
 * @tc.desc: Test whether the return value of the StartVerifyP2pInfo function meets expectations
 *           under different authId conditions
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

/*
 * @tc.name: StartNewHmlListenerTest001
 * @tc.desc: test StartNewHmlListener
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartNewHmlListenerTest001, TestSize.Level1)
{
    ListenerModule moduleType = UNUSE_BUTT;
    int32_t ret = StartNewHmlListener(nullptr, LNN_PROTOCOL_IP, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);

    ret = StartNewHmlListener(g_ip, LNN_PROTOCOL_IP, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ret = StartNewHmlListener(g_localIp, LNN_PROTOCOL_IP, &g_port, &moduleType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/*
 * @tc.name: StartHmlListenerTest001
 * @tc.desc: test StartHmlListener
 *           ListenerList not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest001, TestSize.Level1)
{
    int32_t ret = StartHmlListener(g_ip, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: StartHmlListenerTest002
 * @tc.desc: test StartHmlListener
             ListenerList is init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest002, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_ip, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);

    ListenerModule moduleType = GetModuleByHmlIp(g_ip);
    EXPECT_EQ(moduleType, UNUSE_BUTT);

    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        DelHmlListenerByMoudle((ListenerModule)i);
    }
}

/*
 * @tc.name: StartHmlListenerTest003
 * @tc.desc: test StartHmlListener
 *           ListenerList is init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest003, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_ip, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/*
 * @tc.name: StartHmlListenerTest004
 * @tc.desc: test StartHmlListener
 *           try listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartHmlListenerTest004, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_localIp, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartHmlListener(g_localIp, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        StopHmlListener((ListenerModule)i);
    }
}

/*
 * @tc.name: StartVerifyP2pInfoTest001
 * @tc.desc: Test the behavior of the StartVerifyP2pInfo function under specific conditions
 *           particularly when the input connection type is CONNECT_P2P to verify whether it returns
 *           the expected error code SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, StartVerifyP2pInfoTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_NE(appInfo, nullptr);

    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        SoftBusFree(appInfo);
        appInfo = nullptr;
    }
    EXPECT_NE(conn, nullptr);
    ConnectType type = CONNECT_P2P;

    int32_t ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    SoftBusFree(appInfo);
    appInfo = nullptr;
    SoftBusFree(conn);
    conn = nullptr;
}

/*
 * @tc.name: OnP2pVerifyChannelClosedTest001
 * @tc.desc: Test the function of verifying channel closure
 *           in direct TCP P2P communication
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnP2pVerifyChannelClosedTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    OnP2pVerifyChannelClosed(channelId);
    EXPECT_TRUE(1);
}

/*
 * @tc.name: AddP2pOrHmlTriggerTest001
 * @tc.desc: test AddP2pOrHmlTrigger
 *           use hml addr, not found hml ip
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
    ret = AddP2pOrHmlTrigger(fd, myAddr, seq, 0, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_ADD_HML_TRIGGER_FAILED, ret);
}

/*
 * @tc.name: AddP2pOrHmlTriggerTest002
 * @tc.desc: test AddP2pOrHmlTrigger
 *           not use hml addr, enter AddTrigger return fail
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
    ret = AddP2pOrHmlTrigger(fd, myAddr, seq, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/*
 * @tc.name: TransProxyGetAuthIdByUuidTest001
 * @tc.desc: test TransProxyGetAuthIdByUuid
 *           Test whether the function of obtaining the authentication ID via UUID fails
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

/*
 * @tc.name: StopP2pListenerByRemoteUuidTest001
 * @tc.desc: Test the functionality of stopping the P2P listener
 *           particularly stopping the listener via a remote UUID
 *           and verify the correctness of the related operations
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

/*
 * @tc.name: ClearHmlListenerByUuidTest001
 * @tc.desc: Test the functionality of clearing UUID-based HML listeners and verify the behavior of starting
 *           HML listeners under different scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ClearHmlListenerByUuidTest001, TestSize.Level1)
{
    ClearHmlListenerByUuid(nullptr);
    ClearHmlListenerByUuid(g_uuid);
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartHmlListener(g_ip, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED);
    ClearHmlListenerByUuid(g_uuid);
    ret = StartHmlListener(g_localIp, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClearHmlListenerByUuid(g_uuid);
    AnonymizeIp(g_ip, (char *)g_ip, g_port);
    OutputAnonymizeIpAddress(g_ip, g_ip);
}

/*
 * @tc.name: OnAuthConnOpenedTest001
 * @tc.desc: Testing the scenario of authenticating connection establishment
 *           in direct TCP P2P connections
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

/*
 * @tc.name: OnAuthConnOpenedTest002
 * @tc.desc: Test the behavior of the OnAuthConnOpened function under specific conditions
 *           particularly when the input requestId and authHandle parameters are provided
 *           to verify whether it can correctly handle and release resources
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

/*
 * @tc.name: OnAuthConnOpenFailedTest001
 * @tc.desc: Test the handling logic in TCP direct P2P communication
 *           when the authentication connection fails to open
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

/*
 * @tc.name: PackAndSendVerifyP2pRspTest001
 * @tc.desc: test PackAndSendVerifyP2pRsp
 *           ip is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, PackAndSendVerifyP2pRspTest001, TestSize.Level1)
{
    int32_t seq = 0;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_MAX };
    VerifyP2pInfo info;
    info.myIp = nullptr;
    info.myPort = g_port;
    info.protocol = LNN_PROTOCOL_IP;
    int32_t ret = PackAndSendVerifyP2pRsp(&info, seq, true, authHandle);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/*
 * @tc.name: PackAndSendVerifyP2pRspTest002
 * @tc.desc: Test whether the return value of the PackAndSendVerifyP2pRsp function meets
 *           expectations under different parameter conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, PackAndSendVerifyP2pRspTest002, TestSize.Level1)
{
    int64_t seq = 0;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_MAX };
    VerifyP2pInfo info;
    info.myIp = g_ip;
    info.myPort = g_port;
    info.protocol = LNN_PROTOCOL_IP;
    int32_t ret = PackAndSendVerifyP2pRsp(&info, seq, true, authHandle);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackAndSendVerifyP2pRsp(&info, seq, false, authHandle);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/*
 * @tc.name: TransGetRemoteUuidByAuthHandleTest001
 * @tc.desc: Test whether the function of obtaining the UUID of a remote device through
 *           the authentication handle works properly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, TransGetRemoteUuidByAuthHandleTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_BLE };
    NiceMock<TransTcpDirectCommonInterfaceMock> TransTcpDirectP2pMock;
    EXPECT_CALL(TransTcpDirectP2pMock, AuthGetDeviceUuid).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransGetRemoteUuidByAuthHandle(authHandle, (char *)g_uuid);
    EXPECT_EQ(SOFTBUS_OK, ret);
    authHandle.type = AUTH_INVALID_ID;
    ret = TransGetRemoteUuidByAuthHandle(authHandle, (char *)g_uuid);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddHmlTriggerTest001
 * @tc.desc: Test whether the function of adding HML triggers
 *           under specific conditions meets expectations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, AddHmlTriggerTest001, TestSize.Level1)
{
    int32_t fd = 1;
    int64_t seq = 1;
    int32_t ret = StartHmlListener(g_localIp, &g_port, g_udid, LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddHmlTrigger(fd, g_ip, seq, 0, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
    ClearHmlListenerByUuid(g_uuid);
}

/*
 * @tc.name: OnVerifyP2pReplyTest001
 * @tc.desc: Test whether the OnVerifyP2pReply function behaves as expected
 *           under specific conditions
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

/**
 * @tc.name: OnVerifyP2pReplyTest002
 * @tc.desc: OnVerifyP2pReply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pReplyTest002, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    int64_t req = 1234;
    conn->requestId = requestId;
    conn->channelId = channelId;
    conn->req = req;
    conn->appInfo.businessType = BUSINESS_TYPE_BYTE;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int64_t authId = 1234;
    char myIp[] = "192.168.8.1";
    char peerIp[] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF01";
    VerifyP2pInfo info = {
        .myIp = myIp,
        .peerIp = peerIp,
        .myPort = g_port,
        .myUid = 0,
        .protocol = LNN_PROTOCOL_MINTP,
        .isMinTp = true,
    };
    char* pack = VerifyP2pPack(&info);
    EXPECT_TRUE(pack != nullptr);
    cJSON *json = cJSON_Parse(pack);
    EXPECT_TRUE(json != nullptr);
    ret = OnVerifyP2pReply(authId, req, json);
    EXPECT_NE(ret, SOFTBUS_OK);
    cJSON_Delete(json);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: OnVerifyP2pReplyTest003
 * @tc.desc: OnVerifyP2pReply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnVerifyP2pReplyTest003, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    uint32_t requestId = 12;
    int32_t channelId = 123;
    int64_t req = 1234;
    conn->requestId = requestId;
    conn->channelId = channelId;
    conn->req = req;
    conn->appInfo.businessType = BUSINESS_TYPE_BYTE;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int64_t authId = 1234;
    char myIp[] = "192.168.8.1";
    char peerIp[] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF01";
    VerifyP2pInfo info = {
        .myIp = myIp,
        .peerIp = peerIp,
        .myPort = g_port,
        .myUid = 0,
        .protocol = LNN_PROTOCOL_MINTP,
        .isMinTp = false,
    };
    char* pack = VerifyP2pPack(&info);
    EXPECT_TRUE(pack != nullptr);
    cJSON *json = cJSON_Parse(pack);
    EXPECT_TRUE(json != nullptr);
    ret = OnVerifyP2pReply(authId, req, json);
    EXPECT_NE(ret, SOFTBUS_OK);
    cJSON_Delete(json);
    TransDelSessionConnById(channelId);
}

/*
 * @tc.name: GetModuleByHmlIp001
 * @tc.desc: Test whether the IP address acquisition module functions
 *           properly and verify that the processes of creating starting and
 *           stopping related listeners work as expected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, GetModuleByHmlIp001, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartHmlListener(g_ip, &g_port, g_peerUuid, LNN_PROTOCOL_IP);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED, ret);
    ret = GetModuleByHmlIp(g_ip);
    EXPECT_EQ(UNUSE_BUTT, ret);
    StopHmlListener(DIRECT_CHANNEL_SERVER_HML_START);
}

/*
 * @tc.name: ConnectSocketDirectPeerTest002
 * @tc.desc: Test whether the ConnectSocketDirectPeer interface in the direct TCP P2P connection function
 *           can correctly process parameters and return the expectd results
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ConnectSocketDirectPeerTest002, TestSize.Level1)
{
    int32_t ret = ConnectSocketDirectPeer(g_hmlAddr, g_port, g_localIp, 0);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: OnAuthDataRecv001
 * @tc.desc: Test the behavior of the OnAuthDataRecv function
 *           when receiving specific authentication data
 *           particularly the handling logic when the data length is a negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = -1;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: OnAuthDataRecv002
 * @tc.desc: Test the processing logic for receiving authentication response data from the P2P module
 *           under the WiFi authentication link type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: OnAuthDataRecv003
 * @tc.desc: Test the behavior of the OnAuthDataRecv function under specific conditions
 *           particularly the handling logic when the type of authHandle is AUTH_LINK_TYPE_WIFI -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv003, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI -1 };
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: OnAuthDataRecv004
 * @tc.desc: Test the behavior of the OnAuthDataRecv function
 *           under specific conditions to verify its ability to process authentication data
 *           for the P2P link module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv004, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_MAX };
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: OnAuthDataRecv005
 * @tc.desc: Test the behavior of the OnAuthDataRecv function
 *           under specific conditions to verify its ability to process authentication data
 *           for the P2P listening module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv005, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_MAX };
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LISTEN;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: OnAuthDataRecv006
 * @tc.desc: Test the behavior of the OnAuthDataRecv function
 *           under specific conditions to verify whether its logic for processing
 *           authentication data is correct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, OnAuthDataRecv006, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_MAX };
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_SESSION_KEY_AUTH;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = (const uint8_t *)str;
    data->len = AUTH_TRANS_DATA_LEN;
    OnAuthDataRecv(authHandle, data);
    SoftBusFree(data);
}

/*
 * @tc.name: TransProxyGetAuthIdByUuid001
 * @tc.desc: Test whether the function of obtaining the authentication ID
 *           using the device UUID has failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, TransProxyGetAuthIdByUuid001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memcpy_s(conn->appInfo.peerData.deviceId, DEVICE_ID_SIZE_MAX, g_peerUuid, DEVICE_ID_SIZE_MAX);
    conn->authHandle.authId = 1;
    int32_t ret = TransProxyGetAuthIdByUuid(conn);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);
    SoftBusFree(conn);
}

/**
 * @tc.name: SetProtocolStartListener
 * @tc.desc: test SetProtocolStartListener001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, SetProtocolStartListener001, TestSize.Level1)
{
    VerifyP2pInfo info = { 0 };
    int32_t seq = 0;
    int32_t ret = SetProtocolStartListener(nullptr, nullptr, seq, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    int32_t myPort = 0;
    info.peerUid = 0;
    info.protocol = LNN_PROTOCOL_HTP;
    info.isMinTp = true;
    ret = SetProtocolStartListener(&info, g_hmlAddr, seq, g_uuid, &myPort);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED, ret);
    ClearHmlListenerByUuid(g_uuid);
}

/**
 * @tc.name: ConnectSocketByProtocol
 * @tc.desc: test ConnectSocketByProtocol001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, ConnectSocketByProtocol001, TestSize.Level1)
{
    VerifyP2pInfo info = { 0 };
    SessionConn *conn = TestSetSessionConn();
    ASSERT_NE(conn, nullptr);

    int32_t ret = ConnectSocketByProtocol(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    conn->appInfo.fdProtocol = LNN_PROTOCOL_HTP;
    info.protocol = LNN_PROTOCOL_IP;
    DegradeToTcpListener(&info, conn);
    ret = ConnectSocketByProtocol(&info, conn);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    conn->appInfo.fdProtocol = LNN_PROTOCOL_DETTP;
    conn->appInfo.isLowLatency = true;
    info.protocol = LNN_PROTOCOL_DETTP;
    conn->appInfo.businessType = BUSINESS_TYPE_BYTE;
    ret = ConnectSocketByProtocol(&info, conn);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    conn->appInfo.fdProtocol = LNN_PROTOCOL_MINTP;
    info.isMinTp = false;
    DegradeToTcpListener(&info, conn);
    ret = ConnectSocketByProtocol(&info, conn);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    conn->appInfo.fdProtocol = LNN_PROTOCOL_IP;
    ret = ConnectSocketByProtocol(&info, conn);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(conn);
}

/**
 * @tc.name: CheckIsSupportMintp001
 * @tc.desc: Test that the function returns true when businessType is BUSINESS_TYPE_BYTE,
 *           conn.appInfo.myData.addr is of IPv4 type and conn.appInfo.osType is OH_OS_TYPE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, CheckIsSupportMintp001, TestSize.Level1)
{
    SessionConn conn = { 0 };

    conn.appInfo.businessType = BUSINESS_TYPE_BYTE;
    ASSERT_TRUE(EOK == memcpy_s(conn.appInfo.myData.addr, IP_LEN, g_hmlAddr, (strlen(g_hmlAddr) + 1)));
    conn.appInfo.osType = OH_OS_TYPE;

    int32_t ret = CheckIsSupportMintp(&conn);
    EXPECT_NE(INVALID_VALUE, ret);
}

/**
 * @tc.name: CheckIsSupportMintp002
 * @tc.desc: Test the behavior of the CheckIsSupportMintp function abnormal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, CheckIsSupportMintp002, TestSize.Level1)
{
    SessionConn conn = { 0 };

    conn.appInfo.businessType = BUSINESS_TYPE_BYTE;
    int32_t ret = CheckIsSupportMintp(&conn);
    EXPECT_EQ(false, ret);

    ASSERT_TRUE(EOK == memcpy_s(conn.appInfo.myData.addr, IP_LEN, g_hmlAddr, (strlen(g_hmlAddr) + 1)));
    conn.appInfo.osType = HO_OS_TYPE;
    ret = CheckIsSupportMintp(&conn);
    EXPECT_EQ(false, ret);

#define DFS_SESSIONNAME "DistributedFileService/mnt/hmdfs/100/account"
    ASSERT_TRUE(EOK ==
        memcpy_s(
            conn.appInfo.myData.sessionName, SESSION_NAME_MAX_LEN, DFS_SESSIONNAME, (strlen(DFS_SESSIONNAME) + 1)));
    ret = CheckIsSupportMintp(&conn);
    EXPECT_EQ(false, ret);

    conn.appInfo.businessType = BUSINESS_TYPE_BUTT;
    ret = CheckIsSupportMintp(&conn);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: UpdateHmlModule001
 * @tc.desc: Test the function UpdateHmlModule abnormal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, UpdateHmlModule001, TestSize.Level1)
{
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartHmlListener(g_ip, &g_port, g_peerUuid, LNN_PROTOCOL_IP);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED, ret);
    ListenerModule moduleType = UNUSE_BUTT;
    UpdateHmlModule(g_ip, g_peerUuid, &moduleType);
    EXPECT_EQ(UNUSE_BUTT, moduleType);
    UpdateHmlModule(g_ip, g_peerUuid, nullptr);
    EXPECT_EQ(UNUSE_BUTT, moduleType);
    UpdateHmlModule(g_ip, nullptr, &moduleType);
    EXPECT_EQ(UNUSE_BUTT, moduleType);
    UpdateHmlModule(nullptr, g_peerUuid, &moduleType);
    EXPECT_EQ(UNUSE_BUTT, moduleType);
    StopHmlListener(DIRECT_CHANNEL_SERVER_HML_START);
}

/**
 * @tc.name: CheckNeedStopMintp001
 * @tc.desc: Test the function CheckNeedStopMintp abnormal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pTest, CheckNeedStopMintp001, TestSize.Level1)
{
    SessionConn conn = { 0 };
    int32_t ret = CheckNeedStopMintp(&conn);
    EXPECT_FALSE(ret);
    ret = CheckNeedStopMintp(nullptr);
    EXPECT_FALSE(ret);
}
}