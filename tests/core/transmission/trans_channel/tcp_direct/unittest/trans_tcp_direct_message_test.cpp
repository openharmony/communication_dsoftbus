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
#include "lnn_decision_db.h"
#include "message_handler.h"
#include "softbus_feature_config.h"
#include "softbus_proxychannel_pipeline.h"
#include "trans_auth_message.h"
#include "trans_channel_callback.h"
#include "trans_channel_manager.c"
#include "trans_lane_pending_ctl.h"
#include "trans_session_service.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_test.h"
#include "trans_tcp_direct_wifi.h"

using namespace testing::ext;

namespace OHOS {

#define PID 2024
#define UID 4000
constexpr int32_t DELAY_TIME = 100;

static int32_t g_port = 6000;
static const char *g_pkgName = "dms";
static const char *g_ip = "192.168.8.1";
static int32_t g_netWorkId = 100;

class TransTcpDirectMessageTest : public testing::Test {
public:
    TransTcpDirectMessageTest()
    {}
    ~TransTcpDirectMessageTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectMessageTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    TransProxyPipelineInit();
    (void)LooperInit();
}

void TransTcpDirectMessageTest::TearDownTestCase(void)
{
    ConnServerDeinit();
    AuthDeinit();
    BusCenterServerDeinit();
    TransServerDeinit();
    LooperDeinit();
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
    conn->req = INVALID_VALUE;
    conn->authHandle.authId = 1;
    conn->requestId = 1;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.fd = g_netWorkId;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    return conn;
}

AppInfo *TestSetAppInfo()
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return nullptr;
    }

    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    return appInfo;
}

/**
 * @tc.name: P2pDirectChannelInitTest001
 * @tc.desc: P2pDirectChannelInit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, P2pDirectChannelInitTest001, TestSize.Level1)
{
    int32_t ret = P2pDirectChannelInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: OpenP2pDirectChannelTest001
 * @tc.desc: OpenP2pDirectChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, OpenP2pDirectChannelTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    int32_t channelId = 1;
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    (void)memset_s(connInfo, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = OpenP2pDirectChannel(nullptr, connInfo, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OpenP2pDirectChannel(appInfo, nullptr, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OpenP2pDirectChannel(appInfo, connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    (void)memcpy_s(appInfo->myData.addr, IP_LEN, g_ip, strlen(g_ip));

    connInfo->type = CONNECT_P2P;
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    connInfo->type = CONNECT_BR;
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    StopP2pSessionListener();
    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: GenerateTdcChannelIdTest003
 * @tc.desc: GenerateTdcChannelId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GenerateTdcChannelIdTest003, TestSize.Level1)
{
    uint64_t ret = TransTdcGetNewSeqId();
    EXPECT_TRUE(ret);

    int32_t res = GenerateTdcChannelId();
    EXPECT_TRUE(res);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    res = CreatSessionConnList();
    ASSERT_EQ(res, SOFTBUS_OK);

    SoftBusList *softbuslist = GetSessionConnList();
    EXPECT_TRUE(softbuslist != nullptr);

    res = GetSessionConnLock();
    EXPECT_EQ(res, SOFTBUS_OK);

    ReleaseSessionConnLock();
    TransTcpDirectDeinit();
}

/**
 * @tc.name: GetSessionConnByRequestIdTest004
 * @tc.desc: GetSessionConnByRequestId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetSessionConnByRequestIdTest004, TestSize.Level1)
{
    uint32_t requestId = 1;
    SessionConn *session = GetSessionConnByRequestId(requestId);
    EXPECT_TRUE(session == nullptr);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    session = GetSessionConnByRequestId(requestId);
    EXPECT_TRUE(session != nullptr);

    requestId = INVALID_VALUE;
    session = GetSessionConnByRequestId(requestId);
    EXPECT_TRUE(session == nullptr);

    TransTcpDirectDeinit();
}

/**
 * @tc.name: GetSessionConnByReqTest005
 * @tc.desc: GetSessionConnByReq, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetSessionConnByReqTest005, TestSize.Level1)
{
    int64_t req = INVALID_VALUE;
    SessionConn *session = GetSessionConnByReq(req);
    EXPECT_TRUE(session != nullptr);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *conn = TestSetSessionConn();
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    req = 0;
    session = GetSessionConnByReq(req);
    EXPECT_TRUE(session == nullptr);
    TransTcpDirectDeinit();
}

/**
 * @tc.name: CreateNewSessinConnTest006
 * @tc.desc: CreateNewSessinConn, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, CreateNewSessinConnTest006, TestSize.Level1)
{
    SessionConn *session = CreateNewSessinConn(AUTH_P2P, true);
    EXPECT_EQ(nullptr, session);
}

/**
 * @tc.name: GetSessionConnByFdTest007
 * @tc.desc: GetSessionConnByFd, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetSessionConnByFdTest007, TestSize.Level1)
{
    int32_t fd = g_netWorkId;
    SessionConn *conn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t session = GetSessionConnByFd(fd, conn);
    EXPECT_TRUE(session == SOFTBUS_OK);
    fd = 123;
    session = GetSessionConnByFd(fd, conn);
    EXPECT_TRUE(session == SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);

    SoftBusFree(conn);
}

/**
 * @tc.name: GetSessionConnByIdTest008
 * @tc.desc: GetSessionConnById, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetSessionConnByIdTest008, TestSize.Level1)
{
    int32_t channelId = 1;
    SessionConn *conn = (SessionConn*)SoftBusMalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));

    int32_t session = GetSessionConnById(channelId, nullptr);
    EXPECT_TRUE(session == SOFTBUS_OK);

    channelId = 0;
    session = GetSessionConnById(channelId, conn);
    EXPECT_TRUE(session != SOFTBUS_OK);

    SoftBusFree(conn);
}

/**
 * @tc.name: SetAppInfoByIdTest009
 * @tc.desc: SetAppInfoById, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, SetAppInfoByIdTest009, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo *appInfo = TestSetAppInfo();

    int32_t ret = SetAppInfoById(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = 0;
    ret = SetAppInfoById(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SET_APP_INFO_FAILED);
    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/**
 * @tc.name: GetAppInfoByIdTest0010
 * @tc.desc: GetAppInfoById, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetAppInfoByIdTest0010, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo *appInfo = TestSetAppInfo();
    int32_t ret = GetAppInfoById(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = 0;
    ret = GetAppInfoById(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_APP_INFO_FAILED);

    SoftBusFree(appInfo);
    appInfo = nullptr;
}

/**
 * @tc.name: SetAuthHandleByChanIdTest0011
 * @tc.desc: SetAuthHandleByChanId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, SetAuthHandleByChanIdTest0011, TestSize.Level1)
{
    int32_t channelId = 1;
    AuthHandle authHandle = { .authId = 1, .type = 1 };
    int32_t ret = SetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = 0;
    ret = SetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SET_AUTH_HANDLE_FAILED);
}

/**
 * @tc.name: GetAuthHandleByChanIdTest0012
 * @tc.desc: GetAuthHandleByChanId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetAuthHandleByChanIdTest0012, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    int32_t channelId = 1;
    int32_t ret = GetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t res = TransTcpDirectInit(cb);
    EXPECT_EQ(res, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    res = TransTdcAddSessionConn(con);
    EXPECT_EQ(res, SOFTBUS_OK);

    channelId = 0;
    ret = GetAuthHandleByChanId(channelId, &authHandle);
    EXPECT_EQ(authHandle.authId, AUTH_INVALID_ID);
    TransTcpDirectDeinit();
}

/**
 * @tc.name: GetAuthIdByChanIdTest0013
 * @tc.desc: GetAuthIdByChanId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, GetAuthIdByChanIdTest0013, TestSize.Level1)
{
    int32_t channelId = 1;
    TransDelSessionConnById(channelId);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t res = TransTcpDirectInit(cb);
    EXPECT_EQ(res, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    res = TransTdcAddSessionConn(con);
    EXPECT_EQ(res, SOFTBUS_OK);
    channelId = 0;
    TransDelSessionConnById(channelId);

    TransTcpDirectDeinit();
}

/**
 * @tc.name: TransTdcAddSessionConnTest0014
 * @tc.desc: TransTdcAddSessionConn, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransTdcAddSessionConnTest0014, TestSize.Level1)
{
    SessionConn *con = TestSetSessionConn();
    int32_t ret = TransTdcAddSessionConn(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransTcpDirectDeinit();
}

/**
 * @tc.name: SetSessionKeyByChanIdTest0015
 * @tc.desc: SetSessionKeyByChanId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, SetSessionKeyByChanIdTest0015, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *sessionKey = "key";
    int32_t keyLen = 0;
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SetSessionKeyByChanId(channelId, nullptr, keyLen);
    SetSessionKeyByChanId(channelId, sessionKey, keyLen);

    keyLen = strlen(sessionKey);
    SetSessionKeyByChanId(channelId, sessionKey, keyLen);
    TransTcpDirectDeinit();
}

/**
 * @tc.name: SetSessionConnStatusByIdTest0016
 * @tc.desc: SetSessionConnStatusById, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, SetSessionConnStatusByIdTest0016, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t status = TCP_DIRECT_CHANNEL_STATUS_CONNECTED;
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SetSessionConnStatusById(channelId, status);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channelId = 0;
    ret = SetSessionConnStatusById(channelId, status);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    TransTcpDirectDeinit();
}

/**
 * @tc.name: TcpTranGetAppInfobyChannelIdTest0017
 * @tc.desc: TcpTranGetAppInfobyChannelId, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TcpTranGetAppInfobyChannelIdTest0017, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo* appInfo = TestSetAppInfo();
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TcpTranGetAppInfobyChannelId(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channelId = 0;
    ret = TcpTranGetAppInfobyChannelId(channelId, appInfo);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: OpenTcpDirectChannelTest0018
 * @tc.desc: OpenTcpDirectChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, OpenTcpDirectChannelTest0018, TestSize.Level1)
{
    int32_t channelId = 1;
    AppInfo *appInfo = TestSetAppInfo();
    ConnectOption connInfo;
    connInfo.type = CONNECT_TCP;
    (void)memset_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr),
        0, sizeof(connInfo.socketOption.addr));
    connInfo.socketOption.port = g_port;
    connInfo.socketOption.moduleId = MODULE_MESSAGE_SERVICE;
    connInfo.socketOption.protocol = LNN_PROTOCOL_IP;
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), g_ip) != EOK) {
        return;
    }
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    int64_t authSeq = 0;
    AuthSessionInfo info;
    SessionKey sessionKey;

    ret = AuthManagerSetSessionKey(authSeq, &info, &sessionKey, false, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenTcpDirectChannel(nullptr, &connInfo, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenTcpDirectChannel(appInfo, nullptr, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenTcpDirectChannel(appInfo, &connInfo, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = OpenTcpDirectChannel(appInfo, &connInfo, &channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    AuthDeinit();
}

/**
 * @tc.name: TransGetLocalConfigTest001
 * @tc.desc: TransGetLocalConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransGetLocalConfigTest001, TestSize.Level1)
{
    int32_t channelType = -1;
    int32_t bussinessType = BUSINESS_TYPE_BYTE;
    uint32_t len;
    int32_t ret = TransCommonGetLocalConfig(channelType, bussinessType, &len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransGetLocalConfigTest002
 * @tc.desc: TransGetLocalConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransGetLocalConfigTest002, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t bussinessType = BUSINESS_TYPE_BYTE;
    uint32_t len;
    int32_t ret = TransCommonGetLocalConfig(channelType, bussinessType, &len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransGetChannelIdsByAuthIdAndStatus001
 * @tc.desc: TransGetLocalConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransGetChannelIdsByAuthIdAndStatus001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .type = 1,
        .authId = 1,
    };
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con = TestSetSessionConn();
    con->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
    con->authHandle.type = 1;
    ret = TransTdcAddSessionConn(con);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con2 = TestSetSessionConn();
    con2->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    con2->channelId = 1;
    con2->authHandle.type = 1;
    ret = TransTdcAddSessionConn(con2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SessionConn *con3 = TestSetSessionConn();
    con3->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    con3->channelId = 2;
    con3->authHandle.type = 1;
    ret = TransTdcAddSessionConn(con3);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t count = 0;
    int32_t *channelId = GetChannelIdsByAuthIdAndStatus(&count, &authHandle, TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(channelId[0], 1);
    EXPECT_EQ(channelId[1], 2);
    TransDelSessionConnById(con->channelId);
    TransDelSessionConnById(con2->channelId);
    TransDelSessionConnById(con3->channelId);
    SoftBusFree(channelId);
}

/**
 * @tc.name: TransDealTdcCheckCollabResult001
 * @tc.desc: check collab result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransDealTdcCheckCollabResult001, TestSize.Level1)
{
    int32_t channelId = 1;
    
    TransChannelResultLoopInit();
    TransCheckChannelOpenToLooperDelay(channelId, CHANNEL_TYPE_TCP_DIRECT, DELAY_TIME);
    int32_t checkResult = SOFTBUS_OK;
    int32_t ret = TransDealTdcCheckCollabResult(channelId, checkResult);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransDealTdcCheckCollabResult002
 * @tc.desc: check collab result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageTest, TransDealTdcCheckCollabResult002, TestSize.Level1)
{
    const IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransTcpDirectInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SessionConn *conn = TestSetSessionConn();
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t checkResult = SOFTBUS_ERR;
    ret = TransDealTdcCheckCollabResult(conn->channelId, checkResult);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_IS_NULL);

    TransTcpDirectDeinit();
}
} // namespace OHOS
