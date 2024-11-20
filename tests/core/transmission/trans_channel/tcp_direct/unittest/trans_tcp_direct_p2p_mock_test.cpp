/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include "securec.h"

#include "softbus_error_code.h"
#include "trans_auth_message.h"
#include "trans_tcp_direct_callback.h"
#include "trans_tcp_direct_p2p.h"
#include "trans_tcp_direct_p2p.c"
#include "trans_tcp_direct_p2p_test_mock.h"
#include "trans_tcp_direct_sessionconn.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1
#define TEST_MODULE 20
#define TEST_PORT 43526
#define TEST_SEQ 123
#define TEST_LEN 20
#define TEST_FD 5
#define TEST_AUTHID 947251635
#define TEST_PID 2048
#define TEST_UID 4096
#define TEST_AUTO_CLOSE_TIME 5
#define INVALID_VALUE (-1)
#define TEST_REQ_ID 1234
#define INVALID_AUTH_LINK_TYPE 10
#define PKG_NAME_SIZE_MAX_LEN 65
#define P2P_PORT "P2P_PORT"
#define P2P_IP "P2P_IP"
#define ERR_CODE "ERR_CODE"
static const char *IP = "192.168.8.1";
static const char *MY_IP = "192.168.8.13";
static const char *DATA = "test_send_data";
static const char *SESSION_NAME = "com.test.trans.auth.demo";
static const char *PKGE_NAME = "dms";
static const char *TEST_SESSION_KEY = "Test_OpenHarmony";
static const char *TEST_GROUP_ID = "Test_Group_Id";
static const char *TEST_UDID = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static const char *TEST_UUID = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";

namespace OHOS {

class TransTcpDirectP2pMockTest : public testing::Test {
public:
    TransTcpDirectP2pMockTest()
    {}
    ~TransTcpDirectP2pMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectP2pMockTest::SetUpTestCase(void)
{
    // will free in TearDownTestCase
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_TRUE(list != nullptr);
    SoftBusMutexInit(&list->lock, nullptr);
    ListInit(&list->list);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, CreateSoftBusList).WillOnce(Return(nullptr));
    int32_t ret = CreatHmlListenerList();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    EXPECT_CALL(TcpP2pDirectMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(TcpP2pDirectMock, RegAuthTransListener).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineRegisterListener).WillOnce(Return(SOFTBUS_OK));
    ret = P2pDirectChannelInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    // will free in TearDownTestCase
    SoftBusList *SessionList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_TRUE(SessionList != nullptr);
    SoftBusMutexInit(&SessionList->lock, nullptr);
    ListInit(&SessionList->list);
    EXPECT_CALL(TcpP2pDirectMock, CreateSoftBusList).WillOnce(Return(SessionList));
    ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void TransTcpDirectP2pMockTest::TearDownTestCase(void)
{
    TransSrvDataListDeinit();
    SoftBusList *list = GetSessionConnList();
    DestroySoftBusList(list);
    list = nullptr;
}

SessionConn *TestSetSessionConn()
{
    SessionConn *testConn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (testConn == nullptr) {
        return nullptr;
    }
    testConn->serverSide = true;
    testConn->appInfo.fd = TEST_FD;
    testConn->appInfo.myHandleId = TEST_AUTHID;
    testConn->appInfo.peerHandleId = TEST_AUTHID;
    testConn->appInfo.peerData.uid = TEST_UID;
    testConn->appInfo.peerData.pid = TEST_PID;
    testConn->appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    testConn->appInfo.autoCloseTime = TEST_AUTO_CLOSE_TIME;
    testConn->appInfo.peerData.port = TEST_PORT;
    testConn->appInfo.myData.dataConfig = 1;
    testConn->appInfo.fastTransDataSize = TEST_LEN;
    testConn->channelId = TEST_CHANNEL_ID;
    testConn->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    testConn->timeout = 0;
    testConn->req = TEST_SEQ;
    testConn->authHandle.authId = 1;
    testConn->appInfo.callingTokenId = 1;
    testConn->requestId = TEST_REQ_ID;
    testConn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    testConn->appInfo.myData.pid = 1;
    testConn->appInfo.peerData.dataConfig = 0;
    testConn->appInfo.linkType = 1;
    testConn->appInfo.routeType = WIFI_P2P;
    testConn->appInfo.peerData.channelId = TEST_CHANNEL_ID;
    testConn->authHandle.type = AUTH_LINK_TYPE_WIFI;
    (void)memcpy_s(testConn->appInfo.myData.sessionName, SESSION_NAME_SIZE_MAX,
        SESSION_NAME, (strlen(SESSION_NAME) + 1));
    (void)memcpy_s(testConn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, PKGE_NAME, (strlen(PKGE_NAME) + 1));
    (void)memcpy_s(testConn->appInfo.peerData.sessionName,
        SESSION_NAME_SIZE_MAX, SESSION_NAME, (strlen(SESSION_NAME) + 1));
    (void)memcpy_s(testConn->appInfo.sessionKey, SESSION_KEY_LENGTH, TEST_SESSION_KEY, (strlen(TEST_SESSION_KEY) + 1));
    (void)memcpy_s(testConn->appInfo.groupId, GROUP_ID_SIZE_MAX, TEST_GROUP_ID, (strlen(TEST_GROUP_ID) + 1));
    (void)memcpy_s(testConn->appInfo.peerData.addr, IP_LEN, IP, (strlen(IP) + 1));
    return testConn;
}

static cJSON *TestTransCreateJson(void)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        std::cout << "create json fail" << std::endl;
        return nullptr;
    }
    if (!AddNumberToJsonObject(json, P2P_PORT, TEST_PORT)) {
        std::cout << "add P2p port failed" << std::endl;
        cJSON_Delete(json);
        return nullptr;
    }
    if (!AddStringToJsonObject(json, P2P_IP, IP)) {
        std::cout << "add P2p port failed" << std::endl;
        cJSON_Delete(json);
        return nullptr;
    }
    return json;
}

/**
 * @tc.name: StartNewP2pListenerTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartNewP2pListenerTest001, TestSize.Level1)
{
    int32_t port = TEST_PORT;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    int32_t ret = StartNewP2pListener(IP, &port);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, StopBaseListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    StopP2pSessionListener();
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    ret = StartNewP2pListener(IP, &port);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, StopBaseListener).WillOnce(Return(SOFTBUS_OK));
    StopP2pSessionListener();
}

/**
 * @tc.name: StartNewHmlListenerTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid param..
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartNewHmlListenerTest001, TestSize.Level1)
{
    ListenerModule moudleType;
    int32_t port = TEST_PORT;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    int32_t ret = StartNewHmlListener(IP, &port, &moudleType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: StartHmlListenerTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartHmlListenerTest001, TestSize.Level1)
{
    ListenerModule moudleType = DIRECT_CHANNEL_SERVER_HML_START;
    int32_t port = TEST_PORT;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    int32_t ret = StartHmlListener(IP, &port, TEST_UDID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartHmlListener(IP, &port, TEST_UDID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, StopBaseListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    StopHmlListener(moudleType);
    EXPECT_CALL(TcpP2pDirectMock, StopBaseListener).WillOnce(Return(SOFTBUS_OK));
    StopHmlListener(moudleType);
}

/**
 * @tc.name: GetModuleByHmlIpTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, GetModuleByHmlIpTest001, TestSize.Level1)
{
    ListenerModule moudleType = DIRECT_CHANNEL_SERVER_HML_START;
    int32_t port = TEST_PORT;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    int32_t ret = StartHmlListener(IP, &port, TEST_UDID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    moudleType = GetModuleByHmlIp(IP);
    EXPECT_EQ(DIRECT_CHANNEL_SERVER_HML_START, moudleType);
    EXPECT_CALL(TcpP2pDirectMock, StopBaseListener).WillOnce(Return(SOFTBUS_OK));
    StopHmlListener(moudleType);
    ClearHmlListenerByUuid(nullptr);
    ClearHmlListenerByUuid(TEST_UDID);
}

/**
 * @tc.name: StartP2pListenerTest001
 * @tc.desc: Should return SOFTBUS_OK when given valid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartP2pListenerTest001, TestSize.Level1)
{
    int32_t port = TEST_PORT;
    int32_t ret = StartP2pListener(nullptr, &port, TEST_UUID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillRepeatedly(Return(port));
    ret = StartP2pListener(IP, &port, TEST_UUID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartP2pListener(IP, &port, TEST_UUID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(true));
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillRepeatedly(Return(port));
    ret = StartP2pListener(IP, &port, TEST_UUID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendAuthDataTest001
 * @tc.desc: Should return SOFTBUS_OK when SendAuthData return SOFTBUS_OK.
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when AuthPostTransData return SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, SendAuthDataTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int32_t module = TEST_MODULE;
    int32_t flag = 1;
    int64_t seq = TEST_SEQ;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SendAuthData(authHandle, module, flag, seq, DATA);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_OK));
    ret = SendAuthData(authHandle, module, flag, seq, DATA);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: VerifyP2pTest001
 * @tc.desc: Should return SOFTBUS_PARSE_JSON_ERR when VerifyP2pPack return nullptr.
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when AuthPostTransData return SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, VerifyP2pTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    int64_t seq = TEST_SEQ;
    int32_t port = TEST_PORT;
    // will free in VerifyP2p
    char *data = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(data != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(nullptr));
    int32_t ret = VerifyP2p(authHandle, IP, IP, port, seq);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(data));
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = VerifyP2p(authHandle, IP, IP, port, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    // will free in VerifyP2p
    char *testData = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(testData != nullptr);
    (void)memcpy_s(testData, TEST_LEN, DATA, TEST_LEN);
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(testData));
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_OK));
    ret = VerifyP2p(authHandle, IP, IP, port, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnAuthConnOpenedTest001
 * @tc.desc: Test OnAuthConnOpened.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnAuthConnOpenedTest001, TestSize.Level1)
{
    uint32_t requestId = TEST_REQ_ID;
    AuthHandle authHandle = { .authId = 1, .type = 0 };
    int32_t reason = SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    OnAuthConnOpened(requestId, authHandle);
    authHandle.type = INVALID_AUTH_LINK_TYPE;
    OnAuthConnOpened(requestId, authHandle);
    authHandle.type = AUTH_LINK_TYPE_WIFI;
    OnAuthConnOpened(requestId, authHandle);
    OnAuthConnOpenFailed(requestId, reason);
    // will free in OnAuthConnOpened--VerifyP2p
    char *data = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(data != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);

    // will free in TearDownTestCase--GetSessionConnList--DestroySoftBusList
    SoftBusList *SessionList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_TRUE(SessionList != nullptr);
    SoftBusMutexInit(&SessionList->lock, nullptr);
    ListInit(&SessionList->list);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, CreateSoftBusList).WillOnce(Return(SessionList));
    int32_t ret = CreatSessionConnList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    OnAuthConnOpened(requestId, authHandle);
    OnAuthConnOpenFailed(requestId, reason);
    // will free in OnAuthConnOpened--OnChannelOpenFail--TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TcpP2pDirectMock, NotifyChannelOpenFailed).WillRepeatedly(Return(SOFTBUS_OK));
    OnAuthConnOpenFailed(requestId, reason);

    // will free in OnAuthConnOpened--OnChannelOpenFail--TransDelSessionConnById
    SessionConn *testConn = TestSetSessionConn();
    ASSERT_TRUE(testConn != nullptr);
    ret = TransTdcAddSessionConn(testConn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(data));
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, NotifyChannelOpenFailed).WillRepeatedly(Return(SOFTBUS_OK));
    OnAuthConnOpened(requestId, authHandle);

    
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(nullptr));
    OnAuthConnOpened(requestId, authHandle);
}

/**
 * @tc.name: OpenAuthConnTest001
 * @tc.desc: Should return SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED when AuthOpenConn return error.
 * @tc.desc: Should return SOFTBUS_OK when AuthOpenConn return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OpenAuthConnTest001, TestSize.Level1)
{
    uint32_t reqId = TEST_REQ_ID;
    bool isMeta = false;
    ConnectType type = CONNECT_HML;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, AuthGetHmlConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = OpenAuthConn(IP, reqId, isMeta, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, AuthGetHmlConnInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TcpP2pDirectMock, AuthGetPreferConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillOnce(Return(SOFTBUS_OK));
    ret = OpenAuthConn(IP, reqId, isMeta, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = CONNECT_P2P;
    EXPECT_CALL(TcpP2pDirectMock, AuthGetP2pConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OpenAuthConn(IP, reqId, isMeta, type);
    EXPECT_EQ(SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED, ret);
}

/**
 * @tc.name: PackAndSendVerifyP2pRspTest001
 * @tc.desc: Should return SOFTBUS_PARSE_JSON_ERR when VerifyP2pPack return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, PackAndSendVerifyP2pRspTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = 0 };
    int64_t seq = TEST_SEQ;
    int32_t port = TEST_PORT;
    bool isAuthLink = false;
    // will free in PackAndSendVerifyP2pRsp
    char *data = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(data != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);

    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(nullptr));
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPackError).WillOnce(Return(data));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineSendMessage).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = PackAndSendVerifyP2pRsp(IP, port, seq, isAuthLink, authHandle);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    isAuthLink = true;
    char *testData = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(testData != nullptr);
    (void)memcpy_s(testData, TEST_LEN, DATA, TEST_LEN);
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(nullptr));
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPackError).WillOnce(Return(testData));
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_OK));
    ret = PackAndSendVerifyP2pRsp(IP, port, seq, isAuthLink, authHandle);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
 * @tc.name: PackAndSendVerifyP2pRspTest002
 * @tc.desc: Should return SOFTBUS_OK when AuthPostTransData return SOFTBUS_OK.
 * @tc.desc: Should return SOFTBUS_NOT_FIND when TransProxyPipelineSendMessage return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, PackAndSendVerifyP2pRspTest002, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = 0 };
    int64_t seq = TEST_SEQ;
    int32_t port = TEST_PORT;
    bool isAuthLink = false;
    // will free in PackAndSendVerifyP2pRsp
    char *data = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(data != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);
    char *newData = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(newData != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);

    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(data));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineSendMessage).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = PackAndSendVerifyP2pRsp(IP, port, seq, isAuthLink, authHandle);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    isAuthLink = true;
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPack).WillOnce(Return(newData));
    EXPECT_CALL(TcpP2pDirectMock, AuthPostTransData).WillOnce(Return(SOFTBUS_OK));
    ret = PackAndSendVerifyP2pRsp(IP, port, seq, isAuthLink, authHandle);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnVerifyP2pRequestTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_P2P_INFO_FAILED when TransProxyPipelineSendMessage return error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnVerifyP2pRequestTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = 0 };
    int64_t seq = TEST_SEQ;
    bool isAuthLink = false;
    cJSON *json = TestTransCreateJson();
    ASSERT_TRUE(json != nullptr);
    // will free in VerifyP2pPackError
    char *data = static_cast<char *>(SoftBusCalloc(TEST_LEN));
    ASSERT_TRUE(data != nullptr);
    (void)memcpy_s(data, TEST_LEN, DATA, TEST_LEN);

    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, VerifyP2pPackError).WillOnce(Return(data));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineSendMessage).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = OnVerifyP2pRequest(authHandle, seq, json, isAuthLink);
    EXPECT_EQ(SOFTBUS_TRANS_GET_P2P_INFO_FAILED, ret);

    cJSON_Delete(json);
}

/**
 * @tc.name: ConnectTcpDirectPeerTest001
 * @tc.desc: Should return SOFTBUS_OK when ConnOpenClientSocket return SOFTBUS_OK.
 * @tc.desc: Should return error when ConnOpenClientSocket return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, ConnectTcpDirectPeerTest001, TestSize.Level1)
{
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillOnce(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, ConnOpenClientSocket).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = ConnectTcpDirectPeer(IP, TEST_PORT, MY_IP);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillOnce(Return(true));
    EXPECT_CALL(TcpP2pDirectMock, ConnOpenClientSocket).WillOnce(Return(SOFTBUS_OK));
    ret = ConnectTcpDirectPeer(IP, TEST_PORT, MY_IP);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: AddHmlTriggerTest001
 * @tc.desc: Should return SOFTBUS_OK when ConnOpenClientSocket return SOFTBUS_OK.
 * @tc.desc: Should return error when ConnOpenClientSocket return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, AddHmlTriggerTest001, TestSize.Level1)
{
    int32_t port = TEST_PORT;
    int32_t fd = TEST_FD;
    int64_t seq = TEST_SEQ;
    int32_t ret = AddHmlTrigger(fd, IP, seq);
    EXPECT_EQ(SOFTBUS_TRANS_ADD_HML_TRIGGER_FAILED, ret);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    ret = StartHmlListener(IP, &port, TEST_UDID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = AddHmlTrigger(fd, IP, seq);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_OK));
    ret = AddHmlTrigger(fd, IP, seq);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_OK));
    ret = AddHmlTrigger(fd, IP, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: AddP2pOrHmlTriggerTest001
 * @tc.desc: Should return SOFTBUS_OK when AddTrigger return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, AddP2pOrHmlTriggerTest001, TestSize.Level1)
{
    int32_t fd = TEST_FD;
    int64_t seq = TEST_SEQ;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillOnce(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = AddP2pOrHmlTrigger(fd, IP, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnVerifyP2pReplyTest001
 * @tc.desc: Should return SOFTBUS_OK when AddTrigger return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnVerifyP2pReplyTest001, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = TEST_SEQ;
    cJSON *json = TestTransCreateJson();
    ASSERT_TRUE(json != nullptr);
    // will free in OnVerifyP2pReply---OnChannelOpenFail---TransDelSessionConnById
    SessionConn *testConn = TestSetSessionConn();
    ASSERT_TRUE(testConn != nullptr);
    int32_t ret = TransTdcAddSessionConn(testConn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(true));
    EXPECT_CALL(TcpP2pDirectMock, ConnOpenClientSocket).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_CALL(TcpP2pDirectMock, NotifyChannelOpenFailed).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(SOFTBUS_TRANS_VERIFY_P2P_FAILED, ret);

    // will free in OnVerifyP2pReply---OnChannelOpenFail---TransDelSessionConnById
    SessionConn *newConn = TestSetSessionConn();
    ASSERT_TRUE(newConn != nullptr);
    ret = TransTdcAddSessionConn(newConn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, ConnOpenClientSocket).WillRepeatedly(Return(1));
    EXPECT_CALL(TcpP2pDirectMock, TransSrvAddDataBufNode).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(SOFTBUS_TRANS_VERIFY_P2P_FAILED, ret);

    // will free in OnVerifyP2pReply---OnChannelOpenFail---TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    cJSON *testJson = cJSON_CreateObject();
    ret = OnVerifyP2pReply(authId, seq, testJson);
    EXPECT_EQ(SOFTBUS_TRANS_VERIFY_P2P_FAILED, ret);

    cJSON_Delete(json);
    cJSON_Delete(testJson);
}

/**
 * @tc.name: OnVerifyP2pReplyTest002
 * @tc.desc: Should return SOFTBUS_OK when AddTrigger return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnVerifyP2pReplyTest002, TestSize.Level1)
{
    int64_t authId = 1;
    int64_t seq = TEST_SEQ;
    cJSON *json = TestTransCreateJson();
    ASSERT_TRUE(json != nullptr);
    // will free in OnVerifyP2pReply---OnChannelOpenFail---TransDelSessionConnById
    SessionConn *NewConn = TestSetSessionConn();
    ASSERT_TRUE(NewConn != nullptr);
    int32_t ret = TransTdcAddSessionConn(NewConn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, ConnOpenClientSocket).WillRepeatedly(Return(1));
    EXPECT_CALL(TcpP2pDirectMock, TransSrvAddDataBufNode).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_NO_INIT));
    EXPECT_CALL(TcpP2pDirectMock, NotifyChannelOpenFailed).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(SOFTBUS_TRANS_VERIFY_P2P_FAILED, ret);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, AddTrigger).WillOnce(Return(SOFTBUS_OK));
    ret = OnVerifyP2pReply(authId, seq, json);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelSessionConnById(conn->channelId);
    cJSON_Delete(json);
}

/**
 * @tc.name: OnAuthDataRecvTest001
 * @tc.desc: Test OnAuthDataRecv.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnAuthDataRecvTest001, TestSize.Level1)
{
    // will free in OnAuthDataRecv
    cJSON *json = TestTransCreateJson();
    ASSERT_TRUE(json != nullptr);
    const char *str = "data";
    AuthTransData *data = (AuthTransData*)SoftBusCalloc(sizeof(AuthTransData));
    ASSERT_TRUE(data != nullptr);
    data->module = MODULE_P2P_LINK;
    data->flag = FLAG_REPLY;
    data->seq = 1;
    data->data = nullptr;
    data->len = 0;
    AuthHandle authHandle = { .authId = 1, .type = 0 };
    OnAuthDataRecv(authHandle, nullptr);
    OnAuthDataRecv(authHandle, data);
    data->data = (const uint8_t *)str;
    OnAuthDataRecv(authHandle, data);
    data->len = TEST_LEN;
    OnAuthDataRecv(authHandle, data);
    authHandle.type = INVALID_AUTH_LINK_TYPE;
    OnAuthDataRecv(authHandle, data);
    authHandle.type = AUTH_LINK_TYPE_WIFI;
    OnAuthDataRecv(authHandle, data);
    data->module = MODULE_P2P_LISTEN;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(nullptr));
    OnAuthDataRecv(authHandle, data);
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(json));
    OnAuthDataRecv(authHandle, data);
}

/**
 * @tc.name: OnAuthChannelCloseTest001
 * @tc.desc: Should return SOFTBUS_OK when AddTrigger return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnAuthChannelCloseTest001, TestSize.Level1)
{
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, NotifyChannelOpenFailed).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    OnAuthChannelClose(authHandle);
    OnAuthChannelClose(authHandle);
    TransDelSessionConnById(conn->channelId);
}

/**
 * @tc.name: OpenNewAuthConnTest001
 * @tc.desc: Should return SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED when AuthOpenConn return error.
 * @tc.desc: Should return SOFTBUS_OK when AuthOpenConn return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OpenNewAuthConnTest001, TestSize.Level1)
{
    int32_t newChannelId = TEST_CHANNEL_ID;
    ConnectType type = CONNECT_HML;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, AuthGetHmlConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = OpenNewAuthConn(appInfo, conn, newChannelId, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = CONNECT_P2P;
    EXPECT_CALL(TcpP2pDirectMock, AuthGetP2pConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OpenNewAuthConn(appInfo, conn, newChannelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED, ret);
    TransDelSessionConnById(conn->channelId);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OnP2pVerifyMsgReceivedTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OnP2pVerifyMsgReceivedTest001, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON *testJson = cJSON_CreateObject();
    ASSERT_TRUE(testJson != nullptr);
    cJSON *newJson = cJSON_CreateObject();
    ASSERT_TRUE(newJson != nullptr);
    int64_t msgType = P2P_VERIFY_REQUEST;
    char *data = reinterpret_cast<char *>(&msgType);
    int32_t channelId = TEST_CHANNEL_ID;
    uint32_t len = 1;
    OnP2pVerifyMsgReceived(channelId, nullptr, len);
    OnP2pVerifyMsgReceived(channelId, data, len);
    len = TEST_LEN;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(nullptr));
    OnP2pVerifyMsgReceived(channelId, data, len);
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(json));
    OnP2pVerifyMsgReceived(channelId, data, len);
    msgType = P2P_VERIFY_REPLY;
    data = reinterpret_cast<char *>(&msgType);
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(testJson));
    OnP2pVerifyMsgReceived(channelId, data, len);
    msgType = INVALID_AUTH_LINK_TYPE;
    data = reinterpret_cast<char *>(&msgType);
    EXPECT_CALL(TcpP2pDirectMock, cJSON_ParseWithLength).WillRepeatedly(Return(newJson));
    OnP2pVerifyMsgReceived(channelId, data, len);
}

/**
 * @tc.name: StartVerifyP2pInfoTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartVerifyP2pInfoTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ConnectType type = CONNECT_HML;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    uint32_t reqId = TEST_REQ_ID;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineGetChannelIdByNetworkId).
        WillRepeatedly(Return(INVALID_CHANNEL_ID));
    EXPECT_CALL(TcpP2pDirectMock, AuthGenRequestId).WillRepeatedly(Return(reqId));
    EXPECT_CALL(TcpP2pDirectMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = CONNECT_P2P_REUSE;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(true));
    ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(conn);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: StartVerifyP2pInfoTest002
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return VALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartVerifyP2pInfoTest002, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ConnectType type = CONNECT_HML;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineGetChannelIdByNetworkId).
        WillRepeatedly(Return(TEST_CHANNEL_ID));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyReuseByChannelId).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_CALL(TcpP2pDirectMock, TransProxyReuseByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpP2pDirectMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    ret = StartVerifyP2pInfo(appInfo, conn, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);
    SoftBusFree(conn);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: CopyAppInfoFastTransDataTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return VALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, CopyAppInfoFastTransDataTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
    ASSERT_TRUE(fastTransData != nullptr);
    appInfo->fastTransData = nullptr;
    FreeFastTransData(appInfo);
    int32_t ret = CopyAppInfoFastTransData(conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->fastTransData = fastTransData;
    ret = CopyAppInfoFastTransData(conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->fastTransDataSize = 0;
    ret = CopyAppInfoFastTransData(conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    FreeFastTransData(appInfo);
    FreeFastTransData(nullptr);

    SoftBusFree(conn);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: BuildSessionConnTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return VALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, BuildSessionConnTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, CreateNewSessinConn).WillOnce(Return(nullptr));
    int32_t ret = BuildSessionConn(appInfo, &conn);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    appInfo->fastTransData = nullptr;
    EXPECT_CALL(TcpP2pDirectMock, CreateNewSessinConn).WillRepeatedly(Return(conn));
    ret = BuildSessionConn(appInfo, &conn);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: StartTransP2pDirectListenerTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return VALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, StartTransP2pDirectListenerTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ConnectType type = CONNECT_HML;
    int32_t port = TEST_PORT;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillOnce(Return(port));
    int32_t ret = StartTransP2pDirectListener(type, conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = CONNECT_P2P;
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(false));
    EXPECT_CALL(TcpP2pDirectMock, TransTdcStartSessionListener).WillRepeatedly(Return(port));
    ret = StartTransP2pDirectListener(type, conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(true));
    ret = StartTransP2pDirectListener(type, conn, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(conn);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: OpenP2pDirectChannelTest001
 * @tc.desc: Test OnP2pVerifyMsgReceived when TransProxyPipelineGetChannelIdByNetworkId return VALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectP2pMockTest, OpenP2pDirectChannelTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    connInfo->type = CONNECT_TCP;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memcpy_s(appInfo, sizeof(AppInfo), &conn->appInfo, sizeof(AppInfo));
    uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
    ASSERT_TRUE(fastTransData != nullptr);
    appInfo->fastTransData = fastTransData;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenP2pDirectChannel(nullptr, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenP2pDirectChannel(appInfo, nullptr, &channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = OpenP2pDirectChannel(appInfo, connInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectP2pInterfaceMock> TcpP2pDirectMock;
    EXPECT_CALL(TcpP2pDirectMock, CreateNewSessinConn).WillRepeatedly(Return(nullptr));
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    connInfo->type = CONNECT_HML;
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    connInfo->type = CONNECT_P2P;
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    EXPECT_CALL(TcpP2pDirectMock, CreateNewSessinConn).WillRepeatedly(Return(conn));
    EXPECT_CALL(TcpP2pDirectMock, IsHmlIpAddr).WillRepeatedly(Return(true));
    ret = OpenP2pDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);

    FreeFastTransData(appInfo);
    SoftBusFree(appInfo);
}
}
