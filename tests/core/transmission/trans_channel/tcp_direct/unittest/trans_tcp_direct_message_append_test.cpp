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
#include <gtest/gtest.h>
#include "securec.h"

#include "softbus_def.h"
#include "softbus_error_code.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_server_frame.h"
#include "trans_tcp_direct_listener.c"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_message.c"
#include "trans_tcp_direct_message_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define NORMAL_FD 151
#define TEST_CHANNELID 1
#define TEST_NEW_CHANNEL_ID 1024
#define TEST_AUTHID 947461667
#define PKG_NAME_SIZE_MAX_LEN 65
#define IP_LEN 46
#define DEVICE_ID_SIZE_MAX 65
#define TEST_LEN 50
#define TEST_SEQ 10
#define TEST_FLAG 2
#define TEST_FD 1
#define TEST_PID 1025
#define TEST_UID 1026
#define TEST_PORT 43526
#define ERRMOUDLE 13
#define VALIDRECVLEN 25
#define TEST_AUTO_CLOSE_TIME 10
#define ERR_CHANNELID (-1)
#define INVALID_VALUE (-1)
#define TEST_MODULE 10
#define TEST_MAGICNUM 10
static const char *PKGE_NAME = "dms";
static const char *IP = "192.168.8.1";
static const char *TEST_SESSION_KEY = "Test_OpenHarmony";
static const char *TEST_GROUP_ID = "Test_Group_Id";
static const char *SESSION_NAME = "com.test.trans.auth.demo";
static const char *DEVICE_VERSION = "test.device.version";

namespace OHOS {
class TransTcpDirectMessageAppendTest : public testing::Test {
public:
    TransTcpDirectMessageAppendTest()
    {}
    ~TransTcpDirectMessageAppendTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectMessageAppendTest::SetUpTestCase(void)
{
    // list will free when go to TransSrvDataListDeinit
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_TRUE(list != nullptr);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&list->lock, &mutexAttr);
    ListInit(&list->list);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(list));
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    // list will free when go to TransSrvDataListDeinit
    SoftBusList *SessionList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_TRUE(SessionList != nullptr);
    SoftBusMutexAttr testMutexAttr;
    testMutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&SessionList->lock, &testMutexAttr);
    ListInit(&SessionList->list);
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(SessionList));
    ret = CreatSessionConnList();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void TransTcpDirectMessageAppendTest::TearDownTestCase(void)
{
    (void)TransSrvDataListDeinit();
    SoftBusList *list = GetSessionConnList();
    DestroySoftBusList(list);
    list = nullptr;
}

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }
    conn->serverSide = true;
    conn->appInfo.fd = TEST_FD;
    conn->appInfo.myHandleId = TEST_AUTHID;
    conn->appInfo.peerHandleId = TEST_AUTHID;
    conn->appInfo.peerData.uid = TEST_UID;
    conn->appInfo.peerData.pid = TEST_PID;
    conn->appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    conn->appInfo.autoCloseTime = TEST_AUTO_CLOSE_TIME;
    conn->appInfo.peerData.port = TEST_PORT;
    conn->appInfo.myData.dataConfig = 1;
    conn->appInfo.fastTransDataSize = 1;
    conn->channelId = TEST_CHANNELID;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authHandle.authId = 1;
    conn->appInfo.callingTokenId = 1;
    conn->requestId = 0;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.peerData.dataConfig = 0;
    conn->appInfo.linkType = 1;
    conn->appInfo.routeType = WIFI_P2P;
    conn->appInfo.peerData.channelId = TEST_CHANNELID;
    (void)memcpy_s(conn->appInfo.myData.sessionName, SESSION_NAME_SIZE_MAX, SESSION_NAME, (strlen(SESSION_NAME)+1));
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, PKGE_NAME, (strlen(PKGE_NAME)+1));
    (void)memcpy_s(conn->appInfo.peerData.sessionName, SESSION_NAME_SIZE_MAX, SESSION_NAME, (strlen(SESSION_NAME)+1));
    (void)memcpy_s(conn->appInfo.sessionKey, SESSION_KEY_LENGTH, TEST_SESSION_KEY, (strlen(TEST_SESSION_KEY)+1));
    (void)memcpy_s(conn->appInfo.groupId, GROUP_ID_SIZE_MAX, TEST_GROUP_ID, (strlen(TEST_GROUP_ID)+1));
    (void)memcpy_s(conn->appInfo.peerData.addr, IP_LEN, IP, (strlen(IP)+1));
    return conn;
}

AppInfo *TestSetAppInfo()
{
    AppInfo *appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return nullptr;
    }
    appInfo->fd = TEST_FD;
    appInfo->myHandleId = TEST_AUTHID;
    appInfo->peerHandleId = TEST_AUTHID;
    appInfo->peerData.uid = TEST_UID;
    appInfo->peerData.pid = TEST_PID;
    appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    appInfo->autoCloseTime = TEST_AUTO_CLOSE_TIME;
    appInfo->peerData.port = TEST_PORT;
    appInfo->myData.dataConfig = 1;
    appInfo->fastTransDataSize = 1;
    appInfo->callingTokenId = 1;
    appInfo->myData.pid = 1;
    appInfo->peerData.dataConfig = 0;
    appInfo->linkType = 1;
    appInfo->routeType = WIFI_P2P;
    appInfo->peerData.channelId = TEST_CHANNELID;
    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_SIZE_MAX, SESSION_NAME, (strlen(SESSION_NAME)+1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, PKGE_NAME, (strlen(PKGE_NAME)+1));
    (void)memcpy_s(appInfo->peerData.sessionName, SESSION_NAME_SIZE_MAX, SESSION_NAME, (strlen(SESSION_NAME)+1));
    (void)memcpy_s(appInfo->sessionKey, SESSION_KEY_LENGTH, TEST_SESSION_KEY, (strlen(TEST_SESSION_KEY)+1));
    (void)memcpy_s(appInfo->groupId, GROUP_ID_SIZE_MAX, TEST_GROUP_ID, (strlen(TEST_GROUP_ID)+1));
    (void)memcpy_s(appInfo->peerData.addr, IP_LEN, IP, (strlen(IP)+1));
    return appInfo;
}

void TestTdcPacketHeadInit(TdcPacketHead *packetHead)
{
    if (packetHead == nullptr) {
        return;
    }
    packetHead->dataLen = TEST_LEN;
    packetHead->flags = TEST_FLAG;
    packetHead->seq = TEST_SEQ;
    packetHead->magicNumber = TEST_MAGICNUM;
    packetHead->module = TEST_MODULE;
}

/**
 * @tc.name: TransSrvDataListInitTest001
 * @tc.desc: Should return SOFTBUS_OK when g_tcpSrvDataList is not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvDataListInitTest001, TestSize.Level1)
{
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransSrvDataListInitTest002
 * @tc.desc: Should return SOFTBUS_OK when CreateSoftBusList return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvDataListInitTest002, TestSize.Level1)
{
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(nullptr));
    int32_t ret = TransSrvDataListInit();
    TransSrvDestroyDataBuf();
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
}

/**
 * @tc.name: TransSrvGetDataBufNodeById001
 * @tc.desc: Should return SOFTBUS_OK when CreateSoftBusList return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvGetDataBufNodeById001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    ServerDataBuf *ret = TransSrvGetDataBufNodeById(channelId);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: TransSrvAddDataBufNodeTest001
 * @tc.desc: Should return SOFTBUS_LOCK_ERR when g_tcpSrvDataList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvAddDataBufNodeTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t fd = TEST_FD;
    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/**
 * @tc.name: TransTdcPostBytesTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when given invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    const char *data = "test";
    packetHead.dataLen = 0;
    int32_t ret = TransTdcPostBytes(channelId, nullptr, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransTdcPostBytes(channelId, &packetHead, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransTdcPostBytesTest002
 * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    // will free in TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    int32_t bufferLen = AuthGetEncryptSize(authId, packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillOnce(Return(bufferLen));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: TransTdcPostBytesTest003
 * @tc.desc: Should return GetErrCodeBySocketErr when ConnSendSocketData fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    // will free in TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(0));

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EINTR));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EINTR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_BAD_FD));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_BAD_FD, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EAGAIN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EAGAIN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_ERR));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_ERR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_FULL_FD));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_FULL_FD, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_PIPE_INTER));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_PIPE_INTER, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: TransTdcPostBytesTest003_1
 * @tc.desc: Should return GetErrCodeBySocketErr when ConnSendSocketData fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest003_1, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    // will free in TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(0));

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_SOCKET));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_SOCKET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_IN_USE));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_IN_USE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_DOWN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_NET_REACH));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_NET_REACH, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_RESET));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_RESET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_CONN_RESET));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_CONN_RESET, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: TransTdcPostBytesTest003_2
 * @tc.desc: Should return GetErrCodeBySocketErr when ConnSendSocketData fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest003_2, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    // will free in TransDelSessionConnById
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(0));

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_BUFS));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_BUFS, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_IS_CONN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_IS_CONN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_CONN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_CONN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TIME_OUT));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TIME_OUT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_REFUSED));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_REFUSED, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_HOST_DOWN));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_HOST_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE));
    ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: TransTdcPostBytesTest004
 * @tc.desc: Should return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_GET_SESSION_CONN_FAILED, ret);
}

/**
 * @tc.name: TransTdcPostBytesTest005
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR when AuthEncrypt return SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest005, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
}

/**
 * @tc.name: TransTdcPostBytesTest006
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR when GetAuthHandleByChanId return AUTH_INVALID_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest006, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    const char *data = "test";
    TestTdcPacketHeadInit(&packetHead);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);
}

/**
 * @tc.name: TransSrvAddDataBufNodeTest002
 * @tc.desc: Should return SOFTBUS_OK when given valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvAddDataBufNodeTest002, TestSize.Level1)
{
    // list will free when go to TransSrvDataListDeinit
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    EXPECT_TRUE(list != nullptr);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&list->lock, &mutexAttr);
    ListInit(&list->list);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(list));
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = TEST_CHANNELID;
    int32_t fd = TEST_FD;
    ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransSrvDataListDeinit();
}

/**
 * @tc.name: TransTdcSrvRecvDataTest001
 * @tc.desc: Should return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED when g_tcpSrvDataList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    int32_t ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI), channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, ret);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest002
 * @tc.desc: Should return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED
        when can not find parameter in list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    // list will free when go to TransSrvDataListDeinit
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    EXPECT_TRUE(list != nullptr);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&list->lock, &mutexAttr);
    ListInit(&list->list);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(list));
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI), channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, ret);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest003
 * @tc.desc: Should return SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED  when ConnRecvSocketData return -1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    int32_t fd = TEST_FD;
    int32_t recvLen = -1;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillOnce(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI), channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, ret);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest004
 * @tc.desc: Should return SOFTBUS_DATA_NOT_ENOUGH  when ConnRecvSocketData return 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    int32_t fd = TEST_FD;
    int32_t recvLen = 0;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillOnce(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI),
        channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, ret);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest005
 * @tc.desc: Should return SOFTBUS_DATA_NOT_ENOUGH  when ConnRecvSocketData return 1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest005, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    int32_t fd = TEST_FD;
    int32_t recvLen = 2;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillRepeatedly(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI),
        channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED, ret);
}

/**
 * @tc.name: TransTdcSrvRecvDataTest006
 * @tc.desc: Should return SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED  when ConnRecvSocketData return 25.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcSrvRecvDataTest006, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t type = 0;
    int32_t fd = TEST_FD;
    int32_t recvLen = VALIDRECVLEN;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillRepeatedly(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ServerDataBuf *buf = TransSrvGetDataBufNodeById(channelId);
    EXPECT_NE(nullptr, buf);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI),
        channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED, ret);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED  when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;

    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest002
 * @tc.desc: Should return SOFTBUS_MEM_ERR  when TransTdcGetPkgName return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest002, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest003
 * @tc.desc: Should return SOFTBUS_OK  when TransTdcGetPkgName return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest003, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest004
 * @tc.desc: Should return SOFTBUS_MEM_ERR  when TransTdcOnChannelOpenFailed return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest004, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->serverSide = false;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ChannelInfo info = {0};
    GetChannelInfoFromConn(&info, conn, channelId);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelOpenFailed).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelOpenFailed).WillOnce(Return(SOFTBUS_OK));
    ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: GetServerSideIpInfoTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED when LnnGetLocalStrInfo return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetServerSideIpInfoTest001, TestSize.Level1)
{
    uint32_t len = 10;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_STA;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = GetServerSideIpInfo(&conn->appInfo, const_cast<char *>(IP), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LOCAL_IP_FAILED);
    conn->appInfo.routeType = WIFI_P2P;

    ret = GetServerSideIpInfo(&conn->appInfo, const_cast<char *>(IP), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_P2P_INFO_FAILED);

    ReleaseSessionConn(conn);
}

/**
 * @tc.name: GetClientSideIpInfoTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED when LnnGetLocalStrInfo return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetClientSideIpInfoTest001, TestSize.Level1)
{
    uint32_t len = 10;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_STA;

    char myIp[IP_LEN] = { 0 };
    int32_t ret = GetClientSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    conn->appInfo.routeType = WIFI_P2P;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = GetClientSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = GetClientSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_OK));
    ret = GetClientSideIpInfo(&conn->appInfo, myIp, len);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ReleaseSessionConn(conn);
}

/**
 * @tc.name: TransTdcPostFisrtDataTest001
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR when TransTdcPackFastData return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostFisrtDataTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = TransTdcPostFastData(conn);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);

    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);

    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(1));
    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EINTR));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EINTR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_BAD_FD));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_BAD_FD, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EAGAIN));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EAGAIN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_ERR));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_ERR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_FULL_FD));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_FULL_FD, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_PIPE_INTER));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_PIPE_INTER, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_SOCKET));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_SOCKET, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: TransTdcPostFisrtDataTest001_1
 * @tc.desc: Should return GetErrCodeBySocketErr when ConnSendSocketData return fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostFisrtDataTest001_1, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(1));
    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN));
    int32_t ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_IN_USE));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_IN_USE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_DOWN));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_NET_REACH));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_NET_REACH, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_RESET));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_RESET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_CONN_RESET));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_CONN_RESET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_BUFS));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_BUFS, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_IS_CONN));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_IS_CONN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_CONN));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_CONN, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    ReleaseSessionConn(conn);
}

/**
 * @tc.name: TransTdcPostFisrtDataTest001_2
 * @tc.desc: Should return GetErrCodeBySocketErr when ConnSendSocketData return fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostFisrtDataTest001_2, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillRepeatedly(Return(1));
    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TIME_OUT));
    int32_t ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TIME_OUT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_REFUSED));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_REFUSED, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_HOST_DOWN));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_HOST_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).
        WillOnce(Return(conn->appInfo.fastTransDataSize + FAST_TDC_EXT_DATA_SIZE));
    ret = TransTdcPostFastData(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    ReleaseSessionConn(conn);
}

/**
 * @tc.name: OpenDataBusReplyTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();

    int32_t ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest002
 * @tc.desc: Should return SOFTBUS_OK when UnpackReplyErrCode return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_OK));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest003
 * @tc.desc: Should return SOFTBUS_TRANS_UNPACK_REPLY_FAILED when UnpackReply return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UNPACK_REPLY_FAILED);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest004
 * @tc.desc: Should return SOFTBUS_MEM_ERR when UnpackReply return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest005
 * @tc.desc: Should return SOFTBUS_MEM_ERR when SetAppInfoById return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest005, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EINTR));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EINTR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_BAD_FD));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_BAD_FD, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EAGAIN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EAGAIN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_ERR));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_ERR, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_FULL_FD));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_FULL_FD, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest005_1
 * @tc.desc: Should return SOFTBUS_MEM_ERR when SetAppInfoById return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest005_1, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_PIPE_INTER));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_PIPE_INTER, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_SOCKET));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_SOCKET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_IN_USE));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_IN_USE, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_DOWN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_NET_REACH));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_NET_REACH, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_RESET));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_RESET, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_CONN_RESET));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_CONN_RESET, ret);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest005_2
 * @tc.desc: Should return SOFTBUS_MEM_ERR when SetAppInfoById return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest005_2, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_BUFS));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_BUFS, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_IS_CONN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_IS_CONN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_CONN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_CONN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TIME_OUT));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TIME_OUT, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_REFUSED));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_REFUSED, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_HOST_DOWN));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_HOST_DOWN, ret);

    EXPECT_CALL(TcpMessageMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE, ret);

    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetIpTos).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).
        WillOnce(Return(conn->appInfo.fastTransDataSize + FAST_TDC_EXT_DATA_SIZE));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_P2P_INFO_FAILED);
    testing::Mock::VerifyAndClearExpectations(&TcpMessageMock);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest006
 * @tc.desc: Should return SOFTBUS_MEM_ERR when SetAppInfoById return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest006, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->appInfo.fastTransDataSize = 0;
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_P2P_INFO_FAILED);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: GetUuidByChanIdTest001
 * @tc.desc: Should return SOFTBUS_OK when SetAppInfoById return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetUuidByChanIdTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    const char *uuid = "123123";
    uint32_t len = 7;
    int32_t authId = TEST_AUTHID;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(authId));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = GetUuidByChanId(channelId, const_cast<char *>(uuid), len);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: GetSessionConnFromDataBusRequestTest001
 * @tc.desc: Should return ret when UnpackRequest return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetSessionConnFromDataBusRequestTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_OK));
    SessionConn *connect = GetSessionConnFromDataBusRequest(channelId, reply);
    EXPECT_TRUE(connect != nullptr);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: GetSessionConnFromDataBusRequestTest002
 * @tc.desc: Should return nullptr when UnpackRequest return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetSessionConnFromDataBusRequestTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_MEM_ERR));
    SessionConn *connect = GetSessionConnFromDataBusRequest(channelId, reply);
    EXPECT_TRUE(connect == nullptr);

    TransDelSessionConnById(channelId);
    cJSON_Delete(reply);
}

/**
 * @tc.name: GetSessionConnFromDataBusRequestTest003
 * @tc.desc: Should return nullptr when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetSessionConnFromDataBusRequestTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    cJSON *reply = cJSON_CreateObject();

    SessionConn *connect = GetSessionConnFromDataBusRequest(channelId, reply);
    EXPECT_TRUE(connect == nullptr);

    cJSON_Delete(reply);
}

/**
 * @tc.name: IsMetaSessionTest001
 * @tc.desc: Should return false when sessionname len less than 6.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, IsMetaSessionTest001, TestSize.Level1)
{
    const char *sessionName = "test";

    bool ret = IsMetaSession(sessionName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsMetaSessionTest002
 * @tc.desc: Should return false when sessionname is not IShare.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, IsMetaSessionTest002, TestSize.Level1)
{
    const char *sessionName = "testSessionName";

    bool ret = IsMetaSession(sessionName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsMetaSessionTest003
 * @tc.desc: Should return true when sessionname is IShare.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, IsMetaSessionTest003, TestSize.Level1)
{
    const char *sessionName = "IShare";

    bool ret = IsMetaSession(sessionName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: OpenDataBusRequestTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusRequestTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t flags = 1;
    cJSON *reply = cJSON_CreateObject();

    int32_t ret = OpenDataBusRequest(channelId, flags, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusRequestError001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusRequestError001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t flags = 1;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    char *errDesc = const_cast<char *>(reinterpret_cast<const char *>("Notify SDK Channel Opened Failed"));

    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = OpenDataBusRequestError(channelId, seq, errDesc, errCode, flags);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest001
 * @tc.desc: Should return TEST_AUTHID when GetAuthHandleByChanId return TEST_AUTHID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;
    int32_t ret = GetAuthIdByChannelInfo(channelId, seq, cipherFlag, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, TEST_AUTHID);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest002
 * @tc.desc: Should return AUTH_INVALID_ID when GetAppInfoById return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_MEM_ERR));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_MEM_ERR));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, AUTH_INVALID_ID);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest003
 * @tc.desc: Should return AUTH_INVALID_ID when GetAppInfoById return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, AUTH_INVALID_ID);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest004
 * @tc.desc: Should return AUTH_INVALID_ID when GetRemoteUuidByIp return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_NOT_FIND));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetRemoteUuidByIp).WillRepeatedly(Return(SOFTBUS_NOT_FIND));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, AUTH_INVALID_ID);
}

/**
 * @tc.name: DecryptMessageTest001
 * @tc.desc: Should return SOFTBUS_OK when AuthDecrypt return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, DecryptMessageTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead pktHead = {0};
    pktHead.dataLen = 10;
    uint8_t *pktData = nullptr;
    uint8_t *outData = nullptr;
    uint32_t outDataLen = 10;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, SetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthDecrypt).WillOnce(Return(SOFTBUS_OK));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: DecryptMessageTest002
 * @tc.desc: Should return SOFTBUS_DECRYPT_ERR when AuthDecrypt return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, DecryptMessageTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead pktHead = {0};
    pktHead.dataLen = 10;
    uint8_t *pktData = nullptr;
    uint8_t *outData = nullptr;
    uint32_t outDataLen = 10;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, SetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthDecrypt).WillOnce(Return(SOFTBUS_NOT_FIND));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_DECRYPT_ERR);
}

/**
 * @tc.name: DecryptMessageTest003
 * @tc.desc: Should return SOFTBUS_NOT_FIND when SetAuthHandleByChanId return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, DecryptMessageTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead pktHead = {0};
    pktHead.dataLen = 10;
    uint8_t *pktData = nullptr;
    uint8_t *outData = nullptr;
    uint32_t outDataLen = 10;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, SetAuthHandleByChanId).WillOnce(Return(SOFTBUS_NOT_FIND));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: DecryptMessageTest004
 * @tc.desc: Should return SOFTBUS_NOT_FIND when GetAuthHandleByChanId return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, DecryptMessageTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead pktHead = {0};
    pktHead.dataLen = 10;
    uint8_t *pktData = nullptr;
    uint8_t *outData = nullptr;
    uint32_t outDataLen = 10;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, SetAuthHandleByChanId).WillOnce(Return(SOFTBUS_OK));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: NotifyChannelOpenedTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED
 *     when TransTdcGetPkgName return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);

    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_P2P_INFO_FAILED);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: NotifyChannelOpenedTest002
 * @tc.desc: Should return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED
 *     when TransTdcGetPkgName return SOFTBUS_TRANS_GET_SESSION_CONN_FAILED.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenedTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    conn->serverSide = false;

    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_PID_FAILED);

    EXPECT_CALL(TcpMessageMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnSetDLP2pIp).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetNetworkIdByUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransGetLaneIdByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelOpened).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(TcpMessageMock, SetSessionConnStatusById).WillOnce(Return(SOFTBUS_OK));
    ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: NotifyChannelBindTest001
 * @tc.desc: Should return AUTH_LINK_TYPE_ENHANCED_P2P  when cipherFlag is FLAG_ENHANCE_P2P.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelBindTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t ret = NotifyChannelBind(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);

    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = NotifyChannelBind(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelBind).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = NotifyChannelBind(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: SwitchCipherTypeToAuthLinkTypeTest001
 * @tc.desc: Should return AUTH_LINK_TYPE_ENHANCED_P2P  when cipherFlag is FLAG_ENHANCE_P2P.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, SwitchCipherTypeToAuthLinkTypeTest001, TestSize.Level1)
{
    uint32_t cipherFlag = FLAG_ENHANCE_P2P;
    AuthLinkType linkType = SwitchCipherTypeToAuthLinkType(cipherFlag);
    EXPECT_EQ(linkType, AUTH_LINK_TYPE_ENHANCED_P2P);
}

/**
 * @tc.name: PackBytesTest001
 * @tc.desc: Should return SOFTBUS_OK  when AuthEncrypt return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, PackBytesTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    SessionConn connInfo;
    (void)memset_s(&connInfo, sizeof(SessionConn), 0, sizeof(SessionConn));

    const char *data = "test";
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
    connInfo.appInfo.fd = TEST_FD;
    int64_t authId = TEST_AUTHID;
    int32_t bufferLen = AuthGetEncryptSize(authId, packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = static_cast<char *>(SoftBusCalloc(bufferLen));
    EXPECT_TRUE(buffer != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = PackBytes(channelId, data, &packetHead, buffer, bufferLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(buffer);
}

/**
 * @tc.name: PackBytesTest002
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR  when AuthEncrypt return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, PackBytesTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    SessionConn connInfo;
    (void)memset_s(&connInfo, sizeof(SessionConn), 0, sizeof(SessionConn));

    const char *data = "test";
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
    connInfo.appInfo.fd = TEST_FD;
    int64_t authId = TEST_AUTHID;
    int32_t bufferLen = AuthGetEncryptSize(authId, packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = static_cast<char *>(SoftBusCalloc(bufferLen));
    EXPECT_TRUE(buffer != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = PackBytes(channelId, data, &packetHead, buffer, bufferLen);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);

    SoftBusFree(buffer);
}

/**
 * @tc.name: PackBytesTest003
 * @tc.desc: Should return SOFTBUS_NOT_FIND  when AuthEncrypt return SOFTBUS_NOT_FIND.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, PackBytesTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    TdcPacketHead packetHead = {0};
    SessionConn connInfo;
    (void)memset_s(&connInfo, sizeof(SessionConn), 0, sizeof(SessionConn));

    const char *data = "test";
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
    connInfo.appInfo.fd = TEST_FD;
    int64_t authId = TEST_AUTHID;
    int32_t bufferLen = AuthGetEncryptSize(authId, packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = static_cast<char *>(SoftBusCalloc(bufferLen));
    EXPECT_TRUE(buffer != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = PackBytes(channelId, data, &packetHead, buffer, bufferLen);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    SoftBusFree(buffer);
}

/**
 * @tc.name: TransGetLocalConfigTest001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM  when channelType is invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransGetLocalConfigTest001, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_PROXY;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    uint32_t len = 1;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    int32_t ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransGetLocalConfigTest002
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR  when TransGetLocalConfig return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransGetLocalConfigTest002, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    uint32_t len = 1;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    int32_t ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_GET_CONFIG_VAL_ERR, ret);
}

/**
 * @tc.name: TransTdcProcessDataConfigTest001
 * @tc.desc: Should return SOFTBUS_OK  when TransGetLocalConfig return SOFTBUS_MEM_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcProcessDataConfigTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->peerData.dataConfig = 1;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int32_t ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->peerData.dataConfig = 0;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcProcessDataConfig(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: ProcessMessageTest001
 * @tc.desc: Should return SOFTBUS_OK  when UnpackReplyErrCode return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, ProcessMessageTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = FLAG_REPLY;
    uint64_t seq = TEST_SEQ;
    const char *msg = "testmsg";
    uint32_t dataLen = 0;
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ProcessMessage(channelId, flags, seq, msg, dataLen);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    TransDelSessionConnById(channelId);
}

/**
 * @tc.name: ProcessMessageTest002
 * @tc.desc: Should return SOFTBUS_OK  when UnpackReplyErrCode return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, ProcessMessageTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = FLAG_WIFI;
    uint64_t seq = TEST_SEQ;
    const char *msg = "testmsg";
    uint32_t dataLen = 0;

    int32_t ret = ProcessMessage(channelId, flags, seq, msg, dataLen);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
 * @tc.name: StartVerifySessionTest001
 * @tc.desc: Should return SOFTBUS_TRANS_PACK_REQUEST_FAILED  when PackRequest return NULL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, StartVerifySessionTest001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = StartVerifySession(conn);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GENERATE_SESSIONKEY_FAILED, ret);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: StartVerifySessionTest002
 * @tc.desc: Should return SOFTBUS_TRANS_PACK_REQUEST_FAILED  when PackRequest return NULL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, StartVerifySessionTest002, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusGenerateSessionKey).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthGetServerSide).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, PackRequest).WillOnce(Return(NULL));
    int32_t ret = StartVerifySession(conn);
    EXPECT_EQ(SOFTBUS_TRANS_PACK_REQUEST_FAILED, ret);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: StartVerifySessionTest003
 * @tc.desc: Should return SOFTBUS_TRANS_PACK_REQUEST_FAILED  when PackRequest return NULL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, StartVerifySessionTest003, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    TdcPacketHead packetHead = {0};
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10; // test value
    packetHead.module = 10; // test value
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    // will free in StartVerifySession
    char *data = cJSON_PrintUnformatted(json);
    ASSERT_TRUE(data != nullptr);
    cJSON_Delete(json);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftBusGenerateSessionKey).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthGetServerSide).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthGetConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, PackRequest).WillRepeatedly(Return(data));
    int32_t ret = StartVerifySession(conn);
    EXPECT_EQ(SOFTBUS_TRANS_GET_SESSION_CONN_FAILED, ret);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: CreateSessionConnNode001
 * @tc.desc: Should return SOFTBUS_TRANS_PACK_REQUEST_FAILED  when PackRequest return NULL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, CreateSessionConnNode001, TestSize.Level1)
{
    ConnectOption *clientAddr = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(clientAddr != nullptr);

    ListenerModule module = UNUSE_BUTT;
    int32_t fd = NORMAL_FD;
    int32_t channelId = TEST_CHANNELID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = CreateSessionConnNode(module, fd, channelId, clientAddr);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(clientAddr);
}

/**
 * @tc.name: NotifyFastDataRecv001
 * @tc.desc: test NotifyFastDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyFastDataRecv001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    int32_t channelId = TEST_CHANNELID;
    conn->appInfo.businessType = BUSINESS_TYPE_MESSAGE;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcOnMsgReceived).WillOnce(Return(SOFTBUS_OK));
    NotifyFastDataRecv(conn, channelId);

    conn->appInfo.businessType = BUSINESS_TYPE_BYTE;
    EXPECT_CALL(TcpMessageMock, TransTdcOnMsgReceived).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    NotifyFastDataRecv(conn, channelId);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: TransTdcFillDataConfig001
 * @tc.desc: Should return SOFTBUS_TRANS_PACK_REQUEST_FAILED  when PackRequest return NULL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcFillDataConfig001, TestSize.Level1)
{
    AppInfo *appInfo = TestSetAppInfo();
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->peerData.dataConfig = 0;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_MEM_ERR));
    int32_t ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcFillDataConfig(appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: ReportTransEventExtra001
 * @tc.desc: test ReportTransEventExtra.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, ReportTransEventExtra001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    TransEventExtra extra;
    int32_t channelId = TEST_CHANNELID;
    NodeInfo nodeInfo;
    (void)memcpy_s(nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN, IP, UDID_BUF_LEN);
    (void)memcpy_s(nodeInfo.masterUdid, UDID_BUF_LEN, IP, UDID_BUF_LEN);
    (void)memcpy_s(nodeInfo.deviceInfo.deviceVersion, DEVICE_VERSION_SIZE_MAX, DEVICE_VERSION, DEVICE_VERSION_SIZE_MAX);
    char *peerUuid = const_cast<char *>(reinterpret_cast<const char *>("test.uuid"));
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(1));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_OK));
    ReportTransEventExtra(&extra, channelId, conn, &nodeInfo, peerUuid);
    EXPECT_EQ(extra.channelId, channelId);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: TransTdcFillAppInfoAndNotifyChannel001
 * @tc.desc: Test TransTdcFillAppInfoAndNotifyChannel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcFillAppInfoAndNotifyChannel001, TestSize.Level1)
{
    AppInfo *appInfo = TestSetAppInfo();
    ASSERT_TRUE(appInfo != nullptr);
    int32_t channelId = TEST_CHANNELID;
    char *errDesc = static_cast<char *>(SoftBusCalloc(MAX_ERRDESC_LEN));
    ASSERT_TRUE(errDesc != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransCheckServerAccessControl).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_CHECK_ACL_FAILED);
    appInfo->callingTokenId = 0;
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED);
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(AUTH_INVALID_ID));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_AUTH_ID_FAILED);
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(1));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(1));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillOnce(Return(SOFTBUS_MEM_ERR));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(1));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(TcpMessageMock, TransTdcGetUidAndPid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetAuthIdByChanId).WillOnce(Return(1));
    EXPECT_CALL(TcpMessageMock, AuthGetDeviceUuid).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, CheckCollabRelation).WillOnce(Return(SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION));
    ret = TransTdcFillAppInfoAndNotifyChannel(appInfo, channelId, errDesc);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
    SoftBusFree(appInfo);
    SoftBusFree(errDesc);
}

/**
 * @tc.name: HandleDataBusReply001
 * @tc.desc: test HandleDataBusReply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, HandleDataBusReply001, TestSize.Level1)
{
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    TransEventExtra extra;
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = FLAG_REPLY;
    uint64_t seq = TEST_SEQ;
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelClosed).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = HandleDataBusReply(conn, channelId, &extra, flags, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_SESSION_CONN_FAILED);
    ReleaseSessionConn(conn);
}

/**
 * @tc.name: OpenDataBusRequestTest002
 * @tc.desc: Test GetSessionConnFromDataBusRequest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusRequestTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = 0;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    ASSERT_TRUE(conn != nullptr);
    SessionConn *testConn = TestSetSessionConn();
    ASSERT_TRUE(testConn != nullptr);
    (void)memcpy_s(conn->appInfo.myData.sessionName, SESSION_NAME_SIZE_MAX, META_SESSION, (strlen(SESSION_NAME)+1));
    int32_t ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(ret, SOFTBUS_OK);
    testConn->channelId = TEST_NEW_CHANNEL_ID;
    ret = TransTdcAddSessionConn(testConn);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = OpenDataBusRequest(channelId, flags, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_OK));
    ret = OpenDataBusRequest(channelId, flags, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_SERVER_DENIED);
    flags = FLAG_AUTH_META;
    channelId = TEST_NEW_CHANNEL_ID;
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_OK));
    ret = OpenDataBusRequest(channelId, flags, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NOT_META_SESSION);

    TransDelSessionConnById(TEST_NEW_CHANNEL_ID);
    TransDelSessionConnById(TEST_CHANNELID);
    cJSON_Delete(reply);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest0011
 * @tc.desc: GetCipherFlagByAuthId, use correct parameters.
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(TransTcpDirectMessageAppendTest, GetCipherFlagByAuthIdTest0011, TestSize.Level1)
{
    bool isAuthServer = false;
    bool isLegacyOs = false;
    AuthHandle authHandle = { .authId = 1, .type = AUTH_LINK_TYPE_WIFI };
    uint32_t flag = 0;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, AuthGetServerSide).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, AuthGetConnInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetCipherFlagByAuthId(authHandle, &flag, &isAuthServer, isLegacyOs);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}
