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
#include "softbus_errcode.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_server_frame.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_message.c"
#include "trans_tcp_direct_message_test_mock.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNELID 1
#define TEST_AUTHID 947461667
#define PKG_NAME_SIZE_MAX_LEN 65
#define IP_LEN 46
#define DEVICE_ID_SIZE_MAX 65
#define TEST_LEN 50
#define TEST_SEQ 10
#define TEST_FLAG 2
#define TEST_FD 1
#define ERRMOUDLE 13
#define VALIDRECVLEN 25
#define ERR_CHANNELID (-1)
#define INVALID_VALUE (-1)
static const char *PKGE_NAME = "dms";
static const char *IP = "192.168.8.1";

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
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&list->lock, &mutexAttr);
    ListInit(&list->list);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, CreateSoftBusList).WillOnce(Return(list));
    int32_t ret = TransSrvDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void TransTcpDirectMessageAppendTest::TearDownTestCase(void)
{
    (void)TransSrvDataListDeinit();
}

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }
    conn->serverSide = true;
    conn->appInfo.fd = TEST_FD;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = INVALID_VALUE;
    conn->authHandle.authId = 1;
    conn->requestId = 0;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    conn->appInfo.peerData.dataConfig = 0;
    conn->appInfo.linkType = 1;
    conn->appInfo.routeType = WIFI_P2P;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, PKGE_NAME, (strlen(PKGE_NAME)+1));
    return conn;
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
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransSrvAddDataBufNodeTest001
 * @tc.desc: Should return SOFTBUS_ERR when g_tcpSrvDataList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransSrvAddDataBufNodeTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    int32_t fd = TEST_FD;
    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_ERR, ret);
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
    int bufferLen = AuthGetEncryptSize(packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(&connInfo));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillOnce(Return(bufferLen));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransTdcPostBytesTest003
 * @tc.desc: Should return SOFTBUS_ERR when ConnSendSocketData return zero.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostBytesTest003, TestSize.Level1)
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
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(&connInfo));
    EXPECT_CALL(TcpMessageMock, ConnSendSocketData).WillOnce(Return(0));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_ERR, ret);
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
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
    int64_t authId = TEST_AUTHID;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
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
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
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
    packetHead.dataLen = TEST_LEN;
    packetHead.flags = TEST_FLAG;
    packetHead.seq = TEST_SEQ;
    packetHead.magicNumber = 10;
    packetHead.module = 10;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = TransTdcPostBytes(channelId, &packetHead, data);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
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
    int ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI), channelId, type);
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
 * @tc.desc: Should return SOFTBUS_ERR  when ConnRecvSocketData return -1.
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
    EXPECT_EQ(SOFTBUS_ERR, ret);
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
    EXPECT_EQ(SOFTBUS_DATA_NOT_ENOUGH, ret);
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
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillOnce(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI),
        channelId, type);
    EXPECT_EQ(SOFTBUS_DATA_NOT_ENOUGH, ret);
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
    EXPECT_CALL(TcpMessageMock, ConnRecvSocketData).WillOnce(Return(recvLen));

    int32_t ret = TransSrvAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransTdcSrvRecvData(ListenerModule(DIRECT_CHANNEL_SERVER_WIFI),
        channelId, type);
    EXPECT_EQ(SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED, ret);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest001
 * @tc.desc: Should return SOFTBUS_ERR  when GetSessionConnById return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest001, TestSize.Level1)
{
    int errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest002
 * @tc.desc: Should return SOFTBUS_ERR  when TransTdcGetPkgName return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest002, TestSize.Level1)
{
    int errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(conn);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest003
 * @tc.desc: Should return SOFTBUS_OK  when TransTdcGetPkgName return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest003, TestSize.Level1)
{
    int errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(conn);
}

/**
 * @tc.name: NotifyChannelOpenFailedTest004
 * @tc.desc: Should return SOFTBUS_ERR  when TransTdcOnChannelOpenFailed return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest004, TestSize.Level1)
{
    int errCode = SOFTBUS_OK;
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);
    ChannelInfo info = {0};
    GetChannelInfoFromConn(&info, conn, channelId);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, TransTdcGetPkgName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, TransTdcOnChannelOpenFailed).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = NotifyChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(conn);
}

/**
 * @tc.name: GetServerSideIpInfoTest001
 * @tc.desc: Should return SOFTBUS_TRANS_GET_LOCAL_IP_FAILED when LnnGetLocalStrInfo return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetServerSideIpInfoTest001, TestSize.Level1)
{
    uint32_t len = 10;
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_STA;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = GetServerSideIpInfo(conn, const_cast<char *>(IP), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LOCAL_IP_FAILED);

    SoftBusFree(conn);
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
    EXPECT_TRUE(conn != nullptr);
    conn->appInfo.routeType = WIFI_STA;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = GetClientSideIpInfo(conn, const_cast<char *>(IP), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_GET_LOCAL_IP_FAILED);

    SoftBusFree(conn);
}

/**
 * @tc.name: TransTdcPostFisrtDataTest001
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR when TransTdcPackFastData return nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransTdcPostFisrtDataTest001, TestSize.Level1)
{
    SessionConn conn;
    (void)memset_s(&conn, sizeof(SessionConn), 0, sizeof(SessionConn));

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, TransTdcPackFastData).WillOnce(Return(nullptr));
    int32_t ret = TransTdcPostFisrtData(&conn);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
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

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
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
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillRepeatedly(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(conn);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest003
 * @tc.desc: Should return SOFTBUS_TRANS_UNPACK_REPLY_FAILED when UnpackReply return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_TRANS_UNPACK_REPLY_FAILED);

    SoftBusFree(conn);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest004
 * @tc.desc: Should return SOFTBUS_ERR when UnpackReply return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillRepeatedly(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(conn);
    cJSON_Delete(reply);
}

/**
 * @tc.name: OpenDataBusReplyTest005
 * @tc.desc: Should return SOFTBUS_ERR when SetAppInfoById return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, OpenDataBusReplyTest005, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillRepeatedly(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, UnpackReply).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, SetAppInfoById).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = OpenDataBusReply(channelId, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(conn);
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
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_OK));
    SessionConn *connect = GetSessionConnFromDataBusRequest(channelId, reply);
    EXPECT_TRUE(connect != nullptr);

    SoftBusFree(conn);
    cJSON_Delete(reply);
}

/**
 * @tc.name: GetSessionConnFromDataBusRequestTest002
 * @tc.desc: Should return nullptr when UnpackRequest return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetSessionConnFromDataBusRequestTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    cJSON *reply = cJSON_CreateObject();
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackRequest).WillOnce(Return(SOFTBUS_ERR));
    SessionConn *connect = GetSessionConnFromDataBusRequest(channelId, reply);
    EXPECT_TRUE(connect == nullptr);

    SoftBusFree(conn);
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

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
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

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
    int32_t ret = OpenDataBusRequest(channelId, flags, seq, reply);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON_Delete(reply);
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

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = TEST_AUTHID, .type = 1 }), Return(SOFTBUS_OK)));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, TEST_AUTHID);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest002
 * @tc.desc: Should return AUTH_INVALID_ID when GetAppInfoById return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_ERR));
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
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    (void)GetAuthIdByChannelInfo(channelId, seq, cipherFlag, &authHandle);
    EXPECT_EQ(authHandle.authId, AUTH_INVALID_ID);
}

/**
 * @tc.name: GetAuthIdByChannelInfoTest004
 * @tc.desc: Should return AUTH_INVALID_ID when GetRemoteUuidByIp return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, GetAuthIdByChannelInfoTest004, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    uint64_t seq = TEST_SEQ;
    uint32_t cipherFlag = 1;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(TcpMessageMock, GetAppInfoById).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TcpMessageMock, GetRemoteUuidByIp).WillOnce(Return(SOFTBUS_ERR));
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
 * @tc.desc: Should return SOFTBUS_DECRYPT_ERR when AuthDecrypt return SOFTBUS_ERR.
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
    EXPECT_CALL(TcpMessageMock, AuthDecrypt).WillOnce(Return(SOFTBUS_ERR));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_DECRYPT_ERR);
}

/**
 * @tc.name: DecryptMessageTest003
 * @tc.desc: Should return SOFTBUS_ERR when SetAuthHandleByChanId return SOFTBUS_ERR.
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
    EXPECT_CALL(TcpMessageMock, SetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: DecryptMessageTest004
 * @tc.desc: Should return SOFTBUS_NOT_FIND when GetAuthHandleByChanId return AUTH_INVALID_ID.
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
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
    int64_t ret = DecryptMessage(channelId, &pktHead, pktData, &outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: NotifyChannelOpenedTest001
 * @tc.desc: Should return SOFTBUS_ERR  when TransTdcGetPkgName return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenedTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
    int32_t ret = NotifyChannelOpened(channelId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: NotifyChannelOpenedTest002
 * @tc.desc: Should return SOFTBUS_ERR  when TransTdcGetPkgName return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenedTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNELID;
    SessionConn *conn = TestSetSessionConn();
    EXPECT_TRUE(conn != nullptr);

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(conn));
    int32_t ret = NotifyChannelOpened(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);

    SoftBusFree(conn);
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
    int bufferLen = AuthGetEncryptSize(packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
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
 * @tc.desc: Should return SOFTBUS_ENCRYPT_ERR  when AuthEncrypt return SOFTBUS_ERR.
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
    int bufferLen = AuthGetEncryptSize(packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = static_cast<char *>(SoftBusCalloc(bufferLen));
    EXPECT_TRUE(buffer != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    ON_CALL(TcpMessageMock, GetAuthHandleByChanId(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(AuthHandle{.authId = authId, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(TcpMessageMock, AuthEncrypt).WillOnce(Return(SOFTBUS_ERR));
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
    int bufferLen = AuthGetEncryptSize(packetHead.dataLen) + DC_MSG_PACKET_HEAD_SIZE;
    char *buffer = static_cast<char *>(SoftBusCalloc(bufferLen));
    EXPECT_TRUE(buffer != nullptr);
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillOnce(Return(SOFTBUS_ERR));
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
    EXPECT_CALL(TcpMessageMock, GetAuthHandleByChanId).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransGetLocalConfigTest002
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR  when TransGetLocalConfig return SOFTBUS_ERR.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, TransGetLocalConfigTest002, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    uint32_t len = 1;
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = TransGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_GET_CONFIG_VAL_ERR, ret);
}

/**
 * @tc.name: TransTdcProcessDataConfigTest001
 * @tc.desc: Should return SOFTBUS_ERR  when TransGetLocalConfig return SOFTBUS_ERR.
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
    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = TransTdcProcessDataConfig(appInfo);
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
    // reply will free when go to ProcessMessage
    cJSON *reply = cJSON_CreateObject();
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = FLAG_REPLY;
    uint64_t seq = TEST_SEQ;
    const char *msg = "testmsg";
    SessionConn *conn = TestSetSessionConn();

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, cJSON_Parse).WillRepeatedly(Return(reply));
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillRepeatedly(Return(conn));
    EXPECT_CALL(TcpMessageMock, UnpackReplyErrCode).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = ProcessMessage(channelId, flags, seq, msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(conn);
}

/**
 * @tc.name: ProcessMessageTest002
 * @tc.desc: Should return SOFTBUS_OK  when UnpackReplyErrCode return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, ProcessMessageTest002, TestSize.Level1)
{
    // reply will free when go to ProcessMessage
    cJSON *reply = cJSON_CreateObject();
    int32_t channelId = TEST_CHANNELID;
    uint32_t flags = FLAG_WIFI;
    uint64_t seq = TEST_SEQ;
    const char *msg = "testmsg";

    NiceMock<TransTcpDirectMessageInterfaceMock> TcpMessageMock;
    EXPECT_CALL(TcpMessageMock, cJSON_Parse).WillRepeatedly(Return(reply));
    EXPECT_CALL(TcpMessageMock, GetSessionConnById).WillOnce(Return(nullptr));
    int32_t ret = ProcessMessage(channelId, flags, seq, msg);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
}
