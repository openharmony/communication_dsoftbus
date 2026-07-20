/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include <sys/socket.h>

#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_listener.c"
#include "client_trans_tcp_direct_manager.c"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.c"
#include "client_trans_tcp_direct_message.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "trans_tcp_direct_mock.h"
#include "trans_tcp_process_data.c"
#include "trans_tcp_process_data.h"

#define MAX_LEN        2048
#define TEST_FD        10
#define COUNT          11
#define PKG_LEN        32
#define RECV_BUF       "testABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00"
#define BUF_LEN        10
#define SESSIONKEY_LEN 32
#define INVALID_VALUE  (-1)

#define TRANS_TEST_SESSION_ID         10
#define TRANS_TEST_CHANNEL_ID         1000
#define TRANS_TEST_FILE_ENCRYPT       10
#define TRANS_TEST_ALGORITHM          1
#define TRANS_TEST_CRC                1
#define TRANS_TEST_FD                 1000
#define TRANS_TEST_ADDR_INFO_NUM      2
#define TRANS_TEST_INVALID_SESSION_ID (-1)

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
const char *g_groupId = "TEST_GROUP_ID";
static const char *g_sessionkey = "clientkey";
static int32_t g_fd = socket(AF_INET, SOCK_STREAM, 0);
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};

class TransTcpDirectTest : public testing::Test {
public:
    TransTcpDirectTest(void) { }
    ~TransTcpDirectTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void TransTcpDirectTest::SetUpTestCase(void)
{
    int32_t ret = TransClientInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    SetAccessTokenPermission("dsoftbusTransTest");
}

void TransTcpDirectTest::TearDownTestCase(void) { }

void TransTcpDirectTest::SetUp(void)
{
    ASSERT_EQ(TransDataListInit(), SOFTBUS_OK);
}

void TransTcpDirectTest::TearDown(void)
{
    if (g_tcpDataList != nullptr) {
        TransDataListDeinit();
    }
}

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "OnSessionOpened, sessionId=%{public}d, result=%{public}d", sessionId, result);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "OnSessionClosed, sessionId=%{public}d", sessionId);
}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "OnBytesReceived, sessionId=%{public}d, len=%{public}u", sessionId, len);
}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "OnMessageReceived, sessionId=%{public}d, len=%{public}u", sessionId, len);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

/*
 * @tc.name: CreateSessionServerNullParamTest001
 * @tc.desc: CreateSessionServer with null parameters returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerNullParamTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(nullptr, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CreateSessionServer(g_pkgName, nullptr, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CreateSessionServer(g_pkgName, g_sessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: CreateSessionServerTest002
 * @tc.desc: create and remove session server with valid parameters
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest002, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CreateSessionServerTest003
 * @tc.desc: create session server twice with same parameters returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest003, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CreateSessionServerTest004
 * @tc.desc: create session servers up to max count, overflow returns error
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest004, TestSize.Level1)
{
    char const *sessionName[MAX_SESSION_SERVER_NUMBER + 1] = { "ohos.distributedschedule.dms.test0",
        "ohos.distributedschedule.dms.test1", "ohos.distributedschedule.dms.test2",
        "ohos.distributedschedule.dms.test3", "ohos.distributedschedule.dms.test4",
        "ohos.distributedschedule.dms.test5", "ohos.distributedschedule.dms.test6",
        "ohos.distributedschedule.dms.test7", "ohos.distributedschedule.dms.test8",
        "ohos.distributedschedule.dms.test9", "ohos.distributedschedule.dms.test10" };
    int32_t i;
    int32_t ret;
    for (i = 0; i < COUNT; i++) {
        ret = CreateSessionServer(g_pkgName, sessionName[i], &g_sessionlistener);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    for (i = COUNT; i < MAX_SESSION_SERVER_NUMBER; i++) {
        ret = CreateSessionServer(g_pkgName, sessionName[i], &g_sessionlistener);
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    }
    ret = CreateSessionServer(g_pkgName, sessionName[i], &g_sessionlistener);
    EXPECT_NE(SOFTBUS_OK, ret);

    for (i = 0; i < COUNT; i++) {
        ret = RemoveSessionServer(g_pkgName, sessionName[i]);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    for (i = COUNT; i < MAX_SESSION_SERVER_NUMBER; i++) {
        ret = RemoveSessionServer(g_pkgName, sessionName[i]);
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    }
}

/*
 * @tc.name: RemoveSessionServerNullParamTest001
 * @tc.desc: RemoveSessionServer with null parameters returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerNullParamTest001, TestSize.Level1)
{
    int32_t ret = RemoveSessionServer(nullptr, g_sessionName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = RemoveSessionServer(g_pkgName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = RemoveSessionServer(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: RemoveSessionServerTest002
 * @tc.desc: remove session server twice, second call returns SOFTBUS_TRANS_CHECK_PID_ERROR
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerTest002, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_TRANS_CHECK_PID_ERROR, ret);
}

/*
 * @tc.name: OpenSessionNullParamTest001
 * @tc.desc: OpenSession with null parameters returns error
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, OpenSessionNullParamTest001, TestSize.Level1)
{
    g_sessionAttr.dataType = TYPE_BYTES;
    int32_t ret = OpenSession(nullptr, g_sessionName, g_networkid, g_groupId, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, nullptr, g_networkid, g_groupId, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, nullptr, g_groupId, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, nullptr, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupId, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OpenSessionInvalidDataTypeTest001
 * @tc.desc: OpenSession with TYPE_BUTT dataType returns error
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, OpenSessionInvalidDataTypeTest001, TestSize.Level1)
{
    g_sessionAttr.dataType = TYPE_BUTT;
    int32_t ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupId, &g_sessionAttr);
    EXPECT_NE(ret, SOFTBUS_OK);
    EXPECT_NE(OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupId, &g_sessionAttr), SOFTBUS_OK);
    g_sessionAttr.dataType = TYPE_BYTES;
}

/*
 * @tc.name: SendBytesInvalidParamTest001
 * @tc.desc: SendBytes with invalid parameters returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendBytesInvalidParamTest001, TestSize.Level1)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);
    int32_t ret = SendBytes(-1, data, len);
    EXPECT_NE(ret, SOFTBUS_OK);
    int32_t sessionId = 1;
    ret = SendBytes(sessionId, nullptr, len);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SendBytes(sessionId, data, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SendMessageBytesOverflowTest001
 * @tc.desc: SendMessage with data length exceeding max bytes length returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendMessageBytesOverflowTest001, TestSize.Level1)
{
    uint32_t maxLen;
    int32_t ret =
        SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH, reinterpret_cast<unsigned char *>(&maxLen), sizeof(maxLen));
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 1;
    const char *data = "testdata";
    ret = SendMessage(sessionId, data, maxLen + 1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SendMessageInvalidParamTest001
 * @tc.desc: SendMessage with invalid parameters returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendMessageInvalidParamTest001, TestSize.Level1)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);
    int32_t ret = SendMessage(-1, data, len);
    EXPECT_NE(ret, SOFTBUS_OK);
    int32_t sessionId = 1;
    ret = SendMessage(sessionId, nullptr, len);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = SendMessage(sessionId, data, 0);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SendMessageLengthOverflowTest001
 * @tc.desc: SendMessage with data length exceeding max message length returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendMessageLengthOverflowTest001, TestSize.Level1)
{
    uint32_t maxLen;
    int32_t ret =
        SoftbusGetConfig(SOFTBUS_INT_MAX_MESSAGE_LENGTH, reinterpret_cast<unsigned char *>(&maxLen), sizeof(maxLen));
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t sessionId = 1;
    const char *data = "testdata";
    ret = SendMessage(sessionId, data, maxLen + 1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransClientGetTdcDataBufByChannelNullParamTest001
 * @tc.desc: TransClientGetTdcDataBufByChannel with null params returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientGetTdcDataBufByChannelNullParamTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = TransClientGetTdcDataBufByChannel(channelId, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransClientGetTdcDataBufByChannelNoInitTest001
 * @tc.desc: TransClientGetTdcDataBufByChannel without init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientGetTdcDataBufByChannelNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t channelId = 0;
    int32_t fd = TEST_FD;
    size_t len = BUF_LEN;
    int32_t ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransClientGetTdcDataBufByChannelWithInitTest001
 * @tc.desc: TransClientGetTdcDataBufByChannel with init but no node returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND,
 *           with node returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientGetTdcDataBufByChannelWithInitTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t fd = TEST_FD;
    size_t len = BUF_LEN;
    int32_t ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelDataBufNode(channelId);
}

/*
 * @tc.name: TransClientUpdateTdcDataBufWInfoNullParamTest001
 * @tc.desc: TransClientUpdateTdcDataBufWInfo with null buffer returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoNullParamTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t recvLen = MAX_LEN;
    int32_t ret = TransClientUpdateTdcDataBufWInfo(channelId, nullptr, recvLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelId = INVALID_VALUE;
    ret = TransClientUpdateTdcDataBufWInfo(channelId, nullptr, recvLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransClientUpdateTdcDataBufWInfoNoInitTest001
 * @tc.desc: TransClientUpdateTdcDataBufWInfo without init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t channelId = 0;
    const char *recvBuf = RECV_BUF;
    int32_t recvLen = MAX_LEN;
    int32_t ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransClientUpdateTdcDataBufWInfoNotFoundTest001
 * @tc.desc: TransClientUpdateTdcDataBufWInfo with initialized list but no channel returns
 * SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoNotFoundTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    const char *recvBuf = RECV_BUF;
    int32_t recvLen = MAX_LEN;
    int32_t ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransClientUpdateTdcDataBufWInfoInvalidLenTest001
 * @tc.desc: TransClientUpdateTdcDataBufWInfo with invalid data length returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoInvalidLenTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t fd = TEST_FD;
    int32_t ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
    const char *recvBuf = RECV_BUF;
    int32_t recvLen = MAX_LEN;
    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    TransDelDataBufNode(channelId);
}

/*
 * @tc.name: TransClientUpdateTdcDataBufWInfoValidTest001
 * @tc.desc: TransClientUpdateTdcDataBufWInfo with valid data length returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoValidTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t fd = TEST_FD;
    int32_t ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
    const char *recvBuf = RECV_BUF;
    int32_t recvLen = strlen(recvBuf);
    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelDataBufNode(channelId);
}

/*
 * @tc.name: TransTdcRecvDataNoInitTest001
 * @tc.desc: TransTdcRecvData without data list init returns SOFTBUS_NO_INIT for different channelIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t channelId = -1;
    int32_t ret = TransTdcRecvData(channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    channelId = 0;
    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestSocketEintr
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_EINTR when socket error is EINTR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestSocketEintr, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EINTR));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EINTR, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestBadFd
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_BAD_FD when socket error is BAD_FD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestBadFd, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_BAD_FD));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_BAD_FD, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestEagain
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_EAGAIN when socket error is EAGAIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestEagain, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_EAGAIN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_EAGAIN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestAddrErr
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_ADDR_ERR when socket error is ADDR_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestAddrErr, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_ERR));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_ERR, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestResourceBusy
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_RESOURCE_BUSY when socket error is RESOURCE_BUSY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestResourceBusy, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_RESOURCE_BUSY, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestInvalidVar
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_INVALID_VARIABLE when socket error is INVALID_VARIABLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestInvalidVar, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_INVALID_VARIABLE, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestTooMuchFile
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE when socket error is TOO_MUCH_FILE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestTooMuchFile, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TOO_MUCH_FILE, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestFullFd
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_FULL_FD when socket error is FULL_FD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestFullFd, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_FULL_FD));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_FULL_FD, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNoSpaceLeft
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT when socket error is NO_SPACE_LEFT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNoSpaceLeft, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_SPACE_LEFT, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestPipeInter
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_PIPE_INTER when socket error is PIPE_INTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestPipeInter, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_PIPE_INTER));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_PIPE_INTER, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNotSocket
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NOT_SOCKET when socket error is NOT_SOCKET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNotSocket, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_SOCKET));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_SOCKET, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestOptionUnknown
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN when socket error is OPTION_UNKNOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestOptionUnknown, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_OPTION_UNKNOWN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestAddrInUse
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_ADDR_IN_USE when socket error is ADDR_IN_USE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestAddrInUse, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_IN_USE));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_IN_USE, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestAddrNotAvail
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL when socket error is ADDR_NOT_AVAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestAddrNotAvail, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_ADDR_NOT_AVAIL, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNetDown
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NET_DOWN when socket error is NET_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNetDown, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_DOWN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_DOWN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNetReach
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_NET_REACH when socket error is NET_REACH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNetReach, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_NET_REACH));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_NET_REACH, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNetReset
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NET_RESET when socket error is NET_RESET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNetReset, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NET_RESET));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NET_RESET, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestConnReset
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_CONN_RESET when socket error is CONN_RESET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestConnReset, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_CONN_RESET));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_CONN_RESET, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNoBufs
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NO_BUFS when socket error is NO_BUFS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNoBufs, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_BUFS));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_BUFS, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestIsConn
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_IS_CONN when socket error is IS_CONN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestIsConn, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_IS_CONN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_IS_CONN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNotConn
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NOT_CONN when socket error is NOT_CONN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNotConn, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NOT_CONN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NOT_CONN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestTimeOut
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_TIME_OUT when socket error is TIME_OUT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestTimeOut, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_TIME_OUT));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_TIME_OUT, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestRefused
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_REFUSED when socket error is REFUSED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestRefused, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_REFUSED));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_REFUSED, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestHostDown
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_HOST_DOWN when socket error is HOST_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestHostDown, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_HOST_DOWN));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_HOST_DOWN, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcRecvDataTestNoRoute
 * @tc.desc: TransTdcRecvData returns SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE when socket error is NO_ROUTE_AVALIABLE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTestNoRoute, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(0, -1);
    ASSERT_EQ(ret, SOFTBUS_OK);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, GetErrCodeBySocketErr).WillOnce(Return(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE));
    ret = TransTdcRecvData(0);
    EXPECT_EQ(SOFTBUS_CONN_SOCKET_NO_ROUTE_AVALIABLE, ret);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    ret = TransDelDataBufNode(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransTdcPackDataTest001
 * @tc.desc: TransTdcPackData with null output buffer returns null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcPackDataTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusMalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = g_fd;
    channel->detail.sequence = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t flags = FLAG_ACK;
    char *ret = TransTdcPackData(channel, data, len, flags, nullptr);
    EXPECT_EQ(ret, nullptr);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcProcessPostDataTest001
 * @tc.desc: TransTdcProcessPostData without session info returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessPostDataTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusMalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = g_fd;
    channel->detail.sequence = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t flags = FLAG_ACK;
    int32_t ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcDecryptNullParamTest001
 * @tc.desc: TransTdcDecrypt with null session key returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcDecryptNullParamTest001, TestSize.Level1)
{
    char *out = nullptr;
    uint32_t outLen = 0;
    uint32_t inLen = 0;
    int32_t ret = TransTdcDecrypt(nullptr, nullptr, inLen, out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcDecryptTest002
 * @tc.desc: TransTdcDecrypt with invalid data returns not ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcDecryptTest002, TestSize.Level1)
{
    char output[MAX_LEN];
    (void)memset_s(output, sizeof(output), 0, sizeof(output));
    uint32_t outLen = MAX_LEN;
    int32_t ret = TransTdcDecrypt(g_sessionkey, RECV_BUF, strlen(RECV_BUF) + 1, output, &outLen);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcEncryptWithSeqNullParamTest001
 * @tc.desc: TransTdcEncryptWithSeq with null parameters returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcEncryptWithSeqNullParamTest001, TestSize.Level1)
{
    const char *in = "data";
    uint32_t inLen = static_cast<uint32_t>(strlen(in));
    char *out = nullptr;
    uint32_t outLen = 0;
    EncrptyInfo enInfo = {
        .in = in,
        .inLen = inLen,
        .out = out,
        .outLen = &outLen,
    };
    int32_t seqNum = BUF_LEN;
    int32_t ret = TransTdcEncryptWithSeq(nullptr, seqNum, &enInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcEncryptWithSeq(g_sessionkey, seqNum, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcSetPendingPacketInvalidLenTest001
 * @tc.desc: TransTdcSetPendingPacket with zero length returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSetPendingPacketInvalidLenTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    int32_t ret = TransTdcSetPendingPacket(channelId, data, 0, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransTdcSetPendingPacket(channelId, nullptr, 1, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransTdcSetPendingPacket(-1, data, 1, 1);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PendingInitAndProcTest001
 * @tc.desc: PendingInit returns SOFTBUS_OK, ProcPendingPacket for non-existent channel returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, PendingInitAndProcTest001, TestSize.Level1)
{
    int32_t type = 1;
    int32_t ret = PendingInit(type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 1;
    int32_t seqNum = 1;
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    PendingDeinit(type);
}

/*
 * @tc.name: TransTdcSetPendingPacketNotFoundTest001
 * @tc.desc: TransTdcSetPendingPacket with invalid or non-existent channelId returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSetPendingPacketNotFoundTest001, TestSize.Level1)
{
    int32_t type = 1;
    int32_t ret = PendingInit(type);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *data = "data";
    uint32_t len = ACK_SIZE;
    int32_t channelId = INVALID_VALUE;
    ret = TransTdcSetPendingPacket(channelId, data, len, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    channelId = 1;
    ret = TransTdcSetPendingPacket(channelId, data, len, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    PendingDeinit(type);
}

/*
 * @tc.name: TransTdcSendAckTest001
 * @tc.desc: TransTdcSendAck with invalid channelId returns SOFTBUS_TRANS_TDC_GET_INFO_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendAckTest001, TestSize.Level1)
{
    int32_t seq = 1;
    int32_t channelId = -1;
    int32_t ret = TransTdcSendAck(channelId, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);
    channelId = INVALID_VALUE;
    ret = TransTdcSendAck(channelId, seq);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);
}

/*
 * @tc.name: TransGetDataBufSizeTest001
 * @tc.desc: TransGetDataBufSize returns MIN_BUF_LEN and TransGetTdcDataBufMaxSize returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetDataBufSizeTest001, TestSize.Level1)
{
    uint32_t ret = TransGetDataBufSize();
    EXPECT_EQ(ret, MIN_BUF_LEN);
    EXPECT_NE(ret, 0);
    int32_t res = TransGetTdcDataBufMaxSize();
    EXPECT_EQ(res, SOFTBUS_OK);
}

/*
 * @tc.name: TransDestroyDataBufNoInitTest001
 * @tc.desc: TransDestroyDataBuf without init returns SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransDestroyDataBufNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t ret = TransDestroyDataBuf();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransDestroyDataBufWithInitTest001
 * @tc.desc: TransDestroyDataBuf with init returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransDestroyDataBufWithInitTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    int32_t ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransDestroyDataBuf();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransGetDataBufNodeByIdNoInitTest001
 * @tc.desc: TransGetDataBufNodeById without init returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetDataBufNodeByIdNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t channelId = 1;
    DataBuf *data = TransGetDataBufNodeById(channelId);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: TransGetDataBufNodeByIdWithInitTest001
 * @tc.desc: TransGetDataBufNodeById with init and node returns non-null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetDataBufNodeByIdWithInitTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    int32_t ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    DataBuf *data = TransGetDataBufNodeById(channelId);
    EXPECT_NE(data, nullptr);
}

/*
 * @tc.name: TransTdcProcessDataByFlagNullChannelTest001
 * @tc.desc: TransTdcProcessDataByFlag with null channel and FLAG_ACK returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagNullChannelTest001, TestSize.Level1)
{
    uint32_t flag = FLAG_ACK;
    int32_t seqNum = 1;
    const char *plain = "plain";
    uint32_t plainLen = 0;
    int32_t ret = TransTdcProcessDataByFlag(flag, seqNum, nullptr, plain, plainLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcProcessDataByFlagBytesTest001
 * @tc.desc: TransTdcProcessDataByFlag with FLAG_BYTES returns error for channel without session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagBytesTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    ASSERT_EQ(ret, EOK);
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = TRANS_TEST_FD;
    channel->detail.sequence = 1;
    int32_t seqNum = 1;
    const char *plain = "plain";
    ret = TransTdcProcessDataByFlag(FLAG_BYTES, seqNum, channel, plain, static_cast<uint32_t>(strlen(plain)));
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcProcessDataByFlagAckTest001
 * @tc.desc: TransTdcProcessDataByFlag with FLAG_ACK returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagAckTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    ASSERT_EQ(ret, EOK);
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = TRANS_TEST_FD;
    channel->detail.sequence = 1;
    int32_t seqNum = 1;
    const char *plain = "plain";
    ret = TransTdcProcessDataByFlag(FLAG_ACK, seqNum, channel, plain, static_cast<uint32_t>(strlen(plain)));
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcProcessDataByFlagMessageTest001
 * @tc.desc: TransTdcProcessDataByFlag with FLAG_MESSAGE returns error for channel without session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagMessageTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    ASSERT_EQ(ret, EOK);
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = TRANS_TEST_FD;
    channel->detail.sequence = 1;
    int32_t seqNum = 1;
    const char *plain = "plain";
    ret = TransTdcProcessDataByFlag(FLAG_MESSAGE, seqNum, channel, plain, static_cast<uint32_t>(strlen(plain)));
    EXPECT_NE(ret, SOFTBUS_OK);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcProcessDataByFlagFileFirstFrameTest001
 * @tc.desc: TransTdcProcessDataByFlag with FILE_FIRST_FRAME returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagFileFirstFrameTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    ASSERT_EQ(ret, EOK);
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = TRANS_TEST_FD;
    channel->detail.sequence = 1;
    int32_t seqNum = 1;
    const char *plain = "plain";
    ret = TransTdcProcessDataByFlag(FILE_FIRST_FRAME, seqNum, channel, plain, static_cast<uint32_t>(strlen(plain)));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcProcessDataTest001
 * @tc.desc: TransTdcProcessData without init or channel returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataTest001, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->peerSessionName = const_cast<char *>(g_sessionName);
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = const_cast<char *>(g_sessionkey);
    info->fd = g_fd;
    int32_t channelId = 1;
    int32_t ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    int32_t fd = TEST_FD;
    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcessData(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
    TransTdcManagerDeinit();
    SoftBusFree(info);
}

/*
 * @tc.name: TransResizeDataBufferEmptyBufTest001
 * @tc.desc: TransResizeDataBuffer with empty data buffer returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransResizeDataBufferEmptyBufTest001, TestSize.Level1)
{
    DataBuf *oldBuf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_TRUE(oldBuf != nullptr);
    (void)memset_s(oldBuf, sizeof(DataBuf), 0, sizeof(DataBuf));
    int32_t ret = TransResizeDataBuffer(oldBuf, PKG_LEN);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    SoftBusFree(oldBuf);
}

/*
 * @tc.name: TransResizeDataBufferWithDataTest001
 * @tc.desc: TransResizeDataBuffer with data in buffer returns SOFTBUS_MEM_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransResizeDataBufferWithDataTest001, TestSize.Level1)
{
    DataBuf *oldBuf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_TRUE(oldBuf != nullptr);
    (void)memset_s(oldBuf, sizeof(DataBuf), 0, sizeof(DataBuf));
    (void)memcpy_s(oldBuf->data, strlen("data"), "data", strlen("data"));
    oldBuf->size = BUF_LEN;
    (void)memcpy_s(oldBuf->w, strlen("oldbulf"), "oldbulf", strlen("oldbulf"));
    int32_t ret = TransResizeDataBuffer(oldBuf, PKG_LEN);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    SoftBusFree(oldBuf);
}

/*
 * @tc.name: TransTdcProcAllDataNoInitTest001
 * @tc.desc: TransTdcProcAllData without init returns SOFTBUS_NO_INIT for different channelIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataNoInitTest001, TestSize.Level1)
{
    TransDataListDeinit();
    int32_t channelId = 1;
    int32_t ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    channelId = TRANS_TEST_CHANNEL_ID;
    ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcProcAllDataTest001
 * @tc.desc: TransTdcProcAllData with initialized list and data node returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    int32_t ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcProcAllDataTest002
 * @tc.desc: TransTdcProcAllData with TEST channel id and data node returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataTest002, TestSize.Level1)
{
    int32_t ret = TransAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTdcOnConnectEventTest001
 * @tc.desc: ClientTdcOnConnectEvent with wifi direct channel server and null info returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnConnectEventTest001, TestSize.Level1)
{
    int32_t cfd = 0;
    int32_t ret = ClientTdcOnConnectEvent(DIRECT_CHANNEL_SERVER_WIFI, cfd, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cfd = -1;
    ret = ClientTdcOnConnectEvent(DIRECT_CHANNEL_SERVER_WIFI, cfd, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTdcOnDataEventSocketInTest001
 * @tc.desc: ClientTdcOnDataEvent with SOFTBUS_SOCKET_IN event returns SOFTBUS_NOT_FIND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnDataEventSocketInTest001, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = const_cast<char *>(g_sessionName);
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = const_cast<char *>(g_sessionkey);
    info->fd = g_fd;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t events = SOFTBUS_SOCKET_IN;
    int32_t fd = g_fd;
    ret = ClientTdcOnDataEvent(DIRECT_CHANNEL_SERVER_WIFI, events, fd);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: TransGetNewTcpChannelTest001
 * @tc.desc: TransGetNewTcpChannel with null parameter returns nullptr,
 *           ClientTransCheckTdcChannelExist with valid channelId returns SOFTBUS_OK after manager init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetNewTcpChannelTest001, TestSize.Level1)
{
    TcpDirectChannelInfo *info = TransGetNewTcpChannel(nullptr);
    ASSERT_EQ(info, nullptr);
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channelInfo != nullptr);
    (void)memset_s(channelInfo, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    channelInfo->peerSessionName = const_cast<char *>(g_sessionName);
    channelInfo->channelId = 1;
    channelInfo->channelType = CHANNEL_TYPE_TCP_DIRECT;
    channelInfo->sessionKey = const_cast<char *>(g_sessionkey);
    channelInfo->fd = g_fd;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    int32_t channelId = 1;
    ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenedTest001
 * @tc.desc: ClientTransTdcOnChannelOpened returns SOFTBUS_MEM_ERR when channel info allocation fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTransTdcOnChannelOpenedTest001, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->peerSessionName = const_cast<char *>(g_sessionName);
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = const_cast<char *>(g_sessionkey);
    info->fd = g_fd;
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTdcOnDataEventSocketOutTest001
 * @tc.desc: ClientTdcOnDataEvent with SOFTBUS_SOCKET_OUT event returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnDataEventSocketOutTest001, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    info->channelId = 1;
    info->detail.fd = g_fd;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t events = SOFTBUS_SOCKET_OUT;
    int32_t ret = ClientTdcOnDataEvent(DIRECT_CHANNEL_SERVER_WIFI, events, g_fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTdcOnDataEventSocketExceptionTest001
 * @tc.desc: ClientTdcOnDataEvent with SOFTBUS_SOCKET_EXCEPTION event returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnDataEventSocketExceptionTest001, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    info->channelId = 1;
    info->detail.fd = g_fd;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t events = SOFTBUS_SOCKET_EXCEPTION;
    int32_t ret = ClientTdcOnDataEvent(DIRECT_CHANNEL_SERVER_WIFI, events, g_fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcCreateListenerWithoutAddTriggerTest001
 * @tc.desc: TransTdcCreateListenerWithoutAddTrigger returns SOFTBUS_OK with inited and not-inited states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcCreateListenerWithoutAddTriggerTest001, TestSize.Level1)
{
    g_isInitedFlag = true;
    int32_t fd = g_fd;
    int32_t ret = TransTdcCreateListenerWithoutAddTrigger(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_isInitedFlag = false;
    ret = TransTdcCreateListenerWithoutAddTrigger(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcCloseFdTest001
 * @tc.desc: TransTdcCloseFd with bad fd gets error, with valid fd closes successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcCloseFdTest001, TestSize.Level1)
{
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, SoftBusSocketGetError).WillOnce(Return(SOFTBUS_CONN_BAD_FD));
    int32_t fd = 1000000;
    TransTdcCloseFd(fd);
    testing::Mock::VerifyAndClearExpectations(&tcpDirectMock);
    fd = g_fd;
    TransTdcCloseFd(fd);
    EXPECT_NE(fd, 0);
}

/*
 * @tc.name: UnPackTcpDataPacketHeadTest001
 * @tc.desc: UnPackTcpDataPacketHead preserves seq value for seq=1 and seq=0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, UnPackTcpDataPacketHeadTest001, TestSize.Level1)
{
    TcpDataPacketHead data;
    data.seq = 1;
    UnPackTcpDataPacketHead(&data);
    EXPECT_NE(data.seq, 0);
    data.seq = 0;
    UnPackTcpDataPacketHead(&data);
    EXPECT_EQ(data.seq, 0);
}

/*
 * @tc.name: CheckCollaborationSessionNameTest001
 * @tc.desc: CheckCollaborationSessionName returns true for valid name, false for invalid name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, CheckCollaborationSessionNameTest001, TestSize.Level1)
{
    const char *validSessionName = "ohos.collaborationcenter";
    bool ret = CheckCollaborationSessionName(validSessionName);
    EXPECT_EQ(ret, true);
    const char *invalidSessionName = "nullptr";
    ret = CheckCollaborationSessionName(invalidSessionName);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: TransTdcProcessPostDataTest002
 * @tc.desc: TransTdcProcessPostData with channel but no session info returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessPostDataTest002, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *channel =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    int32_t channelId = 1;
    ChannelType channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->channelId = channelId;
    channel->detail.channelType = channelType;
    ClientSessionServer *serverNode =
        reinterpret_cast<ClientSessionServer *>(SoftBusCalloc(sizeof(ClientSessionServer)));
    ASSERT_NE(serverNode, nullptr);
    SessionInfo *info = reinterpret_cast<SessionInfo *>(SoftBusCalloc(sizeof(SessionInfo)));
    ASSERT_NE(info, nullptr);
    info->channelId = channelId;
    info->channelType = channelType;
    ListInit(&serverNode->sessionList);
    ListAdd(&serverNode->sessionList, &info->node);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &serverNode->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t flags = FLAG_ACK;
    int32_t ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND);
    SoftBusFree(channel);
    SoftBusFree(info);
    SoftBusFree(serverNode);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSendBytesNeedReleaseTest001
 * @tc.desc: TransTdcSendBytes with needRelease=true returns SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendBytesNeedReleaseTest001, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, SoftBusSocketGetError).WillRepeatedly(Return(SOFTBUS_CONN_BAD_FD));
    int32_t channelId = 1;
    info->channelId = channelId;
    info->detail.needRelease = true;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t ret = TransTdcSendBytes(channelId, data, len, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSendBytesNoReleaseTest001
 * @tc.desc: TransTdcSendBytes with channel not found returns SOFTBUS_TRANS_TDC_GET_INFO_FAILED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendBytesNoReleaseTest001, TestSize.Level1)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    NiceMock<TransTcpDirectInterfaceMock> tcpDirectMock;
    EXPECT_CALL(tcpDirectMock, SoftBusSocketGetError).WillRepeatedly(Return(SOFTBUS_CONN_BAD_FD));
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t ret = TransTdcSendBytes(channelId, data, len, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSendMessageNeedReleaseTest001
 * @tc.desc: TransTdcSendMessage with needRelease=true returns SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendMessageNeedReleaseTest001, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    int32_t channelId = 1;
    info->channelId = channelId;
    info->detail.needRelease = true;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_CLOSED_BY_ANOTHER_THREAD);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSendMessageNoReleaseTest001
 * @tc.desc: TransTdcSendMessage with channel not found returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendMessageNoReleaseTest001, TestSize.Level1)
{
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int32_t ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcProcessDataNotFoundTest001
 * @tc.desc: TransTdcProcessData without channel returns SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND for different channelIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataNotFoundTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
    channelId = 0;
    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransTdcProcessDataTest002
 * @tc.desc: TransTdcProcessData with channel in list but no session info returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataTest002, TestSize.Level1)
{
    TransDataListDeinit();
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_NE(info, nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_NE(g_tcpDirectChannelInfoList, nullptr);
    int32_t channelId = 1;
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = TransAddDataBufNode(channelId, TEST_FD);
    ASSERT_EQ(ret, SOFTBUS_OK);
    DataBuf *buf = TransGetDataBufNodeById(channelId);
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead pktHead;
    (void)memset_s(&pktHead, sizeof(pktHead), 0, sizeof(pktHead));
    (void)memcpy_s(buf->data, buf->size, &pktHead, sizeof(pktHead));
    buf->w = buf->data + sizeof(pktHead);
    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcessData(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcProcAllDataNodeNotFoundTest001
 * @tc.desc: TransTdcProcAllData without node in data list returns SOFTBUS_TRANS_NODE_NOT_FOUND
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataNodeNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(SoftBusCalloc(BUF_LEN));
    ASSERT_NE(buf->data, nullptr);
    buf->w = buf->data;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcProcAllDataDataNotEnoughTest001
 * @tc.desc: TransTdcProcAllData with insufficient data returns SOFTBUS_DATA_NOT_ENOUGH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataDataNotEnoughTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = 1;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE - 1;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_DATA_NOT_ENOUGH);
}

/*
 * @tc.name: TransTdcProcAllDataInvalidDataHeadTest001
 * @tc.desc: TransTdcProcAllData with invalid magic number returns SOFTBUS_INVALID_DATA_HEAD
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataInvalidDataHeadTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = 0x01;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_DATA_HEAD);
}

/*
 * @tc.name: TransTdcProcAllDataInvalidDataLenTooLargeTest001
 * @tc.desc: TransTdcProcAllData with data length exceeding max buffer returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataInvalidDataLenTooLargeTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = g_dataBufferMaxLen - DC_DATA_HEAD_SIZE + 1;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransTdcProcAllDataInvalidDataLenOverheadTest001
 * @tc.desc: TransTdcProcAllData with data length equal to OVERHEAD_LEN returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataInvalidDataLenOverheadTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = OVERHEAD_LEN;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransTdcProcAllDataInvalidDataLenOneTest001
 * @tc.desc: TransTdcProcAllData with dataLen=1 and small buffer size returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataInvalidDataLenOneTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = 1;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    buf->size = DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransTdcProcAllDataValidDataTest001
 * @tc.desc: TransTdcProcAllData with valid data length returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataValidDataTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = OVERHEAD_LEN + 1;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    buf->size = DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcProcAllDataZeroDataLenTest001
 * @tc.desc: TransTdcProcAllData with zero dataLen returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataZeroDataLenTest001, TestSize.Level1)
{
    DataBuf *buf = reinterpret_cast<DataBuf *>(SoftBusCalloc(sizeof(DataBuf)));
    ASSERT_NE(buf, nullptr);
    TcpDataPacketHead *pktHead = reinterpret_cast<TcpDataPacketHead *>(SoftBusCalloc(sizeof(TcpDataPacketHead)));
    ASSERT_NE(pktHead, nullptr);
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->dataLen = 0;
    buf->channelId = TRANS_TEST_CHANNEL_ID;
    buf->data = reinterpret_cast<char *>(pktHead);
    buf->w = buf->data + DC_DATA_HEAD_SIZE;
    buf->size = DC_DATA_HEAD_SIZE;
    (void)SoftBusMutexLock(&g_tcpDataList->lock);
    ListAdd(&g_tcpDataList->list, &buf->node);
    (void)SoftBusMutexUnlock(&g_tcpDataList->lock);
    int32_t ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
}

/*
 * @tc.name: TransTdcProcAllDataLockFailTest001
 * @tc.desc: TransTdcProcAllData with null mutex returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataLockFailTest001, TestSize.Level1)
{
    uintptr_t originalMutex = g_tcpDataList->lock.mutex;
    g_tcpDataList->lock.mutex = reinterpret_cast<uintptr_t>(nullptr);
    int32_t channelId = 1;
    int32_t ret = TransTdcProcAllData(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    g_tcpDataList->lock.mutex = originalMutex;
}

/*
 * @tc.name: TransAssembleTlvDataNullParamTest001
 * @tc.desc: TransAssembleTlvData with null parameters returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransAssembleTlvDataNullParamTest001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    int32_t ret = TransAssembleTlvData(nullptr, 1, nullptr, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DataHead pktHead;
    uint8_t *tlvElement = reinterpret_cast<uint8_t *>(SoftBusCalloc(TDC_TLV_ELEMENT * sizeof(TlvElement)));
    pktHead.tlvElement = tlvElement;
    pktHead.magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    ret = TransAssembleTlvData(&pktHead, TLV_TYPE_INNER_SEQ, nullptr, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(tlvElement);
}

/*
 * @tc.name: TransAssembleTlvDataFlagTypeTest001
 * @tc.desc: TransAssembleTlvData with TLV_TYPE_FLAG returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransAssembleTlvDataFlagTypeTest001, TestSize.Level1)
{
    DataHead pktHead;
    uint8_t *tlvElement = reinterpret_cast<uint8_t *>(SoftBusCalloc(TDC_TLV_ELEMENT * sizeof(TlvElement)));
    pktHead.tlvElement = tlvElement;
    pktHead.magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    int32_t bufferSize = 0;
    uint8_t buffer = 0;
    int32_t ret = TransAssembleTlvData(&pktHead, TLV_TYPE_FLAG, &buffer, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(tlvElement);
}

/*
 * @tc.name: TransAssembleTlvDataNullBufferSizeTest001
 * @tc.desc: TransAssembleTlvData with null bufferSize for TLV_TYPE_DATA_LEN returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransAssembleTlvDataNullBufferSizeTest001, TestSize.Level1)
{
    DataHead pktHead;
    uint8_t *tlvElement = reinterpret_cast<uint8_t *>(SoftBusCalloc(TDC_TLV_ELEMENT * sizeof(TlvElement)));
    pktHead.tlvElement = tlvElement;
    pktHead.magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    uint8_t buffer = 0;
    int32_t ret = TransAssembleTlvData(&pktHead, TLV_TYPE_DATA_LEN, &buffer, 1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(tlvElement);
}

/*
 * @tc.name: BuildNeedAckTlvDataNullParamTest001
 * @tc.desc: BuildNeedAckTlvData with null parameters returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, BuildNeedAckTlvDataNullParamTest001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    int32_t ret = BuildNeedAckTlvData(nullptr, true, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = BuildNeedAckTlvData(nullptr, false, 1, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: BuildDataHeadTest001
 * @tc.desc: BuildDataHead with valid parameters returns SOFTBUS_OK and sets buffer size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, BuildDataHeadTest001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    DataHead data;
    int32_t ret = BuildDataHead(&data, 1, 0, 32, &bufferSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_GT(bufferSize, 0);
}

/*
 * @tc.name: TransTdcNeedSendAckNullParamTest001
 * @tc.desc: TransTdcNeedSendAck with null parameter returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcNeedSendAckNullParamTest001, TestSize.Level1)
{
    int32_t ret = TransTdcNeedSendAck(nullptr, 1, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcNeedSendAck(nullptr, 0, 1, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcNeedSendAck(nullptr, 2, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
