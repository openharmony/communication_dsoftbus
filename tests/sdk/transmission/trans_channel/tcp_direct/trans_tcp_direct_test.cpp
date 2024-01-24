/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_manager.c"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_message.c"
#include "client_trans_tcp_direct_listener.c"
#include "client_trans_tcp_direct_message.h"
#include "client_trans_session_manager.h"
#include "client_trans_session_callback.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_app_info.h"
#include "softbus_feature_config.h"
#include "softbus_access_token_test.h"
#include "softbus_conn_interface.h"
#include "softbus_socket.h"

#define MAX_LEN 2048
#define TEST_FD 10
#define COUNT 11
#define PKG_LEN 32
#define RECV_BUF "testrecvBuf"
#define BUF_LEN 10
#define COUNT 11
#define SESSIONKEY_LEN 32
#define INVALID_VALUE (-1)

#define TRANS_TEST_SESSION_ID 10
#define TRANS_TEST_CHANNEL_ID 1000
#define TRANS_TEST_FILE_ENCRYPT 10
#define TRANS_TEST_ALGORITHM 1
#define TRANS_TEST_CRC 1
#define TRANS_TEST_FD 1000
#define TRANS_TEST_ADDR_INFO_NUM 2
#define TRANS_TEST_INVALID_SESSION_ID (-1)

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
    TransTcpDirectTest()
    {
    }
    ~TransTcpDirectTest()
    {
    }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

void TransTcpDirectTest::SetUpTestCase(void)
{
    int32_t ret = TransClientInit();
    ASSERT_EQ(ret,  SOFTBUS_OK);
    SetAceessTokenPermission("dsoftbusTransTest");
}

void TransTcpDirectTest::TearDownTestCase(void)
{
}

static int OnSessionOpened(int sessionId, int result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sessionId=%{public}d", sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d", sessionId);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, sessionId=%{public}d", sessionId);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, sessionId=%{public}d", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

/**
 * @tc.name: CreateSessionServerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest001, TestSize.Level0)
{
    int ret;
    ret = CreateSessionServer(NULL, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CreateSessionServer(g_pkgName, NULL, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CreateSessionServer(g_pkgName, g_sessionName, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CreateSessionServerTest002
 * @tc.desc: extern module active publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest002, TestSize.Level0)
{
    int ret;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CreateSessionServerTest003
 * @tc.desc: extern module active publish, use the same normal parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest003, TestSize.Level0)
{
    int ret;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CreateSessionServerTest004
 * @tc.desc: extern module active publish, create 11 sessionServer, succ 10, failed at 11th.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, CreateSessionServerTest004, TestSize.Level0)
{
    int ret, i;
    char const *sessionName[MAX_SESSION_SERVER_NUMBER + 1] = {
        "ohos.distributedschedule.dms.test0",
        "ohos.distributedschedule.dms.test1",
        "ohos.distributedschedule.dms.test2",
        "ohos.distributedschedule.dms.test3",
        "ohos.distributedschedule.dms.test4",
        "ohos.distributedschedule.dms.test5",
        "ohos.distributedschedule.dms.test6",
        "ohos.distributedschedule.dms.test7",
        "ohos.distributedschedule.dms.test8",
        "ohos.distributedschedule.dms.test9",
        "ohos.distributedschedule.dms.test10"
    };

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

/**
 * @tc.name: RemoveSessionServerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerTest001, TestSize.Level0)
{
    int ret;
    ret = RemoveSessionServer(NULL, g_sessionName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = RemoveSessionServer(g_pkgName, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: RemoveSessionServerTest002
 * @tc.desc: extern module active publish, use the same parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, RemoveSessionServerTest002, TestSize.Level0)
{
    int ret;
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OpenSessionTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransTcpDirectTest, OpenSessionTest001, TestSize.Level0)
{
    int ret;
    g_sessionAttr.dataType = TYPE_BYTES;

    ret = OpenSession(NULL, g_sessionName, g_networkid, g_groupId, &g_sessionAttr);
    EXPECT_GE(SOFTBUS_OK, ret);

    ret = OpenSession(g_sessionName, NULL, g_networkid, g_groupId, &g_sessionAttr);
    EXPECT_GE(SOFTBUS_OK, ret);

    ret = OpenSession(g_sessionName, g_sessionName, NULL, g_groupId, &g_sessionAttr);
    EXPECT_GE(SOFTBUS_OK, ret);

    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, NULL, &g_sessionAttr);
    EXPECT_GE(SOFTBUS_OK, ret);

    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupId, NULL);
    EXPECT_GE(SOFTBUS_OK, ret);

    g_sessionAttr.dataType = TYPE_BUTT;
    ret = OpenSession(g_sessionName, g_sessionName, g_networkid, g_groupId, &g_sessionAttr);
    g_sessionAttr.dataType = TYPE_BYTES;
    EXPECT_GE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendBytesTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendBytesTest001, TestSize.Level0)
{
    int ret;
    int sessionId = 1;
    const char *data = "testdata";
    uint32_t len = strlen(data);
    uint32_t maxLen;

    ret = SendBytes(-1, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendBytes(sessionId, NULL, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendBytes(sessionId, data, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen));
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = SendMessage(sessionId, data, maxLen + 1);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendMessageTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SendMessageTest001, TestSize.Level0)
{
    int ret;
    int sessionId = 1;
    const char *data = "testdata";
    uint32_t len = strlen(data);
    uint32_t maxLen;

    ret = SendMessage(-1, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendMessage(sessionId, NULL, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendMessage(sessionId, data, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SoftbusGetConfig(SOFTBUS_INT_MAX_MESSAGE_LENGTH, (unsigned char *)&maxLen, sizeof(maxLen));
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = SendMessage(sessionId, data, maxLen + 1);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransClientGetTdcDataBufByChannelTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientGetTdcDataBufByChannelTest001, TestSize.Level0)
{
    int ret;
    int channelId = 0;
    int fd = TEST_FD;
    size_t len = BUF_LEN;

    ret = TransClientGetTdcDataBufByChannel(channelId, NULL, NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientGetTdcDataBufByChannel(channelId, &fd, &len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransDataListDeinit();
}

/**
 * @tc.name: TransClientUpdateTdcDataBufWInfoTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransClientUpdateTdcDataBufWInfoTest001, TestSize.Level0)
{
    int ret;
    int channelId = 0;
    int fd = TEST_FD;
    const char *recvBuf = RECV_BUF;
    int recvLen = MAX_LEN;

    ret = TransClientUpdateTdcDataBufWInfo(channelId, NULL, recvLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransDataListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    recvLen = strlen(recvBuf);
    ret = TransClientUpdateTdcDataBufWInfo(channelId, const_cast<char *>(recvBuf), recvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransDataListDeinit();
}

/**
 * @tc.name: TransTdcRecvDataTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcRecvDataTest001, TestSize.Level0)
{
    int ret;
    int channelId = -1;
    int fd = -1;

    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    channelId = 0;
    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    TransDataListDeinit();
}
/**
 * @tc.name: TransTdcPackDataTest001
 * @tc.desc: TransTdcPackData, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcPackDataTest001, TestSize.Level0)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = g_fd;
    channel->detail.sequence = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int flags = FLAG_ACK;
    char *ret = TransTdcPackData(channel, data, len, flags, NULL);
    EXPECT_TRUE(ret == nullptr);
    uint32_t outLen = 0;
    ret = TransTdcPackData(channel, data, len, flags, &outLen);
    EXPECT_TRUE(ret != nullptr);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcProcessPostDataTest001
 * @tc.desc: TransTdcProcessPostData, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessPostDataTest001, TestSize.Level0)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = g_fd;
    channel->detail.sequence = 1;
    const char *data = "data";
    uint32_t len = BUF_LEN;
    int flags = FLAG_ACK;
    int32_t ret = TransTdcProcessPostData(channel, data, len, flags);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcDecryptTest001
 * @tc.desc: TransTdcDecrypt, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcDecryptTest001, TestSize.Level0)
{
    char *out = nullptr;
    uint32_t outLen = 0;
    uint32_t inLen = 0;
    int32_t ret = TransTdcDecrypt(nullptr, nullptr, inLen, out, &outLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcEncryptWithSeqTest001
 * @tc.desc: TransTdcEncryptWithSeq, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcEncryptWithSeqTest001, TestSize.Level0)
{
    const char *in = "data";
    char *out = nullptr;
    uint32_t outLen = 0;
    uint32_t inLen = (uint32_t)strlen(in);
    int32_t seqNum = BUF_LEN;
    int32_t ret = TransTdcEncryptWithSeq(nullptr, seqNum, in, inLen, out, &outLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcEncryptWithSeq(g_sessionkey, seqNum, nullptr, inLen, out, &outLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcEncryptWithSeq(g_sessionkey, seqNum, in, inLen, out, &outLen);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcSetPendingPacketTest001
 * @tc.desc: TransTdcSetPendingPacket, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSetPendingPacketTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = 0;
    int32_t seqNum = 1;
    int type = 1;
    int32_t ret = TransTdcSetPendingPacket(channelId, data, len);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = PendingInit(type);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_NE(SOFTBUS_OK, ret);
    len = ACK_SIZE;
    channelId = INVALID_VALUE;
    ret = TransTdcSetPendingPacket(channelId, data, len);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    channelId = 1;
    ret = TransTdcSetPendingPacket(channelId, data, len);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    PendingDeinit(type);
}

/**
 * @tc.name: TransTdcSendAckTest001
 * @tc.desc: TransTdcSendAck, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcSendAckTest001, TestSize.Level0)
{
    int32_t seq = 1;
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo*)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    (void)memset_s(channel, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    channel->channelId = 1;
    (void)memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = g_fd;
    channel->detail.sequence = 1;
    int32_t ret = TransTdcSendAck(nullptr, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendAck(channel, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransGetDataBufSizeTest001
 * @tc.desc: TransGetDataBufSize, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetDataBufSizeTest001, TestSize.Level0)
{
    uint32_t ret = TransGetDataBufSize();
    EXPECT_TRUE(ret == MIN_BUF_LEN);

    int32_t res = TransGetDataBufMaxSize();
    EXPECT_TRUE(res == SOFTBUS_OK);
}

/**
 * @tc.name: TransDestroyDataBufTest001
 * @tc.desc: TransDestroyDataBuf, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransDestroyDataBufTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    int32_t ret = TransDestroyDataBuf();
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransDestroyDataBuf();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransDataListDeinit();
}

/**
 * @tc.name: TransGetDataBufNodeByIdTest001
 * @tc.desc: TransGetDataBufNodeById, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetDataBufNodeByIdTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    ClientDataBuf *data = TransGetDataBufNodeById(channelId);
    EXPECT_TRUE(data == nullptr);

    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    data = TransGetDataBufNodeById(channelId);
    EXPECT_TRUE(data != nullptr);

    TransDataListDeinit();
}

/**
 * @tc.name: TransTdcProcessDataByFlagTest001
 * @tc.desc: TransTdcProcessDataByFlag, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagTest001, TestSize.Level0)
{
    uint32_t flag = FLAG_BYTES;
    int32_t seqNum = 1;
    const char *plain = "plain";
    uint32_t plainLen = 0;
    flag = FLAG_ACK;
    int32_t ret = TransTdcProcessDataByFlag(flag, seqNum, nullptr, plain, plainLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcProcessDataTest001
 * @tc.desc: TransTdcProcessData, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->peerSessionName = (char *)g_sessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = (char *)g_sessionkey;
    info->fd = g_fd;

    int32_t ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    IClientSessionCallBack *cb = GetClientSessionCb();
    ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcessData(channelId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcessData(channelId);
    EXPECT_NE(SOFTBUS_OK, ret);

    TransDataListDeinit();
    TransTdcManagerDeinit();
    SoftBusFree(info);
}

/**
 * @tc.name: TransResizeDataBufferTest001
 * @tc.desc: TransResizeDataBuffer, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransResizeDataBufferTest001, TestSize.Level0)
{
    ClientDataBuf *oldBuf = (ClientDataBuf *)SoftBusCalloc(sizeof(ClientDataBuf));
    ASSERT_TRUE(oldBuf != nullptr);
    (void)memset_s(oldBuf, sizeof(ClientDataBuf), 0, sizeof(ClientDataBuf));
    int32_t ret = TransResizeDataBuffer(oldBuf, PKG_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    (void)memcpy_s(oldBuf->data, strlen("data"), "data", strlen("data"));
    oldBuf->size = BUF_LEN;
    (void)memcpy_s(oldBuf->w, strlen("oldbulf"), "oldbulf", strlen("oldbulf"));

    ret = TransResizeDataBuffer(oldBuf, PKG_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(oldBuf);
}

 /**
 * @tc.name: TransTdcProcAllDataTest001
 * @tc.desc: TransTdcProcAllData, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = TEST_FD;
    ClientDataBuf *oldBuf = (ClientDataBuf *)SoftBusCalloc(sizeof(ClientDataBuf));
    ASSERT_TRUE(oldBuf != nullptr);
    (void)memset_s(oldBuf, sizeof(ClientDataBuf), 0, sizeof(ClientDataBuf));

    int32_t ret = TransTdcProcAllData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcAllData(channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransDataListDeinit();
    SoftBusFree(oldBuf);
}

/**
 * @tc.name: ClientTdcOnConnectEventTest001
 * @tc.desc: ClientTdcOnConnectEvent, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnConnectEventTest001, TestSize.Level0)
{
    int cfd = 0;
    int32_t ret = ClientTdcOnConnectEvent(DIRECT_CHANNEL_SERVER_WIFI, cfd, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: ClientTdcOnDataEventTest001
 * @tc.desc: ClientTdcOnDataEvent, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTdcOnDataEventTest001, TestSize.Level0)
{
    int events = SOFTBUS_SOCKET_IN;
    int32_t fd = g_fd;
    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = (char *)g_sessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = (char *)g_sessionkey;
    info->fd = g_fd;
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ClientTdcOnDataEvent(DIRECT_CHANNEL_SERVER_WIFI, events, fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransGetNewTcpChannelTest001
 * @tc.desc: TransGetNewTcpChannel, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransGetNewTcpChannelTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = TransGetNewTcpChannel(NULL);
    ASSERT_EQ(info, nullptr);
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channelInfo != nullptr);
    (void)memset_s(channelInfo, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    channelInfo->peerSessionName = (char *)g_sessionName;
    channelInfo->channelId = 1;
    channelInfo->channelType = CHANNEL_TYPE_TCP_DIRECT;
    channelInfo->sessionKey = (char *)g_sessionkey;
    channelInfo->fd = g_fd;

    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = TransTdcManagerInit(cb);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(channelInfo);
}

/**
 * @tc.name: TransTdcProcessDataByFlagTest002
 * @tc.desc: TransTdcProcessDataByFlag, use different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcessDataByFlagTest002, TestSize.Level0)
{
    TcpDirectChannelInfo *channel = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(channel != nullptr);

    int ret = memcpy_s(channel->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    ASSERT_EQ(ret, EOK);
    channel->channelId = TRANS_TEST_CHANNEL_ID;
    channel->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel->detail.fd = TRANS_TEST_FD;
    channel->detail.sequence = 1;
    int32_t seqNum = 1;
    const char *plain = "plain";

    ret = TransTdcProcessDataByFlag(FLAG_BYTES, seqNum, channel, plain, (uint32_t)strlen(plain));
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = TransTdcProcessDataByFlag(FLAG_ACK, seqNum, channel, plain, (uint32_t)strlen(plain));
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcProcessDataByFlag(FLAG_MESSAGE, seqNum, channel, plain, (uint32_t)strlen(plain));
    EXPECT_NE(ret, SOFTBUS_OK);

    ret = TransTdcProcessDataByFlag(FILE_FIRST_FRAME, seqNum, channel, plain, (uint32_t)strlen(plain));
    EXPECT_EQ(ret, SOFTBUS_ERR);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcProcAllDataTest002
 * @tc.desc: TransTdcProcAllData, use different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcProcAllDataTest002, TestSize.Level0)
{
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(TRANS_TEST_CHANNEL_ID, TRANS_TEST_FD);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcProcAllData(TRANS_TEST_CHANNEL_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDataListDeinit();
}

/**
 * @tc.name: TransTdcDecryptTest002
 * @tc.desc: TransTdcDecrypt, use different parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcDecryptTest002, TestSize.Level0)
{
    char output[MAX_LEN] = {0};
    uint32_t outLen = MAX_LEN;
    int32_t ret = TransTdcDecrypt(g_sessionkey, RECV_BUF, strlen(RECV_BUF) + 1, output, &outLen);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: ClientTransTdcOnChannelOpenedTest001
 * @tc.desc: ClientTransTdcOnChannelOpened, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, ClientTransTdcOnChannelOpenedTest001, TestSize.Level0)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    info->peerSessionName = (char *)g_sessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = (char *)g_sessionkey;
    info->fd = g_fd;
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(info);
}
}
