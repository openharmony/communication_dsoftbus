/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "client_trans_tcp_direct_message.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_tcp_direct_listener.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "softbus_access_token_test.h"
#include "softbus_base_listener.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

using namespace testing::ext;

namespace OHOS {
#define INVALID_VALUE (-1)
#define SESSIONKEY_LEN 46
#define SESSION_KEY_LEN 46
static const char *g_sessionName = "ohos.distributedschedule.dms.test";
char g_peerSessionName[SESSIONKEY_LEN] = "ohos.distributedschedule.dms.test";
static const char *g_sessionkey = "clientkey";
char g_peerSessionKey[SESSION_KEY_LEN] = "clientkey";
static const char *g_pkgName = "pkgname";
static int32_t g_fd = socket(AF_INET, SOCK_STREAM, 0);

class TransSdkTcpDirectTest : public testing::Test {
public:
    TransSdkTcpDirectTest()
    {
    }
    ~TransSdkTcpDirectTest()
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

static int OnServerSessionOpened(int sessionId, int result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sesisonId=%{public}d\r\n", sessionId);
    return SOFTBUS_OK;
}

static void OnServerSessionClosed(int sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d\r\n", sessionId);
}

static void OnServerBytesReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, sessionId=%{public}d\r\n", sessionId);
}

static void OnServerMessageReceived(int sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, sessionId=%{public}d\r\n", sessionId);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnServerSessionOpened,
    .OnSessionClosed = OnServerSessionClosed,
    .OnBytesReceived = OnServerBytesReceived,
    .OnMessageReceived = OnServerMessageReceived,
};


static int32_t OnSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sesisonName=%{public}s", sessionName);
    return SOFTBUS_OK;
}

static int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    TRANS_LOGI(TRANS_TEST, "session closed, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t OnDataReceived(int32_t channelId, int32_t channelType,
                              const void *data, uint32_t len, SessionPktType type)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}
static IClientSessionCallBack g_sessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
};

ChannelInfo *TestGetChannelInfo()
{
    ChannelInfo *info = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = g_peerSessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    return info;
}

TcpDirectChannelInfo *TestGetTcpDirectChannelInfo()
{
    TcpDirectChannelInfo *item = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    (void)memset_s(item, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));
    item->channelId = 1;
    (void)memcpy_s(item->detail.sessionKey, SESSIONKEY_LEN, g_sessionkey, strlen(g_sessionkey));
    item->detail.channelType = CHANNEL_TYPE_TCP_DIRECT;
    item->detail.fd = g_fd;
    return item;
}

void TransSdkTcpDirectTest::SetUpTestCase(void)
{
    int32_t ret = TransClientInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransTdcManagerInit(&g_sessionCb);
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = InitBaseListener();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void TransSdkTcpDirectTest::TearDownTestCase(void)
{
    TransTdcManagerDeinit();
}

/**
 * @tc.name: ClientTransTdcOnChannelOpenedTest001
 * @tc.desc: ClientTransTdcOnChannelOpened, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenedTest001, TestSize.Level0)
{
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(nullptr, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ClientTransTdcOnChannelOpened(g_sessionName, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcCloseChannelTest002
 * @tc.desc: TransTdcCloseChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCloseChannelTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    TransTdcManagerInit(&g_sessionCb);

    TransTdcCloseChannel(channelId);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransTdcCloseChannel(channelId);

    channelId = INVALID_VALUE;
    TransTdcCloseChannel(channelId);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetSessionKeyTest003
 * @tc.desc: TransTdcGetSessionKey, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetSessionKeyTest003, TestSize.Level0)
{
    int32_t channelId = 1;
    unsigned int len = 32;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcGetSessionKey(channelId, nullptr, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelId = INVALID_VALUE;
    ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetHandleTest004
 * @tc.desc: TransTdcGetHandle, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetHandleTest004, TestSize.Level0)
{
    int32_t channelId = 1;
    int handle = 0;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcGetHandle(channelId, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelId = INVALID_VALUE;
    ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransDisableSessionListenerTest005
 * @tc.desc: TransDisableSessionListener, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
 
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest005, TestSize.Level0)
{
    int32_t channelId = 1;

    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = const_cast<char *>(g_sessionName);
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = const_cast<char *>(g_sessionkey);
    info->fd = INVALID_VALUE;

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    info->fd = g_fd;
    ret = TransDisableSessionListener(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDisableSessionListener(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelId = INVALID_VALUE;
    ret = TransDisableSessionListener(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    SoftBusFree(info);
}

/**
 * @tc.name: TransTdcGetInfoByIdTest006
 * @tc.desc: TransTdcGetInfoById, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest006, TestSize.Level0)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TcpDirectChannelInfo *item = TransTdcGetInfoById(channelId, nullptr);
    EXPECT_TRUE(item == nullptr);

    item = TransTdcGetInfoById(channelId, info);
    EXPECT_TRUE(item == nullptr);

    channelId = INVALID_VALUE;
    item = TransTdcGetInfoById(channelId, info);
    EXPECT_TRUE(item == nullptr);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetInfoByFdTest007
 * @tc.desc: TransTdcGetInfoByFd, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest007, TestSize.Level0)
{
    int32_t fd = g_fd;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TcpDirectChannelInfo *item = TransTdcGetInfoByFd(fd, nullptr);
    EXPECT_TRUE(item == nullptr);

    item = TransTdcGetInfoByFd(fd, info);
    EXPECT_TRUE(item == nullptr);

    fd = 1;
    item = TransTdcGetInfoByFd(fd, info);
    EXPECT_TRUE(item == nullptr);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetInfoByIdWithIncSeqTest008
 * @tc.desc: TransTdcGetInfoByIdWithIncSeq, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdWithIncSeqTest008, TestSize.Level0)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TcpDirectChannelInfo *item = TransTdcGetInfoByIdWithIncSeq(channelId, nullptr);
    EXPECT_TRUE(item == nullptr);

    item = TransTdcGetInfoByIdWithIncSeq(channelId, info);
    EXPECT_TRUE(item == nullptr);

    channelId = INVALID_VALUE;
    item = TransTdcGetInfoByIdWithIncSeq(channelId, info);
    EXPECT_TRUE(item == nullptr);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/**
 * @tc.name: ClientTransTdcSetCallBackTest009
 * @tc.desc: ClientTransTdcSetCallBack, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcSetCallBackTest009, TestSize.Level0)
{
    const IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransTdcSetCallBack(NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = ClientTransTdcSetCallBack(cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: ClientTransTdcOnSessionOpenedTest0010
 * @tc.desc: ClientTransTdcOnSessionOpened, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest0010, TestSize.Level0)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));

    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    ret = ClientTransTdcOnSessionOpened(g_sessionName, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    info->isServer = true;
    info->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientTransTdcOnSessionOpened(nullptr, info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = ClientTransTdcOnSessionOpened(g_sessionName, info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    info->isServer = false;
    info->channelType = CHANNEL_TYPE_UDP;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(info);
}

/**
 * @tc.name: ClientTransTdcOnSessionClosedTest0011
 * @tc.desc: ClientTransTdcOnSessionClosed, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionClosedTest0011, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    ret = ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = ClientTransTdcOnSessionOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    const char *data = "client";
    uint32_t len = strlen(data);
    ret = ClientTransTdcOnDataReceived(channelId, (void *)data, len, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcCreateListenerTest0012
 * @tc.desc: TransTdcCreateListener, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCreateListenerTest0012, TestSize.Level0)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    fd = g_fd;
    ret = TransTdcCreateListener(fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransTdcReleaseFdTest0013
 * @tc.desc: TransTdcReleaseFd, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcReleaseFdTest0013, TestSize.Level0)
{
    int32_t fd = INVALID_VALUE;
    TransTdcReleaseFd(fd);
    EXPECT_TRUE(INVALID_VALUE == fd);

    fd = g_fd;
    TransTdcReleaseFd(fd);
    EXPECT_TRUE(g_fd == fd);
}

/**
 * @tc.name: TransTdcStopReadTest0014
 * @tc.desc: TransTdcStopRead, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcStopReadTest0014, TestSize.Level0)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcStopRead(fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    fd = g_fd;
    ret = TransTdcStopRead(fd);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: ClientTransTdcOnChannelOpenFailedTest0015
 * @tc.desc: ClientTransTdcOnChannelOpenFailed, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenFailedTest0015, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = ClientTransTdcOnChannelOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    channelId = INVALID_VALUE;
    ret = ClientTransTdcOnChannelOpenFailed(channelId, errCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: TransDataListInitTest0016
 * @tc.desc: TransDataListInit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDataListInitTest0016, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransAddDataBufNode(channelId, fd);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDelDataBufNode(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransDelDataBufNode(channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransDataListDeinit();
}

/**
 * @tc.name: TransTdcSendBytesTest0017
 * @tc.desc: TransTdcSendBytes, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendBytesTest0017, TestSize.Level0)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = (uint32_t)strlen(data);
    int32_t ret = TransTdcSendBytes(channelId, nullptr, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendBytes(channelId, data, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendBytes(channelId, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendBytes(channelId, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcSendMessageTest0018
 * @tc.desc: TransTdcSendMessage, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendMessageTest0018, TestSize.Level0)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = (uint32_t)strlen(data);
    int32_t ret = TransTdcSendMessage(channelId, nullptr, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendMessage(channelId, data, 0);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcRecvDataTest0019
 * @tc.desc: TransTdcRecvData, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcRecvDataTest0019, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    int32_t ret = TransTdcRecvData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcRecvData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcRecvData(channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransDataListDeinit();
}
} // namespace OHOS
