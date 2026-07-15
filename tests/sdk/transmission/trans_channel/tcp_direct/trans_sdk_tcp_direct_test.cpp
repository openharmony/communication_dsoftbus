/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "client_trans_file_listener.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_tcp_direct_listener.h"
#include "client_trans_tcp_direct_manager.c"
#include "client_trans_tcp_direct_message.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

using namespace testing::ext;

namespace OHOS {
#define INVALID_VALUE   (-1)
#define SESSIONKEY_LEN  46
#define SESSION_KEY_LEN 46
static const char *g_sessionName = "ohos.distributedschedule.dms.test";
char g_peerSessionName[SESSIONKEY_LEN] = "ohos.distributedschedule.dms.test";
static const char *g_sessionkey = "clientkey";
char g_peerSessionKey[SESSION_KEY_LEN] = "clientkey";
static const char *g_pkgName = "pkgname";
static int32_t g_fd = socket(AF_INET, SOCK_STREAM, 0);

class TransSdkTcpDirectTest : public testing::Test {
public:
    TransSdkTcpDirectTest(void) { }
    ~TransSdkTcpDirectTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

static int32_t OnServerSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "OnServerSessionOpened, sessionId=%{public}d, result=%{public}d", sessionId, result);
    return SOFTBUS_OK;
}

static void OnServerSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "OnServerSessionClosed, sessionId=%{public}d", sessionId);
}

static void OnServerBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "OnServerBytesReceived, sessionId=%{public}d, len=%{public}u", sessionId, len);
}

static void OnServerMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "OnServerMessageReceived, sessionId=%{public}d, len=%{public}u", sessionId, len);
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnServerSessionOpened,
    .OnSessionClosed = OnServerSessionClosed,
    .OnBytesReceived = OnServerBytesReceived,
    .OnMessageReceived = OnServerMessageReceived,
};

static int32_t OnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    (void)channel;
    (void)flag;
    (void)accessInfo;
    TRANS_LOGI(TRANS_TEST, "OnSessionOpened, sessionName=%{public}s", sessionName);
    return SOFTBUS_OK;
}

static int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    (void)reason;
    TRANS_LOGI(TRANS_TEST, "OnSessionClosed, channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_OK;
}

static int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    TRANS_LOGI(TRANS_TEST, "OnSessionOpenFailed, channelId=%{public}d, channelType=%{public}d, errCode=%{public}d",
        channelId, channelType, errCode);
    return SOFTBUS_OK;
}

static int32_t OnDataReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    (void)data;
    TRANS_LOGI(TRANS_TEST,
        "OnDataReceived, channelId=%{public}d, channelType=%{public}d, len=%{public}u, type=%{public}d", channelId,
        channelType, len, type);
    return SOFTBUS_OK;
}

static int32_t OnChannelBindOne(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_TEST, "OnChannelBindOne, channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_NOT_NEED_UPDATE;
}

static int32_t OnChannelBindTwo(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_TEST, "OnChannelBindTwo, channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_INVALID_PARAM;
}

static int32_t OnChannelBindThree(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_TEST, "OnChannelBindThree, channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_OK;
}

static IClientSessionCallBack g_sessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
};

static IClientSessionCallBack g_sessionCbTestOne = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnChannelBind = OnChannelBindOne,
};

static IClientSessionCallBack g_sessionCbTestTwo = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnChannelBind = OnChannelBindTwo,
};

static IClientSessionCallBack g_sessionCbTestThree = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnDataReceived,
    .OnChannelBind = OnChannelBindThree,
};

ChannelInfo *TestGetChannelInfo(void)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusMalloc(sizeof(ChannelInfo)));
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    info->peerSessionName = g_peerSessionName;
    info->channelId = 1;
    info->channelType = CHANNEL_TYPE_TCP_DIRECT;
    info->sessionKey = g_peerSessionKey;
    info->fd = g_fd;
    return info;
}

TcpDirectChannelInfo *TestGetTcpDirectChannelInfo(void)
{
    TcpDirectChannelInfo *item = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusMalloc(sizeof(TcpDirectChannelInfo)));
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransTdcManagerInit(&g_sessionCb);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitBaseListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TransSdkTcpDirectTest::TearDownTestCase(void)
{
    TransTdcManagerDeinit();
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest001
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_INVALID_PARAM when no OnChannelBind callback is set
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest002
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_OK when OnChannelBind callback returns
 *           SOFTBUS_NOT_NEED_UPDATE
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCbTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest003
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_INVALID_PARAM when OnChannelBind callback returns
 *           SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCbTestTwo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenedTest001
 * @tc.desc: verify ClientTransTdcOnChannelOpened return SOFTBUS_INVALID_PARAM when sessionName or channel is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenedTest001, TestSize.Level1)
{
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(nullptr, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransTdcOnChannelOpened(g_sessionName, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenedTest002
 * @tc.desc: verify ClientTransTdcOnChannelOpened return SOFTBUS_MEM_ERR when valid params with null AccessInfo
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenedTest002, TestSize.Level1)
{
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcCloseChannelTest001
 * @tc.desc: verify TransTdcCloseChannel works correctly when channel info exists in list with fdRefCnt=0
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCloseChannelTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransTdcManagerInit(&g_sessionCb);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    info->detail.fdRefCnt = 0;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransTdcCloseChannel(channelId);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetSessionKeyTest001
 * @tc.desc: verify TransTdcGetSessionKey return SOFTBUS_INVALID_PARAM when key is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetSessionKeyTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    unsigned int len = 32;
    int32_t ret = TransTdcGetSessionKey(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = INVALID_VALUE;
    ret = TransTdcGetSessionKey(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcGetSessionKeyTest002
 * @tc.desc: verify TransTdcGetSessionKey return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channel not found
 *           with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetSessionKeyTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    unsigned int len = 32;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetSessionKeyTest003
 * @tc.desc: verify TransTdcGetSessionKey return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channelId is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetSessionKeyTest003, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    unsigned int len = 32;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetHandleTest001
 * @tc.desc: verify TransTdcGetHandle return SOFTBUS_INVALID_PARAM when handle is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetHandleTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransTdcGetHandle(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = INVALID_VALUE;
    ret = TransTdcGetHandle(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcGetHandleTest002
 * @tc.desc: verify TransTdcGetHandle return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channel not found
 *           with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetHandleTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t handle = 0;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetHandleTest003
 * @tc.desc: verify TransTdcGetHandle return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channelId is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetHandleTest003, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    int32_t handle = 0;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransDisableSessionListenerTest001
 * @tc.desc: verify TransDisableSessionListener return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channel not found
 *           with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransDisableSessionListenerTest002
 * @tc.desc: verify TransDisableSessionListener return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channelId is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest002, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransDisableSessionListenerTest003
 * @tc.desc: verify TransDisableSessionListener return SOFTBUS_INVALID_FD when fd is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errFd = -1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    info->detail.fd = errFd;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransDisableSessionListenerTest004
 * @tc.desc: verify TransDisableSessionListener return SOFTBUS_OK when channel found with valid fd
 *           and needStopListener=false
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    info->detail.fd = g_fd;
    info->detail.needStopListener = false;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdTest001
 * @tc.desc: verify TransTdcGetInfoById return not SOFTBUS_OK when info is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t item = TransTdcGetInfoById(channelId, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);
    channelId = INVALID_VALUE;
    item = TransTdcGetInfoById(channelId, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcGetInfoByIdTest002
 * @tc.desc: verify TransTdcGetInfoById return not SOFTBUS_OK when channel not found with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t item = TransTdcGetInfoById(channelId, info);
    EXPECT_NE(item, SOFTBUS_OK);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdTest003
 * @tc.desc: verify TransTdcGetInfoById return not SOFTBUS_OK when channelId is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest003, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t item = TransTdcGetInfoById(channelId, info);
    EXPECT_NE(item, SOFTBUS_OK);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdTest004
 * @tc.desc: verify TransTdcGetInfoById return SOFTBUS_OK when channel found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t item = TransTdcGetInfoById(channelId, info);
    EXPECT_EQ(item, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdTest005
 * @tc.desc: verify TransTdcGetInfoById return SOFTBUS_OK when multiple channels in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *testInfo =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(testInfo != nullptr);
    TcpDirectChannelInfo *infoTest =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(infoTest != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    testInfo->channelId = 0;
    infoTest->channelId = SESSIONKEY_LEN;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    ListAdd(&g_tcpDirectChannelInfoList->list, &testInfo->node);
    ListAdd(&g_tcpDirectChannelInfoList->list, &infoTest->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t item = TransTdcGetInfoById(channelId, info);
    EXPECT_EQ(item, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    ListDelete(&testInfo->node);
    SoftBusFree(testInfo);
    ListDelete(&infoTest->node);
    SoftBusFree(infoTest);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByFdTest001
 * @tc.desc: verify TransTdcGetInfoByFd return not SOFTBUS_OK when info is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest001, TestSize.Level1)
{
    int32_t fd = g_fd;
    int32_t item = TransTdcGetInfoByFd(fd, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);
    fd = 1;
    item = TransTdcGetInfoByFd(fd, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcGetInfoByFdTest002
 * @tc.desc: verify TransTdcGetInfoByFd return not SOFTBUS_OK when channel not found
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest002, TestSize.Level1)
{
    int32_t fd = g_fd;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t item = TransTdcGetInfoByFd(fd, info);
    EXPECT_NE(item, SOFTBUS_OK);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByFdTest003
 * @tc.desc: verify TransTdcGetInfoByFd return SOFTBUS_OK when channel found by fd in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest003, TestSize.Level1)
{
    int32_t testFd = 123;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *infoTest =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(infoTest != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->detail.fd = testFd;
    infoTest->detail.fd = 1;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    ListAdd(&g_tcpDirectChannelInfoList->list, &infoTest->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t item = TransTdcGetInfoByFd(testFd, info);
    EXPECT_EQ(item, SOFTBUS_OK);
    item = TransTdcGetInfoByFd(1, infoTest);
    EXPECT_EQ(item, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    ListDelete(&infoTest->node);
    SoftBusFree(infoTest);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoIncFdRefByIdTest001
 * @tc.desc: verify TransTdcGetInfoIncFdRefById return nullptr when info is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoIncFdRefByIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *item = TransTdcGetInfoIncFdRefById(channelId, nullptr, true);
    EXPECT_EQ(item, nullptr);
    channelId = INVALID_VALUE;
    item = TransTdcGetInfoIncFdRefById(channelId, nullptr, true);
    EXPECT_EQ(item, nullptr);
}

/*
 * @tc.name: TransTdcGetInfoIncFdRefByIdTest002
 * @tc.desc: verify TransTdcGetInfoIncFdRefById return nullptr when channel not found with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoIncFdRefByIdTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    TcpDirectChannelInfo *item = TransTdcGetInfoIncFdRefById(channelId, info, true);
    EXPECT_EQ(item, nullptr);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoIncFdRefByIdTest003
 * @tc.desc: verify TransTdcGetInfoIncFdRefById return nullptr when channelId is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoIncFdRefByIdTest003, TestSize.Level1)
{
    int32_t channelId = INVALID_VALUE;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    TcpDirectChannelInfo *item = TransTdcGetInfoIncFdRefById(channelId, info, true);
    EXPECT_EQ(item, nullptr);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoIncFdRefByIdTest004
 * @tc.desc: verify TransTdcGetInfoIncFdRefById return non-null when channel found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoIncFdRefByIdTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *infoTest =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(infoTest != nullptr);
    TcpDirectChannelInfo *testInfo =
        reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(testInfo != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    infoTest->channelId = 0;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    ListAdd(&g_tcpDirectChannelInfoList->list, &infoTest->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TcpDirectChannelInfo *item = TransTdcGetInfoIncFdRefById(channelId, testInfo, true);
    EXPECT_NE(item, nullptr);
    channelId = 0;
    item = TransTdcGetInfoIncFdRefById(channelId, testInfo, true);
    EXPECT_NE(item, nullptr);
    ListDelete(&info->node);
    SoftBusFree(info);
    ListDelete(&infoTest->node);
    SoftBusFree(infoTest);
    ListDelete(&testInfo->node);
    SoftBusFree(testInfo);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransTdcSetCallBackTest001
 * @tc.desc: verify ClientTransTdcSetCallBack with null and valid callback
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcSetCallBackTest001, TestSize.Level1)
{
    int32_t ret = ClientTransTdcSetCallBack(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const IClientSessionCallBack *cb = GetClientSessionCb();
    ret = ClientTransTdcSetCallBack(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenedTest001
 * @tc.desc: verify ClientTransTdcOnSessionOpened return SOFTBUS_INVALID_PARAM when channel or sessionName is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest001, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnSessionOpened(g_sessionName, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransTdcOnSessionOpened(nullptr, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenedTest002
 * @tc.desc: verify ClientTransTdcOnSessionOpened return SOFTBUS_OK when isServer=true and channelType=AUTH
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest002, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info->isServer = true;
    info->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenedTest003
 * @tc.desc: verify ClientTransTdcOnSessionOpened return SOFTBUS_OK when isServer=false and channelType=UDP
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest003, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info->isServer = false;
    info->channelType = CHANNEL_TYPE_UDP;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenedTest004
 * @tc.desc: verify ClientTransTdcOnSessionOpened return SOFTBUS_OK when channelType=BUSINESS_TYPE_MESSAGE
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest004, TestSize.Level1)
{
    ChannelInfo *info = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info->isServer = false;
    info->channelType = BUSINESS_TYPE_MESSAGE;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTransTdcOnSessionClosedTest001
 * @tc.desc: verify ClientTransTdcOnSessionClosed return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionClosedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenFailedTest001
 * @tc.desc: verify ClientTransTdcOnSessionOpenFailed return SOFTBUS_OK with valid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenFailedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnSessionOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransTdcOnDataReceivedTest001
 * @tc.desc: verify ClientTransTdcOnDataReceived return SOFTBUS_OK with valid data
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnDataReceivedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "client";
    uint32_t len = static_cast<uint32_t>(strlen(data));
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnDataReceived(channelId, data, len, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcCreateListenerTest001
 * @tc.desc: verify TransTdcCreateListener return SOFTBUS_INVALID_PARAM with invalid fd
 *           and SOFTBUS_OK with valid fd
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCreateListenerTest001, TestSize.Level1)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    fd = g_fd;
    ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcReleaseFdTest001
 * @tc.desc: verify TransTdcReleaseFd works correctly with valid and invalid fd after creating listener
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcReleaseFdTest001, TestSize.Level1)
{
    int32_t fd = g_fd;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransTdcReleaseFd(fd);
    fd = INVALID_VALUE;
    TransTdcReleaseFd(fd);
}

/*
 * @tc.name: TransTdcStopReadTest001
 * @tc.desc: verify TransTdcStopRead return SOFTBUS_OK when fd is invalid
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcStopReadTest001, TestSize.Level1)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcStopReadTest002
 * @tc.desc: verify TransTdcStopRead return SOFTBUS_OK after creating listener
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcStopReadTest002, TestSize.Level1)
{
    int32_t fd = g_fd + 1;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcStopReadTest003
 * @tc.desc: verify TransTdcStopRead return SOFTBUS_NOT_FIND when stop read twice
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcStopReadTest003, TestSize.Level1)
{
    int32_t fd = g_fd + 1;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenFailedTest001
 * @tc.desc: verify ClientTransTdcOnChannelOpenFailed return SOFTBUS_OK with valid and invalid channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = ClientTransTdcOnChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = INVALID_VALUE;
    ret = ClientTransTdcOnChannelOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransDataListInitTest001
 * @tc.desc: verify TransDataListInit return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDataListInitTest001, TestSize.Level1)
{
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransAddDataBufNodeTest001
 * @tc.desc: verify TransAddDataBufNode return SOFTBUS_NO_INIT when data list not initialized
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransAddDataBufNodeTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransDelDataBufNodeTest001
 * @tc.desc: verify TransDelDataBufNode return SOFTBUS_NO_INIT when data list not initialized
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDelDataBufNodeTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransDataListDeinit();
    int32_t ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    channelId = INVALID_VALUE;
    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransAddDataBufNodeTest002
 * @tc.desc: verify TransAddDataBufNode return SOFTBUS_OK when data list initialized
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransAddDataBufNodeTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransDelDataBufNodeTest002
 * @tc.desc: verify TransDelDataBufNode return SOFTBUS_OK when data list initialized and node exists
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDelDataBufNodeTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcSendBytesTest001
 * @tc.desc: verify TransTdcSendBytes return SOFTBUS_INVALID_PARAM when data is nullptr or len is 0
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = static_cast<uint32_t>(strlen(data));
    int32_t ret = TransTdcSendBytes(channelId, nullptr, len, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcSendBytes(channelId, data, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcSendBytesTest002
 * @tc.desc: verify TransTdcSendBytes return SOFTBUS_TRANS_TDC_GET_INFO_FAILED when channel not found
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = static_cast<uint32_t>(strlen(data));
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcSendBytes(channelId, data, len, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSendMessageTest001
 * @tc.desc: verify TransTdcSendMessage return SOFTBUS_INVALID_PARAM when data is nullptr or len is 0
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = static_cast<uint32_t>(strlen(data));
    int32_t ret = TransTdcSendMessage(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransTdcSendMessage(channelId, data, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcSendMessageTest002
 * @tc.desc: verify TransTdcSendMessage return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channel not found
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendMessageTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = static_cast<uint32_t>(strlen(data));
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcRecvDataTest001
 * @tc.desc: verify TransTdcRecvData return SOFTBUS_NO_INIT when data list not initialized
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcRecvDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransDataListDeinit();
    int32_t ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    channelId = INVALID_VALUE;
    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: TransTdcRecvDataTest002
 * @tc.desc: verify TransTdcRecvData return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND when channel not found
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcRecvDataTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TransDataListDeinit();
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcRecvDataTest003
 * @tc.desc: verify TransTdcRecvData return SOFTBUS_TRANS_INVALID_DATA_LENGTH when data buf node exists
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcRecvDataTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcCreateListenerWithoutAddTriggerTest001
 * @tc.desc: verify TransTdcCreateListenerWithoutAddTrigger return SOFTBUS_OK with valid fd
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCreateListenerWithoutAddTriggerTest001, TestSize.Level1)
{
    int32_t fd = g_fd;
    int32_t ret = TransTdcCreateListenerWithoutAddTrigger(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    fd = g_fd + 1;
    ret = TransTdcCreateListenerWithoutAddTrigger(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransCheckTdcChannelExistTest001
 * @tc.desc: verify ClientTransCheckTdcChannelExist return SOFTBUS_OK when no channel exists in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransCheckTdcChannelExistTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    int32_t ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channelId = INVALID_VALUE;
    ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransCheckTdcChannelExistTest002
 * @tc.desc: verify ClientTransCheckTdcChannelExist return SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_EXIST when channel exists
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransCheckTdcChannelExistTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_EXIST);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcDelChannelInfoTest001
 * @tc.desc: verify TransTdcDelChannelInfo works correctly when channel info list is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcDelChannelInfoTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransTdcDelChannelInfo(channelId, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    EXPECT_EQ(g_tcpDirectChannelInfoList, nullptr);
    channelId = INVALID_VALUE;
    TransTdcDelChannelInfo(channelId, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    EXPECT_EQ(g_tcpDirectChannelInfoList, nullptr);
}

/*
 * @tc.name: TransTdcDelChannelInfoTest002
 * @tc.desc: verify TransTdcDelChannelInfo works correctly when channelId not found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcDelChannelInfoTest002, TestSize.Level1)
{
    int32_t channelId1 = 1;
    int32_t channelId2 = 2;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId1;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransTdcDelChannelInfo(channelId2, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcDelChannelInfoTest003
 * @tc.desc: verify TransTdcDelChannelInfo works correctly when channelId found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcDelChannelInfoTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransTdcDelChannelInfo(channelId, errCode);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransUpdateFdStateTest001
 * @tc.desc: verify TransUpdateFdState works correctly when channel info list is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransUpdateFdStateTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TransUpdateFdState(channelId);
    EXPECT_EQ(g_tcpDirectChannelInfoList, nullptr);
    channelId = INVALID_VALUE;
    TransUpdateFdState(channelId);
    EXPECT_EQ(g_tcpDirectChannelInfoList, nullptr);
}

/*
 * @tc.name: TransUpdateFdStateTest002
 * @tc.desc: verify TransUpdateFdState works correctly when channelId not found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransUpdateFdStateTest002, TestSize.Level1)
{
    int32_t channelId1 = 1;
    int32_t channelId2 = 2;
    int32_t fdRefCnt = 3;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId1;
    info->detail.fdRefCnt = fdRefCnt;
    info->detail.needRelease = true;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransUpdateFdState(channelId2);
    EXPECT_EQ(info->detail.fdRefCnt, fdRefCnt);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransUpdateFdStateTest003
 * @tc.desc: verify TransUpdateFdState works correctly when channelId found and needRelease=true
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransUpdateFdStateTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fdRefCnt = 3;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    info->detail.fdRefCnt = fdRefCnt;
    info->detail.needRelease = true;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransUpdateFdState(channelId);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransUpdateFdStateTest004
 * @tc.desc: verify TransUpdateFdState works correctly when channelId found and needRelease=false
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransUpdateFdStateTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fdRefCnt = 3;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    info->detail.fdRefCnt = fdRefCnt;
    info->detail.needRelease = false;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransUpdateFdState(channelId);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSetListenerStateByIdTest001
 * @tc.desc: verify TransTdcSetListenerStateById return SOFTBUS_INVALID_PARAM when channel info list is nullptr
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSetListenerStateByIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransTdcSetListenerStateById(channelId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelId = INVALID_VALUE;
    ret = TransTdcSetListenerStateById(channelId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransTdcSetListenerStateByIdTest002
 * @tc.desc: verify TransTdcSetListenerStateById return SOFTBUS_OK when channelId found and set needStopListener=true
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSetListenerStateByIdTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    info->detail.needStopListener = false;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransTdcSetListenerStateById(channelId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSetListenerStateByIdTest003
 * @tc.desc: verify TransTdcSetListenerStateById return SOFTBUS_NOT_FIND when channelId not found in list
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSetListenerStateByIdTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t invalidChannelId = 2;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransTdcSetListenerStateById(invalidChannelId, true);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcSetListenerStateByIdTest004
 * @tc.desc: verify TransTdcSetListenerStateById return SOFTBUS_OK when set needStopListener=false
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSetListenerStateByIdTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransTdcSetListenerStateById(channelId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: GetFdByPeerIpAndPortTest001
 * @tc.desc: verify GetFdByPeerIpAndPort return SOFTBUS_INVALID_PARAM when channel info list is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, GetFdByPeerIpAndPortTest001, TestSize.Level1)
{
    int32_t fd = -1;
    int32_t ret = GetFdByPeerIpAndPort("127.0.0.1", 1234, &fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    fd = -1;
    ret = GetFdByPeerIpAndPort("192.168.1.1", 5678, &fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetFdByPeerIpAndPortTest002
 * @tc.desc: verify GetFdByPeerIpAndPort return SOFTBUS_OK when matching peerIp and peerPort found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, GetFdByPeerIpAndPortTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t fd = -1;
    int32_t ret = GetFdByPeerIpAndPort("127.0.0.1", 1234, &fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(fd, 123);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: GetFdByPeerIpAndPortTest003
 * @tc.desc: verify GetFdByPeerIpAndPort return SOFTBUS_NOT_FIND when peerIp or peerPort not matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, GetFdByPeerIpAndPortTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t fd = -1;
    int32_t ret = GetFdByPeerIpAndPort("127.0.0.1", 1235, &fd);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransStartTimeSyncTest001
 * @tc.desc: verify TransStartTimeSync return SOFTBUS_STRCPY_ERR when peerIp or peerDeviceId is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStartTimeSyncTest001, TestSize.Level1)
{
    ChannelInfo channel;
    (void)memset_s(&channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    channel.peerIp = nullptr;
    int32_t ret = TransStartTimeSync(&channel);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    channel.peerIp = const_cast<char *>("127.0.0.1");
    channel.peerDeviceId = nullptr;
    ret = TransStartTimeSync(&channel);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
}

/*
 * @tc.name: TransStartTimeSyncTest002
 * @tc.desc: verify TransStartTimeSync return not SOFTBUS_OK when pkgName is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStartTimeSyncTest002, TestSize.Level1)
{
    ChannelInfo channel;
    (void)memset_s(&channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    channel.peerIp = const_cast<char *>("127.0.0.1");
    channel.peerDeviceId = const_cast<char *>("1234567890");
    channel.pkgName = nullptr;
    int32_t ret = TransStartTimeSync(&channel);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnTimeSyncResultByIpTest001
 * @tc.desc: verify OnTimeSyncResultByIp works correctly with null and valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, OnTimeSyncResultByIpTest001, TestSize.Level1)
{
    OnTimeSyncResultByIp(nullptr, -1);
    OnTimeSyncResultByIp(nullptr, SOFTBUS_OK);
    TimeSyncResultWithSocket info;
    (void)memset_s(&info, sizeof(TimeSyncResultWithSocket), 0, sizeof(TimeSyncResultWithSocket));
    (void)strcpy_s(info.targetSocketInfo.peerIp, sizeof(info.targetSocketInfo.peerIp), "127.0.0.1");
    info.targetSocketInfo.peerPort = 1234;
    OnTimeSyncResultByIp(&info, SOFTBUS_OK);
}

/*
 * @tc.name: TransStopTimeSyncTest001
 * @tc.desc: verify TransStopTimeSync return not SOFTBUS_OK when no channel found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStopTimeSyncTest001, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = TransStopTimeSync(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    channelId = INVALID_VALUE;
    ret = TransStopTimeSync(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransStopTimeSyncTest002
 * @tc.desc: verify TransStopTimeSync return SOFTBUS_OK when channel found with LNN_PROTOCOL_IP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStopTimeSyncTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;
    info->detail.fdProtocol = LNN_PROTOCOL_IP;
    (void)strcpy_s(info->detail.peerDeviceId, sizeof(info->detail.peerDeviceId), "1234567890");
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransStopTimeSync(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransStopTimeSyncTest003
 * @tc.desc: verify TransStopTimeSync return not SOFTBUS_OK when channel found with LNN_PROTOCOL_DETTP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStopTimeSyncTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;
    info->detail.fdProtocol = LNN_PROTOCOL_DETTP;
    (void)strcpy_s(info->detail.peerDeviceId, sizeof(info->detail.peerDeviceId), "1234567890");
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransStopTimeSync(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransStopTimeSyncTest004
 * @tc.desc: verify TransStopTimeSync return SOFTBUS_OK when channel found with LNN_PROTOCOL_MINTP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStopTimeSyncTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;
    info->detail.fdProtocol = LNN_PROTOCOL_MINTP;
    (void)strcpy_s(info->detail.peerDeviceId, sizeof(info->detail.peerDeviceId), "1234567890");
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = TransStopTimeSync(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest004
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_NOT_FIND when channelId not found in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->detail.needStopListener = true;
    info->detail.fd = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCbTestThree);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest005
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_OK when channelId found and needStopListener=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    info->detail.needStopListener = true;
    info->detail.fd = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCbTestThree);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest006
 * @tc.desc: verify ClientTransTdcOnChannelBind return SOFTBUS_OK when channelId found and needStopListener=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest006, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TcpDirectChannelInfo *info = reinterpret_cast<TcpDirectChannelInfo *>(SoftBusCalloc(sizeof(TcpDirectChannelInfo)));
    ASSERT_TRUE(info != nullptr);
    info->channelId = channelId;
    info->detail.needStopListener = false;
    info->detail.fd = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCbTestThree);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}
} // namespace OHOS
