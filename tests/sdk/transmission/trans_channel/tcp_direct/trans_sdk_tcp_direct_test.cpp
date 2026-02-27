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
#include "client_trans_tcp_direct_manager.c"
#include "client_trans_file_listener.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_session_callback.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_listener.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
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
    {}
    ~TransSdkTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static int32_t OnServerSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "session opened, sesisonId=%{public}d\r\n", sessionId);
    return SOFTBUS_OK;
}

static void OnServerSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "session closed, sessionId=%{public}d\r\n", sessionId);
}

static void OnServerBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session bytes received, sessionId=%{public}d\r\n", sessionId);
}

static void OnServerMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "session msg received, sessionId=%{public}d\r\n", sessionId);
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
    TRANS_LOGI(TRANS_TEST, "session opened, sesisonName=%{public}s", sessionName);
    return SOFTBUS_OK;
}

static int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    (void)channelType;
    (void)reason;
    TRANS_LOGI(TRANS_TEST, "session closed, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)channelType;
    (void)errCode;
    TRANS_LOGI(TRANS_TEST, "session bytes received, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t OnDataReceived(int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, SessionPktType type)
{
    (void)channelType;
    (void)data;
    (void)len;
    (void)type;
    TRANS_LOGI(TRANS_TEST, "session msg received, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static int32_t OnChannelBindOne(int32_t channelId, int32_t channelType)
{
    (void)channelType;
    TRANS_LOGI(TRANS_TEST, "session on bind, channelId=%{public}d", channelId);
    return SOFTBUS_NOT_NEED_UPDATE;
}

static int32_t OnChannelBindTwo(int32_t channelId, int32_t channelType)
{
    (void)channelType;
    TRANS_LOGI(TRANS_TEST, "session on bind, channelId=%{public}d", channelId);
    return SOFTBUS_INVALID_PARAM;
}

static int32_t OnChannelBindThree(int32_t channelId, int32_t channelType)
{
    (void)channelType;
    TRANS_LOGI(TRANS_TEST, "session on bind, channelId=%{public}d", channelId);
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransTdcManagerInit(&g_sessionCb);
    uint64_t timestamp = 0;
    ret = ClientAddSessionServer(SEC_TYPE_PLAINTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(ret,  SOFTBUS_OK);
    ret = InitBaseListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TransSdkTcpDirectTest::TearDownTestCase(void)
{
    TransTdcManagerDeinit();
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest001
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
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
    ret = ClientTransTdcSetCallBack(&g_sessionCbTestOne);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcSetCallBack(&g_sessionCbTestTwo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenedTest001
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
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

    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcCloseChannelTest002
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCloseChannelTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    TransTdcManagerInit(&g_sessionCb);

    TransTdcCloseChannel(channelId);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    TransTdcCloseChannel(channelId);

    channelId = INVALID_VALUE;
    TransTdcCloseChannel(channelId);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcGetSessionKeyTest003
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetSessionKeyTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    unsigned int len = 32;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = TransTdcGetSessionKey(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    channelId = INVALID_VALUE;
    ret = TransTdcGetSessionKey(channelId, const_cast<char *>(g_sessionkey), len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcGetHandleTest004
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetHandleTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t handle = 0;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = TransTdcGetHandle(channelId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    channelId = INVALID_VALUE;
    ret = TransTdcGetHandle(channelId, &handle);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransDisableSessionListenerTest005
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
 
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest005, TestSize.Level1)
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

    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    info->fd = g_fd;
    ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    channelId = INVALID_VALUE;
    ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    SoftBusFree(info);
}

/*
 * @tc.name: TransTdcGetInfoByIdTest006
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest006, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    int32_t item = TransTdcGetInfoById(channelId, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);

    item = TransTdcGetInfoById(channelId, info);
    EXPECT_NE(item, SOFTBUS_OK);

    channelId = INVALID_VALUE;
    item = TransTdcGetInfoById(channelId, info);
    EXPECT_NE(item, SOFTBUS_OK);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcGetInfoByFdTest007
 * @tc.desc: Test the behavior of the TransTdcGetInfoByFd function
 *           under different exceptional conditions
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest007, TestSize.Level1)
{
    int32_t fd = g_fd;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    int32_t item = TransTdcGetInfoByFd(fd, nullptr);
    EXPECT_NE(item, SOFTBUS_OK);

    item = TransTdcGetInfoByFd(fd, info);
    EXPECT_NE(item, SOFTBUS_OK);

    fd = 1;
    item = TransTdcGetInfoByFd(fd, info);
    EXPECT_NE(item, SOFTBUS_OK);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcGetInfoByIdWithIncSeqTest008
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdWithIncSeqTest008, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusMalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(TcpDirectChannelInfo), 0, sizeof(TcpDirectChannelInfo));

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    TcpDirectChannelInfo *item = TransTdcGetInfoIncFdRefById(channelId, nullptr, true);
    EXPECT_TRUE(item == nullptr);

    item = TransTdcGetInfoIncFdRefById(channelId, info, true);
    EXPECT_TRUE(item == nullptr);

    channelId = INVALID_VALUE;
    item = TransTdcGetInfoIncFdRefById(channelId, info, true);
    EXPECT_TRUE(item == nullptr);

    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientTransTdcSetCallBackTest009
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcSetCallBackTest009, TestSize.Level1)
{
    const IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransTdcSetCallBack(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = ClientTransTdcSetCallBack(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransTdcOnSessionOpenedTest0010
 * @tc.desc: Verify whether the method can correctly return the expected error code
 *           when invalid parameters are passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionOpenedTest0010, TestSize.Level1)
{
    ChannelInfo *info = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)memset_s(info, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));

    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    ret = ClientTransTdcOnSessionOpened(g_sessionName, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    info->isServer = true;
    info->channelType = CHANNEL_TYPE_AUTH;
    ret = ClientTransTdcOnSessionOpened(nullptr, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info->isServer = false;
    info->channelType = CHANNEL_TYPE_UDP;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info->channelType = BUSINESS_TYPE_MESSAGE;
    ret = ClientTransTdcOnSessionOpened(g_sessionName, info, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: ClientTransTdcOnSessionClosedTest0011
 * @tc.desc: Test the TCP direct connection module related functions
 *           in session closure scenarios
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnSessionClosedTest0011, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = SOFTBUS_OK;
    int32_t ret = ClientTransTdcSetCallBack(&g_sessionCb);
    ret = ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ClientTransTdcOnSessionOpenFailed(channelId, errCode);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *data = "client";
    uint32_t len = strlen(data);
    ret = ClientTransTdcOnDataReceived(channelId, (void *)data, len, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcCreateListenerTest0012
 * @tc.desc: Test the parameter validation and normal listener creation functionality
 *           of the TransTdcCreateListener function
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCreateListenerTest0012, TestSize.Level1)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    fd = g_fd;
    ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransTdcReleaseFdTest0013
 * @tc.desc: Test the functionality and behavior of the TransTdcReleaseFd function
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcReleaseFdTest0013, TestSize.Level1)
{
    int32_t fd = INVALID_VALUE;
    TransTdcReleaseFd(fd);
    EXPECT_EQ(fd, INVALID_VALUE);
    fd = g_fd;
    TransTdcReleaseFd(fd);
    EXPECT_TRUE(g_fd == fd);
}

/*
 * @tc.name: TransTdcStopReadTest0014
 * @tc.desc: Test the functionality and boundary conditions of the TransTdcStopRead function
 *           in the TCP direct connection module
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcStopReadTest0014, TestSize.Level1)
{
    int32_t fd = INVALID_VALUE;
    int32_t ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    fd = g_fd + 1;
    ret = TransTdcCreateListener(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransTdcStopRead(fd);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: ClientTransTdcOnChannelOpenFailedTest0015
 * @tc.desc: Test the behavior of the ClientTransTdcOnChannelOpenFailed function
 *           under different channelId inputs
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelOpenFailedTest0015, TestSize.Level1)
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
 * @tc.name: TransDataListInitTest0016
 * @tc.desc: Test the operations related to the data buffer list
 *           including initialization adding nodes and deleting nodes
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDataListInitTest0016, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    TransDataListDeinit();
    int32_t ret = TransAddDataBufNode(channelId, fd);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransDelDataBufNode(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcSendBytesTest0017
 * @tc.desc: Test the behavior of the TransTdcSendBytes function in the TCP direct connection module
 *           under various boundary conditions
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendBytesTest0017, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = (uint32_t)strlen(data);
    int32_t ret = TransTdcSendBytes(channelId, nullptr, len, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcSendBytes(channelId, data, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcSendBytes(channelId, data, len, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = TransTdcSendBytes(channelId, data, len, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_GET_INFO_FAILED);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcSendMessageTest0018
 * @tc.desc: Test the behavior of the TransTdcSendMessage funtion in the TCP direct connection module
 *           under different scenarios
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSendMessageTest0018, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "data";
    uint32_t len = (uint32_t)strlen(data);
    int32_t ret = TransTdcSendMessage(channelId, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcSendMessage(channelId, data, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);
    ret = ClientTransTdcOnChannelOpened(g_sessionName, channel, nullptr);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = TransTdcSendMessage(channelId, data, len);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    SoftBusFree(channel);
}

/*
 * @tc.name: TransTdcRecvDataTest0019
 * @tc.desc: Test the behavior of receiving data over a direct TCP connection
 *           under different initialization states
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcRecvDataTest0019, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t fd = 1;
    int32_t ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = TransDataListInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND);

    ret = TransAddDataBufNode(channelId, fd);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TransTdcRecvData(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_DATA_LENGTH);
    TransDataListDeinit();
}

/*
 * @tc.name: TransTdcCreateListenerWithoutAddTriggerTest0020
 * @tc.desc: Test whether the function can successfully create a lister without adding a trigger and
 *           return the expected success status code SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCreateListenerWithoutAddTriggerTest0020, TestSize.Level1)
{
    int32_t fd = g_fd;
    int32_t ret = TransTdcCreateListenerWithoutAddTrigger(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientTransCheckTdcChannelExist001
 * @tc.desc: Test the functionality of the ClientTransCheckTdcChannelExist fucntion which is used to check
 *           whether a TCP direct cinnection channel already exists
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransCheckTdcChannelExist001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransCheckTdcChannelExist(1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    ret = ClientTransCheckTdcChannelExist(channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_EXIST);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcDelChannelInfo001
 * @tc.desc: Test the correctness of the fucntion for deleting TCP direct connection
 *           channel information
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcDelChannelInfo001, TestSize.Level1)
{
    int32_t channelId1 = 1;
    int32_t channelId2 = 2;
    TransTdcDelChannelInfo(1, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    EXPECT_TRUE(g_tcpDirectChannelInfoList == nullptr);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    info->channelId = channelId1;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    TransTdcDelChannelInfo(channelId2, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    TransTdcDelChannelInfo(channelId1, SOFTBUS_TRANS_NEGOTIATE_REJECTED);
    // info is deleted in the abnormal branch
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcDelChannelInfo002
 * @tc.desc: Test the TransTdcDelChannelInfo function ability to handle
 *           exception branches in the scenario of direct TCP connection
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcDelChannelInfo002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errCode = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    info->channelId = channelId;

    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);
    TransTdcDelChannelInfo(channelId, errCode);
    // info is deleted in the abnormal branch
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransUpdateFdState001
 * @tc.desc: The function of TransUpdateFdState is to update the file
 *           descriptor state of the TCP direct connection channel
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransUpdateFdState001, TestSize.Level1)
{
    int32_t channelId1 = 1;
    int32_t channelId2 = 2;
    int32_t fdRefCnt = 3;
    TransUpdateFdState(channelId1);
    EXPECT_TRUE(g_tcpDirectChannelInfoList == nullptr);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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
    EXPECT_TRUE(info->detail.fdRefCnt == fdRefCnt);
    TransUpdateFdState(channelId1);
    EXPECT_TRUE(info != nullptr);
    info->detail.needRelease = false;
    TransUpdateFdState(channelId1);
    EXPECT_TRUE(info != nullptr);
    TransUpdateFdState(channelId1);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcCloseChannelTest003
 * @tc.desc: Testing the abnormal branch handling of the TCP direct channel
 *           closure function
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcCloseChannelTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo *channel = TestGetChannelInfo();
    ASSERT_TRUE(channel != nullptr);

    TransTdcManagerInit(&g_sessionCb);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    info->channelId = channelId;
    info->detail.fdRefCnt = 0;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    TransTdcCloseChannel(channelId);
    // info is deleted in the abnormal branch
    SoftBusFree(channel);
    if (g_tcpDirectChannelInfoList != nullptr) {
        DestroySoftBusList(g_tcpDirectChannelInfoList);
        g_tcpDirectChannelInfoList = nullptr;
    }
}

/*
 * @tc.name: TransDisableSessionListenerTest006
 * @tc.desc: Test the behavior of the TranDisableSessionListener function in a direct
 *           TCP connection scenario
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest006, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t errFd = -1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    info->channelId = channelId;
    info->detail.fd = errFd;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
    info->detail.fd = g_fd;

    ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(info);
}

/*
 * @tc.name: TransDisableSessionListenerTest007
 * @tc.desc: Verify that the function correctly disables the corresponding session listener
 *           when a valid channelId is passed
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransDisableSessionListenerTest007, TestSize.Level1)
{
    int32_t channelId = 1;
    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    info->channelId = channelId;
    info->detail.fd = g_fd;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    int32_t ret = TransDisableSessionListener(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(info);
}

/*
 * @tc.name: TransTdcGetInfoByIdTest007
 * @tc.desc: The function of TransTdcGetInfoById is to retrieve the corresponding channel information
 *           from the TCP direct channel information list based on the channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest007, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    info->channelId = channelId;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    int32_t item = TransTdcGetInfoById(1, info);
    EXPECT_EQ(item, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdTest008
 * @tc.desc: The function of TransTdcGetInfoById is to retrieve the corresponding channel information
 *           from the TCP direct channel information list based on the channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdTest008, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *testInfo = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(testInfo != nullptr);
    TcpDirectChannelInfo *infoTest = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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

    int32_t item = TransTdcGetInfoById(1, info);
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
 * @tc.name: TransTdcSetListenerStateById001
 * @tc.desc: The function of TransTdcGetInfoById is to retrieve the corresponding channel information from the
 *           TCP direct channel information list based on the channelId
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcSetListenerStateById001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t invalidChannelId = 2;
    int32_t ret = TransTdcSetListenerStateById(1, true);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);

    info->channelId = channelId;
    info->detail.needStopListener = false;
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    ret = TransTdcSetListenerStateById(channelId, true);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcSetListenerStateById(invalidChannelId, true);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);

    ret = TransTdcSetListenerStateById(channelId, false);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByFdTest001
 * @tc.desc: The function TransTdcGetInfoByFd retrieves the corresponding channel information from
 *           the TCP direct channel information list using a file descriptor
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByFdTest001, TestSize.Level1)
{
    int32_t testFd = 123;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *infoTest = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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
    item = TransTdcGetInfoByFd(1, info);
    EXPECT_EQ(item, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
    ListDelete(&infoTest->node);
    SoftBusFree(infoTest);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransTdcGetInfoByIdWithIncSeqTest001
 * @tc.desc: The function TransTdcGetInfoIncFdRefById is used to obtain TCP direct channel information based
 *           on the channelId and increment the reference count of the file descriptor
 *           during the retrieval process
 * @tc.type: FUNC
 * @tc.require:I5HQGA
 */
HWTEST_F(TransSdkTcpDirectTest, TransTdcGetInfoByIdWithIncSeqTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    TcpDirectChannelInfo *infoTest = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(infoTest != nullptr);
    TcpDirectChannelInfo *testInfo = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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
    EXPECT_TRUE(item != nullptr);

    channelId = 0;
    item = TransTdcGetInfoIncFdRefById(channelId, testInfo, true);
    EXPECT_TRUE(item != nullptr);

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
 * @tc.name: GetFdByPeerIpAndPortTest001
 * @tc.desc: The function GetFdByPeerIpAndPort is used to find the corresponding file descriptor in the TCP direct
 *           channel list based on the given peer IP address and port number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, GetFdByPeerIpAndPortTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
    ASSERT_TRUE(info != nullptr);
    (void)strcpy_s(info->detail.peerIp, sizeof(info->detail.peerIp), "127.0.0.1");
    info->detail.peerPort = 1234;
    info->detail.fd = 123;
    info->channelId = channelId;

    int32_t fd = -1;
    int32_t ret = GetFdByPeerIpAndPort("127.0.0.1", 1234, &fd);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_tcpDirectChannelInfoList = CreateSoftBusList();
    ASSERT_TRUE(g_tcpDirectChannelInfoList != nullptr);
    (void)SoftBusMutexLock(&g_tcpDirectChannelInfoList->lock);
    ListAdd(&g_tcpDirectChannelInfoList->list, &info->node);
    (void)SoftBusMutexUnlock(&g_tcpDirectChannelInfoList->lock);

    ret = GetFdByPeerIpAndPort("127.0.0.1", 1234, &fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(fd, 123);
    ret = GetFdByPeerIpAndPort("127.0.0.1", 1235, &fd);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: TransStartTimeSyncTest001
 * @tc.desc: Verify whether the behaviors of the TransStartTimeSync and OnTimeSyncResultByIp
 *           functions meet expectations under different input conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, OnTimeSyncResultByIpTest001, TestSize.Level1)
{
    ChannelInfo channel;
    channel.peerIp = nullptr;
    int32_t ret = TransStartTimeSync(&channel);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    channel.peerIp = (char *)"127.0.0.1";
    channel.peerDeviceId = nullptr;
    ret = TransStartTimeSync(&channel);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);
    channel.peerDeviceId = (char *)"1234567890";
    channel.pkgName = nullptr;
    ret = TransStartTimeSync(&channel);
    EXPECT_NE(ret, SOFTBUS_OK);
    channel.pkgName = (char *)"test";
    ret = TransStartTimeSync(&channel);

    OnTimeSyncResultByIp(nullptr, -1);
    OnTimeSyncResultByIp(nullptr, SOFTBUS_OK);
    TimeSyncResultWithSocket info;
    (void)strcpy_s(info.targetSocketInfo.peerIp, sizeof(info.targetSocketInfo.peerIp), "127.0.0.1");
    info.targetSocketInfo.peerPort = 1234;
    OnTimeSyncResultByIp(&info, SOFTBUS_OK);
}

/*
 * @tc.name: TransStopTimeSyncTest001
 * @tc.desc: The main purpose of the TransStopTimeSync function is to stop the time synchronization feature
 *           on a TCP direct connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, TransStopTimeSyncTest001, TestSize.Level1)
{
    int32_t ret = TransStopTimeSync(0);
    EXPECT_NE(ret, SOFTBUS_OK);

    int32_t channelId = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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

    ret = TransStopTimeSync(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info->detail.fdProtocol = LNN_PROTOCOL_DETTP;
    ret = TransStopTimeSync(channelId);
    EXPECT_NE(ret, SOFTBUS_OK);

    info->detail.fdProtocol = LNN_PROTOCOL_MINTP;
    ret = TransStopTimeSync(channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}

/*
 * @tc.name: ClientTransTdcOnChannelBindTest002
 * @tc.desc: The main purpose of the TransStopTimeSync function is to stop the time synchronization feature
 *           on a TCP direct connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkTcpDirectTest, ClientTransTdcOnChannelBindTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TcpDirectChannelInfo *info = (TcpDirectChannelInfo *)SoftBusCalloc(sizeof(TcpDirectChannelInfo));
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
    
    info->channelId = channelId;
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info->detail.needStopListener = false;
    ret = ClientTransTdcOnChannelBind(channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
    DestroySoftBusList(g_tcpDirectChannelInfoList);
    g_tcpDirectChannelInfoList = nullptr;
}
} // namespace OHOS
