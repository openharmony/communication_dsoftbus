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

#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_proxy_file_manager.h"
#include "client_trans_proxy_manager.c"
#include "client_trans_proxy_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "g_enhance_sdk_func.h"
#include "session.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_proxy_process_data.c"
#include "trans_proxy_process_data.h"

#define TEST_CHANNEL_ID    (-10)
#define TEST_ERR_CODE      (-1)
#define TEST_DATA          "testdata"
#define TEST_DATA_LENGTH   9
#define TEST_DATA_LENGTH_2 100
#define TEST_FILE_CNT      4
#define TEST_SEQ           188
#define SILCE_NUM_COUNT    3
#define SLICE_SEQ_BEGIN    0
#define SLICE_SEQ_MID      1
#define SLICE_SEQ_END      2

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_proxyPkgName = "dms";
const char *g_proxySessionName = "ohos.distributedschedule.dms.test";
const char *g_testProxyFileName[] = {
    "/data/test.txt",
    "/data/ss.txt",
    "/data/test.tar",
    "/data/test.mp3",
};
const char *g_proxyFileSet[] = {
    "/data/data/test.txt",
    "/path/max/length/512/"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "111111111111111111111111111111111111111111111111111",
    "ss",
    "/data/ss",
};
char g_sessionKey[32] = "1234567812345678123456781234567";
#define DEFAULT_NEW_BYTES_LEN   (4 * 1024 * 1024)
#define DEFAULT_NEW_MESSAGE_LEN (4 * 1024)

int32_t TransOnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    return SOFTBUS_OK;
}

int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

int32_t TransOnBytesReceived(
    int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    return SOFTBUS_OK;
}

int32_t TransOnOnStreamRecevied(
    int32_t channelId, int32_t channelType, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    return SOFTBUS_OK;
}

int32_t TransOnGetSessionId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    return SOFTBUS_OK;
}

int32_t TransOnQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    return SOFTBUS_OK;
}

static IClientSessionCallBack g_clientSessionCb = {
    .OnSessionOpened = TransOnSessionOpened,
    .OnSessionClosed = TransOnSessionClosed,
    .OnSessionOpenFailed = TransOnSessionOpenFailed,
    .OnDataReceived = TransOnBytesReceived,
    .OnStreamReceived = TransOnOnStreamRecevied,
    .OnQosEvent = TransOnQosEvent,
};

int32_t OnSessionOpened(
    const char *sessionName, const ChannelInfo *channel, SessionType flag, SocketAccessInfo *accessInfo)
{
    (void)sessionName;
    (void)channel;
    (void)flag;
    (void)accessInfo;
    return SOFTBUS_INVALID_PARAM;
}

int32_t OnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    (void)channelId;
    (void)channelType;
    (void)reason;
    return SOFTBUS_INVALID_PARAM;
}

int32_t OnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)channelId;
    (void)channelType;
    (void)errCode;
    return SOFTBUS_INVALID_PARAM;
}

int32_t OnBytesReceived(int32_t channelId, int32_t channelType, const void *data, uint32_t len, SessionPktType type)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)type;
    return SOFTBUS_INVALID_PARAM;
}

static IClientSessionCallBack g_sessionCb = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnSessionOpenFailed = OnSessionOpenFailed,
    .OnDataReceived = OnBytesReceived,
};

class ClientTransProxyManagerTest : public testing::Test {
public:
    ClientTransProxyManagerTest(void) { }
    ~ClientTransProxyManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransProxyManagerTest::SetUpTestCase(void)
{
    TransClientInit();
    int32_t ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SetAccessTokenPermission("dsoftbusTransTest");
}

void ClientTransProxyManagerTest::TearDownTestCase(void)
{
    TransClientDeinit();
}

/*
 * @tc.name: ClientTransProxyInitTest001
 * @tc.desc: ClientTransProxyInit returns SOFTBUS_INVALID_PARAM when callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyInitTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyOnChannelOpenedTest001
 * @tc.desc: ClientTransProxyOnChannelOpened returns SOFTBUS_INVALID_PARAM when channel is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyOnChannelOpenedTest002
 * @tc.desc: ClientTransProxyOnChannelOpened returns SOFTBUS_MEM_ERR with zeroed channel info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest002, TestSize.Level1)
{
    ChannelInfo channelInfo = { 0 };
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/*
 * @tc.name: ClientTransProxyOnChannelOpenedTest003
 * @tc.desc: ClientTransProxyOnChannelOpened returns SOFTBUS_INVALID_PARAM when error callback
 *           rejects businessType BYTE channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest003, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = 1;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = false;
    channelInfo.businessType = BUSINESS_TYPE_BYTE;
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyOnChannelOpenedTest004
 * @tc.desc: ClientTransProxyOnChannelOpened returns SOFTBUS_INVALID_PARAM when error callback
 *           rejects businessType FILE channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest004, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = 1;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = false;
    channelInfo.businessType = BUSINESS_TYPE_FILE;
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest001
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_INVALID_PARAM when data is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransProxyOnDataReceived(channelId, nullptr, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnDataReceived(channelId, nullptr, TEST_DATA_LENGTH, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnDataReceived(channelId, nullptr, 0, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest002
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID
 *           when channel not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_MESSAGE);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID, ret);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest003
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_INVALID_PARAM when receiving
 *           short data on encrypted channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest004
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD
 *           when slice priority is PROXY_CHANNEL_PRIORITY_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_BUTT;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest005
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD
 *           when sliceNum is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest005, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = 0;
    sliceHead.sliceSeq = 0;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest006
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_NOT_FIND when sliceNum is one
 *           and packet magic number is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest006, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = 1;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = 1;
    ret = memcpy_s(buf + sizeof(SliceHead), TEST_DATA_LENGTH_2, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest007
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_NOT_FIND when packet magic
 *           is valid but dataLen is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest007, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = 1;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = 0;
    ret = memcpy_s(buf + sizeof(SliceHead), TEST_DATA_LENGTH_2, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest008
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_NOT_FIND when packet magic
 *           is valid but dataLen is smaller than PacketHead size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest008, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = 1;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = sizeof(PacketHead) - 1;
    ret = memcpy_s(buf + sizeof(SliceHead), TEST_DATA_LENGTH_2, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest009
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_NOT_FIND for single slice
 *           with valid packet head but no session info for decryption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest009, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = 1;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = TEST_DATA_LENGTH_2 - sizeof(SliceHead) - sizeof(PacketHead);
    ret = memcpy_s(buf + sizeof(SliceHead), TEST_DATA_LENGTH_2, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest010
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           for multi-slice begin sequence without session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest010, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    sliceHead.sliceNum = SILCE_NUM_COUNT;
    sliceHead.sliceSeq = SLICE_SEQ_BEGIN;
    char buf[TEST_DATA_LENGTH_2];
    ret = memcpy_s(buf, TEST_DATA_LENGTH_2, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf, TEST_DATA_LENGTH_2, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest011
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           for BYTES priority slice without session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest011, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_BYTES;
    sliceHead.sliceNum = SILCE_NUM_COUNT;
    sliceHead.sliceSeq = SLICE_SEQ_BEGIN;
    int32_t dataLen = sizeof(SliceHead) + sizeof(PacketHead) + 1;
    char buf2[dataLen];
    ret = memcpy_s(buf2, dataLen, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = TEST_DATA_LENGTH_2 - sizeof(SliceHead) - sizeof(PacketHead);
    ret = memcpy_s(buf2 + sizeof(SliceHead), dataLen, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf2, dataLen, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest012
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID
 *           for mid slice sequence without prior begin slice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest012, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_BYTES;
    sliceHead.sliceNum = SILCE_NUM_COUNT;
    sliceHead.sliceSeq = SLICE_SEQ_MID;
    int32_t dataLen = sizeof(SliceHead) + sizeof(PacketHead) + 1;
    char buf2[dataLen];
    ret = memcpy_s(buf2, dataLen, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = TEST_DATA_LENGTH_2 - sizeof(SliceHead) - sizeof(PacketHead);
    ret = memcpy_s(buf2 + sizeof(SliceHead), dataLen, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf2, dataLen, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest013
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID
 *           for end slice sequence without prior slices
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest013, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SliceHead sliceHead;
    sliceHead.priority = PROXY_CHANNEL_PRIORITY_BYTES;
    sliceHead.sliceNum = SILCE_NUM_COUNT;
    sliceHead.sliceSeq = SLICE_SEQ_END;
    int32_t dataLen = sizeof(SliceHead) + sizeof(PacketHead) + 1;
    char buf2[dataLen];
    ret = memcpy_s(buf2, dataLen, &sliceHead, sizeof(SliceHead));
    EXPECT_EQ(EOK, ret);
    PacketHead packetHead;
    packetHead.magicNumber = MAGIC_NUMBER;
    packetHead.dataLen = TEST_DATA_LENGTH_2 - sizeof(SliceHead) - sizeof(PacketHead);
    ret = memcpy_s(buf2 + sizeof(SliceHead), dataLen, &packetHead, sizeof(PacketHead));
    EXPECT_EQ(EOK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, buf2, dataLen, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: TransProxyChannelSendBytesTest001
 * @tc.desc: TransProxyChannelSendBytes returns SOFTBUS_PERMISSION_DENIED on
 *           unencrypted channel with isSupportTlv=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyChannelSendBytes(channelId, TEST_DATA, TEST_DATA_LENGTH, false);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: TransProxyChannelSendBytesTest002
 * @tc.desc: TransProxyChannelSendBytes returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           on encrypted channel without session info for decryption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyChannelSendBytes(channelId, TEST_DATA, TEST_DATA_LENGTH, false);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: TransProxyChannelSendMessageTest001
 * @tc.desc: TransProxyChannelSendMessage returns SOFTBUS_PERMISSION_DENIED on
 *           unencrypted channel with isSupportTlv=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendMessageTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = false;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyChannelSendMessage(channelId, TEST_DATA, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: TransProxyChannelSendMessageTest002
 * @tc.desc: TransProxyChannelSendMessage returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           on encrypted channel without session info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendMessageTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = true;
    channelInfo.isSupportTlv = false;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransProxyChannelSendMessage(channelId, TEST_DATA, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest014
 * @tc.desc: ClientTransProxyOnDataReceived returns SOFTBUS_OK on unencrypted
 *           channel with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest014, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = channelId;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = true;
    int32_t ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransProxyCloseChannel(channelId);
}

/*
 * @tc.name: ClientTransProxyOnChannelOpenedTest005
 * @tc.desc: ClientTransProxyOnChannelOpened returns SOFTBUS_INVALID_PARAM when
 *           error callback rejects channel open
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnChannelOpenedTest005, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelInfo channelInfo = { 0 };
    channelInfo.channelId = 1;
    channelInfo.sessionKey = g_sessionKey;
    channelInfo.isEncrypt = false;
    channelInfo.isSupportTlv = true;
    ret = ClientTransProxyOnChannelOpened(g_proxySessionName, &channelInfo, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyOnDataReceivedTest015
 * @tc.desc: ClientTransProxyOnDataReceived returns error when error callback
 *           is set and no channel is registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyOnDataReceivedTest015, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = 1;
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_BYTES);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = ClientTransProxyOnDataReceived(channelId, TEST_DATA, TEST_DATA_LENGTH, TRANS_SESSION_MESSAGE);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyCloseChannelTest001
 * @tc.desc: ClientTransProxyCloseChannel closes invalid and valid channel IDs without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyCloseChannelTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransProxyCloseChannel(TEST_CHANNEL_ID);
    int32_t channelId = 1;
    ClientTransProxyCloseChannel(channelId);
    ClientTransProxyCloseChannel(channelId);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransProxyChannelSendFileTest001
 * @tc.desc: TransProxyChannelSendFile returns SOFTBUS_INVALID_PARAM with null
 *           source file list or excessive file count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendFileTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = TransProxyChannelSendFile(channelId, nullptr, g_proxyFileSet, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyChannelSendFile(channelId, g_testProxyFileName, g_proxyFileSet, MAX_SEND_FILE_NUM + TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyChannelSendFile(channelId, nullptr, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyChannelSendFileTest002
 * @tc.desc: TransProxyChannelSendFile returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           with null dest file list and no channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendFileTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char **sFileList = g_testProxyFileName;
    const char **dFileList = nullptr;
    uint32_t fileCnt = TEST_FILE_CNT;
    int32_t ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: TransProxyChannelSendFileTest003
 * @tc.desc: TransProxyChannelSendFile returns SOFTBUS_INVALID_PARAM with valid
 *           params but no channel and invalid file paths
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyChannelSendFileTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    const char **sFileList = g_testProxyFileName;
    const char **dFileList = g_proxyFileSet;
    uint32_t fileCnt = TEST_FILE_CNT;
    int32_t ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyGetInfoByChannelIdTest001
 * @tc.desc: ClientTransProxyGetInfoByChannelId returns SOFTBUS_INVALID_PARAM when info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyGetInfoByChannelIdTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyGetInfoByChannelId(1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyGetInfoByChannelId(-1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyGetInfoByChannelId(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyGetInfoByChannelIdTest002
 * @tc.desc: ClientTransProxyGetInfoByChannelId returns SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND
 *           with invalid channel ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyGetInfoByChannelIdTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    ProxyChannelInfoDetail info;
    (void)memset_s(&info, sizeof(ProxyChannelInfoDetail), 0, sizeof(ProxyChannelInfoDetail));
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: TransProxyPackAndSendDataTest001
 * @tc.desc: ClientTransProxyPackAndSendData returns SOFTBUS_INVALID_PARAM with
 *           null data or null info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyPackAndSendDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = 5;
    ProxyChannelInfoDetail info;
    (void)memset_s(&info, sizeof(ProxyChannelInfoDetail), 0, sizeof(ProxyChannelInfoDetail));
    SessionPktType pktType = TRANS_SESSION_MESSAGE;
    int32_t ret = ClientTransProxyPackAndSendData(channelId, nullptr, len, &info, pktType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyPackAndSendData(channelId, data, len, nullptr, pktType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyPackAndSendDataTest002
 * @tc.desc: ClientTransProxyPackAndSendData returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           with valid params but no channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyPackAndSendDataTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    uint32_t len = 5;
    ProxyChannelInfoDetail info;
    (void)memset_s(&info, sizeof(ProxyChannelInfoDetail), 0, sizeof(ProxyChannelInfoDetail));
    SessionPktType pktType = TRANS_SESSION_MESSAGE;
    int32_t ret = ClientTransProxyPackAndSendData(channelId, static_cast<const void *>(data), len, &info, pktType);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    pktType = TRANS_SESSION_BYTES;
    ret = ClientTransProxyPackAndSendData(channelId, static_cast<const void *>(data), len, &info, pktType);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyGetLinkTypeByChannelIdTest001
 * @tc.desc: ClientTransProxyGetLinkTypeByChannelId returns SOFTBUS_INVALID_PARAM when linkType is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyGetLinkTypeByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t ret = ClientTransProxyGetLinkTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelId = 1;
    ret = ClientTransProxyGetLinkTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelId = 0;
    ret = ClientTransProxyGetLinkTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyGetLinkTypeByChannelIdTest002
 * @tc.desc: ClientTransProxyGetLinkTypeByChannelId returns SOFTBUS_NOT_FIND with invalid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyGetLinkTypeByChannelIdTest002, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t linkType;
    int32_t ret = ClientTransProxyGetLinkTypeByChannelId(channelId, &linkType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    channelId = 1;
    ret = ClientTransProxyGetLinkTypeByChannelId(channelId, &linkType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    channelId = -1;
    ret = ClientTransProxyGetLinkTypeByChannelId(channelId, &linkType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: TransGetActualDataLenTest001
 * @tc.desc: TransGetActualDataLen returns SOFTBUS_OK with valid sliceNum and MESSAGE priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransGetActualDataLenTest001, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    SliceHead head = { 0 };
    head.sliceNum = 1;
    head.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    uint32_t actualDataLen = 0;
    int32_t ret = TransGetActualDataLen(&head, &actualDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(head.sliceNum * SLICE_LEN, actualDataLen);
}

/*
 * @tc.name: TransGetActualDataLenTest002
 * @tc.desc: TransGetActualDataLen returns SOFTBUS_OK with valid sliceNum and BYTES priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransGetActualDataLenTest002, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    SliceHead head = { 0 };
    head.sliceNum = 10;
    head.priority = PROXY_CHANNEL_PRIORITY_BYTES;
    uint32_t actualDataLen = 0;
    int32_t ret = TransGetActualDataLen(&head, &actualDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(head.sliceNum * SLICE_LEN, actualDataLen);
}

/*
 * @tc.name: TransGetActualDataLenTest003
 * @tc.desc: TransGetActualDataLen returns SOFTBUS_INVALID_DATA_HEAD when sliceNum
 *           exceeds MAX_MALLOC_SIZE / SLICE_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransGetActualDataLenTest003, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    SliceHead head = { 0 };
    head.sliceNum = (MAX_MALLOC_SIZE / SLICE_LEN) + 1;
    head.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    uint32_t actualDataLen = 0;
    int32_t ret = TransGetActualDataLen(&head, &actualDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: TransGetActualDataLenTest004
 * @tc.desc: TransGetActualDataLen returns SOFTBUS_INVALID_DATA_HEAD when sliceNum
 *           causes actualLen to exceed maxDataLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransGetActualDataLenTest004, TestSize.Level1)
{
    g_proxyMaxByteBufSize = DEFAULT_NEW_BYTES_LEN;
    g_proxyMaxMessageBufSize = DEFAULT_NEW_MESSAGE_LEN;
    SliceHead head = { 0 };
    head.sliceNum = (g_proxyMaxMessageBufSize / SLICE_LEN) + 2;
    head.priority = PROXY_CHANNEL_PRIORITY_MESSAGE;
    uint32_t actualDataLen = 0;
    int32_t ret = TransGetActualDataLen(&head, &actualDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: ProxyBuildNeedAckTlvDataTest001
 * @tc.desc: ProxyBuildNeedAckTlvData returns SOFTBUS_INVALID_PARAM when pktHead is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildNeedAckTlvDataTest001, TestSize.Level1)
{
    int32_t bufferSize = 0;
    int32_t ret = ProxyBuildNeedAckTlvData(nullptr, true, 1, &bufferSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxyBuildNeedAckTlvData(nullptr, false, 0, &bufferSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxyBuildNeedAckTlvData(nullptr, true, TEST_SEQ, &bufferSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ProxyBuildNeedAckTlvDataTest002
 * @tc.desc: ProxyBuildNeedAckTlvData returns SOFTBUS_INVALID_PARAM when tlvBufferSize is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildNeedAckTlvDataTest002, TestSize.Level1)
{
    DataHead pktHead;
    bool needAck = true;
    int32_t ret = ProxyBuildNeedAckTlvData(&pktHead, needAck, TEST_SEQ, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    needAck = false;
    ret = ProxyBuildNeedAckTlvData(&pktHead, needAck, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxyBuildNeedAckTlvData(&pktHead, true, TEST_SEQ, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ProxyBuildTlvDataHeadTest001
 * @tc.desc: ProxyBuildTlvDataHead returns SOFTBUS_OK with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildTlvDataHeadTest001, TestSize.Level1)
{
    DataHead data;
    int32_t bufferSize = 0;
    int32_t ret = ProxyBuildTlvDataHead(&data, 1, 0, 32, &bufferSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    bufferSize = 0;
    ret = ProxyBuildTlvDataHead(&data, 2, 1, 64, &bufferSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProxyBuildTlvDataHeadTest002
 * @tc.desc: ProxyBuildTlvDataHead returns SOFTBUS_INVALID_PARAM when tlvBufferSize is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildTlvDataHeadTest002, TestSize.Level1)
{
    DataHead pktHead;
    int32_t flag = 0;
    int32_t ret = ProxyBuildTlvDataHead(&pktHead, TEST_SEQ, flag, TEST_DATA_LENGTH_2, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    flag = 1;
    ret = ProxyBuildTlvDataHead(&pktHead, 0, flag, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ProxyBuildTlvDataHead(&pktHead, TEST_SEQ, 0, TEST_DATA_LENGTH_2, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ProxyBuildTlvDataHeadTest003
 * @tc.desc: ProxyBuildTlvDataHead returns SOFTBUS_OK with allocated pktHead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildTlvDataHeadTest003, TestSize.Level1)
{
    DataHead *pktHead = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_TRUE(pktHead != nullptr);
    pktHead->magicNum = 0xBABEFACE;
    pktHead->tlvCount = 5;
    int32_t tlvBufferSize = 0;
    int32_t finalSeq = 1;
    int32_t flag = 0;
    uint32_t dataLen = 32;
    int32_t ret = ProxyBuildTlvDataHead(pktHead, finalSeq, flag, dataLen, &tlvBufferSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(pktHead);
}

/*
 * @tc.name: ProxyBuildNeedAckTlvDataTest003
 * @tc.desc: ProxyBuildNeedAckTlvData returns SOFTBUS_OK after constructing TLV data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ProxyBuildNeedAckTlvDataTest003, TestSize.Level1)
{
    DataHead *pktHead = reinterpret_cast<DataHead *>(SoftBusCalloc(sizeof(DataHead)));
    ASSERT_TRUE(pktHead != nullptr);
    pktHead->magicNum = 0xBABEFACE;
    pktHead->tlvCount = 5;
    int32_t tlvBufferSize = 0;
    int32_t finalSeq = 1;
    int32_t flag = 0;
    uint32_t dataLen = 32;
    int32_t ret = ProxyBuildTlvDataHead(pktHead, finalSeq, flag, dataLen, &tlvBufferSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    bool needAck = true;
    ret = ProxyBuildNeedAckTlvData(pktHead, needAck, TEST_SEQ, &tlvBufferSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(pktHead);
}

/*
 * @tc.name: ClientTransProxyProcSendMsgAckTest001
 * @tc.desc: ClientTransProxyProcSendMsgAck returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL
 *           when data is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcSendMsgAckTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyProcSendMsgAck(1, nullptr, PROXY_ACK_SIZE, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);
    ret = ClientTransProxyProcSendMsgAck(1, nullptr, PROXY_ACK_SIZE, 0, 0);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);
    ret = ClientTransProxyProcSendMsgAck(1, nullptr, PROXY_ACK_SIZE, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);
}

/*
 * @tc.name: ClientTransProxyProcSendMsgAckTest002
 * @tc.desc: ClientTransProxyProcSendMsgAck returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 *           when data length does not match PROXY_ACK_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcSendMsgAckTest002, TestSize.Level1)
{
    const char *data = "test";
    int32_t ret = ClientTransProxyProcSendMsgAck(1, data, 1, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, 2, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE - 1, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyProcSendMsgAckTest003
 * @tc.desc: ClientTransProxyProcSendMsgAck returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           when dataSeq is nonzero and session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcSendMsgAckTest003, TestSize.Level1)
{
    const char *data = "test";
    int32_t ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 2, 2);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyProcSendMsgAckTest004
 * @tc.desc: ClientTransProxyProcSendMsgAck returns SOFTBUS_TRANS_NODE_NOT_FOUND
 *           when dataSeq is zero and pending packet not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcSendMsgAckTest004, TestSize.Level1)
{
    const char *data = "test";
    int32_t ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 1, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 2, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = ClientTransProxyProcSendMsgAck(1, data, PROXY_ACK_SIZE, 1, 0);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyBytesNotifySessionTest001
 * @tc.desc: ClientTransProxyBytesNotifySession with TRANS_SESSION_ACK flag returns
 *           SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND when session not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyBytesNotifySessionTest001, TestSize.Level1)
{
    const char *data = "test";
    DataHeadTlvPacketHead dataHead;
    dataHead.dataSeq = 1;
    dataHead.seq = 1;
    dataHead.flags = TRANS_SESSION_ACK;
    int32_t ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    dataHead.dataSeq = 2;
    dataHead.seq = 2;
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    dataHead.dataSeq = 1;
    dataHead.seq = 1;
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyBytesNotifySessionTest002
 * @tc.desc: ClientTransProxyBytesNotifySession with TRANS_SESSION_BYTES flag and error
 *           callback returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyBytesNotifySessionTest002, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    const char *data = "test";
    DataHeadTlvPacketHead dataHead;
    dataHead.dataSeq = 1;
    dataHead.seq = 1;
    dataHead.flags = TRANS_SESSION_BYTES;
    dataHead.needAck = true;
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    dataHead.flags = TRANS_SESSION_BYTES;
    dataHead.needAck = false;
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyBytesNotifySessionTest003
 * @tc.desc: ClientTransProxyBytesNotifySession with invalid flags returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyBytesNotifySessionTest003, TestSize.Level1)
{
    const char *data = "test";
    DataHeadTlvPacketHead dataHead;
    dataHead.dataSeq = 1;
    dataHead.seq = 1;
    int32_t invalidFlag = 22;
    dataHead.flags = static_cast<SessionPktType>(invalidFlag);
    int32_t ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    invalidFlag = 99;
    dataHead.flags = static_cast<SessionPktType>(invalidFlag);
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    dataHead.flags = static_cast<SessionPktType>(22);
    ret = ClientTransProxyBytesNotifySession(1, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyProcDataTest001
 * @tc.desc: ClientTransProxyProcData returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 *           when dataLen equals OVERHEAD_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    DataHeadTlvPacketHead dataHead;
    dataHead.dataLen = 2;
    const char *data = "test";
    int32_t ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    dataHead.dataLen = 1;
    ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    dataHead.dataLen = 2;
    ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyProcDataTest002
 * @tc.desc: ClientTransProxyProcData returns SOFTBUS_DECRYPT_ERR when dataLen
 *           exceeds OVERHEAD_LEN but decryption fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcDataTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    DataHeadTlvPacketHead dataHead;
    dataHead.dataLen = 34;
    const char *data = "test";
    int32_t ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    dataHead.dataLen = 35;
    ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    dataHead.dataLen = 34;
    ret = ClientTransProxyProcData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
}

/*
 * @tc.name: TransProxyParseTlvTest001
 * @tc.desc: TransProxyParseTlv returns SOFTBUS_INVALID_PARAM with null data or null head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyParseTlvTest001, TestSize.Level1)
{
    uint32_t newDataHeadSize = 0;
    int32_t ret = TransProxyParseTlv(TEST_DATA_LENGTH, nullptr, nullptr, &newDataHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    const char *data = "test";
    ret = TransProxyParseTlv(TEST_DATA_LENGTH, data, nullptr, &newDataHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransProxyParseTlv(TEST_DATA_LENGTH, nullptr, nullptr, &newDataHeadSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyParseTlvTest002
 * @tc.desc: TransProxyParseTlv returns SOFTBUS_OK with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxyParseTlvTest002, TestSize.Level1)
{
    const char *data = "test";
    uint32_t newDataHeadSize = 0;
    DataHeadTlvPacketHead head;
    int32_t ret = TransProxyParseTlv(TEST_DATA_LENGTH_2, data, &head, &newDataHeadSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyGetOsTypeByChannelIdTest001
 * @tc.desc: ClientTransProxyGetOsTypeByChannelId returns SOFTBUS_INVALID_PARAM
 *           when osType is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyGetOsTypeByChannelIdTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransProxyGetOsTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelId = -1;
    ret = ClientTransProxyGetOsTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    channelId = 0;
    ret = ClientTransProxyGetOsTypeByChannelId(channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyBytesNotifySessionTest004
 * @tc.desc: ClientTransProxyBytesNotifySession with TRANS_SESSION_BYTES and needAck=true
 *           returns SOFTBUS_INVALID_PARAM via error callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyBytesNotifySessionTest004, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = 1;
    const char *data = "test";
    DataHeadTlvPacketHead dataHead;
    dataHead.dataSeq = 1;
    dataHead.seq = 1;
    dataHead.flags = TRANS_SESSION_BYTES;
    dataHead.needAck = true;
    ret = ClientTransProxyBytesNotifySession(channelId, &dataHead, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyNotifySessionTest001
 * @tc.desc: ClientTransProxyNotifySession with TRANS_SESSION_MESSAGE returns
 *           SOFTBUS_INVALID_PARAM via error callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNotifySessionTest001, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = 1;
    const char *data = "test";
    SessionPktType flag = TRANS_SESSION_MESSAGE;
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    flag = TRANS_SESSION_MESSAGE;
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ + 1, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyNotifySessionTest002
 * @tc.desc: ClientTransProxyNotifySession with TRANS_SESSION_ACK returns
 *           SOFTBUS_TRANS_NODE_NOT_FOUND when pending packet not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNotifySessionTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    SessionPktType flag = TRANS_SESSION_ACK;
    int32_t ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    flag = TRANS_SESSION_ACK;
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ + 1, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, PROXY_ACK_SIZE);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/*
 * @tc.name: ClientTransProxyNotifySessionTest003
 * @tc.desc: ClientTransProxyNotifySession with TRANS_SESSION_ASYNC_MESSAGE returns
 *           SOFTBUS_INVALID_PARAM via error callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNotifySessionTest003, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(&g_sessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t channelId = 1;
    const char *data = "test";
    SessionPktType flag = TRANS_SESSION_ASYNC_MESSAGE;
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ + 1, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyInit(&g_clientSessionCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyNotifySessionTest004
 * @tc.desc: ClientTransProxyNotifySession with invalid flags returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNotifySessionTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    int32_t invalidFlag = 22;
    SessionPktType flag = static_cast<SessionPktType>(invalidFlag);
    int32_t ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    invalidFlag = 99;
    flag = static_cast<SessionPktType>(invalidFlag);
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    flag = static_cast<SessionPktType>(22);
    ret = ClientTransProxyNotifySession(channelId, flag, TEST_SEQ, data, 4);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyProcessSessionDataTest001
 * @tc.desc: ClientTransProxyProcessSessionData returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 *           when dataLen equals OVERHEAD_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcessSessionDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    PacketHead dataHead;
    dataHead.dataLen = OVERHEAD_LEN;
    const char *data = "test";
    int32_t ret = ClientTransProxyProcessSessionData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: ClientTransProxyProcessSessionDataTest002
 * @tc.desc: ClientTransProxyProcessSessionData returns SOFTBUS_DECRYPT_ERR
 *           when dataLen exceeds OVERHEAD_LEN but decryption fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyProcessSessionDataTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    PacketHead dataHead;
    dataHead.dataLen = TEST_DATA_LENGTH_2;
    dataHead.seq = 1;
    const char *data = "test";
    int32_t ret = ClientTransProxyProcessSessionData(channelId, &dataHead, data);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketTlvProcTest001
 * @tc.desc: ClientTransProxyNoSubPacketTlvProc returns SOFTBUS_INVALID_PARAM when data is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNoSubPacketTlvProcTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ClientTransProxyNoSubPacketTlvProc(channelId, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyNoSubPacketTlvProc(channelId, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyNoSubPacketTlvProc(channelId, nullptr, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketTlvProcTest002
 * @tc.desc: ClientTransProxyNoSubPacketTlvProc returns SOFTBUS_INVALID_DATA_HEAD
 *           when data contains invalid TLV header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNoSubPacketTlvProcTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test";
    int32_t ret = ClientTransProxyNoSubPacketTlvProc(channelId, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
    ret = ClientTransProxyNoSubPacketTlvProc(channelId, data, TEST_DATA_LENGTH_2);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
    ret = ClientTransProxyNoSubPacketTlvProc(channelId, data, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketTlvProcTest003
 * @tc.desc: ClientTransProxyNoSubPacketTlvProc returns SOFTBUS_DATA_NOT_ENOUGH
 *           when data has valid magic but len is zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNoSubPacketTlvProcTest003, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t magic = MAGIC_NUMBER;
    int32_t len = 20;
    char *magicData = reinterpret_cast<char *>(SoftBusCalloc(len));
    ASSERT_TRUE(magicData != nullptr);
    (void)memcpy_s(magicData, MAGICNUM_SIZE, &magic, MAGICNUM_SIZE);
    int32_t ret = ClientTransProxyNoSubPacketTlvProc(channelId, magicData, 0);
    EXPECT_EQ(SOFTBUS_DATA_NOT_ENOUGH, ret);
    SoftBusFree(magicData);
}

/*
 * @tc.name: ClientTransProxyNoSubPacketTlvProcTest004
 * @tc.desc: ClientTransProxyNoSubPacketTlvProc returns SOFTBUS_TRANS_INVALID_DATA_LENGTH
 *           when data has valid magic but mismatched data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyNoSubPacketTlvProcTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t magic = MAGIC_NUMBER;
    int32_t len = 20;
    char *magicData = reinterpret_cast<char *>(SoftBusCalloc(len));
    ASSERT_TRUE(magicData != nullptr);
    (void)memcpy_s(magicData, MAGICNUM_SIZE, &magic, MAGICNUM_SIZE);
    int32_t ret = ClientTransProxyNoSubPacketTlvProc(channelId, magicData, TEST_DATA_LENGTH);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    SoftBusFree(magicData);
}

/*
 * @tc.name: TransProxySliceProcessChkPkgIsValidTest001
 * @tc.desc: TransProxySliceProcessChkPkgIsValid returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH
 *           when buffer length is insufficient for data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxySliceProcessChkPkgIsValidTest001, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    processor.sliceNumber = 2;
    processor.expectedSeq = 1;
    processor.dataLen = 20;
    processor.bufLen = 10;
    SliceHead head;
    head.sliceNum = 2;
    head.sliceSeq = 1;
    char data[16] = "test";
    uint32_t len = 20;
    int32_t ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH, ret);
    processor.bufLen = 20;
    ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH, ret);
}

/*
 * @tc.name: TransProxySliceProcessChkPkgIsValidTest002
 * @tc.desc: TransProxySliceProcessChkPkgIsValid returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL
 *           when processor data buffer is null with sufficient bufLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxySliceProcessChkPkgIsValidTest002, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    processor.sliceNumber = 2;
    processor.expectedSeq = 1;
    processor.dataLen = 20;
    processor.bufLen = 50;
    processor.data = nullptr;
    SliceHead head;
    head.sliceNum = 2;
    head.sliceSeq = 1;
    char data[16] = "test";
    uint32_t len = 20;
    int32_t ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);
}

/*
 * @tc.name: TransProxySliceProcessChkPkgIsValidTest003
 * @tc.desc: TransProxySliceProcessChkPkgIsValid returns SOFTBUS_OK when all conditions are valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxySliceProcessChkPkgIsValidTest003, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    processor.sliceNumber = 2;
    processor.expectedSeq = 1;
    processor.dataLen = 20;
    processor.bufLen = 50;
    processor.data = reinterpret_cast<char *>(SoftBusCalloc(processor.bufLen));
    ASSERT_TRUE(processor.data != nullptr);
    SliceHead head;
    head.sliceNum = 2;
    head.sliceSeq = 1;
    char data[16] = "test";
    uint32_t len = 20;
    int32_t ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(processor.data);
}

/*
 * @tc.name: TransProxySliceProcessChkPkgIsValidTest004
 * @tc.desc: TransProxySliceProcessChkPkgIsValid returns SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID
 *           when slice numbers or sequences do not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, TransProxySliceProcessChkPkgIsValidTest004, TestSize.Level1)
{
    SliceProcessor processor = { 0 };
    processor.sliceNumber = 2;
    processor.expectedSeq = 1;
    processor.dataLen = 20;
    processor.bufLen = 50;
    processor.data = reinterpret_cast<char *>(SoftBusCalloc(processor.bufLen));
    ASSERT_TRUE(processor.data != nullptr);
    SliceHead head;
    head.sliceNum = 3;
    head.sliceSeq = 1;
    char data[16] = "test";
    uint32_t len = 20;
    int32_t ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID, ret);
    head.sliceNum = 2;
    head.sliceSeq = 2;
    ret = TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID, ret);
    SoftBusFree(processor.data);
}

/*
 * @tc.name: IsValidCheckoutProcessTest001
 * @tc.desc: IsValidCheckoutProcess returns false when no processor exists for given channelId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, IsValidCheckoutProcessTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    bool ret = IsValidCheckoutProcess(channelId);
    EXPECT_EQ(false, ret);
    channelId = -1;
    ret = IsValidCheckoutProcess(channelId);
    EXPECT_EQ(false, ret);
    channelId = 0;
    ret = IsValidCheckoutProcess(channelId);
    EXPECT_EQ(false, ret);
}

/*
 * @tc.name: ClientTransProxyPackTlvBytesTest001
 * @tc.desc: ClientTransProxyPackTlvBytes returns SOFTBUS_INVALID_PARAM with null dataInfo or null info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyPackTlvBytesTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    SessionPktType flag = TRANS_SESSION_ACK;
    int32_t ret = ClientTransProxyPackTlvBytes(channelId, nullptr, nullptr, flag, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ProxyDataInfo dataInfo;
    ret = ClientTransProxyPackTlvBytes(channelId, &dataInfo, nullptr, flag, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    flag = TRANS_SESSION_BYTES;
    ret = ClientTransProxyPackTlvBytes(channelId, nullptr, nullptr, flag, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ClientTransProxyPackTlvBytesTest002
 * @tc.desc: ClientTransProxyPackTlvBytes returns SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND
 *           with valid params but no channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, ClientTransProxyPackTlvBytesTest002, TestSize.Level1)
{
    int32_t channelId = 1;
    ProxyDataInfo dataInfo;
    ProxyChannelInfoDetail info;
    (void)memset_s(&info, sizeof(ProxyChannelInfoDetail), 0, sizeof(ProxyChannelInfoDetail));
    SessionPktType flag = TRANS_SESSION_ACK;
    int32_t ret = ClientTransProxyPackTlvBytes(channelId, &dataInfo, &info, flag, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
    flag = TRANS_SESSION_BYTES;
    ret = ClientTransProxyPackTlvBytes(channelId, &dataInfo, &info, flag, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: SessionPktTypeToProxyIndexTest001
 * @tc.desc: SessionPktTypeToProxyIndex returns PROXY_CHANNEL_PRIORITY_MESSAGE
 *           for TRANS_SESSION_ACK type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, SessionPktTypeToProxyIndexTest001, TestSize.Level1)
{
    SessionPktType packetType = TRANS_SESSION_ACK;
    int32_t ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_MESSAGE, ret);
    packetType = TRANS_SESSION_MESSAGE;
    ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_MESSAGE, ret);
    packetType = TRANS_SESSION_ASYNC_MESSAGE;
    ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_MESSAGE, ret);
}

/*
 * @tc.name: SessionPktTypeToProxyIndexTest002
 * @tc.desc: SessionPktTypeToProxyIndex returns PROXY_CHANNEL_PRIORITY_BYTES
 *           for TRANS_SESSION_BYTES type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, SessionPktTypeToProxyIndexTest002, TestSize.Level1)
{
    SessionPktType packetType = TRANS_SESSION_BYTES;
    int32_t ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_BYTES, ret);
    ret = SessionPktTypeToProxyIndex(TRANS_SESSION_BYTES);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_BYTES, ret);
    ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_BYTES, ret);
}

/*
 * @tc.name: SessionPktTypeToProxyIndexTest003
 * @tc.desc: SessionPktTypeToProxyIndex returns PROXY_CHANNEL_PRIORITY_FILE
 *           for file frame types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyManagerTest, SessionPktTypeToProxyIndexTest003, TestSize.Level1)
{
    SessionPktType packetType = TRANS_SESSION_FILE_FIRST_FRAME;
    int32_t ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_FILE, ret);
    packetType = TRANS_SESSION_FILE_LAST_FRAME;
    ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_FILE, ret);
    packetType = TRANS_SESSION_FILE_ONLYONE_FRAME;
    ret = SessionPktTypeToProxyIndex(packetType);
    EXPECT_EQ(PROXY_CHANNEL_PRIORITY_FILE, ret);
}
} // namespace OHOS
