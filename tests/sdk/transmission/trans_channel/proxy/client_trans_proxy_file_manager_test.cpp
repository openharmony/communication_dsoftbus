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

#include "client_trans_proxy_file_manager_test_common.h"

#include "client_trans_proxy_file_helper.c"
#include "client_trans_proxy_file_manager.c"
#include "client_trans_proxy_manager.c"
#include "client_trans_session_manager.c"
#include "client_trans_socket_manager.c"

// Must be the last include: test2.cpp depends on static functions defined in .c files above.
// Placed after all .c includes and before using namespace to avoid lint warnings.
#include "client_trans_proxy_file_manager_test2.cpp"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_peerNetworkId = "1234567789";
const char *g_groupId = "123";
FILE *g_fileTest = nullptr;
FILE *g_fileSs = nullptr;
int32_t g_fd = 0;
char g_writeData[128] = "test111111111111111111111111111111111111111111111111111111111111";
const char *g_rootDir = "/data";
const char *g_destFile = "test.txt";
char g_recvFile[] = "/data/test.txt";
const char *g_sessionKey = "www.test.com";

SessionAttribute g_attr = {
    .dataType = TYPE_MESSAGE,
    .linkTypeNum = LINK_TYPE_WIFI_WLAN_5G,
};

SessionParam g_param = {
    .sessionName = g_sessionName,
    .peerSessionName = g_sessionName,
    .peerDeviceId = g_peerNetworkId,
    .groupId = g_groupId,
    .attr = &g_attr,
};

const char *g_testProxyFileList[] = {
    "/data/test.txt",
    "/data/ss.txt",
};

const char *g_fileList[] = {
    "/data/data/test.txt",
    "/path/max/length/512/"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "111111111111111111111111111111111111111111111111111",
};

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t sessionId) { }

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len) { }

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len) { }

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

static int32_t OnSendFileProcess(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    return SOFTBUS_OK;
}

static int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    return SOFTBUS_OK;
}

static void OnFileTransError(int32_t sessionId) { }

static int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    return SOFTBUS_OK;
}

static int32_t OnReceiveFileProcess(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    return SOFTBUS_OK;
}

static void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt) { }

const IFileSendListener g_listener = {
    .OnSendFileProcess = OnSendFileProcess,
    .OnSendFileFinished = OnSendFileFinished,
    .OnFileTransError = OnFileTransError,
};

const IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileProcess = OnReceiveFileProcess,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnFileTransError = OnFileTransError,
};

void ClientTransProxyFileManagerTest::SetUpTestCase(void)
{
    SetAccessTokenPermission("dsoftbusTransTest");
    g_fileTest = fopen(g_testProxyFileList[0], "w+");
    EXPECT_NE(g_fileTest, nullptr);

    g_fileSs = fopen(g_testProxyFileList[1], "w+");
    EXPECT_NE(g_fileSs, nullptr);
    int32_t ret = fprintf(g_fileSs, "%s", "Hello world!\n");
    EXPECT_LT(0, ret);
    g_fd = open(TEST_FILE_PATH, O_RDWR | O_CREAT, S_IRWXU);
    EXPECT_NE(g_fd, -1);
    write(g_fd, g_writeData, sizeof(g_writeData));
    ClientTransProxyListInit();
}

void ClientTransProxyFileManagerTest::TearDownTestCase(void)
{
    int32_t ret = fclose(g_fileTest);
    EXPECT_EQ(ret, 0);
    g_fileTest = nullptr;
    ret = fclose(g_fileSs);
    EXPECT_EQ(ret, 0);
    g_fileSs = nullptr;
    close(g_fd);
    g_fd = -1;
    ret = remove(g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = remove(g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = remove(TEST_FILE_PATH);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClinetTransProxyFileManagerDeinit();
    ClientTransProxyListDeinit();
}

/*
 * @tc.name: ProxyChannelSendFileInvalidParamTest001
 * @tc.desc: proxy channel send file with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyChannelSendFileInvalidParamTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ProxyChannelSendFile(channelId, g_testProxyFileList, g_testProxyFileList, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ProxyChannelSendFile(channelId, nullptr, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *proxyNullFileList[] = {
        nullptr,
        "/path/max/length/512",
    };
    ret = ProxyChannelSendFile(channelId, proxyNullFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *proxyZeroFileList[] = {
        "",
        "/path/max/length/512",
    };
    ret = ProxyChannelSendFile(channelId, proxyZeroFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *proxyLengthFileList[] = {
        "/path/max/length/512",
        "/path/max/length/512/"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111111111111111",
    };
    ret = ProxyChannelSendFile(channelId, proxyLengthFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ProxyChannelSendFile(channelId, g_testProxyFileList, nullptr, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ProxyChannelSendFile(channelId, g_testProxyFileList, proxyNullFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ProxyChannelSendFileNoLockTest001
 * @tc.desc: proxy channel send file with valid params but file manager not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyChannelSendFileNoLockTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = ProxyChannelSendFile(channelId, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);

    ret = ProxyChannelSendFile(channelId + 1, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataNullFrameTest001
 * @tc.desc: process recv file frame data with null frame returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataNullFrameTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    int32_t ret = ProcessRecvFileFrameData(sessionId, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ProcessRecvFileFrameData(sessionId + 1, channelId + 1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataOverflowTest001
 * @tc.desc: process recv file frame data with frame length overflow returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataOverflowTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->osType = OH_TYPE;
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE + 1;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataFirstFrameTest001
 * @tc.desc: process recv file frame data with first frame type returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataFirstFrameTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->osType = OH_TYPE;
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;
    fileFrame.frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataWriteFrameTest001
 * @tc.desc: process recv file frame data with write frame types returns not find when no recipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataWriteFrameTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;

    fileFrame.frameType = TRANS_SESSION_FILE_ONGOINE_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_ONLYONE_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_LAST_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_ACK_REQUEST_SENT;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_CRC_CHECK_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_ALLFILE_SENT;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataAckResponseTest001
 * @tc.desc: process recv file frame data with ack response type returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataAckResponseTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;
    fileFrame.frameType = TRANS_SESSION_FILE_ACK_RESPONSE_SENT;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataResultFrameTest001
 * @tc.desc: process recv file frame data with result frame type returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataResultFrameTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;
    fileFrame.frameType = TRANS_SESSION_FILE_RESULT_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessRecvFileFrameDataInvalidTypeTest001
 * @tc.desc: process recv file frame data with invalid frame type returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessRecvFileFrameDataInvalidTypeTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;
    fileFrame.frameType = -1;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ClientTransProxyCreateChannelInfoTest001
 * @tc.desc: create channel info with d2d disabled and valid session key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClientTransProxyCreateChannelInfoTest001, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->osType = OH_TYPE;
    channel->isD2D = 0;
    channel->dataLen = 0;
    channel->isServer = 1;
    channel->keyLen = TEST_SEQ32;
    ClientProxyChannelInfo *info = ClientTransProxyCreateChannelInfo(channel);
    ASSERT_TRUE(info != nullptr);
    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientTransProxyCreateChannelInfoTest002
 * @tc.desc: create channel info with d2d enabled and extra data within max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClientTransProxyCreateChannelInfoTest002, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->osType = OH_TYPE;
    channel->isD2D = 1;
    channel->dataLen = EXTRA_DATA_MAX_LEN - 1;
    channel->isServer = 0;
    channel->pagingNonce = const_cast<char *>(g_sessionKey);
    channel->pagingSessionkey = const_cast<char *>(g_sessionKey);
    channel->extraData = const_cast<char *>(g_sessionKey);
    channel->pagingAccountId = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    ClientProxyChannelInfo *info = ClientTransProxyCreateChannelInfo(channel);
    ASSERT_TRUE(info != nullptr);
    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClientTransProxyCreateChannelInfoTest003
 * @tc.desc: create channel info with d2d enabled and extra data exceeding max length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClientTransProxyCreateChannelInfoTest003, TestSize.Level1)
{
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->osType = OH_TYPE;
    channel->isD2D = 1;
    channel->dataLen = EXTRA_DATA_MAX_LEN + 1;
    channel->isServer = 0;
    channel->pagingNonce = const_cast<char *>(g_sessionKey);
    channel->pagingSessionkey = const_cast<char *>(g_sessionKey);
    channel->extraData = const_cast<char *>(g_sessionKey);
    channel->pagingAccountId = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    ClientProxyChannelInfo *info = ClientTransProxyCreateChannelInfo(channel);
    ASSERT_TRUE(info != nullptr);
    SoftBusFree(info);
    SoftBusFree(channel);
}

/*
 * @tc.name: ClinetTransProxyFileManagerInitTest001
 * @tc.desc: client trans proxy file manager init returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileManagerInitTest001, TestSize.Level1)
{
    int32_t ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendFileTransResultTest001
 * @tc.desc: send file trans result with no proxy channel returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendFileTransResultTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    int32_t ret = SendFileTransResult(channelId, seq, result, side);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendFileTransResult(channelId + 1, seq, result, side);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: UnpackFileTransResultFrameInvalidParamTest001
 * @tc.desc: unpack file trans result frame with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransResultFrameInvalidParamTest001, TestSize.Level1)
{
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    uint32_t data = 0;
    const uint8_t *data1 = reinterpret_cast<const uint8_t *>(&data);
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t ret = UnpackFileTransResultFrame(data1, len, nullptr, &result, &side);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackFileTransResultFrame(data1, len, &seq, nullptr, &side);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackFileTransResultFrame(data1, len, &seq, &result, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: UnpackFileTransResultFrameInvalidDataTest001
 * @tc.desc: unpack file trans result frame with null data or short length returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransResultFrameInvalidDataTest001, TestSize.Level1)
{
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    uint32_t data = 0;
    const uint8_t *data1 = reinterpret_cast<const uint8_t *>(&data);
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t ret = UnpackFileTransResultFrame(nullptr, len, &seq, &result, &side);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    ret = UnpackFileTransResultFrame(data1, 0, &seq, &result, &side);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: UnpackFileTransResultFrameInvalidHeadTest001
 * @tc.desc: unpack file trans result frame with wrong magic returns invalid data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransResultFrameInvalidHeadTest001, TestSize.Level1)
{
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    uint32_t data = 0;
    const uint8_t *data1 = reinterpret_cast<const uint8_t *>(&data);
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t ret = UnpackFileTransResultFrame(data1, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);

    data = FILE_MAGIC_NUMBER;
    const uint8_t *data2 = reinterpret_cast<const uint8_t *>(&data);
    ret = UnpackFileTransResultFrame(data2, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetSessionFileLockTest001
 * @tc.desc: get session file lock returns valid lock and increments count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetSessionFileLockTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    ProxyFileMutexLock *sessionLock = GetSessionFileLock(channelId);
    EXPECT_NE(nullptr, sessionLock);

    sessionLock = GetSessionFileLock(channelId);
    EXPECT_NE(nullptr, sessionLock);

    sessionLock = GetSessionFileLock(channelId + 1);
    EXPECT_NE(nullptr, sessionLock);
}

/*
 * @tc.name: DelSessionFileLockTest001
 * @tc.desc: del session file lock decrements count and handles null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, DelSessionFileLockTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    ProxyFileMutexLock *sessionLock = GetSessionFileLock(channelId);
    ASSERT_NE(nullptr, sessionLock);

    DelSessionFileLock(nullptr);
    sessionLock->count = 1;
    DelSessionFileLock(sessionLock);

    sessionLock = GetSessionFileLock(channelId);
    ASSERT_NE(nullptr, sessionLock);
    sessionLock->count = 2;
    DelSessionFileLock(sessionLock);
    DelSessionFileLock(sessionLock);
}

/*
 * @tc.name: CreateSendListenerInfoNoInitTest001
 * @tc.desc: create send listener info returns no init when session server not created
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateSendListenerInfoNoInitTest001, TestSize.Level1)
{
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);

    int32_t sessionId = 1;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(&g_param, &sessionId, &isEnabled);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);

    SendListenerInfo *sendListenerInfo = nullptr;
    ret = CreateSendListenerInfo(&sendListenerInfo, TEST_CHANNEL_ID, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_SERVER_NOINIT, ret);
}

/*
 * @tc.name: CreateSendListenerInfoNotFoundTest001
 * @tc.desc: create send listener info returns not found when session info not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateSendListenerInfoNotFoundTest001, TestSize.Level1)
{
    int32_t ret = TransClientInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    int32_t channelId = 1;
    int32_t sessionId = 1;
    SessionInfo sessionInfo;
    sessionInfo.sessionId = sessionId;
    sessionInfo.channelId = channelId;
    sessionInfo.channelType = CHANNEL_TYPE_PROXY;
    ret = AddSession(g_sessionName, &sessionInfo);
    EXPECT_EQ(SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED, ret);

    ret = TransSetFileSendListener(g_sessionName, &g_listener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransSetFileReceiveListener(g_sessionName, &g_fileRecvListener, g_rootDir);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendListenerInfo *sendListenerInfo = nullptr;
    ret = CreateSendListenerInfo(&sendListenerInfo, channelId, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);
}

/*
 * @tc.name: AddSendListenerInfoTest001
 * @tc.desc: add send listener info with null param returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, AddSendListenerInfoTest001, TestSize.Level1)
{
    int32_t ret = AddSendListenerInfo(nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->crc = 1;
    info->channelId = 1;
    ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DelSendListenerInfo(info);
}

/*
 * @tc.name: CreateNewRecipientTest001
 * @tc.desc: create new recipient returns null when session not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateNewRecipientTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t channelId = 1;
    int32_t osType = TEST_OS_TYPE;
    FileRecipientInfo *result = CreateNewRecipient(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);

    result = CreateNewRecipient(sessionId + 1, channelId, osType);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: GetAndCheckFileSizeTest001
 * @tc.desc: get and check file size with null source file returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetAndCheckFileSizeTest001, TestSize.Level1)
{
    uint64_t fileSize = 0;
    uint64_t frameNum = 0;
    int32_t ret =
        GetAndCheckFileSize(nullptr, &fileSize, &frameNum, APP_INFO_FILE_FEATURES_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetAndCheckFileSize(
        nullptr, &fileSize, &frameNum, APP_INFO_FILE_FEATURES_NO_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: GetAndCheckFileSizeTest002
 * @tc.desc: get and check file size with valid file and crc support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetAndCheckFileSizeTest002, TestSize.Level1)
{
    uint64_t fileSize = 0;
    uint64_t frameNum = 0;
    int32_t ret = GetAndCheckFileSize(
        g_testProxyFileList[0], &fileSize, &frameNum, APP_INFO_FILE_FEATURES_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetAndCheckFileSizeTest003
 * @tc.desc: get and check file size with valid file and crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetAndCheckFileSizeTest003, TestSize.Level1)
{
    uint64_t fileSize = 0;
    uint64_t frameNum = 0;
    int32_t ret = GetAndCheckFileSize(
        g_testProxyFileList[1], &fileSize, &frameNum, APP_INFO_FILE_FEATURES_NO_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameInvalidParamTest001
 * @tc.desc: send one frame with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameInvalidParamTest001, TestSize.Level1)
{
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = nullptr,
    };
    int32_t ret = SendOneFrame(nullptr, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SendListenerInfo info;
    info.sessionId = TEST_SESSION_ID;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.channelId = TEST_CHANNEL_ID;
    ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SendOneFrameNoChannelTest001
 * @tc.desc: send one frame with valid data but no channel returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameNoChannelTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = TEST_SESSION_ID;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    info.channelId = TEST_CHANNEL_ID;
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
    };
    int32_t ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: SendOneFrameFrontTest001
 * @tc.desc: send one frame front with null info and various frame types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameFrontTest001, TestSize.Level1)
{
    int32_t ret = SendOneFrameFront(nullptr, TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo info;
    info.sessionId = 1;
    info.channelId = 1;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendOneFrameFront(&info, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SendOneFrameFront(&info, TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameFrontCrcOngoineTest001
 * @tc.desc: send one frame front with crc support and ongoing frame returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameFrontCrcOngoineTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.channelId = 1;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.seq = 0;
    int32_t ret = SendOneFrameFront(&info, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameFrontCrcFirstFrameTest001
 * @tc.desc: send one frame front with crc support and first frame returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameFrontCrcFirstFrameTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.channelId = 1;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.seq = TEST_SEQ;
    int32_t ret = SendOneFrameFront(&info, TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameMiddleTest001
 * @tc.desc: send one frame middle with null info and crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameMiddleTest001, TestSize.Level1)
{
    int32_t ret = SendOneFrameMiddle(nullptr, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo info;
    info.sessionId = 1;
    info.channelId = 1;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendOneFrameMiddle(&info, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameMiddleCrcTest001
 * @tc.desc: send one frame middle with crc support and ongoing frame returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameMiddleCrcTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.channelId = 1;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.seq = 0;
    int32_t ret = SendOneFrameMiddle(&info, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SendOneFrameMiddle(&info, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendOneFrameRearTest001
 * @tc.desc: send one frame rear with null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameRearTest001, TestSize.Level1)
{
    int32_t ret = SendOneFrameRear(nullptr, TRANS_SESSION_BYTES);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->channelId = 1;
    info->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendOneFrameRear(info, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(info);
}

/*
 * @tc.name: SendOneFrameRearCrcTest001
 * @tc.desc: send one frame rear with crc support and onlyone frame returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameRearCrcTest001, TestSize.Level1)
{
    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->channelId = 1;
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int32_t ret = SendOneFrameRear(info, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(info);
}

/*
 * @tc.name: SendOneFrameRearWaitSeqTest001
 * @tc.desc: send one frame rear with crc support and wait seq zero returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameRearWaitSeqTest001, TestSize.Level1)
{
    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->channelId = 1;
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->waitSeq = 0;
    int32_t ret = SendOneFrameRear(info, TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(info);
}

/*
 * @tc.name: SendOneFrameRearTimeoutTest001
 * @tc.desc: send one frame rear with crc support and non-zero wait seq returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendOneFrameRearTimeoutTest001, TestSize.Level1)
{
    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->channelId = 1;
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->waitSeq = TEST_SEQ;
    int32_t ret = SendOneFrameRear(info, TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    SoftBusFree(info);
}

/*
 * @tc.name: ClearRecipientResourcesErrStateTest001
 * @tc.desc: clear recipient resources with error state and crc support
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClearRecipientResourcesErrStateTest001, TestSize.Level1)
{
    FileRecipientInfo info;
    info.recvFileInfo.fileFd = -2;
    info.recvState = TRANS_FILE_RECV_ERR_STATE;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.channelId = 1;
    info.recvFileInfo.seq = TEST_SEQ;
    info.fileListener.recvListener.OnFileTransError = nullptr;
    ClearRecipientResources(&info);

    info.fileListener.recvListener.OnFileTransError = OnFileTransError;
    ClearRecipientResources(&info);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
}

/*
 * @tc.name: ClearRecipientResourcesCrcNotSupportTest001
 * @tc.desc: clear recipient resources with crc not support and idle state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClearRecipientResourcesCrcNotSupportTest001, TestSize.Level1)
{
    FileRecipientInfo info;
    info.recvFileInfo.fileFd = INVALID_FD;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    info.recvState = TRANS_FILE_RECV_ERR_STATE;
    ClearRecipientResources(&info);

    info.recvFileInfo.fileFd = INVALID_FD;
    ClearRecipientResources(&info);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
}

/*
 * @tc.name: SetRecipientRecvStateTest001
 * @tc.desc: set recipient recv state to idle and process state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SetRecipientRecvStateTest001, TestSize.Level1)
{
    FileRecipientInfo info;
    info.recvFileInfo.fileFd = INVALID_FD;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.recvState = TRANS_FILE_RECV_IDLE_STATE;
    SetRecipientRecvState(&info, TRANS_FILE_RECV_IDLE_STATE);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);

    SetRecipientRecvState(&info, TRANS_FILE_RECV_PROCESS_STATE);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
    ClearRecipientResources(&info);
}

/*
 * @tc.name: SendFileAckReqAndResDataTest001
 * @tc.desc: send file ack req and res data with no proxy channel returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendFileAckReqAndResDataTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    int32_t ret = SendFileAckReqAndResData(channelId, startSeq, value, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendFileAckReqAndResData(channelId + 1, startSeq, value, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: UnpackAckReqAndResDataInvalidParamTest001
 * @tc.desc: unpack ack req and res data with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackAckReqAndResDataInvalidParamTest001, TestSize.Level1)
{
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    int32_t ret = UnpackAckReqAndResData(nullptr, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    FileFrame frame;
    frame.frameLength = 0;
    frame.data = nullptr;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackAckReqAndResData(&frame, nullptr, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: UnpackAckReqAndResDataInvalidLengthTest001
 * @tc.desc: unpack ack req and res data with short frame length returns invalid data length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackAckReqAndResDataInvalidLengthTest001, TestSize.Level1)
{
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    uint64_t dataTest = 0;
    FileFrame frame;
    frame.frameLength = 0;
    frame.data = reinterpret_cast<uint8_t *>(&dataTest);
    int32_t ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: UnpackAckReqAndResDataInvalidHeadTest001
 * @tc.desc: unpack ack req and res data with wrong magic returns invalid data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackAckReqAndResDataInvalidHeadTest001, TestSize.Level1)
{
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    uint64_t dataTest = 0;
    FileFrame frame;
    frame.frameLength = TEST_HEADER_LENGTH;
    frame.data = reinterpret_cast<uint8_t *>(&dataTest);
    int32_t ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    dataTest = TEST_HEADER_LENGTH;
    frame.data = reinterpret_cast<uint8_t *>(&dataTest);
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
}

/*
 * @tc.name: UnpackAckReqAndResDataValidTest001
 * @tc.desc: unpack ack req and res data with valid magic returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackAckReqAndResDataValidTest001, TestSize.Level1)
{
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    uint8_t dataBuffer[TEST_HEADER_LENGTH] = { 0 };
    *reinterpret_cast<uint32_t *>(dataBuffer) = FILE_MAGIC_NUMBER;
    *reinterpret_cast<uint64_t *>(dataBuffer + FRAME_MAGIC_OFFSET) = FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    FileFrame frame;
    frame.frameLength = TEST_HEADER_LENGTH;
    frame.data = dataBuffer;
    int32_t ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PackReadFileDataNullDataTest001
 * @tc.desc: pack read file data with null frame data returns invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackReadFileDataNullDataTest001, TestSize.Level1)
{
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = nullptr,
    };
    uint64_t readLength = TEST_FILE_LENGTH;
    uint64_t fileOffset = 0;
    SendListenerInfo info;
    info.fd = g_fd;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);
}

/*
 * @tc.name: PackReadFileRetransDataNullDataTest001
 * @tc.desc: pack read file retrans data with null frame data returns invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackReadFileRetransDataNullDataTest001, TestSize.Level1)
{
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = nullptr,
    };
    uint64_t readLength = TEST_FILE_LENGTH;
    uint64_t fileOffset = 0;
    uint32_t seq = TEST_SEQ;
    SendListenerInfo info;
    info.fd = g_fd;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    int64_t len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);
}

/*
 * @tc.name: PackReadFileDataCrcNotSupportTest001
 * @tc.desc: pack read file data with crc not support returns file length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackReadFileDataCrcNotSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    uint64_t readLength = TEST_FILE_LENGTH;
    uint64_t fileOffset = 0;
    SendListenerInfo info;
    info.fd = g_fd;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);
}

/*
 * @tc.name: PackReadFileDataCrcSupportTest001
 * @tc.desc: pack read file data with crc support returns file length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackReadFileDataCrcSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    uint64_t readLength = TEST_FILE_LENGTH;
    uint64_t fileOffset = 0;
    SendListenerInfo info;
    info.fd = g_fd;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);
}

/*
 * @tc.name: PackReadFileRetransDataCrcSupportTest001
 * @tc.desc: pack read file retrans data with crc support returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackReadFileRetransDataCrcSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    uint64_t readLength = TEST_FILE_LENGTH;
    uint64_t fileOffset = 0;
    uint32_t seq = TEST_SEQ;
    SendListenerInfo info;
    info.fd = g_fd;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int64_t len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, len);
}

/*
 * @tc.name: UnpackFileDataFrameCrcNotSupportTest001
 * @tc.desc: unpack file data frame with crc not support and short length returns invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileDataFrameCrcNotSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .magic = FILE_MAGIC_NUMBER,
        .frameType = TRANS_SESSION_BYTES,
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    FileRecipientInfo info = {
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
        .osType = OH_TYPE,
    };
    uint32_t fileDataLen = 0;
    int32_t ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileFrame.frameLength = TEST_HEADER_LENGTH;
    ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: UnpackFileDataFrameCrcSupportTest001
 * @tc.desc: unpack file data frame with crc support returns invalid data head
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileDataFrameCrcSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .magic = FILE_MAGIC_NUMBER,
        .frameType = TRANS_SESSION_BYTES,
        .frameLength = TEST_HEADER_LENGTH,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    FileRecipientInfo info = {
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .osType = OH_TYPE,
    };
    uint32_t fileDataLen = 0;
    int32_t ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    fileFrame.magic = 0;
    fileFrame.frameLength = TEST_HEADER_LENGTH_MIN;
    ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: RetransFileFrameBySeqNullInfoTest001
 * @tc.desc: retrans file frame by seq with null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, RetransFileFrameBySeqNullInfoTest001, TestSize.Level1)
{
    int32_t ret = RetransFileFrameBySeq(nullptr, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = RetransFileFrameBySeq(nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: RetransFileFrameBySeqCrcNotSupportTest001
 * @tc.desc: retrans file frame by seq with crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, RetransFileFrameBySeqCrcNotSupportTest001, TestSize.Level1)
{
    SendListenerInfo info = {
        .channelId = 1,
        .fd = g_fd,
        .fileSize = TEST_FILE_SIZE,
        .frameNum = 1,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    int32_t ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_OK, ret);

    int32_t seq = 0;
    ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: RetransFileFrameBySeqCrcSupportTest001
 * @tc.desc: retrans file frame by seq with crc support and valid seq returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, RetransFileFrameBySeqCrcSupportTest001, TestSize.Level1)
{
    SendListenerInfo info = {
        .fileSize = TEST_FILE_SIZE,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    int32_t seq = TEST_SEQ_SECOND;
    int32_t ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: RetransFileFrameBySeqZeroFileSizeTest001
 * @tc.desc: retrans file frame by seq with crc support and zero file size returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, RetransFileFrameBySeqZeroFileSizeTest001, TestSize.Level1)
{
    SendListenerInfo info = {
        .fileSize = 0,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    int32_t seq = 0;
    int32_t ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = RetransFileFrameBySeq(&info, -1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: AckResponseDataHandleTest001
 * @tc.desc: ack response data handle with null data and zero len returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, AckResponseDataHandleTest001, TestSize.Level1)
{
    SendListenerInfo info = {
        .fileSize = TEST_FILE_SIZE,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    uint32_t len = 0;
    int32_t ret = AckResponseDataHandle(&info, nullptr, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *data = "test_data";
    ret = AckResponseDataHandle(&info, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AckResponseDataHandleValidDataTest001
 * @tc.desc: ack response data handle with valid data returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, AckResponseDataHandleValidDataTest001, TestSize.Level1)
{
    SendListenerInfo info = {
        .fileSize = TEST_FILE_SIZE,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    AckResponseData ackResponseData = {
        .startSeq = FILE_SEND_ACK_RESULT_SUCCESS,
        .seqResult = TEST_SEQ_SECOND,
    };
    uint32_t len = sizeof(AckResponseData);
    const char *data = reinterpret_cast<const char *>(&ackResponseData);
    int32_t ret = AckResponseDataHandle(&info, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetFullRecvPathNullParamTest001
 * @tc.desc: get full recv path with null params returns null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetFullRecvPathNullParamTest001, TestSize.Level1)
{
    char *result = GetFullRecvPath(nullptr, nullptr);
    EXPECT_EQ(nullptr, result);

    result = GetFullRecvPath(nullptr, g_rootDir);
    EXPECT_EQ(nullptr, result);

    result = GetFullRecvPath(g_destFile, nullptr);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: GetFullRecvPathTest001
 * @tc.desc: get full recv path with various path combinations returns valid path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetFullRecvPathTest001, TestSize.Level1)
{
    const char *filePath1 = "";
    const char *recvRootDir1 = "";
    char *result = GetFullRecvPath(filePath1, recvRootDir1);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);

    const char *filePath2 = "/test.txt";
    result = GetFullRecvPath(filePath2, recvRootDir1);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);

    const char *recvRootDir2 = "/data/";
    result = GetFullRecvPath(filePath1, recvRootDir2);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);

    result = GetFullRecvPath(filePath2, recvRootDir2);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);

    const char *filePath3 = "/test.txt";
    const char *recvRootDir3 = "/data";
    result = GetFullRecvPath(filePath3, recvRootDir2);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);

    result = GetFullRecvPath(filePath2, recvRootDir3);
    EXPECT_NE(nullptr, result);
    SoftBusFree(result);
}

/*
 * @tc.name: GetDirPathInvalidParamTest001
 * @tc.desc: get dir path with null or invalid params returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetDirPathInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = GetDirPath(nullptr, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath1 = "";
    ret = GetDirPath(fullPath1, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath2 = "/data/txt/";
    ret = GetDirPath(fullPath2, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath3 = "/d/t.txt";
    char dirPath1[TEST_FILE_LENGTH] = { 0 };
    ret = GetDirPath(fullPath3, dirPath1, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetDirPathTest001
 * @tc.desc: get dir path with valid full path returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetDirPathTest001, TestSize.Level1)
{
    const char *fullPath = "/d/t.txt";
    char dirPath[TEST_FILE_LENGTH] = { 0 };
    int32_t ret = GetDirPath(fullPath, dirPath, TEST_FILE_LENGTH);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetDirPath(fullPath, dirPath, TEST_FILE_LENGTH + 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetAbsFullPathNullParamTest001
 * @tc.desc: get abs full path with null params returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetAbsFullPathNullParamTest001, TestSize.Level1)
{
    int32_t ret = GetAbsFullPath(nullptr, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = GetAbsFullPath(nullptr, nullptr, TEST_PATH_SIZE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = GetAbsFullPath(g_testProxyFileList[0], nullptr, TEST_PATH_SIZE);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetAbsFullPathTest001
 * @tc.desc: get abs full path with valid file path returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetAbsFullPathTest001, TestSize.Level1)
{
    char recvAbsPath[TEST_PATH_SIZE];
    int32_t ret = GetAbsFullPath(g_testProxyFileList[0], recvAbsPath, TEST_PATH_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetAbsFullPath(g_testProxyFileList[0], recvAbsPath, TEST_FILE_LENGTH);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CreateDirAndGetAbsPathTest001
 * @tc.desc: create dir and get abs path with null recv path returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateDirAndGetAbsPathTest001, TestSize.Level1)
{
    int32_t ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], nullptr, TEST_PATH_SIZE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(nullptr, nullptr, TEST_PATH_SIZE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(nullptr, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CreateDirAndGetAbsPathValidTest001
 * @tc.desc: create dir and get abs path with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateDirAndGetAbsPathValidTest001, TestSize.Level1)
{
    char recvAbsPath[TEST_PATH_SIZE];
    int32_t ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], recvAbsPath, TEST_PATH_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], recvAbsPath, TEST_FILE_LENGTH);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddSendListenerInfoAndProcessTest001
 * @tc.desc: add send listener info and process file recv result returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, AddSendListenerInfoAndProcessTest001, TestSize.Level1)
{
    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->crc = 1;
    info->channelId = 1;
    int32_t ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    int32_t sessionId = 1;
    uint32_t seq = 0;
    int32_t res = 0;
    ret = ProcessFileRecvResult(sessionId, seq, res);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DelSendListenerInfo(nullptr);
    DelSendListenerInfo(info);
}

/*
 * @tc.name: PackFileTransStartInfoInvalidParamTest001
 * @tc.desc: pack file trans start info with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackFileTransStartInfoInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = PackFileTransStartInfo(nullptr, nullptr, TEST_FILE_TEST_TXT_FILE, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = PackFileTransStartInfo(nullptr, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PackFileTransStartInfoCrcSupportTest001
 * @tc.desc: pack file trans start info with crc support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackFileTransStartInfoCrcSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.sessionId = 1;
    info.channelId = 1;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    int32_t ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PackFileTransStartInfoCrcNotSupportTest001
 * @tc.desc: pack file trans start info with crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PackFileTransStartInfoCrcNotSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    info.sessionId = 1;
    info.channelId = 1;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    int32_t ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: UnpackFileTransStartInfoInvalidParamTest001
 * @tc.desc: unpack file trans start info with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransStartInfoInvalidParamTest001, TestSize.Level1)
{
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = UnpackFileTransStartInfo(nullptr, nullptr, nullptr, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: UnpackFileTransStartInfoCrcSupportTest001
 * @tc.desc: unpack file trans start info with crc support and short length returns invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransStartInfoCrcSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = TEST_HEADER_LENGTH,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    uint32_t data = FILE_MAGIC_NUMBER;
    fileFrame.data = reinterpret_cast<uint8_t *>(&data);
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/*
 * @tc.name: UnpackFileTransStartInfoCrcNotSupportTest001
 * @tc.desc: unpack file trans start info with crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileTransStartInfoCrcNotSupportTest001, TestSize.Level1)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(&dataTest),
        .fileData = reinterpret_cast<uint8_t *>(&dataTest),
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileFrame.frameLength = FRAME_DATA_SEQ_OFFSET;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    fileFrame.frameLength = FRAME_DATA_SEQ_OFFSET + TEST_HEADER_LENGTH;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendFileCrcCheckSumTest001
 * @tc.desc: send file crc check sum with null info and crc not support
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendFileCrcCheckSumTest001, TestSize.Level1)
{
    int32_t ret = SendFileCrcCheckSum(nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendFileCrcCheckSum(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendFileCrcCheckSumCrcSupportTest001
 * @tc.desc: send file crc check sum with crc support returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendFileCrcCheckSumCrcSupportTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.channelId = 1;
    info.sessionId = 1;
    int32_t ret = SendFileCrcCheckSum(&info);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: UnpackFileCrcCheckSumInvalidParamTest001
 * @tc.desc: unpack file crc check sum with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileCrcCheckSumInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = UnpackFileCrcCheckSum(nullptr, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileRecipientInfo fileInfo;
    fileInfo.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    FileFrame fileFrame;
    ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: UnpackFileCrcCheckSumCrcSupportTest001
 * @tc.desc: unpack file crc check sum with crc support returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UnpackFileCrcCheckSumCrcSupportTest001, TestSize.Level1)
{
    FileRecipientInfo fileInfo;
    fileInfo.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    FileFrame fileFrame;
    int32_t ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileFrame.frameLength = 20;
    ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SendSingleFileNullParamTest001
 * @tc.desc: send single file with null source file returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendSingleFileNullParamTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.crc = 1;
    info.channelId = 1;
    int32_t ret = SendSingleFile(&info, nullptr, g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SendSingleFile(&info, g_testProxyFileList[0], nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FileToFrameAndSendFileNullInfoTest001
 * @tc.desc: file to frame and send file with null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, FileToFrameAndSendFileNullInfoTest001, TestSize.Level1)
{
    int32_t ret = FileToFrameAndSendFile(nullptr, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FileToFrameAndSendFile(nullptr, nullptr, g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FileToFrameAndSendFile(nullptr, g_testProxyFileList[0], nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FileToFrameAndSendFileInvalidDestTest001
 * @tc.desc: file to frame and send file with null dest file returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, FileToFrameAndSendFileInvalidDestTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.crc = 1;
    info.channelId = 1;
    int32_t ret = FileToFrameAndSendFile(&info, g_testProxyFileList[0], nullptr);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrameAndSendFile(&info, nullptr, g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrameAndSendFile(&info, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}
} // namespace OHOS
