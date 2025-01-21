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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "securec.h"

#include "client_trans_proxy_file_manager.c"
#include "client_trans_proxy_file_helper.c"
#include "client_trans_proxy_manager.c"
#include "client_trans_session_manager.c"
#include "client_trans_socket_manager.c"
#include "client_trans_file_listener.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_frame.h"
#include "session.h"
#include "softbus_app_info.h"
#include "softbus_access_token_test.h"

#define TEST_FILE_LENGTH 10
#define TEST_FILE_CNT 2
#define TEST_CHANNEL_ID 2
#define TEST_SESSION_ID 1
#define TEST_SEQ 1020
#define TEST_SEQ_SECOND 2
#define TEST_HEADER_LENGTH 24
#define TEST_HEADER_LENGTH_MIN 13
#define TEST_FILE_PATH "/data/file.txt"
#define TEST_DATA_LENGTH 6
#define TEST_FILE_SIZE 1000
#define TEST_PATH_SIZE 50
#define TEST_FILE_TEST_TXT_FILE 16
#define TEST_FILE_MAGIC_OFFSET 0
#define TEST_FRAME_NUMBER 2
#define TEST_FRAME_DATA_LENGTH 10
#define TEST_FILEPATH_LENGTH 4
#define TEST_SEQ8 8
#define TEST_SEQ16 16
#define TEST_SEQ32 32
#define TEST_SEQ126 126
#define TEST_SEQ128 128
#define TEST_OS_TYPE 10
#define TEST_PACKET_SIZE 1024
#define TEST_INVALID_LEN (-1)

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_peerNetworkId = "1234567789";
const char *g_groupId = "123";
FILE *g_fileTest = NULL;
FILE *g_fileSs = NULL;
int32_t g_fd = 0;
char g_writeData[128] = "test111111111111111111111111111111111111111111111111111111111111";
const char *g_rootDir = "/data";
const char *g_destFile = "test.txt";
char g_recvFile[] = "/data/test.txt";
const char *g_sessionKey = "www.huaweitest.com";

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

static void OnSessionClosed(int32_t sessionId)
{
}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
}

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

void OnFileTransError(int32_t sessionId)
{
    return;
}

static int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    return SOFTBUS_OK;
}

static int32_t OnReceiveFileProcess(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    return SOFTBUS_OK;
}
static void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{
    return;
}

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

class ClientTransProxyFileManagerTest : public testing::Test {
public:
    ClientTransProxyFileManagerTest() {}
    ~ClientTransProxyFileManagerTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
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
    g_fileTest = NULL;
    ret = fclose(g_fileSs);
    EXPECT_EQ(ret, 0);
    g_fileSs = NULL;
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

/**
 * @tc.name: ClinetTransProxySendFileTest001
 * @tc.desc: client trans proxy send file test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxySendFileTest001, TestSize.Level0)
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

    const char *proxyZeroLileList[] = {
        "",
        "/path/max/length/512",
    };
    ret = ProxyChannelSendFile(channelId, proxyZeroLileList, g_testProxyFileList, TEST_FILE_CNT);
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

    ret = ProxyChannelSendFile(channelId, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/**
 * @tc.name: ClinetTransRecvFileFrameDataTest001
 * @tc.desc: clent trans recv file frame data test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransRecvFileFrameDataTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t sessionId = 1;
    int32_t ret = ProcessRecvFileFrameData(sessionId, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = (char *)g_sessionKey;
    channel->osType = OH_TYPE;
    ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE + 1;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransRecvFileFrameDataTest002
 * @tc.desc: client trans recv file frame data test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransRecvFileFrameDataTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    int32_t sessionId = 1;

    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 1;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BR;
    channel->sessionKey = (char *)g_sessionKey;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    FileFrame fileFrame;
    fileFrame.frameLength = PROXY_BR_MAX_PACKET_SIZE - 1;
 
    fileFrame.frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

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

    fileFrame.frameType = TRANS_SESSION_FILE_ACK_RESPONSE_SENT;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_CRC_CHECK_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_RESULT_FRAME;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_ALLFILE_SENT;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    fileFrame.frameType = -1;
    ret = ProcessRecvFileFrameData(sessionId, channelId, &fileFrame);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyFileManagerInitDataTest001
 * @tc.desc: client trans proxy file manager init data test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileManagerInitDataTest001, TestSize.Level0)
{
    int32_t ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    int32_t channelId = 1;
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    ret = SendFileTransResult(channelId, seq, result, side);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    uint32_t data = 0;
    const uint8_t *data1 = (const uint8_t *)&data;
    uint32_t len = TEST_HEADER_LENGTH;
    ret = UnpackFileTransResultFrame(data1, len, nullptr, &result, &side);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackFileTransResultFrame(nullptr, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackFileTransResultFrame(data1, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);

    data = FILE_MAGIC_NUMBER;
    const uint8_t *data2 = (const uint8_t *)&data;
    ret = UnpackFileTransResultFrame(data2, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyGetSessionFileLockTest001
 * @tc.desc: client trans proxy get session file lock test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetSessionFileLockTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    ProxyFileMutexLock *sessionLock = GetSessionFileLock(channelId);
    EXPECT_NE(nullptr, sessionLock);

    sessionLock = GetSessionFileLock(channelId);
    EXPECT_NE(nullptr, sessionLock);

    DelSessionFileLock(nullptr);
    sessionLock->count = 1;
    DelSessionFileLock(sessionLock);

    sessionLock->count = 2;
    DelSessionFileLock(sessionLock);
}

/**
 * @tc.name: ClinetTransProxyCreateSendListenerInfoTest001
 * @tc.desc: client trans proxy create send listener info test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyCreateSendListenerInfoTest001, TestSize.Level0)
{
    int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    ASSERT_EQ(SOFTBUS_OK, ret);

    int32_t sessionId = 1;
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;

    ret = ClientAddSession(&g_param, &sessionId, &isEnabled);
    ASSERT_EQ(SOFTBUS_OK, ret);

    SendListenerInfo *sendListenerInfo;
    ret = CreateSendListenerInfo(&sendListenerInfo, TEST_CHANNEL_ID, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);

    int32_t channelId = 1;
    int32_t osType = TEST_OS_TYPE;
    SessionInfo sessionInfo;
    sessionInfo.sessionId = sessionId;
    sessionInfo.channelId = channelId;
    sessionInfo.channelType = CHANNEL_TYPE_PROXY;
    ret = TransClientInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = AddSession(g_sessionName, &sessionInfo);
    ASSERT_EQ(SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED, ret);

    ret = TransSetFileSendListener(g_sessionName, &g_listener);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = TransSetFileReceiveListener(g_sessionName, &g_fileRecvListener, g_rootDir);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = CreateSendListenerInfo(&sendListenerInfo, channelId, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);

    ret = CreateSendListenerInfo(&sendListenerInfo, channelId, 0);
    EXPECT_EQ(SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND, ret);

    ret = AddSendListenerInfo(nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileRecipientInfo *result = CreateNewRecipient(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);
}

/**
 * @tc.name: ClinetTransProxyGetAndCheckFileSizeTest001
 * @tc.desc: improve branch coverage, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetAndCheckFileSizeTest001, TestSize.Level0)
{
    uint64_t fileSize = 0;
    uint64_t frameNum = 0;
    int32_t ret =
        GetAndCheckFileSize(nullptr, &fileSize, &frameNum, APP_INFO_FILE_FEATURES_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetAndCheckFileSize(
        g_testProxyFileList[0], &fileSize, &frameNum, APP_INFO_FILE_FEATURES_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetAndCheckFileSize(
        g_testProxyFileList[1], &fileSize, &frameNum, APP_INFO_FILE_FEATURES_NO_SUPPORT, PROXY_BLE_MAX_PACKET_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxySendOneFrameTest001
 * @tc.desc: client trans proxy send one frame test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxySendOneFrameTest001, TestSize.Level0)
{
    SendListenerInfo info;
    info.sessionId = TEST_SESSION_ID;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.channelId = TEST_CHANNEL_ID;

    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = nullptr,
    };
    int32_t ret = SendOneFrame(nullptr, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    uint32_t dataTest = TEST_DATA_LENGTH;
    fileFrame.data = (uint8_t *)&dataTest;
    ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    fileFrame.frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    ret = SendOneFrame(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendOneFrameFront(nullptr, fileFrame.frameType);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo infoMiddle;
    infoMiddle.sessionId = 1;
    infoMiddle.channelId = 1;
    infoMiddle.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendOneFrameMiddle(nullptr, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendOneFrameMiddle(&infoMiddle, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SendOneFrameFront(&infoMiddle, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    infoMiddle.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    infoMiddle.seq = 0;
    ret = SendOneFrameMiddle(&infoMiddle, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SendOneFrameMiddle(&infoMiddle, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendOneFrameFront(&infoMiddle, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SendOneFrameFront(&infoMiddle, TRANS_SESSION_FILE_FIRST_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    infoMiddle.seq = TEST_SEQ;
    ret = SendOneFrameMiddle(&infoMiddle, TRANS_SESSION_FILE_ONGOINE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxySendOneFrameTest002
 * @tc.desc: client trans proxy send one frame test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxySendOneFrameTest002, TestSize.Level0)
{
    SendListenerInfo *infoRear = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    infoRear->sessionId = 1;
    infoRear->channelId = 1;
    infoRear->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int32_t ret = SendOneFrameRear(nullptr, TRANS_SESSION_BYTES);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendOneFrameRear(infoRear, TRANS_SESSION_BYTES);
    EXPECT_EQ(SOFTBUS_OK, ret);

    infoRear->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = SendOneFrameRear(infoRear, TRANS_SESSION_FILE_ONLYONE_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    infoRear->waitSeq = 0;
    ret = SendOneFrameRear(infoRear, TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    infoRear->waitSeq = TEST_SEQ;
    ret = SendOneFrameRear(infoRear, TRANS_SESSION_FILE_LAST_FRAME);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    SoftBusFree(infoRear);
}

/**
 * @tc.name: ClinetTransProxyFileRecipientInfoTest001
 * @tc.desc: client trans proxy file recipient info test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileRecipientInfoTest001, TestSize.Level0)
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
    SetRecipientRecvState(&info, TRANS_FILE_RECV_IDLE_STATE);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
    ClearRecipientResources(&info);

    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ClearRecipientResources(&info);

    info.recvState = TRANS_FILE_RECV_IDLE_STATE;
    SetRecipientRecvState(&info, TRANS_FILE_RECV_IDLE_STATE);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
    SetRecipientRecvState(&info, TRANS_FILE_RECV_PROCESS_STATE);
    EXPECT_EQ(info.recvFileInfo.fileFd, INVALID_FD);
    ClearRecipientResources(&info);

    info.recvFileInfo.fileFd = INVALID_FD;
    ClearRecipientResources(&info);
}

/**
 * @tc.name: ClinetTransProxyFileAckReqAndResDataTest001
 * @tc.desc: client trans proxy file ack req and res data test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileAckReqAndResDataTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    int32_t ret = SendFileAckReqAndResData(channelId, startSeq, value, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    FileFrame frame;
    frame.frameLength = 0;
    frame.data = nullptr;
    uint64_t dataTest = 0;
    ret = UnpackAckReqAndResData(nullptr, &startSeq, &value);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.data = (uint8_t *)&dataTest;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameLength = TEST_HEADER_LENGTH;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataTest = FILE_MAGIC_NUMBER;
    frame.data = (uint8_t *)&dataTest;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyPackFileDataTest001
 * @tc.desc: client trans proxy pack file data test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyPackFileDataTest001, TestSize.Level0)
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
    uint32_t seq = TEST_SEQ;
    int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_TRUE(len == -1);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_TRUE(len == -1);

    len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_TRUE(len == -1);

    uint32_t dataTest = TEST_DATA_LENGTH;
    fileFrame.data = (uint8_t *)&dataTest;
    fileFrame.fileData = (uint8_t *)&dataTest;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);

    len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, len);
}

/**
 * @tc.name: ClinetTransProxyPackFileDataFrameTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyPackFileDataFrameTest001, TestSize.Level0)
{
    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .magic = FILE_MAGIC_NUMBER,
        .frameType = TRANS_SESSION_BYTES,
        .frameLength = 0,
        .data = (uint8_t *)&dataTest,
        .fileData = (uint8_t *)&dataTest,
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

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    fileFrame.magic = 0;
    fileFrame.frameLength = TEST_HEADER_LENGTH_MIN;
    ret = UnpackFileDataFrame(&info, &fileFrame, &fileDataLen);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: ClinetTransProxyRetransFileFrameTest001
 * @tc.desc: client trans proxy retrans file frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyRetransFileFrameTest001, TestSize.Level0)
{
    SendListenerInfo info = {
        .channelId = 1,
        .fd = g_fd,
        .fileSize = TEST_FILE_SIZE,
        .frameNum = 1,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    int32_t ret = RetransFileFrameBySeq(nullptr, TEST_SEQ);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int32_t seq = TEST_SEQ_SECOND;
    ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClinetTransProxyAckResponseDataHandleTest001
 * @tc.desc: client trans proxy handle response data test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyAckResponseDataHandleTest001, TestSize.Level0)
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

    len = sizeof(AckResponseData);
    ret = AckResponseDataHandle(&info, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    AckResponseData ackResponseData = {
        .startSeq = FILE_SEND_ACK_RESULT_SUCCESS,
        .seqResult = TEST_SEQ_SECOND,
    };
    const char *dataTest = reinterpret_cast<const char*>(&ackResponseData);
    ret = AckResponseDataHandle(&info, dataTest, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyGetFullRecvPathTest001
 * @tc.desc: client trans proxy get full recv path test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetFullRecvPathTest001, TestSize.Level0)
{
    char *result = GetFullRecvPath(nullptr, nullptr);
    EXPECT_EQ(nullptr, result);
    const char *filePath1 = "";
    const char *recvRootDir1 = "";

    result = GetFullRecvPath(filePath1, recvRootDir1);
    EXPECT_NE(nullptr, result);

    const char *filePath2 = "/test.txt";
    result = GetFullRecvPath(filePath2, recvRootDir1);
    EXPECT_NE(nullptr, result);

    const char *recvRootDir2 = "/data/";
    result = GetFullRecvPath(filePath1, recvRootDir2);
    EXPECT_NE(nullptr, result);

    result = GetFullRecvPath(filePath2, recvRootDir2);
    EXPECT_NE(nullptr, result);

    const char *filePath3 = "/test.txt";
    const char *recvRootDir3 = "/data";
    result = GetFullRecvPath(filePath3, recvRootDir2);
    EXPECT_NE(nullptr, result);

    result = GetFullRecvPath(filePath2, recvRootDir3);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: ClinetTransProxyGetDirPathTest001
 * @tc.desc: client trans proxy get dir path test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetDirPathTest001, TestSize.Level0)
{
    int32_t ret = GetDirPath(nullptr, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath1 = "";
    char dirPath1[TEST_FILE_LENGTH] = {0};
    ret = GetDirPath(fullPath1, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath2 = "/data/txt/";
    ret = GetDirPath(fullPath2, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    const char *fullPath3 = "/d/t.txt";
    ret = GetDirPath(fullPath3, dirPath1, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = GetDirPath(fullPath3, dirPath1, TEST_FILE_LENGTH);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyGetAbsFullPathTest001
 * @tc.desc: client trans proxy get path test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetAbsFullPathTest001, TestSize.Level0)
{
    int32_t ret = GetAbsFullPath(nullptr, nullptr, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    char recvAbsPath[TEST_PATH_SIZE];
    ret = GetAbsFullPath(g_testProxyFileList[0], recvAbsPath, TEST_PATH_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = GetAbsFullPath(g_testProxyFileList[0], recvAbsPath, TEST_FILE_LENGTH);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], nullptr, TEST_PATH_SIZE);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], recvAbsPath, TEST_PATH_SIZE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreateDirAndGetAbsPath(g_testProxyFileList[0], recvAbsPath, TEST_FILE_LENGTH);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxySendListenerInfoTest001
 * @tc.desc: client trans proxy add and del SendListenerInfo test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxySendListenerInfoTest001, TestSize.Level0)
{
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    EXPECT_TRUE(info != nullptr);
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

/**
 * @tc.name: ClinetTransProxyFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file start info test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileTransStartInfoTest001, TestSize.Level0)
{
    int32_t ret = PackFileTransStartInfo(nullptr, nullptr, TEST_FILE_TEST_TXT_FILE, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = (uint8_t *)&dataTest,
        .fileData = (uint8_t *)&dataTest,
    };
    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.sessionId = 1;
    info.channelId = 1;
    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyUnFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyUnFileTransStartInfoTest001, TestSize.Level0)
{
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = UnpackFileTransStartInfo(nullptr, nullptr, nullptr, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint32_t dataTest = TEST_DATA_LENGTH;
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = (uint8_t *)&dataTest,
        .fileData = (uint8_t *)&dataTest,
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fileFrame.frameLength = TEST_HEADER_LENGTH;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    uint32_t data = FILE_MAGIC_NUMBER;
    fileFrame.data = (uint8_t *)&data;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    fileFrame.frameLength = 0;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileFrame.frameLength = FRAME_DATA_SEQ_OFFSET;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    fileFrame.frameLength = FRAME_DATA_SEQ_OFFSET + TEST_HEADER_LENGTH;
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyFileCrcCheckSumTest001
 * @tc.desc: client trans proxy crc check test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileCrcCheckSumTest001, TestSize.Level0)
{
    int32_t ret = SendFileCrcCheckSum(nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo info;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = SendFileCrcCheckSum(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = SendFileCrcCheckSum(&info);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = UnpackFileCrcCheckSum(nullptr, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileRecipientInfo fileInfo;
    fileInfo.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    FileFrame fileFrame;
    ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_EQ(SOFTBUS_OK, ret);

    fileInfo.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileFrame.frameLength = 20;
    ret = UnpackFileCrcCheckSum(&fileInfo, &fileFrame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyFileToFrameTest001
 * @tc.desc: client trans proxy send file test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileToFrameTest001, TestSize.Level0)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.crc = 1;
    info.channelId = 1;

    int32_t ret = SendSingleFile(&info, nullptr, g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FileToFrameAndSendFile(nullptr, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = FileToFrameAndSendFile(&info, g_testProxyFileList[0], nullptr);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrameAndSendFile(&info, nullptr, g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrameAndSendFile(&info, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = SendSingleFile(&info, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = SendFileList(info.channelId, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendFileList(info.channelId, nullptr, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClinetTransProxyFileToFrameTest002
 * @tc.desc: client trans proxy file to frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileToFrameTest002, TestSize.Level0)
{
    SendListenerInfo sendInfo = {
        .channelId = 1,
        .sessionId = 1,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };

    int32_t ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_destFile);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrame(&sendInfo, TEST_FRAME_NUMBER, g_destFile, TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    sendInfo.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = FileToFrame(&sendInfo, TEST_FRAME_NUMBER, g_destFile, TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: ClinetTransProxyStartSendFileTest001
 * @tc.desc: client trans proxy start send file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyStartSendFileTest001, TestSize.Level0)
{
    SendListenerInfo sendInfo = {
        .channelId = 1,
        .sessionId = 1,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };

    int32_t ret = ProxyStartSendFile(&sendInfo, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: ClinetTransProxyCheckFileTest001
 * @tc.desc: client trans proxy start send file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyCheckFileTest001, TestSize.Level0)
{
    bool result = CheckRecvFileExist(nullptr);
    EXPECT_EQ(false, result);

    result = CheckRecvFileExist(g_testProxyFileList[0]);
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: ClinetTransProxyPutToRcvListTest001
 * @tc.desc: client trans proxy put to file list test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyPutToRcvListTest001, TestSize.Level0)
{
    int32_t ret = PutToRecvFileList(nullptr, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileRecipientInfo recipient = {
        .recvFileInfo.fileStatus = NODE_ERR,
    };
    const SingleFileInfo file = {0};
    ret = PutToRecvFileList(&recipient, &file);
    EXPECT_NE(SOFTBUS_OK, ret);

    recipient.recvFileInfo.fileStatus = NODE_IDLE;
    ret = PutToRecvFileList(&recipient, &file);
    EXPECT_NE(SOFTBUS_OK, ret);

    SingleFileInfo trueFile = {0};
    (void)memcpy_s(trueFile.filePath, MAX_FILE_PATH_NAME_LEN, g_recvFile, sizeof(g_recvFile));
    ret = PutToRecvFileList(&recipient, &trueFile);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyRecvRecipientInfoListTest001
 * @tc.desc: client trans proxy recv recipient info test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyRecvRecipientInfoListTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    FileRecipientInfo *result = GetRecipientNoLock(sessionId);
    EXPECT_EQ(nullptr, result);

    uint32_t seq = 0;
    int32_t res = 0;
    int32_t ret = ProcessFileSendResult(sessionId, seq, res);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    sessionId = -1;
    result = GetRecipientNoLock(sessionId);
    EXPECT_EQ(nullptr, result);

    ret = ProcessFileSendResult(sessionId, seq, res);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileRecvResult(sessionId, seq, res);
    EXPECT_NE(SOFTBUS_OK, ret);

    ReleaseRecipientRef(nullptr);

    FileRecipientInfo *info = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    info->objRefCount = 2,
    ReleaseRecipientRef(info);

    info->objRefCount = 1;
    ReleaseRecipientRef(info);
}

/**
 * @tc.name: ClinetTransProxyGetRecipientInfoListTest001
 * @tc.desc: client trans proxy get recipient info test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetRecipientInfoListTest001, TestSize.Level0)
{
    int32_t sessionId = -1;
    int32_t channelId = 1;
    int32_t osType = TEST_OS_TYPE;
    FileRecipientInfo *result = GetRecipientInProcessRef(sessionId);
    EXPECT_EQ(nullptr, result);

    result = GetRecipientInCreateFileRef(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);

    sessionId = 1;
    result = GetRecipientInCreateFileRef(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);

    result = GetRecipientInProcessRef(sessionId);
    EXPECT_EQ(nullptr, result);
}

/**
 * @tc.name: ClinetTransProxyWriteEmptyFrameTest001
 * @tc.desc: client trans proxy write empty frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyWriteEmptyFrameTest001, TestSize.Level0)
{
    int32_t cnt = 0;
    int32_t ret = WriteEmptyFrame(nullptr, cnt);
    EXPECT_NE(SOFTBUS_OK, ret);

    SingleFileInfo info = {0};
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    cnt = 1;
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_NE(SOFTBUS_OK, ret);

    info.fileFd = g_fd;
    info.oneFrameLen = -1;
    info.fileOffset = 0;
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_NE(SOFTBUS_OK, ret);

    info.oneFrameLen = TEST_FILE_LENGTH;
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyProcessOneFrameCRCTest001
 * @tc.desc: client trans proxy process one frameCRC test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyProcessOneFrameCRCTest001, TestSize.Level0)
{
    uint32_t dataLen = 0;
    int32_t ret = ProcessOneFrameCRC(nullptr, dataLen, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint8_t *emptyBuff = (uint8_t *)SoftBusCalloc(TEST_FILE_SIZE);
    if (emptyBuff == NULL) {
        return;
    }
    FileFrame frame = {
        .frameType = TRANS_SESSION_FILE_FIRST_FRAME,
        .seq = TEST_SEQ32,
        .fileData = emptyBuff,
    };
    SingleFileInfo fileInfo = {
        .seq = 0,
        .fileFd = g_fd,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = 0,
        .preStartSeq = 0,
    };
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.seq = TEST_SEQ128;
    fileInfo.seq = TEST_SEQ126;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileInfo.preStartSeq = TEST_SEQ128;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameType = TRANS_SESSION_FILE_LAST_FRAME;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileInfo.startSeq = TEST_SEQ8;
    frame.seq = TEST_SEQ_SECOND;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    dataLen = TEST_SEQ16;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(emptyBuff);
}

/**
 * @tc.name: ClinetTransProxyProcessOneFrameTest001
 * @tc.desc: client trans proxy process one frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyProcessOneFrameTest001, TestSize.Level0)
{
    FileFrame frame = {
        .frameType = TRANS_SESSION_FILE_FIRST_FRAME,
        .seq = TEST_SEQ32,
    };
    uint32_t dataLen = TEST_SEQ16;
    int32_t crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int32_t osType = TEST_OS_TYPE;
    SingleFileInfo fileInfo = {
        .seq = 0,
        .fileFd = g_fd,
        .fileStatus = NODE_ERR,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = 0,
        .preStartSeq = 0,
    };
    int32_t ret = ProcessOneFrame(&frame, dataLen, crc, &fileInfo, osType);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileInfo.fileStatus = NODE_IDLE;
    ret = ProcessOneFrame(&frame, dataLen, crc, &fileInfo, osType);
    EXPECT_NE(SOFTBUS_OK, ret);

    crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = ProcessOneFrame(&frame, dataLen, crc, &fileInfo, osType);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyCrcCheckTest001
 * @tc.desc: client trans proxy process crc check test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyCrcCheckTest001, TestSize.Level0)
{
    FileFrame frame = {
        .seq = TEST_SEQ32,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    int32_t sessionId = -1;

    int32_t ret = ProcessCrcCheckSumData(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyFileAckRequestTest001
 * @tc.desc: client trans proxy file ack request test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileAckRequestTest001, TestSize.Level0)
{
    FileFrame frame = {
        .frameLength = TEST_HEADER_LENGTH,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = nullptr,
    };
    int32_t sessionId = -1;

    int32_t ret = ProcessFileAckRequest(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileAckRequest(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    uint32_t dataTest = 0;
    dataTest = FILE_MAGIC_NUMBER;
    frame.data = (uint8_t *)&dataTest;
    ret = ProcessFileAckRequest(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileAckRequest(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyFileAckResponseTest001
 * @tc.desc: client trans proxy file ack response test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileAckResponseTest001, TestSize.Level0)
{
    FileFrame frame = {
        .frameLength = 0,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = nullptr,
    };
    int32_t sessionId = -1;

    int32_t ret = ProcessFileAckResponse(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    uint32_t dataTest[TEST_FRAME_DATA_LENGTH] = {0};
    dataTest[TEST_FILE_MAGIC_OFFSET] = FILE_MAGIC_NUMBER;
    frame.data = (uint8_t *)dataTest;
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    SendListenerInfo info;
    info.sessionId = 1;
    info.crc = 1;
    info.channelId = 1;
    ret = AddSendListenerInfo(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    frame.frameLength = TEST_HEADER_LENGTH;
    *(uint64_t *)(frame.data + FRAME_MAGIC_OFFSET) = FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyCheckParameterTest001
 * @tc.desc: client trans proxy check parameter test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyCheckParameterTest001, TestSize.Level0)
{
    bool result = IsValidFileString(nullptr, TEST_FILE_CNT, TEST_FILE_LENGTH);
    EXPECT_EQ(false, result);

    uint32_t fileNum = 0;
    result = IsValidFileString(g_testProxyFileList, fileNum, TEST_FILE_LENGTH);
    EXPECT_EQ(false, result);

    int32_t sessionId = 1;
    int32_t ret = ProcessFileTransResult(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyProcessFileListDataTest001
 * @tc.desc: client trans proxy process file list data test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyProcessFileListDataTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    FileFrame frame = {
        .frameLength = TEST_FILE_SIZE,
        .data = (uint8_t *)"00010010datatest,"
    };
    int32_t ret = ProcessFileListData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyGetFileInfoTest001
 * @tc.desc: client trans proxy get file info test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetFileInfoTest001, TestSize.Level0)
{
    FileFrame frame = {
        .frameLength = 0,
        .data = (uint8_t *)"00010010datatest.txt",
    };
    FileRecipientInfo info = {
        .fileListener.rootDir = "../test",
    };
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    SingleFileInfo file;
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = GetFileInfoByStartFrame(nullptr, nullptr, nullptr, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = memcpy_s(info.fileListener.rootDir, TEST_FILEPATH_LENGTH, g_rootDir + 1, TEST_FILEPATH_LENGTH);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameLength = FRAME_DATA_SEQ_OFFSET + 9;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyWriteFrameTest001
 * @tc.desc: client trans proxy write frame to file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyWriteFrameTest001, TestSize.Level0)
{
    int32_t sessionId = 1;
    FileFrame frame = {
        .frameLength = 0,
        .data = (uint8_t *)"00010010datatest.txt",
    };
    int32_t ret = WriteFrameToFile(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameLength = TEST_DATA_LENGTH;
    ret = WriteFrameToFile(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyChannelSendFileStreamTest001
 * @tc.desc: client trans proxy write frame to file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyChannelSendFileStreamTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    const char *data = "test_data";
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t type = 1;

    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, type);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/**
 * @tc.name: ClinetTransProxySendFileTransResult001
 * @tc.desc: client trans proxy write frame to file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxySendFileTransResultTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    
    int32_t ret = SendFileTransResult(channelId, seq, result, side);
    EXPECT_NE(SOFTBUS_MALLOC_ERR, ret);
}

/**
 * @tc.name: ClinetUnpackFileTransResultFrame001
 * @tc.desc: client trans proxy write frame to file test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyUnpackFileTransResultFrame001, TestSize.Level0)
{
    uint32_t seq = TEST_SEQ;
    int32_t result = 0;
    uint32_t side = 0;
    uint32_t data = 0;
    const uint8_t *data1 = (const uint8_t *)&data;
    uint32_t len = TEST_HEADER_LENGTH;

    int32_t ret = UnpackFileTransResultFrame(data1, len, nullptr, &result, &side);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = UnpackFileTransResultFrame(data1, len, &seq, nullptr, &side);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = UnpackFileTransResultFrame(data1, len, &seq, &result, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = UnpackFileTransResultFrame(nullptr, len, &seq, &result, &side);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    
    ret = UnpackFileTransResultFrame(data1, len, &seq, &result, &side);
    EXPECT_NE(SOFTBUS_OK, ret);
    
    len = 0;
    ret = UnpackFileTransResultFrame(data1, len, &seq, &result, &side);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: ClinetTransProxyFileAckReqAndResDataTest002
 * @tc.desc: client trans proxy file ack req and res data test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyFileAckReqAndResDataTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    uint32_t startSeq = TEST_SEQ;
    uint32_t value = 0;
    int32_t ret = SendFileAckReqAndResData(channelId, startSeq, value, CHANNEL_TYPE_PROXY);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    FileFrame frame;
    frame.frameLength = 0;
    frame.data = nullptr;
    uint64_t dataTest = 0;
    ret = UnpackAckReqAndResData(nullptr, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackAckReqAndResData(&frame, nullptr, &value);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    frame.data = (uint8_t *)&dataTest;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    frame.frameLength = TEST_HEADER_LENGTH;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    dataTest = TEST_HEADER_LENGTH;
    frame.data = (uint8_t *)&dataTest;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    dataTest = FILE_MAGIC_NUMBER;
    frame.data = (uint8_t *)&dataTest;
    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = UnpackAckReqAndResData(&frame, &startSeq, &value);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClinetTransProxyPackFileDataTest002
 * @tc.desc: client trans proxy pack file data test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyPackFileDataTest002, TestSize.Level0)
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
    uint32_t seq = TEST_SEQ;
    int64_t len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);

    len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_INVALID_LEN, len);

    uint32_t dataTest = TEST_DATA_LENGTH;
    fileFrame.data = (uint8_t *)&dataTest;
    fileFrame.fileData = (uint8_t *)&dataTest;
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    len = PackReadFileData(&fileFrame, readLength, fileOffset, &info);
    EXPECT_EQ(TEST_FILE_LENGTH, len);

    len = PackReadFileRetransData(&fileFrame, seq, readLength, fileOffset, &info);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, len);
}

/**
 * @tc.name: ClinetTransProxyRetransFileFrameTest002
 * @tc.desc: client trans proxy retrans file frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyRetransFileFrameTest002, TestSize.Level0)
{
    SendListenerInfo info = {
        .fileSize = TEST_FILE_SIZE,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    int32_t seq = 0;

    int32_t ret = RetransFileFrameBySeq(nullptr, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
 
    ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    seq = TEST_SEQ_SECOND;

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_NE(SOFTBUS_MALLOC_ERR, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = RetransFileFrameBySeq(&info, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    info.fileSize = 0;
    ret = RetransFileFrameBySeq(&info, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClinetTransProxyCalcAllFilesInfoTest001
 * @tc.desc: client trans proxy calc all files info test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyGetFileSizeTest001, TestSize.Level0)
{
    const char *fileList[] = {
        "test0",
        "test1",
        "test2",
        "test3",
        "test4"
    };
    FilesInfo totalInfo = {
        .files = fileList,
        .fileCnt = TEST_FILE_CNT,
        .bytesProcessed = 0,
    };
    uint32_t fileCnt = TEST_FILE_CNT;

    SendListenerInfo info = {
        .fileSize = TEST_FILE_SIZE,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    ClearSendInfo(&info);

    int32_t ret = CalcAllFilesInfo(&totalInfo, fileList, fileCnt);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: ClinetTransProxyUpdateFileReceivePathTest001
 * @tc.desc: client trans proxy update file receive path test, use normal and error parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyUpdateFileReceivePathTest001, TestSize.Level0)
{
    int32_t sessionId = TEST_SESSION_ID;
    FileListener *fileListener = (FileListener *)SoftBusCalloc(sizeof(FileListener));

    fileListener->socketRecvCallback = NULL;
    int32_t ret = UpdateFileReceivePath(sessionId, fileListener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = UpdateFileReceivePath(sessionId, fileListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(fileListener);

    GetRecipientInfo(sessionId);
}

/**
 * @tc.name: ClinetTransProxyCreateFileFromFrameTest001
 * @tc.desc: client trans proxy create file from frame test, use normal and error parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyCreateFileFromFrameTest001, TestSize.Level0)
{
    int32_t sessionId = TEST_SESSION_ID;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t osType = TEST_OS_TYPE;
    uint8_t data = 0;
    uint32_t packetSize = TEST_PACKET_SIZE;
    FileFrame fileFrame = {
        .frameType = TRANS_SESSION_BYTES,
        .data = &data,
        .fileData = &data,
    };

    int32_t ret = CreateFileFromFrame(sessionId, channelId, &fileFrame, osType, packetSize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    const char *dataFile = "TEST_FILE_DATA";
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t type = 0;
    ProcessFileFrameData(sessionId, channelId, dataFile, len, type);
}

/**
 * @tc.name: ClinetTransProxyChannelSendFileTest001
 * @tc.desc: client trans proxy channel send file test, use normal and error parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ClinetTransProxyChannelSendFileTest001, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNEL_ID;
    const char *sFileList[] = {
        "test0",
        "test1",
        "test2",
        "test3",
        "test4"
    };
    const char *dFileList[] = {
        "test0",
        "test1",
        "test2",
        "test3",
        "test4"
    };
    uint32_t fileCnt = TEST_FILE_CNT;

    GenerateRemoteFiles(sFileList, fileCnt);

    int32_t ret = TransProxyChannelSendFile(channelId, nullptr, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    fileCnt = 0;
    ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fileCnt = 12; // 为满足if条件语句大于10，所以赋值12
    ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: CheckFrameLengthTest
 * @tc.desc: client trans proxy channel send file test, use normal and error parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CheckFrameLengthTest, TestSize.Level0)
{
    int32_t osType = TEST_OS_TYPE;
    uint32_t packetSize;
    int32_t ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ChannelInfo *channel1 = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel1 != nullptr);
    channel1->channelId = 1;
    channel1->isEncrypt = 0;
    channel1->linkType = LANE_BR;
    channel1->sessionKey = (char *)g_sessionKey;
    ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel1));
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE + 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE - 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ChannelInfo *channel2 = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel2 != nullptr);
    channel2->channelId = 2;
    channel2->isEncrypt = 0;
    channel2->linkType = LANE_BLE_DIRECT;
    channel2->sessionKey = (char *)g_sessionKey;
    ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel2));
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CheckFrameLength(2, PROXY_BLE_MAX_PACKET_SIZE + 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = CheckFrameLength(2, PROXY_BLE_MAX_PACKET_SIZE - 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyDelChannelInfo(2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel1);
    SoftBusFree(channel2);
}
} // namespace OHOS