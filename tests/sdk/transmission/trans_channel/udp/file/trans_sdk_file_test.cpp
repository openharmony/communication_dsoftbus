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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "client_trans_file.c"
#include "client_trans_file_listener.c"
#include "client_trans_session_callback.h"
#include "client_trans_stream.h"
#include "client_trans_udp_manager.c"
#include "client_trans_udp_manager.h"
#include "file_adapter.c"
#include "nstackx_dfile.h"
#include "session.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;

#define TEST_SESSIONID 10
#define TEST_CHANNELID 1025

namespace OHOS {

const uint32_t g_keyLen = 10;
char g_mySessionName[] = {"my sessionName"};
char g_peerSessionName[] = {"peer sessionName"};
char g_peerDeviceId[] = {"127.0.0.4"};
char g_groupId[] = {"12345"};
char g_peerIp[] = {"11111"};
char g_sessionKey[] = {"123548246"};
char g_myIp[] = {"coms.132465"};

UdpChannel *TransAddChannelTest()
{
    UdpChannel *channel = (UdpChannel *)SoftBusCalloc(sizeof(UdpChannel));
    if (channel == NULL) {
        return nullptr;
    }
    channel->channelId = 1;
    channel->dfileId = -1;
    channel->channelId = 1;
    channel->businessType = 1;
    channel->isEnable = true;
    channel->routeType = 1;
    channel->info.isServer = 0;
    channel->info.peerUid = 0;
    channel->info.peerPid = 0;
    (void)strcpy_s(channel->info.mySessionName, strlen("my sessionName")+1, "my sessionName");
    (void)strcpy_s(channel->info.peerSessionName, strlen("peer sessionName")+1, "peer sessionName");
    (void)strcpy_s(channel->info.peerDeviceId, strlen("127.0.0.4")+1, "127.0.0.4");
    (void)strcpy_s(channel->info.groupId, strlen("12345")+1, "12345");
    return channel;
}
ChannelInfo *TransAddChannleInfoTest()
{
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    if (channelInfo == NULL) {
        return nullptr;
    }
    channelInfo->channelId = 1;
    channelInfo->channelType = 1;
    channelInfo->businessType = 1;
    channelInfo->fd = 1;
    channelInfo->isServer = true;
    channelInfo->isEnabled = true;
    channelInfo->peerUid = 1;
    channelInfo->peerPid = 1;
    channelInfo->groupId = g_groupId;
    channelInfo->keyLen = g_keyLen;
    channelInfo->sessionKey = g_sessionKey;
    channelInfo->peerSessionName = g_peerSessionName;
    channelInfo->peerDeviceId = g_peerDeviceId;
    channelInfo->myIp = g_myIp;
    channelInfo->peerIp = g_peerIp;

    channelInfo->peerPort = 1;
    channelInfo->routeType = 1;
    channelInfo->streamType = 1;
    channelInfo->encrypt = 1;
    channelInfo->algorithm = 1;
    channelInfo->crc = 1;
    channelInfo->isUdpFile = false;
    return channelInfo;
}

class TransSdkFileTest : public testing::Test {
public:
    TransSdkFileTest()
    {}
    ~TransSdkFileTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransSdkFileTest::SetUpTestCase(void)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void TransSdkFileTest::TearDownTestCase(void)
{
    ClientTransUdpMgrDeinit();
    TransFileDeinit();
}

void OnFileTransErrorTest(int32_t sessionId)
{
    std::cout << "OnFileTransError sessionId = %d\n" << sessionId << std::endl;
}

int32_t OnReceiveFileStartedTest(int32_t sessionId, const char *files, int32_t fileCnt)
{
    std::cout << "File receive start sessionId = %d" << sessionId << std::endl;
    return 0;
}

void OnReceiveFileFinishedTest(int32_t sessionId, const char *files, int32_t fileCnt)
{
    std::cout << "File receive finished sessionId = %d\n" << sessionId << std::endl;
}

int32_t OnReceiveFileProcessTest(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "File receive process sessionId = %d\n" << sessionId << std::endl;
    return 0;
}

int32_t OnSendFileProcessTest(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "send process id = " << sessionId << " upload = "
        << bytesUpload << ", total = " << bytesTotal << std::endl;
    return 0;
}

int32_t OnSendFileFinishedTest(int32_t sessionId, const char *firstFile)
{
    std::cout << "send finished id = %d," << sessionId << "first file = %s." << firstFile << std::endl;
    return 0;
}

void DFileMsgReceiverTest(int32_t sessionId, DFileMsgType msgType, const DFileMsg *msg)
{
    std::cout << "file receiver id = %d" << sessionId << std::endl;
    return;
}


static IFileSendListener g_fileSendListener = {
    .OnSendFileProcess = OnSendFileProcessTest,
    .OnSendFileFinished = OnSendFileFinishedTest,
    .OnFileTransError = OnFileTransErrorTest,
};

static IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStartedTest,
    .OnReceiveFileProcess = OnReceiveFileProcessTest,
    .OnReceiveFileFinished = OnReceiveFileFinishedTest,
    .OnFileTransError = OnFileTransErrorTest,
};

static DFileMsgReceiver g_fileMsgRecviver = DFileMsgReceiverTest;

void GenerateAndAddUdpChannel(UdpChannel *channel)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channel->channelId = 1;
    channel->dfileId = 1;
    channel->businessType = BUSINESS_TYPE_STREAM;
    memcpy_s(channel->info.mySessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", strlen("normal sessionName"));
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

static void SocketFileCallbackFuncTest(int32_t socket, FileEvent *event)
{
    (void)socket;
    (void)event;
}

/**
 * @tc.name: TransFileListenerTest001
 * @tc.desc: trans file listener init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileListenerTest001, TestSize.Level0)
{
    TransFileDeinit();

    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransFileDeinit();
    TransFileDeinit();
}

/**
 * @tc.name: TransFileListenerTest002
 * @tc.desc: trans set file receive listener by sessionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileListenerTest002, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
    
    TransFileDeinit();
}

/**
 * @tc.name: TransFileListenerTest003
 * @tc.desc: trans delete file listener by sessionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileListenerTest003, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    const char* inValidName = "invald file receive";
    TransDeleteFileListener(NULL);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDeleteFileListener(inValidName);
    
    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/**
 * @tc.name: TransFileListenerTest004
 * @tc.desc: trans set file send listener by sessionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileListenerTest004, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* sessionName = "file send";
    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
}

/**
 * @tc.name: TransFileListenerTest005
 * @tc.desc: trans get file listener by sessionName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileListenerTest005, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    const char* inValidName = "invald file receive";
    FileListener* fileListener = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    if (fileListener == NULL) {
        return;
    }
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetFileListener(inValidName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
    SoftBusFree(fileListener);
}

/**
 * @tc.name: TransFileTest001
 * @tc.desc: trans register file callback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest001, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    UdpChannelMgrCb *fileCb = NULL;
    RegisterFileCb(NULL);
    RegisterFileCb(fileCb);

    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest002
 * @tc.desc: trans open file channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest002, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* sessionName = "file send";
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    if (channelInfo == NULL) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    int32_t filePort = 22;

    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    channelInfo->isServer = false;
    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest003
 * @tc.desc: trans open file channel use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest003, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    (void)TransFileInit();
    IFileSendListener *sendListener = (IFileSendListener *)SoftBusCalloc(sizeof(IFileSendListener));
    if (sendListener == NULL) {
        return;
    }
    int32_t filePort = 22;
    ChannelInfo *channelInfo = TransAddChannleInfoTest();
    UdpChannel *channel = TransAddChannelTest();
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, msgData);
    int32_t ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest004
 * @tc.desc: trans file send listener use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest004, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsgType msgType = DFILE_ON_CONNECT_SUCCESS;
    DFileMsg msgData = {};
    UdpChannel *channel = (UdpChannel*)SoftBusCalloc(sizeof(UdpChannel));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgData.rate = 1;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_SESSION_IN_PROGRESS;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_SESSION_TRANSFER_RATE;
    FileSendListener(channel->dfileId, msgType, &msgData);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FILE_SEND_FAIL;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_SESSION_TRANSFER_RATE;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_CONNECT_FAIL;
    FileSendListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FATAL_ERROR;
    FileSendListener(channel->dfileId, msgType, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest005
 * @tc.desc: trans file recv listener use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest005, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsgType msgType = DFILE_ON_CONNECT_SUCCESS;
    DFileMsg msgData = {};
    UdpChannel *channel = (UdpChannel*)SoftBusCalloc(sizeof(UdpChannel));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgData.rate = 1;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    string rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);

    msgType = DFILE_ON_FILE_LIST_RECEIVED;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FILE_RECEIVE_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FILE_RECEIVE_FAIL;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_CONNECT_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_CONNECT_FAIL;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    msgType = DFILE_ON_FATAL_ERROR;
    FileReceiveListener(channel->dfileId, msgType, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest006
 * @tc.desc: trans file channel open use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest006, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* sessionName = "file send";
    IFileSendListener *sendListener;
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    if (channelInfo == NULL) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    int32_t filePort = 22;

    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    channelInfo->isServer = false;
    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest007
 * @tc.desc: trans file channel use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest007, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    (void)TransFileInit();
    IFileSendListener *sendListener = (IFileSendListener *)SoftBusCalloc(sizeof(IFileSendListener));
    if (sendListener == NULL) {
        return;
    };
    int32_t filePort = 22;
    ChannelInfo *channelInfo = TransAddChannleInfoTest();
    UdpChannel *channel = TransAddChannelTest();
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, msgData);

    int32_t ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    
    TransCloseFileChannel(channel->dfileId);
    
    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest008
 * @tc.desc: trans file send use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest008, TestSize.Level0)
{
    int32_t sessionId = 0;
    const char *sFileList = nullptr;
    const char *dFileList = nullptr;
    const char *fileList = "/file not null list/";
    uint32_t fileCnt = 0;
    int32_t ret = TransSendFile(sessionId, &sFileList, &dFileList, fileCnt);
    EXPECT_TRUE(ret);

    ret = TransSendFile(sessionId, &fileList, &dFileList, fileCnt);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TransFileTest009
 * @tc.desc: trans set reuse addr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest009, TestSize.Level0)
{
    int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
    int32_t on = 65536;
    int32_t ret = SetReuseAddr(fd, on);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SetReuseAddr(-1, -1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
    
    ret = SetReuseAddr(0, on);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
    ret = close(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransFileTest010
 * @tc.desc: trans set reuse port.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest010, TestSize.Level0)
{
    int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
    int32_t on = 65536;
    int32_t ret = SetReusePort(fd, on);
    EXPECT_EQ(ret, SOFTBUS_OK);
    
    ret = SetReusePort(0, on);
    EXPECT_EQ(ret, SOFTBUS_INVALID_FD);
    ret = close(fd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransFileTest011
 * @tc.desc: trans open tcp server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest011, TestSize.Level0)
{
    int32_t port = 5683;
    int32_t ret = CreateServerSocketByIpv4("127.0.0.1", port);
    EXPECT_TRUE(ret);

    ret = CreateServerSocketByIpv4("280567565", port);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);

    ret = CreateServerSocketByIpv4("127.0.0.1", 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TransFileTest012
 * @tc.desc: trans start nstackx file at server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest012, TestSize.Level0)
{
    uint8_t key = 215;
    uint32_t keyLen = 8;
    int32_t filePort = 25;
    int32_t ret = StartNStackXDFileServer(NULL, &key, keyLen, g_fileMsgRecviver, &filePort);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = StartNStackXDFileServer("127.0.0.1", &key, keyLen, g_fileMsgRecviver, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    (void)StartNStackXDFileServer("127.0.0.1", &key, keyLen, g_fileMsgRecviver, &filePort);
    ConnDeinitSockets();
}

/**
 * @tc.name: TransFileTest013
 * @tc.desc: trans start nstackx file at client.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest013, TestSize.Level0)
{
    uint8_t key = 215;
    uint32_t keyLen = 8;
    int32_t peerPort = 25;
    int32_t ret = StartNStackXDFileClient(NULL, peerPort, &key, keyLen, g_fileMsgRecviver);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    (void)StartNStackXDFileClient("127.0.0.1", peerPort, &key, keyLen, g_fileMsgRecviver);
}

/**
 * @tc.name: TransFileTest014
 * @tc.desc: trans register file callback of socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest014, TestSize.Level0)
{
    int32_t ret = TransSetSocketFileListener(nullptr, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSetSocketFileListener(g_mySessionName, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSetSocketFileListener(nullptr, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSetSocketFileListener(g_mySessionName, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
}

/**
 * @tc.name: TransFileTest015
 * @tc.desc: trans add new file callback of socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest015, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAddNewSocketFileListener(nullptr, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAddNewSocketFileListener(g_mySessionName, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAddNewSocketFileListener(nullptr, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAddNewSocketFileListener(g_mySessionName, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
}

/**
 * @tc.name: TransFileTest016
 * @tc.desc: trans open tcp server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest016, TestSize.Level0)
{
    int32_t port = 5683;
    int32_t ret = CreateServerSocketByIpv6("3FFF:FFFF:0000:0000:0000:0000:0000:0000", port);
    EXPECT_TRUE(ret);

    ret = CreateServerSocketByIpv6("280567565", port);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);

    ret = CreateServerSocketByIpv6("3FFF:FFFF:0000:0000:0000:0000:0000:0000", 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: TransFileTest017
 * @tc.desc: trans open tcp server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest017, TestSize.Level0)
{
    int32_t port = 5683;
    int32_t fd = 1;
    int32_t ret = CreateServerSocket(nullptr, &fd, &port);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", nullptr, &port);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", &fd, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", &fd, &port);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    ret = CreateServerSocket("280567565", &fd, &port);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    ret = CreateServerSocket("127.0.0.1", &fd, &port);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/**
 * @tc.name: TransFileTest018
 * @tc.desc: trans open tcp server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest018, TestSize.Level0)
{
    struct sockaddr_in localAddr = { 0 };
    int32_t port = 5683;
    int32_t ret = InitSockAddrInByIpPort(nullptr, port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrInByIpPort("127.0.0.1", -1, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrInByIpPort("127.0.0.1", port, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrInByIpPort("280567565", port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitSockAddrInByIpPort("127.0.0.1", port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransFileTest019
 * @tc.desc: trans open tcp server.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest019, TestSize.Level0)
{
    struct sockaddr_in6 localAddr = { 0 };
    int32_t port = 5683;
    int32_t ret = InitSockAddrIn6ByIpPort(nullptr, port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrIn6ByIpPort("3FFF:FFFF:0000:0000:0000:0000:0000:0000", -1, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrIn6ByIpPort("3FFF:FFFF:0000:0000:0000:0000:0000:0000", port, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = InitSockAddrIn6ByIpPort("280567565", port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
    ret = InitSockAddrIn6ByIpPort("3FFF:FFFF:0000:0000:0000:0000:0000:0000", port, &localAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: FreeFileStatusListTest001
 * @tc.desc: test free file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FreeFileStatusListTest001, TestSize.Level0)
{
    FileEvent event;
    event.statusList.completedList.fileCnt = 1;
    event.statusList.notCompletedList.fileCnt = 1;
    event.statusList.notStartedList.fileCnt = 1;
    event.statusList.completedList.files =
        (char **)SoftBusCalloc(event.statusList.completedList.fileCnt * sizeof(char *));
    event.statusList.notCompletedList.files =
        (char **)SoftBusCalloc(event.statusList.notCompletedList.fileCnt * sizeof(char *));
    event.statusList.notStartedList.files =
        (char **)SoftBusCalloc(event.statusList.notStartedList.fileCnt * sizeof(char *));

    FreeFileStatusList(&event);

    ASSERT_EQ(event.statusList.completedList.files, nullptr);
    ASSERT_EQ(event.statusList.notCompletedList.files, nullptr);
    ASSERT_EQ(event.statusList.notStartedList.files, nullptr);
    SoftBusFree(event.statusList.completedList.files);
    SoftBusFree(event.statusList.notCompletedList.files);
    SoftBusFree(event.statusList.notStartedList.files);

    FileEvent *event2 = nullptr;
    FreeFileStatusList(event2);
}

/**
 * @tc.name: FreeFileStatusListTest002
 * @tc.desc: test free file status list with null files
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FreeFileStatusListTest002, TestSize.Level0)
{
    FileEvent event;
    event.statusList.completedList.files = nullptr;
    event.statusList.notCompletedList.files = nullptr;
    event.statusList.notStartedList.files = nullptr;

    FreeFileStatusList(&event);
    ASSERT_EQ(event.statusList.completedList.files, nullptr);
    ASSERT_EQ(event.statusList.notCompletedList.files, nullptr);
    ASSERT_EQ(event.statusList.notStartedList.files, nullptr);
}

/**
 * @tc.name: FillFileStatusListTest001
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest001, TestSize.Level0)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 3;
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = (char *)"file1";
    fileInfo[1].stat = FILE_STAT_NOT_COMPLETE;
    fileInfo[1].file = (char *)"file2";
    fileInfo[2].stat = FILE_STAT_NOT_START;
    fileInfo[2].file = (char *)"file3";
    msgData.clearPolicyFileList.fileInfo = fileInfo;

    FillFileStatusList(&msgData, &event);

    // Check status list content
    ASSERT_EQ(1, event.statusList.completedList.fileCnt);
    ASSERT_STREQ("file1", event.statusList.completedList.files[0]);
    ASSERT_EQ(1, event.statusList.notCompletedList.fileCnt);
    ASSERT_STREQ("file2", event.statusList.notCompletedList.files[0]);
    ASSERT_EQ(1, event.statusList.notStartedList.fileCnt);
    ASSERT_STREQ("file3", event.statusList.notStartedList.files[0]);
    SoftBusFree(fileInfo);
}

/**
 * @tc.name: FillFileStatusListTest002
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest002, TestSize.Level0)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 0;

    FillFileStatusList(&msgData, &event);

    // Check status list content
    ASSERT_EQ(nullptr, event.statusList.completedList.files);
    ASSERT_EQ(0, event.statusList.completedList.fileCnt);
    ASSERT_EQ(nullptr, event.statusList.notCompletedList.files);
    ASSERT_EQ(0, event.statusList.notCompletedList.fileCnt);
    ASSERT_EQ(nullptr, event.statusList.notStartedList.files);
    ASSERT_EQ(0, event.statusList.notStartedList.fileCnt);
}

/**
 * @tc.name: FillFileStatusListTest003
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest003, TestSize.Level0)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 3;
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    EXPECT_NE(nullptr, fileInfo);
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = (char *)"file1";
    fileInfo[1].stat = FILE_STAT_COMPLETE;
    fileInfo[1].file = (char *)"file2";
    fileInfo[2].stat = FILE_STAT_COMPLETE;
    fileInfo[2].file = (char *)"file3";
    msgData.clearPolicyFileList.fileInfo = fileInfo;

    FillFileStatusList(&msgData, &event);

    // Check status list content
    ASSERT_EQ(3, event.statusList.completedList.fileCnt);
    ASSERT_STREQ("file1", event.statusList.completedList.files[0]);
    ASSERT_STREQ("file2", event.statusList.completedList.files[1]);
    ASSERT_STREQ("file3", event.statusList.completedList.files[2]);
    ASSERT_EQ(0, event.statusList.notCompletedList.fileCnt);
    ASSERT_EQ(0, event.statusList.notStartedList.fileCnt);
    SoftBusFree(fileInfo);
}

void MockSocketSendCallback(int32_t socket, FileEvent *event)
{
    (void)socket;
    (void)event;
}

void MockSocketRecvCallback(int32_t socket, FileEvent *event)
{
    (void)socket;
    (void)event;
}

void InitDFileMsg(DFileMsg *msgData)
{
    msgData->fileList.files = nullptr;
    msgData->fileList.fileNum = 0;
    msgData->clearPolicyFileList.fileNum = 0;
    msgData->clearPolicyFileList.fileInfo = nullptr;
    msgData->errorCode = 0;
    msgData->transferUpdate.bytesTransferred = 0;
    msgData->transferUpdate.totalBytes = 0;
    msgData->transferUpdate.transId = 0;
    msgData->rate = 0;
}

/**
 * @tc.name: FillFileStatusListTest004
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest004, TestSize.Level0)
{
    DFileMsg msgData;
    msgData.clearPolicyFileList.fileNum = 3; // test value
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    EXPECT_NE(nullptr, fileInfo);
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = (char *)"file1";
    fileInfo[1].stat = FILE_STAT_COMPLETE;
    fileInfo[1].file = (char *)"file2";
    fileInfo[2].stat = FILE_STAT_COMPLETE;
    fileInfo[2].file = (char *)"file3";
    msgData.clearPolicyFileList.fileInfo = fileInfo;
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileListener* listener = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    EXPECT_NE(nullptr, listener);
    UdpChannel *channel = TransAddChannelTest();
    FileSendErrorEvent(channel, listener, &msgData, msgType, sessionId);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    listener->socketSendCallback = nullptr;
    FileSendErrorEvent(channel, listener, &msgData, msgType, sessionId);

    NotifySendResult(sessionId, msgType, nullptr, nullptr);

    msgType = DFILE_ON_FILE_SEND_SUCCESS;
    NotifySendResult(sessionId, msgType, &msgData, listener);

    msgType = DFILE_ON_FILE_SEND_FAIL;
    NotifySendResult(sessionId, msgType, &msgData, listener);

    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    NotifySendResult(sessionId, msgType, &msgData, listener);

    msgType = DFILE_ON_BIND;
    NotifySendResult(sessionId, msgType, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/**
 * @tc.name: FillFileStatusListTest005
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest005, TestSize.Level0)
{
    DFileMsg msgData;
    msgData.clearPolicyFileList.fileNum = 3; // test value
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    EXPECT_NE(nullptr, fileInfo);
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = (char *)"file1";
    fileInfo[1].stat = FILE_STAT_COMPLETE;
    fileInfo[1].file = (char *)"file2";
    fileInfo[2].stat = FILE_STAT_COMPLETE;
    fileInfo[2].file = (char *)"file3";
    msgData.clearPolicyFileList.fileInfo = fileInfo;
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileListener* listener = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    EXPECT_NE(nullptr, listener);
    UdpChannel *channel = TransAddChannelTest();
    FileSendErrorEvent(channel, listener, &msgData, msgType, sessionId);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;

    NotifyRecvResult(sessionId, msgType, nullptr, nullptr);

    msgType = DFILE_ON_FILE_LIST_RECEIVED;
    NotifyRecvResult(sessionId, msgType, &msgData, listener);
    msgType = DFILE_ON_FILE_RECEIVE_SUCCESS;
    NotifyRecvResult(sessionId, msgType, &msgData, listener);
    msgType = DFILE_ON_FILE_RECEIVE_FAIL;
    NotifySendResult(sessionId, msgType, &msgData, listener);
    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    NotifySendResult(sessionId, msgType, &msgData, listener);
    msgType = DFILE_ON_BIND;
    NotifySendResult(sessionId, msgType, &msgData, listener);

    FileRecvErrorEvent(channel, listener, &msgData, msgType, sessionId);
    listener->socketSendCallback = nullptr;
    FileRecvErrorEvent(channel, listener, &msgData, msgType, sessionId);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/**
 * @tc.name: FillFileStatusListTest006
 * @tc.desc: test fill file status list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest006, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNELID;
    uint8_t tos = 1;
    RenameHook(nullptr);
    int32_t ret = NotifyTransLimitChanged(channelId, tos);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: NotifySocketSendResultTest001
 * @tc.desc: test notify socket send result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySocketSendResultTest001, TestSize.Level0)
{
    int32_t socket = 1;
    DFileMsg msgData;
    InitDFileMsg(&msgData);
    FileListener listener;
    listener.socketSendCallback = MockSocketSendCallback;
    listener.socketRecvCallback = MockSocketRecvCallback;

    NotifySocketSendResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, &listener);
    NotifySocketSendResult(socket, DFILE_ON_FILE_SEND_SUCCESS, &msgData, &listener);
    NotifySocketSendResult(socket, DFILE_ON_FILE_SEND_FAIL, &msgData, &listener);
    NotifySocketSendResult(socket, DFILE_ON_CLEAR_POLICY_FILE_LIST, &msgData, &listener);
    NotifySocketSendResult(socket, DFILE_ON_CONNECT_FAIL, &msgData, &listener);

    NotifySocketRecvResult(socket, DFILE_ON_FILE_LIST_RECEIVED, &msgData, &listener);
    NotifySocketRecvResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, &listener);
    NotifySocketRecvResult(socket, DFILE_ON_FILE_RECEIVE_SUCCESS, &msgData, &listener);
    NotifySocketRecvResult(socket, DFILE_ON_FILE_RECEIVE_FAIL, &msgData, &listener);
    NotifySocketRecvResult(socket, DFILE_ON_CLEAR_POLICY_FILE_LIST, &msgData, &listener);
    NotifySocketRecvResult(socket, DFILE_ON_CONNECT_FAIL, &msgData, &listener);
}

/**
 * @tc.name: FillFileEventErrorCodeTest
 * @tc.desc: test fill file event error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest, TestSize.Level0)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_EOK;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_OK, event.errorCode);

    msgData.errorCode = NSTACKX_EPERM;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_PERMISSION_DENIED, event.errorCode);

    msgData.errorCode = NSTACKX_EDQUOT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_DISK_QUOTA_EXCEEDED, event.errorCode);

    msgData.errorCode = NSTACKX_ENOMEM;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NO_MEMORY, event.errorCode);

    msgData.errorCode = NSTACKX_ENETDOWN;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NETWORK_ERROR, event.errorCode);

    msgData.errorCode = NSTACKX_ENOENT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NOT_FOUND, event.errorCode);

    msgData.errorCode = NSTACKX_EEXIST;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_EXISTED, event.errorCode);

    msgData.errorCode = NSTACKX_NOTSUPPORT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(NSTACKX_NOTSUPPORT, event.errorCode);
}
}