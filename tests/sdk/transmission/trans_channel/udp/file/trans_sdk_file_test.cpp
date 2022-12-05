/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "client_trans_udp_manager.h"
#include "client_trans_udp_manager.c"
#include "file_adapter.c"
#include "session.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;

namespace OHOS {

const uint32_t g_keyLen = 10;
char g_mySessionName[] = {"my sessionName"};
char g_peerSessionName[] = {"peer sessionName"};
char g_peerDeviceId[] = {"127.0.0.4"};
char g_groupId[] = {"12345"};
char g_peerIp[] = {"11111"};
char g_sessionKey[] = {"123548246"};
char g_myIp[] = {"coms.132465"};

UdpChannel *TransGenerateChannelTest()
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
ChannelInfo *TransGenerateChannleInfoTest()
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
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void TransSdkFileTest::TearDownTestCase(void)
{
    ClientTransUdpMgrDeinit();
    TransFileDeinit();
}

void OnFileTransErrorTest(int sessionId)
{
    std::cout << "OnFileTransError sessionId = %d\n" << sessionId << std::endl;
}

int OnReceiveFileStartedTest(int sessionId, const char *files, int fileCnt)
{
    std::cout << "File receive start sessionId = %d" << sessionId << std::endl;
    return 0;
}

void OnReceiveFileFinishedTest(int sessionId, const char *files, int fileCnt)
{
    std::cout << "File receive finished sessionId = %d\n" << sessionId << std::endl;
}

int OnReceiveFileProcessTest(int sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "File receive process sessionId = %d\n" << sessionId << std::endl;
    return 0;
}

int OnSendFileProcessTest(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "send process id = " << sessionId << " upload = "
        << bytesUpload << ", total = " << bytesTotal << std::endl;
    return 0;
}

int OnSendFileFinishedTest(int sessionId, const char *firstFile)
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
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
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
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_TRUE(ret == SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
    
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
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    const char* inValidName = "invald file receive";
    TransDeleteFileListener(NULL);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    ASSERT_TRUE(ret == SOFTBUS_OK);
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
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* sessionName = "file send";
    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    const char* inValidName = "invald file receive";
    FileListener* fileListener = (FileListener *)SoftBusCalloc(sizeof(FileListener));
    ASSERT_TRUE(fileListener != nullptr);
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransGetFileListener(inValidName, fileListener);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    ASSERT_TRUE(ret == SOFTBUS_OK);

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
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransFileInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* sessionName = "file send";
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channelInfo != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t filePort = 22;
    ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelInfo->isServer = false;
    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    ASSERT_TRUE(sendListener != nullptr);
    int32_t filePort = 22;
    ChannelInfo *channelInfo = TransGenerateChannleInfoTest();
    ASSERT_TRUE(channelInfo != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, msgData);
    int32_t ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest004
 * @tc.desc: trans get udp channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest004, TestSize.Level0)
{
    int32_t dfileId = 0;
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    UdpChannel *newchannel = (UdpChannel *)SoftBusCalloc(sizeof(UdpChannel));
    ASSERT_TRUE(newchannel != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    int32_t ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = GetUdpChannel(channel->dfileId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = GetUdpChannel(dfileId, newchannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = GetUdpChannel(channel->dfileId, newchannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SoftBusFree(newchannel);
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest005
 * @tc.desc: trans file receive listener use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest005, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    (void)TransFileInit();
    const char* rootDir = "rootDir";
    const char* sessionName = "file receive";
    IFileReceiveListener *recvListener = (IFileReceiveListener *)SoftBusCalloc(sizeof(IFileReceiveListener));
    ASSERT_TRUE(recvListener != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    int32_t ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransSetFileReceiveListener(sessionName, recvListener, rootDir);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    
    msgType = DFILE_ON_FILE_LIST_RECEIVED;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    msgType = DFILE_ON_FILE_RECEIVE_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    msgType = DFILE_ON_FILE_RECEIVE_FAIL;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    msgType = DFILE_ON_CONNECT_FAIL;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    
    TransDeleteFileListener(sessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest006
 * @tc.desc: trans file receive listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest006, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    (void)TransFileInit();
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    const char *rootDir = "root_dir";
    const char* sessionName = "file receive";
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    int32_t ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    msgType = DFILE_ON_FILE_LIST_RECEIVED;
    FileReceiveListener(channel->dfileId, msgType, msgData);

    msgType = DFILE_ON_FILE_RECEIVE_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);

    msgType = DFILE_ON_FILE_RECEIVE_FAIL;
    FileReceiveListener(channel->dfileId, msgType, msgData);

    msgType = DFILE_ON_TRANS_IN_PROGRESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);

    msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileReceiveListener(channel->dfileId, msgType, msgData);

    msgType = DFILE_ON_CONNECT_FAIL;
    FileReceiveListener(channel->dfileId, msgType, msgData);
    TransDeleteFileListener(sessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest007
 * @tc.desc: trans file channel open use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest007, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransFileInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    const char* sessionName = "file send";
    IFileSendListener *sendListener;
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channelInfo != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    int32_t filePort = 22;

    ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, sendListener);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channelInfo->isServer = false;
    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest008
 * @tc.desc: trans file channel use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest008, TestSize.Level0)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    (void)ClientTransUdpMgrInit(cb);
    (void)TransFileInit();
    IFileSendListener *sendListener = (IFileSendListener *)SoftBusCalloc(sizeof(IFileSendListener));
    ASSERT_TRUE(sendListener != nullptr);
    int32_t filePort = 22;
    ChannelInfo *channelInfo = TransGenerateChannleInfoTest();
    ASSERT_TRUE(channelInfo != nullptr);
    UdpChannel *channel = TransGenerateChannelTest();
    ASSERT_TRUE(channel != nullptr);
    DFileMsg *msgData = {};
    DFileMsgType msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, msgData);

    int32_t ret = ClientTransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    
    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    
    TransCloseFileChannel(channel->dfileId);
    
    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/**
 * @tc.name: TransFileTest009
 * @tc.desc: trans file send use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileTest009, TestSize.Level0)
{
    int32_t sessionId = 0;
    const char *sFileList = nullptr;
    const char *dFileList = nullptr;
    const char *fileList = "/file not null list/";
    uint32_t fileCnt = 0;
    int32_t ret = TransSendFile(sessionId, &sFileList, &dFileList, fileCnt);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransSendFile(sessionId, &fileList, &dFileList, fileCnt);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}
}