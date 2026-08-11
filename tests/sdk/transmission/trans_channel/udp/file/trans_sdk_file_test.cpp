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
char g_mySessionName[] = { "my sessionName" };
char g_peerSessionName[] = { "peer sessionName" };
char g_peerDeviceId[] = { "127.0.0.4" };
char g_groupId[] = { "12345" };
char g_peerIp[] = { "11111" };
char g_sessionKey[] = { "123548246" };
char g_myIp[] = { "coms.132465" };

UdpChannel *TransAddChannelTest(void)
{
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    if (channel == nullptr) {
        return nullptr;
    }
    channel->channelId = 1;
    channel->dfileId = -1;
    channel->businessType = 1;
    channel->isEnable = true;
    channel->routeType = 1;
    channel->info.isServer = 0;
    channel->info.peerUid = 0;
    channel->info.peerPid = 0;
    (void)strcpy_s(channel->info.mySessionName, strlen("my sessionName") + 1, "my sessionName");
    (void)strcpy_s(channel->info.peerSessionName, strlen("peer sessionName") + 1, "peer sessionName");
    (void)strcpy_s(channel->info.peerDeviceId, strlen("127.0.0.4") + 1, "127.0.0.4");
    (void)strcpy_s(channel->info.groupId, strlen("12345") + 1, "12345");
    return channel;
}
ChannelInfo *TransAddChannelInfoTest(void)
{
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
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
    TransSdkFileTest(void) { }
    ~TransSdkFileTest(void) { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
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
    std::cout << "OnFileTransError, sessionId=" << sessionId << std::endl;
}

int32_t OnReceiveFileStartedTest(int32_t sessionId, const char *files, int32_t fileCnt)
{
    std::cout << "OnReceiveFileStarted, sessionId=" << sessionId << std::endl;
    return SOFTBUS_OK;
}

void OnReceiveFileFinishedTest(int32_t sessionId, const char *files, int32_t fileCnt)
{
    std::cout << "OnReceiveFileFinished, sessionId=" << sessionId << std::endl;
}

int32_t OnReceiveFileProcessTest(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "OnReceiveFileProcess, sessionId=" << sessionId << std::endl;
    return SOFTBUS_OK;
}

int32_t OnSendFileProcessTest(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    std::cout << "OnSendFileProcess, sessionId=" << sessionId << ", bytesUpload=" << bytesUpload
              << ", bytesTotal=" << bytesTotal << std::endl;
    return SOFTBUS_OK;
}

int32_t OnSendFileFinishedTest(int32_t sessionId, const char *firstFile)
{
    std::cout << "OnSendFileFinished, sessionId=" << sessionId << ", firstFile=" << firstFile << std::endl;
    return SOFTBUS_OK;
}

void DFileMsgReceiverTest(int32_t sessionId, DFileMsgType msgType, const DFileMsg *msg)
{
    std::cout << "DFileMsgReceiver, sessionId=" << sessionId << std::endl;
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

static DFileMsgReceiver g_fileMsgReceiver = DFileMsgReceiverTest;

void GenerateAndAddUdpChannel(UdpChannel *channel)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    channel->channelId = 1;
    channel->dfileId = 1;
    channel->businessType = BUSINESS_TYPE_STREAM;
    (void)memcpy_s(
        channel->info.mySessionName, SESSION_NAME_SIZE_MAX, "normal sessionName", strlen("normal sessionName"));
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

static void SocketFileCallbackFuncTest(int32_t socket, FileEvent *event)
{
    (void)socket;
    (void)event;
}

/*
 * @tc.name: TransFileInitTest001
 * @tc.desc: trans file init and deinit lifecycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransFileInitTest001, TestSize.Level0)
{
    TransFileDeinit();

    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransFileDeinit();
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileReceiveListenerTest001
 * @tc.desc: trans set file receive listener with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileReceiveListenerTest001, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileReceiveListenerTest002
 * @tc.desc: trans set file receive listener repeated returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileReceiveListenerTest002, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileReceiveListenerTest003
 * @tc.desc: trans set file receive listener after deinit returns not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileReceiveListenerTest003, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);

    TransFileDeinit();
}

/*
 * @tc.name: TransDeleteFileListenerTest001
 * @tc.desc: trans delete file listener with various conditions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransDeleteFileListenerTest001, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    const char *inValidName = "invald file receive";
    TransDeleteFileListener(nullptr);

    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDeleteFileListener(inValidName);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileSendListenerTest001
 * @tc.desc: trans set file send listener with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileSendListenerTest001, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileSendListenerTest002
 * @tc.desc: trans set file send listener repeated returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileSendListenerTest002, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
}

/*
 * @tc.name: TransSetFileSendListenerTest003
 * @tc.desc: trans set file send listener after deinit returns not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileSendListenerTest003, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
    const char *sessionName = "file send";
    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
}

/*
 * @tc.name: TransGetFileListenerTest001
 * @tc.desc: trans get file listener with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransGetFileListenerTest001, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    if (fileListener == nullptr) {
        return;
    }
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetFileListener(nullptr, fileListener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransGetFileListener(sessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
    SoftBusFree(fileListener);
}

/*
 * @tc.name: TransGetFileListenerTest002
 * @tc.desc: trans get file listener with invalid name returns node not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransGetFileListenerTest002, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    const char *inValidName = "invald file receive";
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    if (fileListener == nullptr) {
        return;
    }
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetFileListener(inValidName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_NODE_NOT_FOUND);

    TransDeleteFileListener(sessionName);
    TransFileDeinit();
    SoftBusFree(fileListener);
}

/*
 * @tc.name: TransGetFileListenerTest003
 * @tc.desc: trans get file listener with valid name returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransGetFileListenerTest003, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *rootDir = "rootDir";
    const char *sessionName = "file receive";
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    if (fileListener == nullptr) {
        return;
    }
    ret = TransSetFileReceiveListener(sessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransDeleteFileListener(sessionName);
    TransFileDeinit();
    SoftBusFree(fileListener);
}

/*
 * @tc.name: TransGetFileListenerTest004
 * @tc.desc: trans get file listener after deinit returns not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransGetFileListenerTest004, TestSize.Level0)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
    const char *sessionName = "file receive";
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    if (fileListener == nullptr) {
        return;
    }
    ret = TransGetFileListener(sessionName, fileListener);
    EXPECT_EQ(ret, SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT);
    SoftBusFree(fileListener);
}

/*
 * @tc.name: RegisterFileCbTest001
 * @tc.desc: trans register file callback with null param no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, RegisterFileCbTest001, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    UdpChannelMgrCb *fileCb = nullptr;
    RegisterFileCb(nullptr);
    RegisterFileCb(fileCb);

    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest001
 * @tc.desc: trans on file channel opened with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest001, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    SocketAccessInfo accessInfo = { 0 };
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, nullptr, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransOnFileChannelOpened(sessionName, nullptr, nullptr, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest002
 * @tc.desc: trans on file channel opened without myIp returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest002, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    int32_t filePort = 22;
    SocketAccessInfo accessInfo = { 0 };
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest003
 * @tc.desc: trans on file channel opened with myIp server mode returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest003, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    int32_t filePort = 22;
    SocketAccessInfo accessInfo = { 0 };
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest004
 * @tc.desc: trans on file channel opened with myIp client mode returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest004, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
        return;
    }
    UdpChannel *channel = TransAddChannelTest();
    int32_t filePort = 22;
    SocketAccessInfo accessInfo = { 0 };
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(sessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)strcpy_s(channelInfo->myIp, strlen("127.0.0.5") + 1, "127.0.0.5");
    (void)strcpy_s(channelInfo->sessionKey, strlen("session key") + 1, "session key");
    channelInfo->isServer = false;

    ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransSetFileSendListenerTest004
 * @tc.desc: trans set file send listener with null listener triggers memcpy_s failure returns mem err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetFileSendListenerTest004, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *sessionName = "file send";
    IFileSendListener *sendListener = nullptr;
    ret = TransSetFileSendListener(sessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest005
 * @tc.desc: trans on file channel opened with null accessInfo DFile start fails returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest005, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    IFileSendListener *sendListener = reinterpret_cast<IFileSendListener *>(SoftBusCalloc(sizeof(IFileSendListener)));
    if (sendListener == nullptr) {
        return;
    }
    int32_t filePort = 22;
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    UdpChannel *channel = TransAddChannelTest();
    DFileMsg *msgData = nullptr;
    DFileMsgType msgType = DFILE_ON_BIND;
    FileSendListener(channel->dfileId, msgType, msgData);

    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort, nullptr);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);

    SoftBusFree(channelInfo);
    SoftBusFree(sendListener);
    TransCloseFileChannel(channel->dfileId);
    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransOnFileChannelOpenedTest006
 * @tc.desc: trans on file channel opened with send listener returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransOnFileChannelOpenedTest006, TestSize.Level1)
{
    IClientSessionCallBack *cb = GetClientSessionCb();
    int32_t ret = ClientTransUdpMgrInit(cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    IFileSendListener *sendListener = reinterpret_cast<IFileSendListener *>(SoftBusCalloc(sizeof(IFileSendListener)));
    if (sendListener == nullptr) {
        return;
    }
    int32_t filePort = 22;
    SocketAccessInfo accessInfo = { 0 };
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    UdpChannel *channel = TransAddChannelTest();
    ret = ClientTransAddUdpChannel(channel);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransSetFileSendListener(g_mySessionName, sendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransOnFileChannelOpened(g_mySessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    SoftBusFree(channelInfo);
    SoftBusFree(sendListener);
    TransDeleteFileListener(g_mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest001
 * @tc.desc: file send listener without listener set no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest001, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);
    FileSendListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, &msgData);

    msgData.rate = 1;
    FileSendListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, &msgData);

    FileSendListener(channel->dfileId, DFILE_ON_BIND, &msgData);

    FileSendListener(channel->dfileId, DFILE_ON_SESSION_IN_PROGRESS, &msgData);

    FileSendListener(channel->dfileId, DFILE_ON_SESSION_TRANSFER_RATE, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest002
 * @tc.desc: file send listener with listener set DFILE_ON_SESSION_TRANSFER_RATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest002, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_SESSION_TRANSFER_RATE, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest003
 * @tc.desc: file send listener with listener set DFILE_ON_FILE_SEND_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest003, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_FILE_SEND_SUCCESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest004
 * @tc.desc: file send listener with listener set DFILE_ON_FILE_SEND_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest004, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_FILE_SEND_FAIL, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest005
 * @tc.desc: file send listener with listener set DFILE_ON_TRANS_IN_PROGRESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest005, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_TRANS_IN_PROGRESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest006
 * @tc.desc: file send listener with listener set DFILE_ON_CONNECT_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest006, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_CONNECT_FAIL, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileSendListenerTest007
 * @tc.desc: file send listener with listener set DFILE_ON_FATAL_ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerTest007, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    ret = TransSetFileSendListener(channel->info.mySessionName, &g_fileSendListener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileSendListener(channel->dfileId, DFILE_ON_FATAL_ERROR, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest001
 * @tc.desc: file receive listener without listener set no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest001, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);
    FileReceiveListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, nullptr);
    FileReceiveListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, &msgData);

    msgData.rate = 1;
    FileReceiveListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest002
 * @tc.desc: file receive listener with listener set DFILE_ON_FILE_LIST_RECEIVED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest002, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_FILE_LIST_RECEIVED, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest003
 * @tc.desc: file receive listener with listener set DFILE_ON_FILE_RECEIVE_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest003, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_FILE_RECEIVE_SUCCESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest004
 * @tc.desc: file receive listener with listener set DFILE_ON_TRANS_IN_PROGRESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest004, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_TRANS_IN_PROGRESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest005
 * @tc.desc: file receive listener with listener set DFILE_ON_FILE_RECEIVE_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest005, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_FILE_RECEIVE_FAIL, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest006
 * @tc.desc: file receive listener with listener set DFILE_ON_CONNECT_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest006, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_CONNECT_SUCCESS, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest007
 * @tc.desc: file receive listener with listener set DFILE_ON_CONNECT_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest007, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_CONNECT_FAIL, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: FileReceiveListenerTest008
 * @tc.desc: file receive listener with listener set DFILE_ON_FATAL_ERROR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileReceiveListenerTest008, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DFileMsg msgData = { };
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    ASSERT_TRUE(channel != nullptr);
    GenerateAndAddUdpChannel(channel);

    const char *rootDir = "rootDir";
    ret = TransSetFileReceiveListener(channel->info.mySessionName, &g_fileRecvListener, rootDir);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FileReceiveListener(channel->dfileId, DFILE_ON_FATAL_ERROR, &msgData);

    TransDeleteFileListener(channel->info.mySessionName);
    TransFileDeinit();
    ClientTransUdpMgrDeinit();
}

/*
 * @tc.name: TransSendFileTest001
 * @tc.desc: trans send file with null source and dest file list returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSendFileTest001, TestSize.Level1)
{
    int32_t sessionId = 0;
    const char *sFileList = nullptr;
    const char *dFileList = nullptr;
    uint32_t fileCnt = 0;
    int32_t ret = TransSendFile(sessionId, &sFileList, &dFileList, fileCnt);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TransSendFileTest002
 * @tc.desc: trans send file with valid source but null dest file list returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSendFileTest002, TestSize.Level1)
{
    int32_t sessionId = 0;
    const char *dFileList = nullptr;
    const char *fileList = "/file not null list/";
    uint32_t fileCnt = 0;
    int32_t ret = TransSendFile(sessionId, &fileList, &dFileList, fileCnt);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SetReuseAddrTest001
 * @tc.desc: trans set reuse addr with valid and invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, SetReuseAddrTest001, TestSize.Level1)
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

/*
 * @tc.name: SetReusePortTest001
 * @tc.desc: trans set reuse port with valid and invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, SetReusePortTest001, TestSize.Level1)
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

/*
 * @tc.name: CreateServerSocketByIpv4Test001
 * @tc.desc: trans create server socket by ipv4 with various params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketByIpv4Test001, TestSize.Level1)
{
    int32_t port = 5683;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocketByIpv4("127.0.0.1", port, capabilityValue);
    EXPECT_TRUE(ret);

    ret = CreateServerSocketByIpv4("280567565", port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);

    ret = CreateServerSocketByIpv4("127.0.0.1", 0, capabilityValue);
    EXPECT_TRUE(ret);

    capabilityValue = NSTACKX_WLAN_CAT_TCP;
    ret = CreateServerSocketByIpv4("280567565", port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: StartNStackXDFileServerTest001
 * @tc.desc: trans start nstackx file server with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerTest001, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = StartNStackXDFileServer(nullptr, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ret = StartNStackXDFileServer(channelInfo, g_fileMsgReceiver, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channelInfo->myIp = nullptr;
    ret = StartNStackXDFileServer(channelInfo, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileServerTest002
 * @tc.desc: trans start nstackx file server with valid params returns not invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerTest002, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    channelInfo->myIp = g_myIp;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = StartNStackXDFileServer(channelInfo, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileClientTest001
 * @tc.desc: trans start nstackx file client with null channel and null peerIp returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientTest001, TestSize.Level1)
{
    int32_t ret = StartNStackXDFileClient(nullptr, g_keyLen, g_fileMsgReceiver);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    channelInfo->peerIp = nullptr;
    ret = StartNStackXDFileClient(channelInfo, g_keyLen, g_fileMsgReceiver);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransSetSocketFileListenerTest001
 * @tc.desc: trans set socket file listener with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetSocketFileListenerTest001, TestSize.Level1)
{
    int32_t ret = TransSetSocketFileListener(nullptr, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSetSocketFileListener(g_mySessionName, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransSetSocketFileListener(nullptr, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransSetSocketFileListenerTest002
 * @tc.desc: trans set socket file listener with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransSetSocketFileListenerTest002, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransSetSocketFileListener(g_mySessionName, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
}

/*
 * @tc.name: TransAddNewSocketFileListenerTest001
 * @tc.desc: trans add new socket file listener with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransAddNewSocketFileListenerTest001, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAddNewSocketFileListener(nullptr, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAddNewSocketFileListener(g_mySessionName, nullptr, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAddNewSocketFileListener(nullptr, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    TransFileDeinit();
}

/*
 * @tc.name: TransAddNewSocketFileListenerTest002
 * @tc.desc: trans add new socket file listener with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransAddNewSocketFileListenerTest002, TestSize.Level1)
{
    int32_t ret = TransFileInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransAddNewSocketFileListener(g_mySessionName, SocketFileCallbackFuncTest, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransFileDeinit();
}

/*
 * @tc.name: CreateServerSocketByIpv6Test001
 * @tc.desc: trans create server socket by ipv6 with various params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketByIpv6Test001, TestSize.Level1)
{
    int32_t port = 5683;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocketByIpv6("3FFF:FFFF:0000:0000:0000:0000:0000:0000", port, capabilityValue);
    EXPECT_TRUE(ret);

    ret = CreateServerSocketByIpv6("280567565", port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);

    ret = CreateServerSocketByIpv6("3FFF:FFFF:0000:0000:0000:0000:0000:0000", 0, capabilityValue);
    EXPECT_TRUE(ret);

    capabilityValue = NSTACKX_WLAN_CAT_TCP;
    ret = CreateServerSocketByIpv6("280567565", port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: CreateServerSocketTest001
 * @tc.desc: trans create server socket with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketTest001, TestSize.Level1)
{
    int32_t port = 5683;
    int32_t fd = 1;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocket(nullptr, &fd, &port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", nullptr, &port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", &fd, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CreateServerSocketTest002
 * @tc.desc: trans create server socket with valid ipv6 returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketTest002, TestSize.Level1)
{
    int32_t port = 5683;
    int32_t fd = 1;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocket("3FFF:FFFF:0000:0000:0000:0000:0000:0000", &fd, &port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
}

/*
 * @tc.name: CreateServerSocketTest003
 * @tc.desc: trans create server socket with invalid ip returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketTest003, TestSize.Level1)
{
    int32_t port = 5683;
    int32_t fd = 1;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocket("280567565", &fd, &port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
}

/*
 * @tc.name: CreateServerSocketTest004
 * @tc.desc: trans create server socket with ipv4 address returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, CreateServerSocketTest004, TestSize.Level1)
{
    int32_t port = 5683;
    int32_t fd = 1;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = CreateServerSocket("127.0.0.1", &fd, &port, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: InitSockAddrInByIpPortTest001
 * @tc.desc: trans init sock addr in by ip port with various params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, InitSockAddrInByIpPortTest001, TestSize.Level1)
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

/*
 * @tc.name: InitSockAddrIn6ByIpPortTest001
 * @tc.desc: trans init sock addr in6 by ip port with various params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, InitSockAddrIn6ByIpPortTest001, TestSize.Level1)
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

/*
 * @tc.name: FreeFileStatusListTest001
 * @tc.desc: test free populated file status list clears pointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FreeFileStatusListTest001, TestSize.Level1)
{
    FileEvent event;
    event.statusList.completedList.fileCnt = 1;
    event.statusList.notCompletedList.fileCnt = 1;
    event.statusList.notStartedList.fileCnt = 1;
    event.statusList.completedList.files =
        reinterpret_cast<char **>(SoftBusCalloc(event.statusList.completedList.fileCnt * sizeof(char *)));
    event.statusList.notCompletedList.files =
        reinterpret_cast<char **>(SoftBusCalloc(event.statusList.notCompletedList.fileCnt * sizeof(char *)));
    event.statusList.notStartedList.files =
        reinterpret_cast<char **>(SoftBusCalloc(event.statusList.notStartedList.fileCnt * sizeof(char *)));

    FreeFileStatusList(&event);

    ASSERT_EQ(event.statusList.completedList.files, nullptr);
    ASSERT_EQ(event.statusList.notCompletedList.files, nullptr);
    ASSERT_EQ(event.statusList.notStartedList.files, nullptr);

    FileEvent *event2 = nullptr;
    FreeFileStatusList(event2);
}

/*
 * @tc.name: FreeFileStatusListTest002
 * @tc.desc: test free file status list with null files
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FreeFileStatusListTest002, TestSize.Level1)
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

/*
 * @tc.name: FillFileStatusListTest001
 * @tc.desc: test fill file status list with null params no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest001, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 3;
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = const_cast<char *>("file1");
    fileInfo[1].stat = FILE_STAT_NOT_COMPLETE;
    fileInfo[1].file = const_cast<char *>("file2");
    fileInfo[2].stat = FILE_STAT_NOT_START;
    fileInfo[2].file = const_cast<char *>("file3");
    msgData.clearPolicyFileList.fileInfo = fileInfo;
    FillFileStatusList(nullptr, &event);
    FillFileStatusList(&msgData, nullptr);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: FillFileStatusListTest002
 * @tc.desc: test fill file status list with mixed file stats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest002, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 3;
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = const_cast<char *>("file1");
    fileInfo[1].stat = FILE_STAT_NOT_COMPLETE;
    fileInfo[1].file = const_cast<char *>("file2");
    fileInfo[2].stat = FILE_STAT_NOT_START;
    fileInfo[2].file = const_cast<char *>("file3");
    msgData.clearPolicyFileList.fileInfo = fileInfo;

    FillFileStatusList(&msgData, &event);

    ASSERT_EQ(1, event.statusList.completedList.fileCnt);
    ASSERT_STREQ("file1", event.statusList.completedList.files[0]);
    ASSERT_EQ(1, event.statusList.notCompletedList.fileCnt);
    ASSERT_STREQ("file2", event.statusList.notCompletedList.files[0]);
    ASSERT_EQ(1, event.statusList.notStartedList.fileCnt);
    ASSERT_STREQ("file3", event.statusList.notStartedList.files[0]);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: FillFileStatusListTest003
 * @tc.desc: test fill file status list with zero file num
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest003, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 0;

    FillFileStatusList(&msgData, &event);

    ASSERT_EQ(nullptr, event.statusList.completedList.files);
    ASSERT_EQ(0, event.statusList.completedList.fileCnt);
    ASSERT_EQ(nullptr, event.statusList.notCompletedList.files);
    ASSERT_EQ(0, event.statusList.notCompletedList.fileCnt);
    ASSERT_EQ(nullptr, event.statusList.notStartedList.files);
    ASSERT_EQ(0, event.statusList.notStartedList.fileCnt);
}

/*
 * @tc.name: FillFileStatusListTest004
 * @tc.desc: test fill file status list with all files complete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileStatusListTest004, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;
    msgData.clearPolicyFileList.fileNum = 3;
    DFileFileInfo *fileInfo =
        static_cast<DFileFileInfo *>(SoftBusCalloc(msgData.clearPolicyFileList.fileNum * sizeof(DFileFileInfo)));
    EXPECT_NE(nullptr, fileInfo);
    fileInfo[0].stat = FILE_STAT_COMPLETE;
    fileInfo[0].file = const_cast<char *>("file1");
    fileInfo[1].stat = FILE_STAT_COMPLETE;
    fileInfo[1].file = const_cast<char *>("file2");
    fileInfo[2].stat = FILE_STAT_COMPLETE;
    fileInfo[2].file = const_cast<char *>("file3");
    msgData.clearPolicyFileList.fileInfo = fileInfo;

    FillFileStatusList(&msgData, &event);

    ASSERT_EQ(3, event.statusList.completedList.fileCnt);
    ASSERT_STREQ("file1", event.statusList.completedList.files[0]);
    ASSERT_STREQ("file2", event.statusList.completedList.files[1]);
    ASSERT_STREQ("file3", event.statusList.completedList.files[2]);
    ASSERT_EQ(0, event.statusList.notCompletedList.fileCnt);
    ASSERT_EQ(0, event.statusList.notStartedList.fileCnt);
    SoftBusFree(fileInfo);
}
} // namespace OHOS
