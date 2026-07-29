/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
    msgData->rate = 1;
}

/*
 * @tc.name: FileSendErrorEventTest001
 * @tc.desc: file send error event without socket send callback no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendErrorEventTest001, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    UdpChannel *channel = TransAddChannelTest();
    FileSendErrorEvent(channel, listener, &msgData, msgType, sessionId);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: FileSendErrorEventTest002
 * @tc.desc: file send error event with then null socket send callback no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendErrorEventTest002, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    UdpChannel *channel = TransAddChannelTest();
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    listener->socketSendCallback = nullptr;
    FileSendErrorEvent(channel, listener, &msgData, msgType, sessionId);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifySendResultTest001
 * @tc.desc: notify send result with null msgData null listener and msgData only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendResultTest001, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    NotifySendResult(sessionId, msgType, nullptr, nullptr);
    NotifySendResult(sessionId, msgType, &msgData, nullptr);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifySendResultTest002
 * @tc.desc: notify send result DFILE_ON_FILE_SEND_SUCCESS with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendResultTest002, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifySendResult(sessionId, DFILE_ON_FILE_SEND_SUCCESS, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifySendResultTest003
 * @tc.desc: notify send result DFILE_ON_FILE_SEND_FAIL with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendResultTest003, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifySendResult(sessionId, DFILE_ON_FILE_SEND_FAIL, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifySendResultTest004
 * @tc.desc: notify send result DFILE_ON_TRANS_IN_PROGRESS with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendResultTest004, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifySendResult(sessionId, DFILE_ON_TRANS_IN_PROGRESS, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifySendResultTest005
 * @tc.desc: notify send result DFILE_ON_BIND with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendResultTest005, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifySendResult(sessionId, DFILE_ON_BIND, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifyRecvResultTest001
 * @tc.desc: notify recv result with null msgData null listener and msgData only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifyRecvResultTest001, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_FILE_SEND_SUCCESS;
    NotifyRecvResult(sessionId, msgType, nullptr, nullptr);
    NotifyRecvResult(sessionId, msgType, &msgData, nullptr);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifyRecvResultTest002
 * @tc.desc: notify recv result DFILE_ON_FILE_LIST_RECEIVED with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifyRecvResultTest002, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifyRecvResult(sessionId, DFILE_ON_FILE_LIST_RECEIVED, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifyRecvResultTest003
 * @tc.desc: notify recv result DFILE_ON_FILE_RECEIVE_SUCCESS with listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifyRecvResultTest003, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    NotifyRecvResult(sessionId, DFILE_ON_FILE_RECEIVE_SUCCESS, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: FileRecvErrorEventTest001
 * @tc.desc: file recv error event with callbacks no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileRecvErrorEventTest001, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_BIND;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    UdpChannel *channel = TransAddChannelTest();
    FileRecvErrorEvent(channel, listener, &msgData, msgType, sessionId);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: FileRecvErrorEventTest002
 * @tc.desc: file recv error event with null send callback no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileRecvErrorEventTest002, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_BIND;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = nullptr;
    UdpChannel *channel = TransAddChannelTest();
    FileRecvErrorEvent(channel, listener, &msgData, msgType, sessionId);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifyRecvResultTest004
 * @tc.desc: notify recv result with negative file num no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifyRecvResultTest004, TestSize.Level1)
{
    DFileMsg msgData;
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
    int32_t sessionId = TEST_SESSIONID;
    DFileMsgType msgType = DFILE_ON_BIND;
    FileListener *listener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    EXPECT_NE(nullptr, listener);
    listener->socketSendCallback = MockSocketSendCallback;
    listener->socketRecvCallback = MockSocketRecvCallback;
    msgData.fileList.fileNum = -1;
    NotifyRecvResult(sessionId, msgType, &msgData, listener);
    SoftBusFree(listener);
    SoftBusFree(fileInfo);
}

/*
 * @tc.name: NotifyTransLimitChangedTest001
 * @tc.desc: trans rename hook and notify trans limit changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifyTransLimitChangedTest001, TestSize.Level1)
{
    RenameHook(nullptr);
    int32_t channelId = TEST_CHANNELID;
    uint8_t tos = 1;
    int32_t ret = NotifyTransLimitChanged(channelId, tos);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: NotifySocketSendResultTest001
 * @tc.desc: notify socket send result with null msgData and null listener no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySocketSendResultTest001, TestSize.Level1)
{
    int32_t socket = 1;
    DFileMsg msgData;
    InitDFileMsg(&msgData);
    FileListener listener;
    listener.socketSendCallback = MockSocketSendCallback;
    listener.socketRecvCallback = MockSocketRecvCallback;
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_TRANS_IN_PROGRESS, nullptr, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, nullptr));
}

/*
 * @tc.name: NotifySocketRecvResultTest001
 * @tc.desc: notify socket recv result with null msgData and null listener no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySocketRecvResultTest001, TestSize.Level1)
{
    int32_t socket = 1;
    DFileMsg msgData;
    InitDFileMsg(&msgData);
    FileListener listener;
    listener.socketSendCallback = MockSocketSendCallback;
    listener.socketRecvCallback = MockSocketRecvCallback;
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_FILE_LIST_RECEIVED, nullptr, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, nullptr));
}

/*
 * @tc.name: NotifySocketSendResultTest002
 * @tc.desc: notify socket send result with different msg types no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySocketSendResultTest002, TestSize.Level1)
{
    int32_t socket = 1;
    DFileMsg msgData;
    InitDFileMsg(&msgData);
    FileListener listener;
    listener.socketSendCallback = MockSocketSendCallback;
    listener.socketRecvCallback = MockSocketRecvCallback;
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_FILE_SEND_SUCCESS, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_FILE_SEND_FAIL, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_CLEAR_POLICY_FILE_LIST, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketSendResult(socket, DFILE_ON_CONNECT_FAIL, &msgData, &listener));
}

/*
 * @tc.name: NotifySocketRecvResultTest002
 * @tc.desc: notify socket recv result with different msg types no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySocketRecvResultTest002, TestSize.Level1)
{
    int32_t socket = 1;
    DFileMsg msgData;
    InitDFileMsg(&msgData);
    FileListener listener;
    listener.socketSendCallback = MockSocketSendCallback;
    listener.socketRecvCallback = MockSocketRecvCallback;
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_FILE_LIST_RECEIVED, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_TRANS_IN_PROGRESS, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_FILE_RECEIVE_SUCCESS, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_FILE_RECEIVE_FAIL, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_CLEAR_POLICY_FILE_LIST, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_SESSION_TRANSFER_RATE, &msgData, &listener));
    EXPECT_NO_FATAL_FAILURE(NotifySocketRecvResult(socket, DFILE_ON_CONNECT_FAIL, &msgData, &listener));
}

/*
 * @tc.name: FillFileEventErrorCodeTest001
 * @tc.desc: test fill file event error code with NSTACKX_EOK returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest001, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_EOK;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_OK, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest002
 * @tc.desc: test fill file event error code with NSTACKX_EPERM returns permission denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest002, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_EPERM;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_PERMISSION_DENIED, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest003
 * @tc.desc: test fill file event error code with NSTACKX_EDQUOT returns disk quota exceeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest003, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_EDQUOT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_DISK_QUOTA_EXCEEDED, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest004
 * @tc.desc: test fill file event error code with NSTACKX_ENOMEM returns no memory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest004, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_ENOMEM;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NO_MEMORY, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest005
 * @tc.desc: test fill file event error code with NSTACKX_ENETDOWN returns network error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest005, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_ENETDOWN;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NETWORK_ERROR, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest006
 * @tc.desc: test fill file event error code with NSTACKX_ENOENT returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest006, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_ENOENT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_NOT_FOUND, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest007
 * @tc.desc: test fill file event error code with NSTACKX_EEXIST returns existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest007, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_EEXIST;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(SOFTBUS_TRANS_FILE_EXISTED, event.errorCode);
}

/*
 * @tc.name: FillFileEventErrorCodeTest008
 * @tc.desc: test fill file event error code with NSTACKX_NOTSUPPORT returns not support
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillFileEventErrorCodeTest008, TestSize.Level1)
{
    DFileMsg msgData;
    FileEvent event;

    msgData.errorCode = NSTACKX_NOTSUPPORT;
    FillFileEventErrorCode(&msgData, &event);
    ASSERT_EQ(NSTACKX_NOTSUPPORT, event.errorCode);
}

/*
 * @tc.name: ConvertDFileLinkToLinkMediumTest001
 * @tc.desc: convert dfile link to link medium with various link types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, ConvertDFileLinkToLinkMediumTest001, TestSize.Level1)
{
    LinkMediumType linkmediumtype = ConvertDFileLinkToLinkMedium(DFILE_LINK_WIRELESS);
    EXPECT_EQ(linkmediumtype, LINK_TYPE_WIFI);

    linkmediumtype = ConvertDFileLinkToLinkMedium(DFILE_LINK_WIRED);
    EXPECT_EQ(linkmediumtype, LINK_TYPE_WIRED);

    linkmediumtype = ConvertDFileLinkToLinkMedium(DFILE_LINK_MAX);
    EXPECT_EQ(linkmediumtype, LINK_TYPE_UNKNOWN);
}

/*
 * @tc.name: ConvertOnEventReasonTest001
 * @tc.desc: convert on event reason with various link types and states
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, ConvertOnEventReasonTest001, TestSize.Level1)
{
    SoftBusMPErrNo softbusErrNo = ConvertOnEventReason(1, DFILE_LINK_WIRELESS);
    EXPECT_EQ(softbusErrNo, MP_HML_LINK_ON);

    softbusErrNo = ConvertOnEventReason(0, DFILE_LINK_WIRELESS);
    EXPECT_EQ(softbusErrNo, MP_HML_LINK_DOWN);

    softbusErrNo = ConvertOnEventReason(1, DFILE_LINK_WIRED);
    EXPECT_EQ(softbusErrNo, MP_USB_LINK_ON);

    softbusErrNo = ConvertOnEventReason(0, DFILE_LINK_WIRED);
    EXPECT_EQ(softbusErrNo, MP_USB_LINK_DOWN);

    softbusErrNo = ConvertOnEventReason(0, DFILE_LINK_MAX);
    EXPECT_EQ(softbusErrNo, MP_UNKNOWN_REASON);
}

/*
 * @tc.name: NotifySendRateTest001
 * @tc.desc: notify send rate with null and valid channel no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendRateTest001, TestSize.Level1)
{
    DFileMsgType msgType = DFILE_ON_BIND;
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(nullptr, msgType, nullptr));

    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(&udpChannel, msgType, nullptr));
}

/*
 * @tc.name: FileSendListenerExTest001
 * @tc.desc: file send listener ex with null and valid channel no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FileSendListenerExTest001, TestSize.Level1)
{
    DFileMsgType msgType = DFILE_ON_BIND;
    EXPECT_NO_FATAL_FAILURE(FileSendListenerEx(nullptr, msgType, nullptr));

    UdpChannel udpChannel;
    (void)memset_s(&udpChannel, sizeof(UdpChannel), 0, sizeof(UdpChannel));
    EXPECT_NO_FATAL_FAILURE(FileSendListenerEx(&udpChannel, msgType, nullptr));
}

/*
 * @tc.name: TransServerStartDFileTest001
 * @tc.desc: trans server start dfile with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransServerStartDFileTest001, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    bool isAddMultipath = true;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = TransServerStartDFile(nullptr, &isAddMultipath, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransServerStartDFile(channel, nullptr, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransServerStartDFile(channel, &isAddMultipath, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: TransClientStartDFileTest001
 * @tc.desc: trans client start dfile with null channelInfo returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransClientStartDFileTest001, TestSize.Level1)
{
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    EXPECT_NE(channelInfo, nullptr);
    int32_t ret = TransClientStartDFile(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest001
 * @tc.desc: convert route to dfile link type with various route types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, ConvertRouteToDFileLinkTypeTest001, TestSize.Level1)
{
    DFileLinkType linktype = ConvertRouteToDFileLinkType(WIFI_USB);
    EXPECT_EQ(linktype, DFILE_LINK_WIRED);

    linktype = ConvertRouteToDFileLinkType(WIFI_STA);
    EXPECT_EQ(linktype, DFILE_LINK_WIRELESS);

    linktype = ConvertRouteToDFileLinkType(WIFI_P2P);
    EXPECT_EQ(linktype, DFILE_LINK_WIRELESS);

    linktype = ConvertRouteToDFileLinkType(BT_SLE);
    EXPECT_EQ(linktype, DFILE_LINK_MAX);
}

/*
 * @tc.name: DFileServerAddSecondPathTest001
 * @tc.desc: DFileServer add second path with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, DFileServerAddSecondPathTest001, TestSize.Level1)
{
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    int32_t dfileId = 1;
    int32_t fileport = 22;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;

    int32_t ret = DFileServerAddSecondPath(nullptr, &fileport, dfileId, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DFileServerAddSecondPath(channelInfo, nullptr, dfileId, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DFileServerAddSecondPath(channelInfo, &fileport, dfileId, nullptr, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: DFileClientAddSecondPathTest001
 * @tc.desc: DFileClient add second path with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, DFileClientAddSecondPathTest001, TestSize.Level1)
{
    int32_t dfileId = 1;
    int32_t keyLen = 1;
    int32_t ret = DFileClientAddSecondPath(nullptr, dfileId, keyLen, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ret = DFileClientAddSecondPath(channelInfo, dfileId, keyLen, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileServerV2Test001
 * @tc.desc: trans start nstackx file server V2 with null and valid channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerV2Test001, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    int32_t ret = StartNStackXDFileServerV2(nullptr, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ChannelInfo *channel = TransAddChannelInfoTest();
    ret = StartNStackXDFileServerV2(channel, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileClientV2Test001
 * @tc.desc: trans start nstackx file client V2 with null channel returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientV2Test001, TestSize.Level1)
{
    uint32_t keyLen = 8;
    int32_t ret = StartNStackXDFileClientV2(nullptr, keyLen, g_fileMsgReceiver);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ChannelInfo channel;
    (void)memset_s(&channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    (void)memcpy_s(channel.peerIp, IP_LEN, "127.0.0.1", strlen("127.0.0.1"));
    channel.peerPort = 1;
    channel.linkType = 1;

    ret = StartNStackXDFileClientV2(&channel, keyLen, g_fileMsgReceiver);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: FillDFileParamTest001
 * @tc.desc: trans fill dfile param with null params and various addresses
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, FillDFileParamTest001, TestSize.Level1)
{
    int32_t srvport = 22;
    int32_t ret = FillDFileParam(nullptr, srvport, 1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FillDFileParam("127.0.0.1", srvport, 1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NSTACKX_SessionParaMpV2 para[1];
    (void)memset_s(para, sizeof(NSTACKX_SessionParaMpV2), 0, sizeof(NSTACKX_SessionParaMpV2));
    struct sockaddr_in addrIn;
    (void)memset_s(&addrIn, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in));
    para[0].addr = &addrIn;

    const char *ipv6Addr = "[::1]:8080";
    ret = FillDFileParam(ipv6Addr, srvport, 1, para);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);

    const char *ipv4Addr = "192.168.1.1";
    ret = FillDFileParam(ipv4Addr, srvport, 1, para);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: StartNStackXDFileServerWithCancelEncryptionTest001
 * @tc.desc: trans start nstackx file server with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerWithCancelEncryptionTest001, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->cancelEncryption = true;
    channelInfo->myIp = g_myIp;

    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = StartNStackXDFileServer(channelInfo, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    ConnDeinitSockets();
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileClientWithCancelEncryptionTest001
 * @tc.desc: trans start nstackx file client with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientWithCancelEncryptionTest001, TestSize.Level1)
{
    uint32_t keyLen = 8;
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->cancelEncryption = true;
    channelInfo->peerIp = g_peerIp;
    channelInfo->peerPort = 1;

    int32_t ret = StartNStackXDFileClient(channelInfo, keyLen, g_fileMsgReceiver);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: DFileServerAddSecondPathWithCancelEncryptionTest001
 * @tc.desc: DFileServer add second path with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, DFileServerAddSecondPathWithCancelEncryptionTest001, TestSize.Level1)
{
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->cancelEncryption = true;
    channelInfo->myIp = g_myIp;
    int32_t dfileId = 1;
    int32_t fileport = 22;
    AddrInfo addrInfo;
    (void)memset_s(&addrInfo, sizeof(AddrInfo), 0, sizeof(AddrInfo));
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;

    int32_t ret = DFileServerAddSecondPath(channelInfo, &fileport, dfileId, &addrInfo, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: DFileClientAddSecondPathWithCancelEncryptionTest001
 * @tc.desc: DFileClient add second path with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, DFileClientAddSecondPathWithCancelEncryptionTest001, TestSize.Level1)
{
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->cancelEncryption = true;
    channelInfo->peerIp = g_peerIp;
    channelInfo->peerPort = 1;
    int32_t dfileId = 1;
    int32_t keyLen = 8;
    AddrInfo addrInfo;
    (void)memset_s(&addrInfo, sizeof(AddrInfo), 0, sizeof(AddrInfo));

    int32_t ret = DFileClientAddSecondPath(channelInfo, dfileId, keyLen, &addrInfo);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileServerV2WithCancelEncryptionTest001
 * @tc.desc: trans start nstackx file server V2 with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerV2WithCancelEncryptionTest001, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    ChannelInfo *channelInfo = TransAddChannelInfoTest();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->cancelEncryption = true;
    channelInfo->myIp = g_myIp;

    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = StartNStackXDFileServerV2(channelInfo, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    ConnDeinitSockets();
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: StartNStackXDFileClientV2WithCancelEncryptionTest001
 * @tc.desc: trans start nstackx file client V2 with cancelEncryption enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientV2WithCancelEncryptionTest001, TestSize.Level1)
{
    uint32_t keyLen = 8;
    ChannelInfo channel;
    (void)memset_s(&channel, sizeof(ChannelInfo), 0, sizeof(ChannelInfo));
    (void)memcpy_s(channel.peerIp, IP_LEN, "127.0.0.1", strlen("127.0.0.1"));
    channel.peerPort = 1;
    channel.linkType = 1;
    channel.cancelEncryption = true;

    int32_t ret = StartNStackXDFileClientV2(&channel, keyLen, g_fileMsgReceiver);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

static char g_testIpv6[] = "3FFF:FFFF:0000:0000:0000:0000:0000:0000";
static char g_testIpv4[] = "127.0.0.1";

/*
 * @tc.name: StartDFileServerIpv6Test001
 * @tc.desc: start dfile server ipv6 with null channel/sessionId/myIp returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv6Test001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = StartDFileServerIpv6(nullptr, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    ret = StartDFileServerIpv6(channel, 0, g_fileMsgReceiver, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channel->myIp = nullptr;
    ret = StartDFileServerIpv6(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerIpv6Test002
 * @tc.desc: start dfile server ipv6 with cancelEncryption enabled returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv6Test002, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv6;
    channel->cancelEncryption = true;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerIpv6(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerIpv6Test003
 * @tc.desc: start dfile server ipv6 with sessionKey returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv6Test003, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv6;
    channel->cancelEncryption = false;
    char sessionKey[DEFAULT_KEY_LENGTH] = "123548246";
    channel->sessionKey = sessionKey;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerIpv6(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerIpv4Test001
 * @tc.desc: start dfile server ipv4 with null channel/sessionId/myIp returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv4Test001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = StartDFileServerIpv4(nullptr, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    ret = StartDFileServerIpv4(channel, 0, g_fileMsgReceiver, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    channel->myIp = nullptr;
    ret = StartDFileServerIpv4(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerIpv4Test002
 * @tc.desc: start dfile server ipv4 with cancelEncryption enabled returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv4Test002, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = true;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerIpv4(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerIpv4Test003
 * @tc.desc: start dfile server ipv4 with sessionKey returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerIpv4Test003, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = false;
    char sessionKey[DEFAULT_KEY_LENGTH] = "123548246";
    channel->sessionKey = sessionKey;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerIpv4(channel, 0, g_fileMsgReceiver, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerMpV2Test001
 * @tc.desc: start dfile server mp v2 with null channel/myIp returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerMpV2Test001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = StartDFileServerMpV2(nullptr, g_fileMsgReceiver, 0, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = nullptr;
    ret = StartDFileServerMpV2(channel, g_fileMsgReceiver, 0, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerMpV2Test002
 * @tc.desc: start dfile server mp v2 with cancelEncryption enabled returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerMpV2Test002, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = true;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerMpV2(channel, g_fileMsgReceiver, 0, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartDFileServerMpV2Test003
 * @tc.desc: start dfile server mp v2 with sessionKey returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartDFileServerMpV2Test003, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = false;
    char sessionKey[DEFAULT_KEY_LENGTH] = "123548246";
    channel->sessionKey = sessionKey;
    int32_t sessionId = -1;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartDFileServerMpV2(channel, g_fileMsgReceiver, 0, &sessionId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileServerTest003
 * @tc.desc: start nstackx dfile server with valid ipv4 and cancelEncryption reaches dfile server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerTest003, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = true;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartNStackXDFileServer(channel, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileClientTest002
 * @tc.desc: start nstackx dfile client with valid ipv4 and cancelEncryption reaches dfile client
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientTest002, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->peerIp = g_testIpv4;
    channel->peerPort = 1;
    channel->cancelEncryption = true;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartNStackXDFileClient(channel, g_keyLen, g_fileMsgReceiver);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileClientTest003
 * @tc.desc: start nstackx dfile client with valid ipv6 and sessionKey reaches dfile client
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientTest003, TestSize.Level1)
{
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->peerIp = g_testIpv6;
    channel->peerPort = 1;
    channel->cancelEncryption = false;
    char sessionKey[DEFAULT_KEY_LENGTH] = "123548246";
    channel->sessionKey = sessionKey;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartNStackXDFileClient(channel, g_keyLen, g_fileMsgReceiver);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileServerV2Test002
 * @tc.desc: start nstackx dfile server v2 with valid ipv4 and cancelEncryption reaches mp v2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileServerV2Test002, TestSize.Level1)
{
    int32_t filePort = 25;
    uint32_t capabilityValue = NSTACKX_WLAN_CAT_DIRECT;
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->myIp = g_testIpv4;
    channel->cancelEncryption = true;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartNStackXDFileServerV2(channel, g_fileMsgReceiver, &filePort, capabilityValue);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: StartNStackXDFileClientV2Test002
 * @tc.desc: start nstackx dfile client v2 with valid ipv4 and cancelEncryption reaches mp v2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, StartNStackXDFileClientV2Test002, TestSize.Level1)
{
    uint32_t keyLen = 8;
    ChannelInfo *channel = TransAddChannelInfoTest();
    ASSERT_NE(channel, nullptr);
    channel->peerIp = g_testIpv4;
    channel->peerPort = 1;
    channel->linkType = 1;
    channel->cancelEncryption = true;
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StartNStackXDFileClientV2(channel, keyLen, g_fileMsgReceiver);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
    ConnDeinitSockets();
    SoftBusFree(channel);
}

/*
 * @tc.name: NotifySendRateTest002
 * @tc.desc: notify send rate with DFILE_ON_SESSION_TRANSFER_RATE reports file rate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendRateTest002, TestSize.Level1)
{
    UdpChannel *channel = TransAddChannelTest();
    ASSERT_NE(channel, nullptr);
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.rate = 100;
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(channel, DFILE_ON_SESSION_TRANSFER_RATE, &msgData));
    SoftBusFree(channel);
}

/*
 * @tc.name: NotifySendRateTest003
 * @tc.desc: notify send rate with DFILE_ON_MP_SPEED and wireless link first reports rates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendRateTest003, TestSize.Level1)
{
    UdpChannel *channel = TransAddChannelTest();
    ASSERT_NE(channel, nullptr);
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.notifyLinkRate[0].linkType = DFILE_LINK_WIRELESS;
    msgData.notifyLinkRate[0].rate = 100;
    msgData.notifyLinkRate[1].rate = 200;
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(channel, DFILE_ON_MP_SPEED, &msgData));
    SoftBusFree(channel);
}

/*
 * @tc.name: NotifySendRateTest004
 * @tc.desc: notify send rate with DFILE_ON_MP_SPEED and wired link first reports rates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendRateTest004, TestSize.Level1)
{
    UdpChannel *channel = TransAddChannelTest();
    ASSERT_NE(channel, nullptr);
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.notifyLinkRate[0].linkType = DFILE_LINK_WIRED;
    msgData.notifyLinkRate[0].rate = 100;
    msgData.notifyLinkRate[1].rate = 200;
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(channel, DFILE_ON_MP_SPEED, &msgData));
    SoftBusFree(channel);
}

/*
 * @tc.name: NotifySendRateTest005
 * @tc.desc: notify send rate with enableMultipath sets multipath tag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, NotifySendRateTest005, TestSize.Level1)
{
    UdpChannel *channel = TransAddChannelTest();
    ASSERT_NE(channel, nullptr);
    channel->enableMultipath = true;
    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.rate = 50;
    EXPECT_NO_FATAL_FAILURE(NotifySendRate(channel, DFILE_ON_SESSION_TRANSFER_RATE, &msgData));
    SoftBusFree(channel);
}

/*
 * @tc.name: TransCloseDFileReserveProcTaskTest001
 * @tc.desc: close dfile reserve proc task with null args returns null and valid args frees resources
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransCloseDFileReserveProcTaskTest001, TestSize.Level1)
{
    EXPECT_EQ(TransCloseDFileReserveProcTask(nullptr), nullptr);
    int32_t ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);
    struct sockaddr_in *addr = reinterpret_cast<struct sockaddr_in *>(SoftBusCalloc(sizeof(struct sockaddr_in)));
    ASSERT_NE(addr, nullptr);
    ClearMultiPathArgs *args = reinterpret_cast<ClearMultiPathArgs *>(SoftBusCalloc(sizeof(ClearMultiPathArgs)));
    ASSERT_NE(args, nullptr);
    args->dfileId = 1;
    args->addrLen = sizeof(struct sockaddr_in);
    args->addr = addr;
    args->paraNum = 1;
    EXPECT_EQ(TransCloseDFileReserveProcTask(args), nullptr);
    ConnDeinitSockets();
}

/*
 * @tc.name: TransCloseReserveFileChannelTest001
 * @tc.desc: close reserve file channel with null addr or oversized addrLen returns early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransSdkFileTest, TransCloseReserveFileChannelTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(1, nullptr, sizeof(struct sockaddr_storage), 1));
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(2, nullptr, sizeof(struct sockaddr_storage), 2));
    struct sockaddr_storage addr;
    (void)memset_s(&addr, sizeof(struct sockaddr_storage), 0, sizeof(struct sockaddr_storage));
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(1, &addr, sizeof(struct sockaddr_storage) + 1, 1));
}
} // namespace OHOS
