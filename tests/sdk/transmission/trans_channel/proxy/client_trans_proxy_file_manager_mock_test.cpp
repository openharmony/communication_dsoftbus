/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>
#include "securec.h"
#include <sys/stat.h>
#include <sys/types.h>

#include "client_trans_proxy_file_manager.c"
#include "client_trans_proxy_file_manager_mock.h"
#include "client_trans_proxy_manager.c"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

using namespace testing;
using namespace testing::ext;

#define TEST_SESSION_ID 1026
#define TEST_CHANNEL_ID 2058
#define TEST_HEADER_LENGTH 24
#define TEST_DATA_LENGTH 100
#define TEST_PACKET_SIZE 1024
#define TEST_FILE_LENGTH 12
#define TEST_FILE_DATA_SIZE 958
#define TEST_FILE_TEST_TXT_FILE 16
#define TEST_SEQ 15
#define TEST_ZERO 0
#define TEST_NUM 2
#define TEST_DATA_LEN 5000

static const char *TEST_SESSION_NAME = "test.trans.proxy.demo";
static const char *TEST_SESSION_KEY = "Test_OpenHarmony";

namespace OHOS {

const char *g_testProxyFileList[] = {
    "/data/test.txt",
    "/data/ss.txt",
};

class ClientTransProxyFileManagerMockTest : public testing::Test {
public:
    ClientTransProxyFileManagerMockTest() {}
    ~ClientTransProxyFileManagerMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyFileManagerMockTest::SetUpTestCase(void)
{
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, InitPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransProxyListInit();
}

void ClientTransProxyFileManagerMockTest::TearDownTestCase(void)
{
    ClinetTransProxyFileManagerDeinit();
    ClientTransProxyListDeinit();
}

ClientProxyChannelInfo *TestCreatInfo(void)
{
    ClientProxyChannelInfo *info = (ClientProxyChannelInfo *)SoftBusCalloc(sizeof(ClientProxyChannelInfo));
    if (info == nullptr) {
        return nullptr;
    }
    info->channelId = TEST_CHANNEL_ID;
    info->detail.linkType = LANE_HML;
    info->detail.osType = OH_TYPE;
    info->detail.isEncrypted = true;
    return info;
}

/**
 * @tc.name: AddSendListenerInfoTest001
 * @tc.desc: client add send listener info, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, AddSendListenerInfoTest001, TestSize.Level0)
{
    // will free in DelSendListenerInfo
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    EXPECT_TRUE(info != nullptr);
    info->sessionId = TEST_SESSION_ID;

    int32_t ret = AddSendListenerInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    ReleaseSendListenerInfo(info);
}

/**
 * @tc.name: PackFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, PackFileTransStartInfoTest001, TestSize.Level0)
{
    uint8_t data[TEST_DATA_LENGTH] = {0};
    FileFrame fileFrame = {
        .frameLength = TEST_HEADER_LENGTH,
        .data = data,
        .fileData = data,
    };
    SendListenerInfo info = {
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .osType = OH_TYPE,
        .packetSize = 1,
    };

    int32_t ret = PackFileTransStartInfo(nullptr, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, nullptr, TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(FILE_MAGIC_NUMBER));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(
        Return(FILE_MAGIC_NUMBER + FRAME_MAGIC_OFFSET));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(TEST_FILE_DATA_SIZE));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(Return(TEST_FILE_TEST_TXT_FILE));

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: UnpackFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, UnpackFileTransStartInfoTest001, TestSize.Level0)
{
    uint32_t packetSize = TEST_PACKET_SIZE;

    uint8_t data[TEST_DATA_LENGTH] = {0};
    FileFrame fileFrame = {
        .frameLength = TEST_HEADER_LENGTH,
        .data = data,
        .fileData = data,
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;
    int32_t ret = UnpackFileTransStartInfo(nullptr, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileTransStartInfo(&fileFrame, nullptr, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileTransStartInfo(&fileFrame, &info, nullptr, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_FILE_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE));
    
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_FILE_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE + 1));
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_FILE_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_DATA_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE + 1));
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_SESSION_ID));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE + 1));
    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}

/**
 * @tc.name: GetAndCheckFileSizeTest001
 * @tc.desc: client get and check file size, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, GetAndCheckFileSizeTest001, TestSize.Level0)
{
    uint64_t fileSize = MAX_FILE_SIZE + 1;
    uint64_t frameNum = 1;
    int32_t crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    uint32_t packetSize = FRAME_DATA_SEQ_OFFSET;
    int32_t ret = GetAndCheckFileSize(nullptr, &fileSize, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAndCheckFileSize(g_testProxyFileList[0], nullptr, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAndCheckFileSize(g_testProxyFileList[0], &fileSize, nullptr, crc, packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetAndCheckFileSize(g_testProxyFileList[0], &fileSize, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetAndCheckFileSize(g_testProxyFileList[0], &fileSize, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    fileSize = MAX_FILE_SIZE;
    ret = GetAndCheckFileSize(g_testProxyFileList[0], &fileSize, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    packetSize = FRAME_DATA_SEQ_OFFSET + 1;
    ret = GetAndCheckFileSize(g_testProxyFileList[0], &fileSize, &frameNum, crc, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendOneFrameMiddleTest001
 * @tc.desc: client send one frame middle test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, SendOneFrameMiddleTest001, TestSize.Level0)
{
    SendListenerInfo info = {
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
        .seq = FILE_SEND_ACK_INTERVAL,
    };
    int32_t frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    int32_t ret = SendOneFrameMiddle(nullptr, frameType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SendOneFrameMiddle(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = SendOneFrameMiddle(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendOneFrameRearTest001
 * @tc.desc: client send one frame rear test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, SendOneFrameRearTest001, TestSize.Level0)
{
    SendListenerInfo info = {
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
        .seq = FILE_SEND_ACK_INTERVAL,
        .waitSeq = 0,
        .waitTimeoutCount = WAIT_FRAME_ACK_TIMEOUT_COUNT,
    };
    int32_t frameType = TRANS_SESSION_FILE_ONLYONE_FRAME;
    int32_t ret = SendOneFrameRear(nullptr, frameType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    frameType = TRANS_SESSION_FILE_FIRST_FRAME;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, GetPendingPacketData).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ALREADY_TRIGGERED)).WillOnce(Return(SOFTBUS_TIMOUT)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ALREADY_TRIGGERED)).WillRepeatedly(Return(SOFTBUS_TIMOUT));
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    frameType = TRANS_SESSION_FILE_LAST_FRAME;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.waitSeq = 1;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.waitSeq = 1;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.waitSeq = 1;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    frameType = TRANS_SESSION_ACK;
    info.waitSeq = 1;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.waitTimeoutCount = WAIT_FRAME_ACK_TIMEOUT_COUNT - 1;
    ret = SendOneFrameRear(&info, frameType);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendFileCrcCheckSumTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, SendFileCrcCheckSumTest001, TestSize.Level0)
{
    SendListenerInfo info = {
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
        .seq = FILE_SEND_ACK_INTERVAL,
        .osType = OH_TYPE,
        .checkSumCRC = TEST_FILE_TEST_TXT_FILE,
    };
    int32_t ret = SendFileCrcCheckSum(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SendFileCrcCheckSum(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(FILE_SEND_ACK_INTERVAL + 1));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(TEST_FILE_TEST_TXT_FILE));
    EXPECT_CALL(ClientProxyFileManagerMock, CreatePendingPacket).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = SendFileCrcCheckSum(&info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: UnpackFileCrcCheckSumTest001
 * @tc.desc: client unpack file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, UnpackFileCrcCheckSumTest001, TestSize.Level0)
{
    SendListenerInfo fileInfo = {
        .checkSumCRC = TEST_FILE_DATA_SIZE,
    };
    FileRecipientInfo info = {
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .osType = OH_TYPE,
    };
    (void)memcpy_s(&info.recvFileInfo, sizeof(SendListenerInfo), &fileInfo, sizeof(SendListenerInfo));
    uint8_t data[TEST_DATA_LENGTH] = {0};
    FileFrame fileFrame = {
        .frameLength = TEST_FILE_LENGTH,
        .data = data,
        .fileData = data,
    };
    int32_t ret = UnpackFileCrcCheckSum(nullptr, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileCrcCheckSum(&info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileCrcCheckSum(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    fileFrame.frameLength = FRAME_HEAD_LEN + FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t);
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(TEST_DATA_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_DATA_LENGTH));
    ret = UnpackFileCrcCheckSum(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_DATA_LENGTH));
    ret = UnpackFileCrcCheckSum(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_INVALID_DATA_HEAD, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(FILE_SEND_ACK_INTERVAL + 1));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll)
        .WillOnce(Return(FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t)))
        .WillRepeatedly(Return(FILE_SEND_ACK_INTERVAL + 1));
    ret = UnpackFileCrcCheckSum(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(FILE_SEND_ACK_INTERVAL + 1));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll)
        .WillOnce(Return(FRAME_DATA_SEQ_OFFSET + sizeof(uint64_t)))
        .WillRepeatedly(Return(TEST_ZERO));
    ret = UnpackFileCrcCheckSum(&info, &fileFrame);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: FileToFrameTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, FileToFrameTest001, TestSize.Level0)
{
    SendListenerInfo sendInfo = {
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .seq = FILE_SEND_ACK_INTERVAL,
        .osType = OH_TYPE,
        .checkSumCRC = TEST_FILE_TEST_TXT_FILE,
        .packetSize = TEST_HEADER_LENGTH,
    };
    uint64_t frameNum = TEST_NUM;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, FrameIndexToType).WillRepeatedly(Return(TRANS_SESSION_FILE_ONLYONE_FRAME));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(FILE_MAGIC_NUMBER));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(Return(
        FILE_MAGIC_NUMBER + FRAME_MAGIC_OFFSET));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(TEST_FILE_DATA_SIZE));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(Return(TEST_FILE_TEST_TXT_FILE));
    int32_t ret = FileToFrame(&sendInfo, frameNum, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    frameNum = 0;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(FILE_SEND_ACK_INTERVAL + 1));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(TEST_FILE_TEST_TXT_FILE));
    EXPECT_CALL(ClientProxyFileManagerMock, CreatePendingPacket).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = FileToFrame(&sendInfo, frameNum, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    sendInfo.osType = TEST_ZERO;
    ret = FileToFrame(&sendInfo, frameNum, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: FileToFrameAndSendFileTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, FileToFrameAndSendFileTest001, TestSize.Level0)
{
    SendListenerInfo sendInfo = {
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
        .seq = FILE_SEND_ACK_INTERVAL,
        .osType = OH_TYPE,
        .checkSumCRC = TEST_FILE_TEST_TXT_FILE,
        .packetSize = FRAME_DATA_SEQ_OFFSET + 1,
    };
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, CheckDestFilePathValid).WillOnce(Return(false));
    int32_t ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    EXPECT_CALL(ClientProxyFileManagerMock, CheckDestFilePathValid).WillRepeatedly(Return(true));
    EXPECT_CALL(ClientProxyFileManagerMock, GetAndCheckRealPath).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    EXPECT_CALL(ClientProxyFileManagerMock, GetAndCheckRealPath).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusOpenFile).WillOnce(Return(-1));
    ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    sendInfo.osType = TEST_ZERO;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusOpenFile).WillRepeatedly(Return(1));
    EXPECT_CALL(ClientProxyFileManagerMock, TryFileLock).WillOnce(Return(SOFTBUS_OK));
    ret = FileToFrameAndSendFile(&sendInfo, g_testProxyFileList[0], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: ClearSendInfoTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClearSendInfoTest001, TestSize.Level0)
{
    SendListenerInfo testSendInfo = {
        .fd = -1,
        .fileSize = 1,
    };
    ClearSendInfo(&testSendInfo);
    EXPECT_EQ(0, testSendInfo.fileSize);
}

/**
 * @tc.name: GetFileSizeTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, GetFileSizeTest001, TestSize.Level0)
{
    uint64_t fileSize = TEST_PACKET_SIZE;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, GetAndCheckRealPath).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetFileSize(g_testProxyFileList[0], &fileSize);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillOnce(Return(SOFTBUS_OK));
    ret = GetFileSize(g_testProxyFileList[0], &fileSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ProxyStartSendFileTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ProxyStartSendFileTest001, TestSize.Level0)
{
    SendListenerInfo testSendInfo = {
        .fd = -1,
        .fileSize = 1,
    };
    uint32_t fileCnt = 1;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, GetAndCheckRealPath).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ProxyStartSendFile(&testSendInfo, &g_testProxyFileList[0], &g_testProxyFileList[1], fileCnt);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, CheckDestFilePathValid).WillOnce(Return(false));
    ret = ProxyStartSendFile(&testSendInfo, &g_testProxyFileList[0], &g_testProxyFileList[1], fileCnt);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    fileCnt = 0;
    ret = ProxyStartSendFile(&testSendInfo, &g_testProxyFileList[0], &g_testProxyFileList[1], fileCnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetSendListenerInfoByChannelIdTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, GetSendListenerInfoByChannelIdTest001, TestSize.Level0)
{
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    EXPECT_TRUE(info != nullptr);
    info->sessionId = TEST_SESSION_ID;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t osType = OH_TYPE;
    // will free in ClientTransProxyDelChannelInfo
    ClientProxyChannelInfo *channelInfo = TestCreatInfo();
    ASSERT_TRUE(channelInfo != nullptr);

    int32_t ret = GetSendListenerInfoByChannelId(channelId, nullptr, osType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionIdByChannelId).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionDataById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionDataById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetFileConfigInfoById).WillOnce(Return(SOFTBUS_NO_INIT));
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetFileConfigInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, TransGetFileListener).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, TransGetFileListener).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetSendListenerInfoByChannelId(channelId, info, osType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(info);
}

/**
 * @tc.name: CreateSendListenerInfoTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, CreateSendListenerInfoTest001, TestSize.Level0)
{
    // will free in DelSendListenerInfo
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    EXPECT_TRUE(info != nullptr);
    info->sessionId = TEST_SESSION_ID;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t osType = OH_TYPE;
    // will free in ClientTransProxyDelChannelInfo
    ClientProxyChannelInfo *channelInfo = TestCreatInfo();
    ASSERT_TRUE(channelInfo != nullptr);
    int32_t ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionDataById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetFileConfigInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, TransGetFileListener).WillRepeatedly(Return(SOFTBUS_OK));
    ret = CreateSendListenerInfo(&info, channelId, osType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ReleaseSendListenerInfo(info);
}

/**
 * @tc.name: HandleFileSendingProcessTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, HandleFileSendingProcessTest001, TestSize.Level0)
{
    int channelId = TEST_CHANNEL_ID;
    uint32_t fileCnt = 1;
    // will free in ClientTransProxyDelChannelInfo
    ClientProxyChannelInfo *channelInfo = TestCreatInfo();
    ASSERT_TRUE(channelInfo != nullptr);
    int32_t ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionIdByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetSessionDataById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, ClientGetFileConfigInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, TransGetFileListener).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, GetAndCheckRealPath).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusGetFileSize).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientProxyFileManagerMock, CheckDestFilePathValid).WillOnce(Return(false));
    ret = HandleFileSendingProcess(channelId, &g_testProxyFileList[0], &g_testProxyFileList[1], fileCnt);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SENDMSG_ERR, ret);

    fileCnt = 0;
    ret = HandleFileSendingProcess(channelId, &g_testProxyFileList[0], &g_testProxyFileList[1], fileCnt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyAddChannelInfoTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClientTransProxyAddChannelInfoTest001, TestSize.Level0)
{
    // will free in ClientTransProxyDelChannelInfo
    ClientProxyChannelInfo *channelInfo = TestCreatInfo();
    ASSERT_TRUE(channelInfo != nullptr);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelOpenedTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClientTransProxyOnChannelOpenedTest001, TestSize.Level0)
{
    ChannelInfo channel = {
        .channelId = TEST_CHANNEL_ID,
        .isEncrypt = true,
        .linkType = LANE_HML,
        .osType = OH_TYPE,
        .sessionKey = const_cast<char *>(TEST_SESSION_KEY),
    };
    // will free in ClientTransProxyDelChannelInfo
    ClientProxyChannelInfo *channelInfo = TestCreatInfo();
    ASSERT_TRUE(channelInfo != nullptr);
    int32_t ret = ClientTransProxyAddChannelInfo(channelInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientTransProxyOnChannelOpened(TEST_SESSION_NAME, &channel);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);
    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxySessionDataLenCheckTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClientTransProxySessionDataLenCheckTest001, TestSize.Level0)
{
    uint32_t len = TEST_DATA_LEN;
    SessionPktType type = TRANS_SESSION_MESSAGE;
    int32_t ret = ClientTransProxySessionDataLenCheck(len, type);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    type = TRANS_SESSION_BYTES;
    ret = ClientTransProxySessionDataLenCheck(len, type);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
    type = TRANS_SESSION_FILE_LAST_FRAME;
    ret = ClientTransProxySessionDataLenCheck(len, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    len = 0;
    type = TRANS_SESSION_ASYNC_MESSAGE;
    ret = ClientTransProxySessionDataLenCheck(len, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    type = TRANS_SESSION_BYTES;
    ret = ClientTransProxySessionDataLenCheck(len, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyDecryptPacketDataTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClientTransProxyDecryptPacketDataTest001, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t seq = TEST_SEQ;
    ClientProxyDataInfo dataInfo;
    int32_t ret = ClientTransProxyDecryptPacketData(channelId, seq, &dataInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = ClientTransProxyCheckSliceHead(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyProcSendMsgAckTest001
 * @tc.desc: client send file crc check sum, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, ClientTransProxyProcSendMsgAckTest001, TestSize.Level0)
{
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t len = TEST_DATA_LEN;
    int32_t dataHeadSeq = TEST_DATA_LEN;
    int32_t ret = ClientTransProxyProcSendMsgAck(channelId, TEST_SESSION_NAME, len, dataHeadSeq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    len = PROXY_ACK_SIZE;
    ret = ClientTransProxyProcSendMsgAck(channelId, nullptr, len, dataHeadSeq);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL, ret);

    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusNtoHl).WillRepeatedly(Return(FILE_MAGIC_NUMBER));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusNtoHl).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = ClientTransProxyProcSendMsgAck(channelId, TEST_SESSION_NAME, len, dataHeadSeq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyProcSendMsgAck(channelId, TEST_SESSION_NAME, len, dataHeadSeq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS