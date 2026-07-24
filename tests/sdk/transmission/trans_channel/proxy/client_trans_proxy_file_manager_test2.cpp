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

/*
 * This file is textually included by client_trans_proxy_file_manager_test.cpp
 * Do not compile separately. It shares the translation unit to avoid
 * duplicate symbol conflicts from #include of .c source files.
 */

namespace OHOS {
using namespace std;
using namespace testing::ext;

/*
 * @tc.name: SendSingleFileTest001
 * @tc.desc: send single file with valid params returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendSingleFileTest001, TestSize.Level1)
{
    SendListenerInfo info;
    info.sessionId = 1;
    info.crc = 1;
    info.channelId = 1;
    int32_t ret = SendSingleFile(&info, g_testProxyFileList[0], g_testProxyFileList[0]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = SendSingleFile(&info, g_testProxyFileList[1], g_testProxyFileList[1]);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/*
 * @tc.name: SendFileListTest001
 * @tc.desc: send file list with no channel returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, SendFileListTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = SendFileList(channelId, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = SendFileList(channelId, nullptr, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: FileToFrameCrcNotSupportTest001
 * @tc.desc: file to frame with crc not support returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, FileToFrameCrcNotSupportTest001, TestSize.Level1)
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
}

/*
 * @tc.name: FileToFrameCrcSupportTest001
 * @tc.desc: file to frame with crc support returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, FileToFrameCrcSupportTest001, TestSize.Level1)
{
    SendListenerInfo sendInfo = {
        .channelId = 1,
        .sessionId = 1,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    int32_t ret = FileToFrame(&sendInfo, TEST_FRAME_NUMBER, g_destFile, TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = FileToFrame(&sendInfo, TEST_FRAME_NUMBER + 1, g_destFile, TEST_FILE_TEST_TXT_FILE);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/*
 * @tc.name: ProxyStartSendFileTest001
 * @tc.desc: proxy start send file with valid params returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyStartSendFileTest001, TestSize.Level1)
{
    SendListenerInfo sendInfo = {
        .channelId = 1,
        .sessionId = 1,
        .crc = APP_INFO_FILE_FEATURES_NO_SUPPORT,
    };
    int32_t ret = ProxyStartSendFile(&sendInfo, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = ProxyStartSendFile(&sendInfo, g_testProxyFileList, g_testProxyFileList, TEST_FILE_CNT + 1);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/*
 * @tc.name: CheckRecvFileExistTest001
 * @tc.desc: check recv file exist with null path and nonexistent file returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CheckRecvFileExistTest001, TestSize.Level1)
{
    bool result = CheckRecvFileExist(nullptr);
    EXPECT_EQ(false, result);

    result = CheckRecvFileExist(g_testProxyFileList[0]);
    EXPECT_EQ(false, result);

    result = CheckRecvFileExist(g_testProxyFileList[1]);
    EXPECT_EQ(false, result);
}

/*
 * @tc.name: PutToRecvFileListInvalidParamTest001
 * @tc.desc: put to recv file list with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PutToRecvFileListInvalidParamTest001, TestSize.Level1)
{
    int32_t ret = PutToRecvFileList(nullptr, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileRecipientInfo recipient = { };
    recipient.recvFileInfo.fileStatus = NODE_ERR;
    const SingleFileInfo file = { 0 };
    ret = PutToRecvFileList(&recipient, &file);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: PutToRecvFileListIdleTest001
 * @tc.desc: put to recv file list with idle status and valid file returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, PutToRecvFileListIdleTest001, TestSize.Level1)
{
    FileRecipientInfo recipient = { };
    recipient.recvFileInfo.fileStatus = NODE_IDLE;
    SingleFileInfo trueFile = { 0 };
    (void)memcpy_s(trueFile.filePath, MAX_FILE_PATH_NAME_LEN, g_recvFile, strlen(g_recvFile) + 1);
    int32_t ret = PutToRecvFileList(&recipient, &trueFile);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const SingleFileInfo file = { 0 };
    ret = PutToRecvFileList(&recipient, &file);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetRecipientNoLockTest001
 * @tc.desc: get recipient no lock returns null when not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetRecipientNoLockTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    FileRecipientInfo *result = GetRecipientNoLock(sessionId);
    EXPECT_EQ(nullptr, result);

    sessionId = -1;
    result = GetRecipientNoLock(sessionId);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ProcessFileSendResultTest001
 * @tc.desc: process file send result with no recipient returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileSendResultTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    uint32_t seq = 0;
    int32_t res = 0;
    int32_t ret = ProcessFileSendResult(sessionId, seq, res);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    sessionId = -1;
    ret = ProcessFileSendResult(sessionId, seq, res);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileRecvResultTest001
 * @tc.desc: process file recv result with no listener returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileRecvResultTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    uint32_t seq = 0;
    int32_t res = 0;
    int32_t ret = ProcessFileRecvResult(sessionId, seq, res);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    ret = ProcessFileRecvResult(sessionId, seq, res);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ReleaseRecipientRefTest001
 * @tc.desc: release recipient ref with null and valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ReleaseRecipientRefTest001, TestSize.Level1)
{
    ReleaseRecipientRef(nullptr);

    FileRecipientInfo *info = reinterpret_cast<FileRecipientInfo *>(SoftBusCalloc(sizeof(FileRecipientInfo)));
    ASSERT_TRUE(info != nullptr);
    info->objRefCount = 2;
    ReleaseRecipientRef(info);

    info->objRefCount = 1;
    ReleaseRecipientRef(info);
}

/*
 * @tc.name: GetRecipientInProcessRefTest001
 * @tc.desc: get recipient in process ref returns null when no recipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetRecipientInProcessRefTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    FileRecipientInfo *result = GetRecipientInProcessRef(sessionId);
    EXPECT_EQ(nullptr, result);

    sessionId = 1;
    result = GetRecipientInProcessRef(sessionId);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: GetRecipientInCreateFileRefTest001
 * @tc.desc: get recipient in create file ref returns null when no session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetRecipientInCreateFileRefTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t channelId = 1;
    int32_t osType = TEST_OS_TYPE;
    FileRecipientInfo *result = GetRecipientInCreateFileRef(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);

    sessionId = 1;
    result = GetRecipientInCreateFileRef(sessionId, channelId, osType);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: WriteEmptyFrameInvalidParamTest001
 * @tc.desc: write empty frame with null info returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, WriteEmptyFrameInvalidParamTest001, TestSize.Level1)
{
    int32_t cnt = 0;
    int32_t ret = WriteEmptyFrame(nullptr, cnt);
    EXPECT_NE(SOFTBUS_OK, ret);

    SingleFileInfo info = { 0 };
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: WriteEmptyFrameInvalidLenTest001
 * @tc.desc: write empty frame with negative one frame len returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, WriteEmptyFrameInvalidLenTest001, TestSize.Level1)
{
    int32_t cnt = 1;
    SingleFileInfo info = { 0 };
    info.fileFd = g_fd;
    info.oneFrameLen = -1;
    info.fileOffset = 0;
    int32_t ret = WriteEmptyFrame(&info, cnt);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: WriteEmptyFrameTest001
 * @tc.desc: write empty frame with valid params returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, WriteEmptyFrameTest001, TestSize.Level1)
{
    int32_t cnt = 1;
    SingleFileInfo info = { 0 };
    info.fileFd = g_fd;
    info.oneFrameLen = TEST_FILE_LENGTH;
    info.fileOffset = 0;
    int32_t ret = WriteEmptyFrame(&info, cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.oneFrameLen = TEST_FILE_LENGTH + 1;
    ret = WriteEmptyFrame(&info, cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessOneFrameCRCInvalidParamTest001
 * @tc.desc: process one frame crc with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCRCInvalidParamTest001, TestSize.Level1)
{
    uint32_t dataLen = 0;
    int32_t ret = ProcessOneFrameCRC(nullptr, dataLen, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessOneFrameCRC(nullptr, dataLen + 1, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessOneFrameCRCSeqTest001
 * @tc.desc: process one frame crc with seq less than start seq returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCRCSeqTest001, TestSize.Level1)
{
    uint8_t *emptyBuff = reinterpret_cast<uint8_t *>(SoftBusCalloc(TEST_FILE_SIZE));
    ASSERT_TRUE(emptyBuff != nullptr);
    uint32_t dataLen = 0;
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
    int32_t ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.seq = TEST_SEQ128;
    fileInfo.seq = TEST_SEQ126;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(emptyBuff);
}

/*
 * @tc.name: ProcessOneFrameCRCLastFrameTest001
 * @tc.desc: process one frame crc with last frame type returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCRCLastFrameTest001, TestSize.Level1)
{
    uint8_t *emptyBuff = reinterpret_cast<uint8_t *>(SoftBusCalloc(TEST_FILE_SIZE));
    ASSERT_TRUE(emptyBuff != nullptr);
    uint32_t dataLen = 0;
    FileFrame frame = {
        .frameType = TRANS_SESSION_FILE_LAST_FRAME,
        .seq = TEST_SEQ128,
        .fileData = emptyBuff,
    };
    SingleFileInfo fileInfo = {
        .seq = TEST_SEQ126,
        .fileFd = g_fd,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = 0,
        .preStartSeq = TEST_SEQ128,
    };
    int32_t ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);

    fileInfo.startSeq = TEST_SEQ8;
    frame.seq = TEST_SEQ_SECOND;
    ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(emptyBuff);
}

/*
 * @tc.name: ProcessOneFrameCRCValidTest001
 * @tc.desc: process one frame crc with valid data returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCRCValidTest001, TestSize.Level1)
{
    uint8_t *emptyBuff = reinterpret_cast<uint8_t *>(SoftBusCalloc(TEST_FILE_SIZE));
    ASSERT_TRUE(emptyBuff != nullptr);
    uint32_t dataLen = TEST_SEQ16;
    FileFrame frame = {
        .frameType = TRANS_SESSION_FILE_LAST_FRAME,
        .seq = TEST_SEQ_SECOND,
        .fileData = emptyBuff,
    };
    SingleFileInfo fileInfo = {
        .seq = TEST_SEQ126,
        .fileFd = g_fd,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = TEST_SEQ8,
        .preStartSeq = TEST_SEQ128,
    };
    int32_t ret = ProcessOneFrameCRC(&frame, dataLen, &fileInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(emptyBuff);
}

/*
 * @tc.name: ProcessOneFrameErrStatusTest001
 * @tc.desc: process one frame with error file status returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameErrStatusTest001, TestSize.Level1)
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
}

/*
 * @tc.name: ProcessOneFrameCrcSupportTest001
 * @tc.desc: process one frame with crc support and idle status returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCrcSupportTest001, TestSize.Level1)
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
        .fileStatus = NODE_IDLE,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = 0,
        .preStartSeq = 0,
    };
    int32_t ret = ProcessOneFrame(&frame, dataLen, crc, &fileInfo, osType);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessOneFrameCrcNotSupportTest001
 * @tc.desc: process one frame with crc not support returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessOneFrameCrcNotSupportTest001, TestSize.Level1)
{
    FileFrame frame = {
        .frameType = TRANS_SESSION_FILE_FIRST_FRAME,
        .seq = TEST_SEQ32,
    };
    uint32_t dataLen = TEST_SEQ16;
    int32_t crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    int32_t osType = TEST_OS_TYPE;
    SingleFileInfo fileInfo = {
        .seq = 0,
        .fileFd = g_fd,
        .fileStatus = NODE_IDLE,
        .fileOffset = 0,
        .oneFrameLen = TEST_FILE_LENGTH,
        .startSeq = 0,
        .preStartSeq = 0,
    };
    int32_t ret = ProcessOneFrame(&frame, dataLen, crc, &fileInfo, osType);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessCrcCheckSumDataNullFrameTest001
 * @tc.desc: process crc check sum data with null frame returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessCrcCheckSumDataNullFrameTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = ProcessCrcCheckSumData(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileFrame frame = {
        .seq = TEST_SEQ32,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessCrcCheckSumDataTest001
 * @tc.desc: process crc check sum data with valid session returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessCrcCheckSumDataTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    FileFrame frame = {
        .seq = TEST_SEQ32,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
    };
    int32_t ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    ret = ProcessCrcCheckSumData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileAckRequestNullFrameTest001
 * @tc.desc: process file ack request with null frame returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileAckRequestNullFrameTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = ProcessFileAckRequest(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    ret = ProcessFileAckRequest(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileAckRequestTest001
 * @tc.desc: process file ack request with valid frame returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileAckRequestTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    FileFrame frame = {
        .frameLength = TEST_HEADER_LENGTH,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = nullptr,
    };
    int32_t ret = ProcessFileAckRequest(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    sessionId = 1;
    uint32_t dataTest = FILE_MAGIC_NUMBER;
    frame.data = reinterpret_cast<uint8_t *>(&dataTest);
    ret = ProcessFileAckRequest(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileAckResponseNullFrameTest001
 * @tc.desc: process file ack response with null frame returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileAckResponseNullFrameTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    int32_t ret = ProcessFileAckResponse(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileFrame frame = {
        .frameLength = 0,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = nullptr,
    };
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileAckResponseTest001
 * @tc.desc: process file ack response with valid data returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileAckResponseTest001, TestSize.Level1)
{
    int32_t sessionId = -1;
    uint32_t dataTest[TEST_FRAME_DATA_LENGTH] = { 0 };
    dataTest[TEST_FILE_MAGIC_OFFSET] = FILE_MAGIC_NUMBER;
    FileFrame frame = {
        .frameLength = 0,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = reinterpret_cast<uint8_t *>(dataTest),
    };
    int32_t ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameLength = TEST_HEADER_LENGTH;
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileAckResponseWithListenerTest001
 * @tc.desc: process file ack response with send listener returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileAckResponseWithListenerTest001, TestSize.Level1)
{
    uint32_t dataTest[TEST_FRAME_DATA_LENGTH] = { 0 };
    dataTest[TEST_FILE_MAGIC_OFFSET] = FILE_MAGIC_NUMBER;
    FileFrame frame = {
        .frameLength = TEST_HEADER_LENGTH,
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .data = reinterpret_cast<uint8_t *>(dataTest),
    };
    SendListenerInfo *info = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    ASSERT_TRUE(info != nullptr);
    info->sessionId = 1;
    info->crc = 1;
    info->channelId = 1;
    int32_t ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    *reinterpret_cast<uint64_t *>(frame.data + FRAME_MAGIC_OFFSET) = FRAME_DATA_SEQ_OFFSET + FRAME_DATA_SEQ_OFFSET;
    int32_t sessionId = 1;
    ret = ProcessFileAckResponse(sessionId, &frame);
    EXPECT_EQ(SOFTBUS_OK, ret);

    DelSendListenerInfo(info);
}

/*
 * @tc.name: IsValidFileStringTest001
 * @tc.desc: is valid file string with null list and zero count returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, IsValidFileStringTest001, TestSize.Level1)
{
    bool result = IsValidFileString(nullptr, TEST_FILE_CNT, TEST_FILE_LENGTH);
    EXPECT_EQ(false, result);

    uint32_t fileNum = 0;
    result = IsValidFileString(g_testProxyFileList, fileNum, TEST_FILE_LENGTH);
    EXPECT_EQ(false, result);
}

/*
 * @tc.name: ProcessFileTransResultNullFrameTest001
 * @tc.desc: process file trans result with null frame returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileTransResultNullFrameTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    int32_t ret = ProcessFileTransResult(sessionId, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileTransResult(sessionId + 1, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProcessFileListDataTest001
 * @tc.desc: process file list data with no recipient returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileListDataTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    FileFrame frame = {
        .frameLength = TEST_FILE_SIZE,
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>("00010010datatest,")),
    };
    int32_t ret = ProcessFileListData(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileListData(sessionId + 1, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetFileInfoByStartFrameInvalidParamTest001
 * @tc.desc: get file info by start frame with null params returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetFileInfoByStartFrameInvalidParamTest001, TestSize.Level1)
{
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = GetFileInfoByStartFrame(nullptr, nullptr, nullptr, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);

    FileFrame frame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>("00010010datatest.txt")),
    };
    FileRecipientInfo info = { };
    (void)strcpy_s(info.fileListener.rootDir, sizeof(info.fileListener.rootDir), "../test");
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    SingleFileInfo file;
    ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: GetFileInfoByStartFrameCrcNotSupportTest001
 * @tc.desc: get file info by start frame with crc not support returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetFileInfoByStartFrameCrcNotSupportTest001, TestSize.Level1)
{
    FileFrame frame = {
        .frameLength = FRAME_DATA_SEQ_OFFSET + 9,
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>("00010010datatest.txt")),
    };
    FileRecipientInfo info = { };
    (void)strcpy_s(info.fileListener.rootDir, sizeof(info.fileListener.rootDir), "/data");
    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    SingleFileInfo file;
    uint32_t packetSize = TEST_PACKET_SIZE;
    int32_t ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    info.crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    frame.frameLength = FRAME_DATA_SEQ_OFFSET + 10;
    ret = GetFileInfoByStartFrame(&frame, &info, &file, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: WriteFrameToFileTest001
 * @tc.desc: write frame to file with no recipient returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, WriteFrameToFileTest001, TestSize.Level1)
{
    int32_t sessionId = 1;
    FileFrame frame = {
        .frameLength = 0,
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>("00010010datatest.txt")),
    };
    int32_t ret = WriteFrameToFile(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);

    frame.frameLength = TEST_DATA_LENGTH;
    ret = WriteFrameToFile(sessionId, &frame);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ProxyChannelSendFileStreamTest001
 * @tc.desc: proxy channel send file stream with no channel returns not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProxyChannelSendFileStreamTest001, TestSize.Level1)
{
    int32_t channelId = 1;
    const char *data = "test_data";
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t type = 1;
    int32_t ret = ProxyChannelSendFileStream(channelId, data, len, type);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);

    ret = ProxyChannelSendFileStream(channelId + 1, data, len, type);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
}

/*
 * @tc.name: UpdateFileReceivePathTest001
 * @tc.desc: update file receive path with null callback returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, UpdateFileReceivePathTest001, TestSize.Level1)
{
    int32_t sessionId = TEST_SESSION_ID;
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    ASSERT_TRUE(fileListener != nullptr);
    fileListener->socketRecvCallback = nullptr;
    int32_t ret = UpdateFileReceivePath(sessionId, fileListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(fileListener);
}

/*
 * @tc.name: GetRecipientInfoTest001
 * @tc.desc: get recipient info returns null when no recipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, GetRecipientInfoTest001, TestSize.Level1)
{
    int32_t sessionId = TEST_SESSION_ID;
    FileRecipientInfo *result = GetRecipientInfo(sessionId);
    EXPECT_EQ(nullptr, result);

    result = GetRecipientInfo(sessionId + 1);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: CreateFileFromFrameTest001
 * @tc.desc: create file from frame with no recipient returns no init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CreateFileFromFrameTest001, TestSize.Level1)
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

    ret = CreateFileFromFrame(sessionId + 1, channelId, &fileFrame, osType, packetSize);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
 * @tc.name: ProcessFileFrameDataTest001
 * @tc.desc: process file frame data with byte type returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, ProcessFileFrameDataTest001, TestSize.Level1)
{
    int32_t sessionId = TEST_SESSION_ID;
    int32_t channelId = TEST_CHANNEL_ID;
    const char *dataFile = "TEST_FILE_DATA";
    uint32_t len = TEST_HEADER_LENGTH;
    int32_t type = 0;
    int32_t ret = ProcessFileFrameData(sessionId, channelId, dataFile, len, type);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ProcessFileFrameData(sessionId, channelId, dataFile, len, type + 1);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CalcAllFilesInfoTest001
 * @tc.desc: calc all files info with nonexistent files returns file err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CalcAllFilesInfoTest001, TestSize.Level1)
{
    const char *fileList[] = {
        "test0",
        "test1",
        "test2",
        "test3",
        "test4",
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

/*
 * @tc.name: TransProxyChannelSendFileInvalidParamTest001
 * @tc.desc: trans proxy channel send file with null sFileList returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, TransProxyChannelSendFileInvalidParamTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    const char *sFileList[] = {
        "test0",
        "test1",
    };
    const char *dFileList[] = {
        "test0",
        "test1",
    };
    int32_t ret = TransProxyChannelSendFile(channelId, nullptr, dFileList, TEST_FILE_CNT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint32_t fileCnt = 0;
    ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fileCnt = 12;
    ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransProxyChannelSendFileGenerateRemoteTest001
 * @tc.desc: trans proxy channel send file with null dFileList generates remote files
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, TransProxyChannelSendFileGenerateRemoteTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    const char *sFileList[] = {
        "test0",
        "test1",
    };
    const char *dFileList[] = {
        "test0",
        "test1",
    };
    GenerateRemoteFiles(sFileList, TEST_FILE_CNT);
    int32_t ret = TransProxyChannelSendFile(channelId, sFileList, dFileList, TEST_FILE_CNT);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CheckFrameLengthBrTest001
 * @tc.desc: check frame length with br channel and overflow returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CheckFrameLengthBrTest001, TestSize.Level1)
{
    int32_t osType = TEST_OS_TYPE;
    uint32_t packetSize;
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
    ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE + 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE - 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CheckFrameLengthBleTest001
 * @tc.desc: check frame length with ble channel and overflow returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CheckFrameLengthBleTest001, TestSize.Level1)
{
    int32_t osType = TEST_OS_TYPE;
    uint32_t packetSize;
    ChannelInfo *channel = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    ASSERT_TRUE(channel != nullptr);
    channel->channelId = 2;
    channel->isEncrypt = 0;
    channel->linkType = LANE_BLE_DIRECT;
    channel->sessionKey = const_cast<char *>(g_sessionKey);
    channel->keyLen = TEST_SEQ32;
    int32_t ret = ClientTransProxyAddChannelInfo(ClientTransProxyCreateChannelInfo(channel));
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
    ret = CheckFrameLength(2, PROXY_BLE_MAX_PACKET_SIZE + 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckFrameLength(2, PROXY_BLE_MAX_PACKET_SIZE - 1, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(2);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CheckFrameLengthNoChannelTest001
 * @tc.desc: check frame length with no channel returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerTest, CheckFrameLengthNoChannelTest001, TestSize.Level1)
{
    int32_t osType = TEST_OS_TYPE;
    uint32_t packetSize;
    int32_t ret = CheckFrameLength(1, PROXY_BR_MAX_PACKET_SIZE, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = CheckFrameLength(2, PROXY_BLE_MAX_PACKET_SIZE, osType, &packetSize);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}
} // namespace OHOS
