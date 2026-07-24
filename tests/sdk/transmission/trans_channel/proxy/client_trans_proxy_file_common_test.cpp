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

#include <arpa/inet.h>
#include <iostream>
#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_proxy_file_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_FILE_LENGTH         10
#define TEST_FRAME_NUMBER        3
#define TEST_FRAME_NUMBER_SECOND 10
#define TEST_BUFFER_SIZE         1024
#define TEST_FD                  (-1)
#define TEST_RETRY_TIMES         2
#define TEST_DATA                26559
#define TEST_NORMAL_FD           128

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_filePath = "data/...ss/";
const char *g_testFileName = "test.txt";
const char *g_fileSet1[] = {
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

class ClientTransProxyFileCommonTest : public testing::Test {
public:
    ClientTransProxyFileCommonTest(void) { }
    ~ClientTransProxyFileCommonTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransProxyFileCommonTest::SetUpTestCase(void) { }
void ClientTransProxyFileCommonTest::TearDownTestCase(void) { }

/**
 * @tc.name: FileListToBufferTest001
 * @tc.desc: file list to buffer with valid file paths returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTest001, TestSize.Level1)
{
    FileListBuffer bufferInfo = { 0 };
    int32_t ret = FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(nullptr, bufferInfo.buffer);
    EXPECT_NE(0, bufferInfo.bufferSize);
    SoftBusFree(bufferInfo.buffer);
}

/**
 * @tc.name: FileListToBufferNullParamTest001
 * @tc.desc: file list to buffer with null or zero params returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferNullParamTest001, TestSize.Level1)
{
    FileListBuffer bufferInfo = { 0 };
    int32_t ret = FileListToBuffer(nullptr, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, bufferInfo.buffer);
    EXPECT_EQ(0, bufferInfo.bufferSize);
    ret = FileListToBuffer(g_fileSet1, 0, &bufferInfo);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, bufferInfo.buffer);
    EXPECT_EQ(0, bufferInfo.bufferSize);
    ret = FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: FileListToBufferInvalidPathTest001
 * @tc.desc: file list to buffer with path exceeding max length or empty path returns invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferInvalidPathTest001, TestSize.Level1)
{
    const char *longPathSet[] = { "/dev/path/to",
        "/path/max/length/more/than/512/"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111111111111111" };
    FileListBuffer bufferInfo = { 0 };
    int32_t ret = FileListToBuffer(longPathSet, sizeof(longPathSet) / sizeof(const char *), &bufferInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    const char *emptyPathSet[] = { "/dev/path/to", "" };
    FileListBuffer bufferInfo2 = { 0 };
    ret = FileListToBuffer(emptyPathSet, sizeof(emptyPathSet) / sizeof(const char *), &bufferInfo2);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: BufferToFileListValidDataTest001
 * @tc.desc: buffer to file list with valid encoded buffer returns correct file list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, BufferToFileListValidDataTest001, TestSize.Level1)
{
    FileListBuffer bufferInfo = { 0 };
    int32_t ret = FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo);
    ASSERT_EQ(SOFTBUS_OK, ret);
    int32_t fileCount = 0;
    char *result = BufferToFileList(bufferInfo.buffer, bufferInfo.bufferSize, &fileCount);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(sizeof(g_fileSet1) / sizeof(const char *), fileCount);
    EXPECT_STREQ(g_fileSet1[0], result);
    SoftBusFree(bufferInfo.buffer);
}

/**
 * @tc.name: BufferToFileListNullParamTest001
 * @tc.desc: buffer to file list with null or zero params returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, BufferToFileListNullParamTest001, TestSize.Level1)
{
    int32_t fileCount = 0;
    char *result = BufferToFileList(nullptr, TEST_BUFFER_SIZE, &fileCount);
    EXPECT_STREQ(nullptr, result);
    uint8_t buffer[] = { 0 };
    result = BufferToFileList(buffer, 0, &fileCount);
    EXPECT_STREQ(nullptr, result);
    result = BufferToFileList(buffer, TEST_BUFFER_SIZE, nullptr);
    EXPECT_STREQ(nullptr, result);
}

/**
 * @tc.name: BufferToFileListInvalidContentTest001
 * @tc.desc: buffer to file list with invalid buffer content returns nullptr and file count unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, BufferToFileListInvalidContentTest001, TestSize.Level1)
{
    int32_t fileCount = 0;
    uint8_t buffer[] = { 0 };
    char *result = BufferToFileList(buffer, TEST_BUFFER_SIZE, &fileCount);
    EXPECT_STREQ(nullptr, result);
    EXPECT_EQ(0, fileCount);
}

/**
 * @tc.name: IsPathValidTest001
 * @tc.desc: is path valid with null empty non-leading-slash and overlength paths returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, IsPathValidTest001, TestSize.Level1)
{
    bool result = IsPathValid(nullptr);
    EXPECT_EQ(false, result);
    char filePath[TEST_FILE_LENGTH] = { 0 };
    result = IsPathValid(filePath);
    EXPECT_EQ(false, result);
    result = IsPathValid(const_cast<char *>(g_fileSet1[1]));
    EXPECT_EQ(false, result);
    result = IsPathValid(const_cast<char *>(g_filePath));
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: IsPathValidTest002
 * @tc.desc: is path valid with valid paths returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, IsPathValidTest002, TestSize.Level1)
{
    bool result = IsPathValid(const_cast<char *>(g_fileSet1[0]));
    EXPECT_EQ(true, result);
    result = IsPathValid(const_cast<char *>(g_fileSet1[3]));
    EXPECT_EQ(true, result);
    char validPath[] = "/tmp/test";
    result = IsPathValid(validPath);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: GetAndCheckRealPathTest001
 * @tc.desc: get and check real path with null or non-existent paths returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, GetAndCheckRealPathTest001, TestSize.Level1)
{
    char absPath[PATH_MAX] = { 0 };
    int32_t ret = GetAndCheckRealPath(nullptr, absPath);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = GetAndCheckRealPath(g_fileSet1[0], absPath);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    ret = GetAndCheckRealPath(g_fileSet1[2], absPath);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: CheckDestFilePathValidTest001
 * @tc.desc: check dest file path valid with null empty and non-leading-slash paths returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, CheckDestFilePathValidTest001, TestSize.Level1)
{
    bool result = CheckDestFilePathValid(nullptr);
    EXPECT_EQ(false, result);
    char filePath[TEST_FILE_LENGTH] = { 0 };
    result = CheckDestFilePathValid(filePath);
    EXPECT_EQ(false, result);
    result = CheckDestFilePathValid(g_filePath);
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: CheckDestFilePathValidTest002
 * @tc.desc: check dest file path valid with valid dest paths returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, CheckDestFilePathValidTest002, TestSize.Level1)
{
    bool result = CheckDestFilePathValid(g_fileSet1[1]);
    EXPECT_EQ(true, result);
    result = CheckDestFilePathValid(g_fileSet1[2]);
    EXPECT_EQ(true, result);
    result = CheckDestFilePathValid(g_fileSet1[3]);
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: FrameIndexToTypeTest001
 * @tc.desc: frame index to type returns correct frame type for each position
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FrameIndexToTypeTest001, TestSize.Level1)
{
    int32_t ret = FrameIndexToType(FRAME_NUM_0, FRAME_NUM_1);
    EXPECT_EQ(TRANS_SESSION_FILE_FIRST_FRAME, ret);
    ret = FrameIndexToType(FRAME_NUM_1, FRAME_NUM_2);
    EXPECT_EQ(TRANS_SESSION_FILE_ONLYONE_FRAME, ret);
    ret = FrameIndexToType(FRAME_NUM_2, TEST_FRAME_NUMBER);
    EXPECT_EQ(TRANS_SESSION_FILE_LAST_FRAME, ret);
    ret = FrameIndexToType(FRAME_NUM_2, TEST_FRAME_NUMBER_SECOND);
    EXPECT_EQ(TRANS_SESSION_FILE_ONGOINE_FRAME, ret);
}

/**
 * @tc.name: RtuCrcTest001
 * @tc.desc: rtu crc calculation returns expected value for known input and non-zero for other inputs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, RtuCrcTest001, TestSize.Level1)
{
    const unsigned char strTmp[] = "test";
    uint16_t ret = RTU_CRC(strTmp, 1);
    EXPECT_EQ(TEST_DATA, ret);
    ret = RTU_CRC(strTmp, 4);
    EXPECT_NE(0, ret);
    const unsigned char strTmp2[] = "ab";
    ret = RTU_CRC(strTmp2, 2);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: TransGetFileNameTest001
 * @tc.desc: trans get file name with null empty and no-separator paths returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, TransGetFileNameTest001, TestSize.Level1)
{
    const char *result = TransGetFileName(nullptr);
    EXPECT_STREQ(nullptr, result);
    const char fileName[TEST_FILE_LENGTH] = { 0 };
    result = TransGetFileName(fileName);
    EXPECT_STREQ(nullptr, result);
    result = TransGetFileName(g_filePath);
    EXPECT_STREQ(nullptr, result);
}

/**
 * @tc.name: TransGetFileNameTest002
 * @tc.desc: trans get file name with valid file paths returns correct filename
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, TransGetFileNameTest002, TestSize.Level1)
{
    const char *result = TransGetFileName(g_testFileName);
    EXPECT_STREQ(g_testFileName, result);
    result = TransGetFileName(g_fileSet1[0]);
    EXPECT_STREQ(g_testFileName, result);
    result = TransGetFileName(g_fileSet1[3]);
    EXPECT_STREQ("ss", result);
}

/**
 * @tc.name: TryFileLockTest001
 * @tc.desc: try file lock with various fd and retry times returns expected error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, TryFileLockTest001, TestSize.Level1)
{
    int32_t fd = TEST_NORMAL_FD;
    int32_t ret = TryFileLock(fd, SOFTBUS_F_RDLCK, 0);
    EXPECT_EQ(SOFTBUS_FILE_BUSY, ret);
    ret = TryFileLock(TEST_FD, SOFTBUS_F_RDLCK, TEST_RETRY_TIMES);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
    ret = TryFileLock(fd, SOFTBUS_F_RDLCK, TEST_RETRY_TIMES);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: FileLockTest001
 * @tc.desc: file lock and unlock with valid and invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileLockTest001, TestSize.Level1)
{
    int32_t fd = TEST_NORMAL_FD;
    int32_t ret = FileLock(fd, SOFTBUS_F_RDLCK, false);
    EXPECT_NE(SOFTBUS_OK, ret);
    ret = FileLock(fd, SOFTBUS_F_RDLCK, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = FileUnLock(TEST_FD);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = FileUnLock(fd);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS
