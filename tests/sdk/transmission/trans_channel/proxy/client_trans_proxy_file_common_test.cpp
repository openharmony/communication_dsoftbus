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

#include <arpa/inet.h>
#include <iostream>

#include <gtest/gtest.h>
#include "securec.h"

#include "client_trans_proxy_file_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_FILE_LENGTH 10
#define TEST_INDEX 5
#define TEST_FRAME_NUMBER 3
#define TEST_FRAME_NUMBER_SECOND 10
#define TEST_BUFFER_SIZE 1024
#define TEST_FD (-1)
#define TEST_RETRY_TIMES 2
#define TEST_DATA 26559
#define TEST_NORMAL_FD 128

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
    ClientTransProxyFileCommonTest() {}
    ~ClientTransProxyFileCommonTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyFileCommonTest::SetUpTestCase(void) {}
void ClientTransProxyFileCommonTest::TearDownTestCase(void) {}

/**
 * @tc.name: FileListToBufferTest
 * @tc.desc: file list to buffer test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTest, TestSize.Level0)
{
    FileListBuffer bufferInfo = {0};
    EXPECT_EQ(0, FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo));

    int32_t fileCount = 0;
    const char *oldFirstFileName = BufferToFileList(bufferInfo.buffer, bufferInfo.bufferSize, &fileCount);

    ASSERT_NE(oldFirstFileName, nullptr);
    EXPECT_EQ(fileCount, sizeof(g_fileSet1) / sizeof(const char *));

    EXPECT_EQ(0, strcmp(oldFirstFileName, g_fileSet1[0]));

    SoftBusFree(bufferInfo.buffer);
}

/**
 * @tc.name: FileListToBufferTestBadInput1
 * @tc.desc: file list to buffer test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput1, TestSize.Level0)
{
    FileListBuffer bufferInfo = {0};
    EXPECT_NE(0, FileListToBuffer(nullptr, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo));

    EXPECT_EQ(bufferInfo.buffer, nullptr);
    EXPECT_EQ(bufferInfo.bufferSize, 0);
}

/**
 * @tc.name: FileListToBufferTestBadInput2
 * @tc.desc: file list to buffer test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput2, TestSize.Level0)
{
    FileListBuffer bufferInfo = {0};
    EXPECT_NE(0, FileListToBuffer(g_fileSet1, 0, &bufferInfo));

    EXPECT_EQ(bufferInfo.buffer, nullptr);
    EXPECT_EQ(bufferInfo.bufferSize, 0);
}

/**
 * @tc.name: FileListToBufferTestBadInput3
 * @tc.desc: file list to buffer test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput3, TestSize.Level0)
{
    EXPECT_NE(0, FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), nullptr));
}

/**
 * @tc.name: FileListToBufferTestBadInput4
 * @tc.desc: file list to buffer test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput4, TestSize.Level0)
{
    const char *fileSet[] = {
        "/dev/path/to",
        "/path/max/length/more/than/512/"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111111111111111"
    };
    FileListBuffer bufferInfo = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, FileListToBuffer(fileSet, sizeof(fileSet) / sizeof(const char *), &bufferInfo));
}

/**
 * @tc.name: FileListToBufferTestBadInput5
 * @tc.desc: file list to buffer test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput5, TestSize.Level0)
{
    const char *fileSet[] = {"/dev/path/to", ""};
    FileListBuffer bufferInfo = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, FileListToBuffer(fileSet, sizeof(fileSet) / sizeof(const char *), &bufferInfo));
}

/**
 * @tc.name: ClinetTransProxyFilePathTest
 * @tc.desc: client trans proxy file path test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, ClinetTransProxyFilePathTest, TestSize.Level0)
{
    bool result = IsPathValid(nullptr);
    EXPECT_EQ(false, result);

    char filePath[TEST_FILE_LENGTH] = {0};
    result = IsPathValid(filePath);
    EXPECT_EQ(false, result);

    result = IsPathValid(const_cast<char*>(g_fileSet1[1]));
    EXPECT_EQ(false, result);

    result = IsPathValid(const_cast<char*>(g_filePath));
    EXPECT_EQ(false, result);

    result = IsPathValid(const_cast<char*>(g_fileSet1[0]));
    EXPECT_EQ(true, result);

    int32_t ret = GetAndCheckRealPath(nullptr, const_cast<char*>(g_fileSet1[0]));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    char absPath[PATH_MAX] = {0};
    ret = GetAndCheckRealPath(g_fileSet1[0], absPath);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = GetAndCheckRealPath(g_fileSet1[2], absPath);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    result = CheckDestFilePathValid(nullptr);
    EXPECT_EQ(false, result);

    result = CheckDestFilePathValid(filePath);
    EXPECT_EQ(false, result);

    result = CheckDestFilePathValid(g_fileSet1[1]);
    EXPECT_EQ(true, result);

    result = CheckDestFilePathValid(g_filePath);
    EXPECT_EQ(false, result);

    result = CheckDestFilePathValid(g_fileSet1[2]);
    EXPECT_EQ(true, result);

    ret = FrameIndexToType(FRAME_NUM_0, FRAME_NUM_1);
    EXPECT_EQ(TRANS_SESSION_FILE_FIRST_FRAME, ret);

    ret = FrameIndexToType(FRAME_NUM_1, FRAME_NUM_2);
    EXPECT_EQ(TRANS_SESSION_FILE_ONLYONE_FRAME, ret);

    ret = FrameIndexToType(FRAME_NUM_2, TEST_FRAME_NUMBER);
    EXPECT_EQ(TRANS_SESSION_FILE_LAST_FRAME, ret);

    ret = FrameIndexToType(FRAME_NUM_2, TEST_FRAME_NUMBER_SECOND);
    EXPECT_EQ(TRANS_SESSION_FILE_ONGOINE_FRAME, ret);
}

/**
 * @tc.name: ClinetTransProxyFileNameTest
 * @tc.desc: client trans proxy file name test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, ClinetTransProxyFileNameTest, TestSize.Level0)
{
    uint16_t usDataLen = 1;
    const unsigned char strTmp[] = "test";
    uint16_t ret = RTU_CRC(strTmp, usDataLen);
    EXPECT_EQ(TEST_DATA, ret);
    
    const char *resultFirst = TransGetFileName(nullptr);
    EXPECT_STREQ(nullptr, resultFirst);

    const char fileName[TEST_FILE_LENGTH] = {0};
    const char *resultSecond = TransGetFileName(fileName);
    EXPECT_STREQ(nullptr, resultSecond);

    const char *resultThird = TransGetFileName(g_filePath);
    EXPECT_STREQ(nullptr, resultThird);

    const char *resultFourth = TransGetFileName(g_testFileName);
    EXPECT_STREQ(g_testFileName, resultFourth);

    const char *resultFifth = TransGetFileName(g_fileSet1[0]);
    EXPECT_STREQ(g_testFileName, resultFifth);
}

/**
 * @tc.name: BufferToFileListTest
 * @tc.desc: buffer to file list test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, BufferToFileListTest, TestSize.Level0)
{
    int32_t fileCount = 0;
    char *result = BufferToFileList(nullptr, TEST_BUFFER_SIZE, &fileCount);
    EXPECT_STREQ(nullptr, result);

    uint8_t buffer[] = {0};
    result = BufferToFileList(buffer, 0, &fileCount);
    EXPECT_STREQ(nullptr, result);

    result = BufferToFileList(buffer, TEST_BUFFER_SIZE, nullptr);
    EXPECT_STREQ(nullptr, result);

    result = BufferToFileList(buffer, TEST_BUFFER_SIZE, &fileCount);
    EXPECT_STREQ(nullptr, result);
}

/**
 * @tc.name: FileLockTest
 * @tc.desc: file lock test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileCommonTest, FileLockTest, TestSize.Level0)
{
    int32_t fd = TEST_NORMAL_FD;
    int32_t ret = TryFileLock(fd, SOFTBUS_F_RDLCK, 0);
    EXPECT_EQ(SOFTBUS_FILE_BUSY, ret);

    ret = TryFileLock(TEST_FD, SOFTBUS_F_RDLCK, TEST_RETRY_TIMES);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = TryFileLock(fd, SOFTBUS_F_RDLCK, TEST_RETRY_TIMES);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = FileLock(fd, SOFTBUS_F_RDLCK, false);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = FileLock(fd, SOFTBUS_F_RDLCK, true);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = FileUnLock(TEST_FD);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = FileUnLock(fd);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS