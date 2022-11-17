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
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_fileSet1[] = {
    "/dev/path/to",
    "/path/max/length/512/"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "111111111111111111111111111111111111111111111111111"
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

HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput1, TestSize.Level0)
{
    FileListBuffer bufferInfo = {0};
    EXPECT_NE(0, FileListToBuffer(nullptr, sizeof(g_fileSet1) / sizeof(const char *), &bufferInfo));

    EXPECT_EQ(bufferInfo.buffer, nullptr);
    EXPECT_EQ(bufferInfo.bufferSize, 0);
}

HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput2, TestSize.Level0)
{
    FileListBuffer bufferInfo = {0};
    EXPECT_NE(0, FileListToBuffer(g_fileSet1, 0, &bufferInfo));

    EXPECT_EQ(bufferInfo.buffer, nullptr);
    EXPECT_EQ(bufferInfo.bufferSize, 0);
}

HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput3, TestSize.Level0)
{
    EXPECT_NE(0, FileListToBuffer(g_fileSet1, sizeof(g_fileSet1) / sizeof(const char *), nullptr));
}

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

HWTEST_F(ClientTransProxyFileCommonTest, FileListToBufferTestBadInput5, TestSize.Level0)
{
    const char *fileSet[] = {"/dev/path/to", ""};
    FileListBuffer bufferInfo = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, FileListToBuffer(fileSet, sizeof(fileSet) / sizeof(const char *), &bufferInfo));
}
} // namespace OHOS
