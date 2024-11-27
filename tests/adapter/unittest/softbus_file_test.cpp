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
#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_errcode.h"
#include "softbus_adapter_file.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const int32_t DEFAULT_NEW_PATH_AUTHORITY = 750;

class AdaptorDsoftbusFileTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdaptorDsoftbusFileTest::SetUpTestCase(void) { }
void AdaptorDsoftbusFileTest::TearDownTestCase(void) { }
void AdaptorDsoftbusFileTest::SetUp() { }
void AdaptorDsoftbusFileTest::TearDown() { }

/**
 * @tc.name: SoftBusAdapter_ReadFileTest_001
 * @tc.desc: read file test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusFileTest, SoftBusReadFileTest001, TestSize.Level1)
{
    int32_t fd = 0;
    uint32_t value = 0;
    int32_t ret;
    ret = SoftBusOpenFile(NULL, SOFTBUS_O_RDONLY);
    EXPECT_EQ(SOFTBUS_INVALID_FD, ret);
    ret = SoftBusOpenFile("/data", SOFTBUS_O_RDONLY);
    EXPECT_NE(SOFTBUS_INVALID_FD, ret);
    fd = SoftBusOpenFile("/dev/urandom", SOFTBUS_O_RDONLY);
    EXPECT_NE(SOFTBUS_INVALID_FD, fd);
    ret = SoftBusReadFile(fd, NULL, sizeof(uint32_t));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusReadFile(fd, &value, sizeof(uint32_t));
    EXPECT_NE(SOFTBUS_ERR, ret);
    SoftBusCloseFile(SOFTBUS_INVALID_FD);
    SoftBusCloseFile(fd);
}

/**
 * @tc.name: SoftBusAdapter_OpenFileWithPermsTest_001
 * @tc.desc: softbus open file with perms test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusFileTest, SoftBusOpenFileWithPermsTest001, TestSize.Level1)
{
    int32_t fd = 0;
    int32_t ret =
        SoftBusOpenFileWithPerms(NULL, SOFTBUS_O_WRONLY | SOFTBUS_O_CREATE, SOFTBUS_S_IRUSR | SOFTBUS_S_IWUSR);
    EXPECT_EQ(SOFTBUS_INVALID_FD, ret);
    fd = SoftBusOpenFileWithPerms(
        "/dev/urandom", SOFTBUS_O_WRONLY | SOFTBUS_O_CREATE, SOFTBUS_S_IRUSR | SOFTBUS_S_IWUSR);
    EXPECT_NE(SOFTBUS_INVALID_FD, fd);
    SoftBusCloseFile(fd);
}

/**
 * @tc.name: SoftBusAdapter_PreadFileTest_001
 * @tc.desc: pread file test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusFileTest, SoftBusPreadFileTest001, TestSize.Level1)
{
    int32_t fd = 0;
    uint32_t value = 0;
    uint64_t readBytes = 4;
    uint64_t offset = 1;
    int64_t ret;
    fd = SoftBusOpenFile("/dev/urandom", SOFTBUS_O_RDONLY);
    EXPECT_NE(SOFTBUS_INVALID_FD, fd);
    ret = SoftBusPreadFile(fd, NULL, readBytes, offset);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = SoftBusPreadFile(fd, &value, readBytes, offset);
    EXPECT_NE(SOFTBUS_ERR, ret);
    ret = SoftBusPwriteFile(fd, NULL, readBytes, offset);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    SoftBusCloseFile(fd);
}

/**
 * @tc.name: SoftBusAdapter_MakeDirTest_001
 * @tc.desc: make dir test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusFileTest, SoftBusMakeDirTest001, TestSize.Level1)
{
    int32_t ret = SoftBusMakeDir(NULL, DEFAULT_NEW_PATH_AUTHORITY);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_GetFileSizeTest_001
 * @tc.desc: make dir test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdaptorDsoftbusFileTest, SoftBusGetFileSize001, TestSize.Level1)
{
    uint64_t fileSize = 0;
    int32_t ret = SoftBusGetFileSize(NULL, &fileSize);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = SoftBusGetFileSize("/data", &fileSize);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGetFileSize("/dev/test", &fileSize);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // namespace OHOS