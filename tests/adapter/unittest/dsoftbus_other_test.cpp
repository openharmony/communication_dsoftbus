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

#include <fcntl.h>
#include <cstring>

#include "gtest/gtest.h"
#include "lnn_ip_utils_adapter.h"
#include "bus_center_adapter.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_adapter_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_FileName = "example.txt";

class DsoftbusOtherTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void DsoftbusOtherTest::SetUpTestCase(void)
{
}
void DsoftbusOtherTest::TearDownTestCase(void)
{
    int32_t ret = remove(g_FileName);
    if (ret == 0) {
        return;
    }
}
void DsoftbusOtherTest::SetUp(void)
{
}
void DsoftbusOtherTest::TearDown(void)
{
}

/*
* @tc.name: GetNetworkIpByIfName001
* @tc.desc: ifName is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusOtherTest, GetNetworkIpByIfName001, TestSize.Level0)
{
    const char *ifName = "abcdefgh";
    char netmask[] = "abcdefd";
    char ip[32] = "0";
    int32_t len = 10;
    int32_t ret = GetNetworkIpByIfName(ifName, ip, netmask, len);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: GetNetworkIpByIfName002
* @tc.desc: ifName is nullptr
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusOtherTest, GetNetworkIpByIfName002, TestSize.Level0)
{
    const char *ifName = "abcdefgh";
    char netmask[] = "abcdefd";
    char ip[32] = "0";
    int32_t len = 10;
    int32_t ret = GetNetworkIpByIfName(NULL, ip, netmask, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = GetNetworkIpByIfName(ifName, NULL, netmask, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: GetNetworkIpByIfName003
* @tc.desc: netmask is nullptr
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusOtherTest, GetNetworkIpByIfName003, TestSize.Level0)
{
    const char *ifName = "abcdefgh";
    char ip[32] = "0";
    int32_t len = 10;
    int32_t ret = GetNetworkIpByIfName(ifName, ip, NULL, len);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_ReadFullFileTest_001
 * @tc.desc: Read File
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusReadFullFileTest001, TestSize.Level0)
{
    const char *writeBuf = "abcdef";
    char readbuf[1024] = {"\0"};
    int32_t maxLen = 100;
    int32_t ret = SoftBusWriteFile(g_FileName, writeBuf, strlen(writeBuf));
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusReadFullFile(g_FileName, readbuf, maxLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusAdapter_ReadFullFileTest_002
 * @tc.desc: g_FileName is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusReadFullFileTest002, TestSize.Level0)
{
    char readbuf[1024] = {"\0"};
    int32_t maxLen = 100;
    int32_t ret = SoftBusReadFullFile(nullptr, readbuf, maxLen);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = SoftBusReadFullFile(g_FileName, nullptr, maxLen);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_ReadFullFileTest_003
 * @tc.desc: maxLen is ivaild param
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusReadFullFileTest003, TestSize.Level0)
{
    char readbuf[1024] = {"\0"};
    int32_t maxLen = 0;
    int32_t ret = SoftBusReadFullFile(g_FileName, readbuf, maxLen);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_WriterFileTest_001
 * @tc.desc: writeBuf isn't nullptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusWriterFileTest001, TestSize.Level0)
{
    const char *writeBuf = "abcdef";
    int32_t ret = SoftBusWriteFile(g_FileName, writeBuf, strlen(writeBuf));
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusAdapter_WriterFileTest_002
 * @tc.desc: g_FileName and writeBuf is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusWriterFileTest002, TestSize.Level0)
{
    const char *writeBuf = "abcdef";
    int32_t ret = SoftBusWriteFile(nullptr, writeBuf, strlen(writeBuf));
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    ret = SoftBusWriteFile(g_FileName, nullptr, strlen(writeBuf));
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_WriterFileTest_003
 * @tc.desc: len is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusWriterFileTest003, TestSize.Level0)
{
    const char *writeBuf = "abcdef";
    int32_t len = 0;
    int32_t ret = SoftBusWriteFile(g_FileName, writeBuf, len);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    int32_t len1 = -10;
    ret = SoftBusWriteFile(g_FileName, writeBuf, len1);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);
}

/**
 * @tc.name: SoftBusAdapter_MallocTest_001
 * @tc.desc: size is zero
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusMallocTest001, TestSize.Level0)
{
    void *ret = SoftBusMalloc(0);
    EXPECT_TRUE(ret != NULL);
    SoftBusFree(ret);
}

/**
 * @tc.name: SoftBusAdapter_MallocTest_002
 * @tc.desc: size is MAX_MALLOC_SIZE+1
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusMallocTest002, TestSize.Level0)
{
    void *ret = SoftBusMalloc(MAX_MALLOC_SIZE + 1);
    EXPECT_EQ(NULL, ret);
}

/**
 * @tc.name: SoftBusAdapter_MallocTest_003
 * @tc.desc: size is -1
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusMallocTest003, TestSize.Level0)
{
    void *ret = SoftBusMalloc(-1);
    EXPECT_EQ(NULL, ret);
}

/**
 * @tc.name: SoftBusAdapter_MallocTest_004
 * @tc.desc: size is MAX_MALLOC_SIZE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusMallocTest004, TestSize.Level0)
{
    void *ret = SoftBusMalloc(12);
    EXPECT_TRUE(ret != NULL);
    SoftBusFree(ret);
}

/**
 * @tc.name: SoftBusAdapter_FreeTest_001
 * @tc.desc: malloc size is 256
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusFreeTest001, TestSize.Level0)
{
    void *ret = SoftBusMalloc(256);
    EXPECT_TRUE(ret != NULL);
    SoftBusFree(ret);
}

/**
 * @tc.name: SoftBusAdapter_CallocTest_001
 * @tc.desc: calloc size is zero
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusCallocTest001, TestSize.Level0)
{
    void *ret = SoftBusCalloc(0);
    EXPECT_TRUE(ret != NULL);
    SoftBusFree(ret);
}

/**
 * @tc.name: SoftBusAdapter_CallocTest_002
 * @tc.desc: calloc size is 22
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusCallocTest002, TestSize.Level0)
{
    void *ret = SoftBusCalloc(22);
    EXPECT_TRUE(ret != NULL);
    SoftBusFree(ret);
}

/**
 * @tc.name: SoftBusAdapter_CallocTest_003
 * @tc.desc: calloc size is 256
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusCallocTest003, TestSize.Level0)
{
    void *ret = SoftBusCalloc(-1);
    EXPECT_EQ(NULL, ret);
}

/**
 * @tc.name: SoftBusAdapter_CallocTest_004
 * @tc.desc: calloc size is 256
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusCallocTest004, TestSize.Level0)
{
    void *ret = SoftBusCalloc(MAX_MALLOC_SIZE + 1);
    EXPECT_EQ(NULL, ret);
}

/**
 * @tc.name: SoftBusAdapter_OutPrintTest_001
 * @tc.desc: OutPrintLog is SOFTBUS_LOG_DBG
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusOutPrintTest001, TestSize.Level0)
{
    const char buf[20] = "123";
    SoftBusOutPrint(buf, SOFTBUS_LOG_DBG);
}

/**
 * @tc.name: SoftBusAdapter_OutPrintTest_002
 * @tc.desc: OutPrintLog is SOFTBUS_LOG_INFO
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusOutPrintTest002, TestSize.Level0)
{
    const char buf[20] = "123";
    SoftBusOutPrint(buf, SOFTBUS_LOG_INFO);
}

/**
 * @tc.name: SoftBusAdapter_OutPrintTest_003
 * @tc.desc: OutPrintLog is SOFTBUS_LOG_WARN
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusOutPrintTest003, TestSize.Level0)
{
    const char buf[20] = "123";
    SoftBusOutPrint(buf, SOFTBUS_LOG_WARN);
}

/**
 * @tc.name: SoftBusAdapter_OutPrintTest_004
 * @tc.desc: OutPrintLog is SOFTBUS_LOG_ERROR
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusOutPrintTest004, TestSize.Level0)
{
    const char buf[20] = "123";
    SoftBusOutPrint(buf, SOFTBUS_LOG_ERROR);
}

/**
 * @tc.name: SoftBusAdapter_OutPrintTest_005
 * @tc.desc: OutPrintLog is SOFTBUS_LOG_LEVEL_MAX
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(DsoftbusOtherTest, SoftBusOutPrintTest005, TestSize.Level0)
{
    const char buf[20] = "123";
    SoftBusOutPrint(buf, SOFTBUS_LOG_LEVEL_MAX);
}
}