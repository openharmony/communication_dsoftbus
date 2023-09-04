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

#include "softbushidumper_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "softbus_error_code.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_buscenter.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hidumper_interface.h"
#include "softbus_hidumper_nstack.h"
#include "softbus_hidumper_trans.h"

namespace OHOS {
static constexpr int TEST_ARGV_STRING_MAX_LEN = 255;
static constexpr int TEST_PKG_NAME_MAX_LEN = 65;
static constexpr int TEST_SESSION_NAME_MAX_LEN = 256;
static constexpr int TEST_DUMP_VAR_MAX_LEN = 32;
static constexpr int MAX_ARGV_NUM = 3;
int32_t SoftBusVarDumpCbFunc(int fd)
{
    (void)fd;
    return 0;
}

int32_t TransSessionShowInfoFunc(int fd)
{
    (void)fd;
    return SOFTBUS_OK;
}

void SoftBusHiDumperFuzzTest(const uint8_t* data, size_t size)
{
    char tmpArgvString[TEST_ARGV_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpArgvString, sizeof(tmpArgvString) - 1, data, size) != EOK) {
        return;
    }
    const char *tmpData[MAX_ARGV_NUM] = {nullptr};
    for (int32_t i = 0; i < MAX_ARGV_NUM; i++) {
        tmpData[i] = tmpArgvString;
    }
    int32_t tmpValue = *(reinterpret_cast<const int32_t *>(data));
    SoftBusDumpDispatch(tmpValue, tmpValue, tmpData);
}

void SoftBusHiDumperBusCenterFuzzTest(const uint8_t* data, size_t size)
{
    char tmpDumpVar[TEST_DUMP_VAR_MAX_LEN] = {0};
    if (memcpy_s(tmpDumpVar, sizeof(tmpDumpVar) - 1, data, size) != EOK) {
        return;
    }
    int32_t ret = SoftBusRegBusCenterVarDump(tmpDumpVar, &SoftBusVarDumpCbFunc);
    if (ret != SOFTBUS_OK) {
        return;
    }

    char tmpArgvString[TEST_ARGV_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpArgvString, sizeof(tmpArgvString) - 1, data, size) != EOK) {
        return;
    }
    const char *tmpData[MAX_ARGV_NUM] = {nullptr};
    for (int32_t i = 0; i < MAX_ARGV_NUM; i++) {
        tmpData[i] = tmpArgvString;
    }
    int32_t tmpValue = *(reinterpret_cast<const int32_t *>(data));
    SoftBusDumpDispatch(tmpValue, tmpValue, tmpData);
}

void SoftBusHiDumperConnFuzzTest(const uint8_t* data, size_t size)
{
    char tmpDumpVar[TEST_DUMP_VAR_MAX_LEN] = {0};
    if (memcpy_s(tmpDumpVar, sizeof(tmpDumpVar) - 1, data, size) != EOK) {
        return;
    }
    int32_t ret = SoftBusRegConnVarDump(tmpDumpVar, &SoftBusVarDumpCbFunc);
    if (ret != SOFTBUS_OK) {
        return;
    }

    char tmpArgvString[TEST_ARGV_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpArgvString, sizeof(tmpArgvString) - 1, data, size) != EOK) {
        return;
    }
    const char *tmpData[MAX_ARGV_NUM] = {nullptr};
    for (int32_t i = 0; i < MAX_ARGV_NUM; i++) {
        tmpData[i] = tmpArgvString;
    }
    int32_t tmpValue = *(reinterpret_cast<const int32_t *>(data));
    SoftBusDumpDispatch(tmpValue, tmpValue, tmpData);
}

void SoftBusHiDumperDiscFuzzTest(const uint8_t* data, size_t size)
{
    char tmpDumpVar[TEST_DUMP_VAR_MAX_LEN] = {0};
    if (memcpy_s(tmpDumpVar, sizeof(tmpDumpVar) - 1, data, size) != EOK) {
        return;
    }
    int32_t ret = SoftBusRegDiscVarDump(tmpDumpVar, &SoftBusVarDumpCbFunc);
    if (ret != SOFTBUS_OK) {
        return;
    }

    char tmpArgvString[TEST_ARGV_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpArgvString, sizeof(tmpArgvString) - 1, data, size) != EOK) {
        return;
    }
    const char *tmpData[MAX_ARGV_NUM] = {nullptr};
    for (int32_t i = 0; i < MAX_ARGV_NUM; i++) {
        tmpData[i] = tmpArgvString;
    }
    int32_t tmpValue = *(reinterpret_cast<const int32_t *>(data));
    SoftBusDumpDispatch(tmpValue, tmpValue, tmpData);
}

void SoftBusHiDumperInterfaceFuzzTest(const uint8_t* data, size_t size)
{
    char tmpArgvString[TEST_ARGV_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpArgvString, sizeof(tmpArgvString) - 1, data, size) != EOK) {
        return;
    }
    const char *tmpData[MAX_ARGV_NUM] = {nullptr};
    for (int32_t i = 0; i < MAX_ARGV_NUM; i++) {
        tmpData[i] = tmpArgvString;
    }
    int32_t tmpValue = *(reinterpret_cast<const int32_t *>(data));
    SoftBusDumpProcess(tmpValue, tmpValue, tmpData);
}

void SoftBusHiDumperNstackFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SoftBusNStackHiDumperInit();
}

void SoftBusHiDumperTransFuzzTest(const uint8_t* data, size_t size)
{
    char tmpDumpVar[SOFTBUS_DUMP_VAR_NAME_LEN] = {0};
    if (memcpy_s(tmpDumpVar, sizeof(tmpDumpVar) - 1, data, size) != EOK) {
        return;
    }
    SoftBusRegTransVarDump(tmpDumpVar, TransSessionShowInfoFunc);
    SoftBusTransDumpHandlerInit();
    int32_t tmpValue = *(reinterpret_cast<const int *>(data));
    char tmpPkgName[TEST_PKG_NAME_MAX_LEN] = {0};
    if (memcpy_s(tmpPkgName, sizeof(tmpPkgName) - 1, data, size) != EOK) {
        return;
    }
    char tmpSessionName[TEST_SESSION_NAME_MAX_LEN] = {0};
    if (memcpy_s(tmpSessionName, sizeof(tmpSessionName) - 1, data, size) != EOK) {
        return;
    }
    SoftBusTransDumpRegisterSession(tmpValue, tmpPkgName, tmpSessionName, tmpValue, tmpValue);

    if (size < sizeof(AppInfo)) {
        return;
    }
    AppInfo testAppInfo;
    if (memcpy_s(&testAppInfo, sizeof(AppInfo), data, sizeof(AppInfo)) != EOK) {
        return;
    }
    TransDumpLaneLinkType laneLinkType = *(reinterpret_cast<const TransDumpLaneLinkType *>(data));
    SoftBusTransDumpRunningSession(tmpValue, laneLinkType, &testAppInfo);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    int32_t ret = SoftBusHiDumperInit();
    if (ret != SOFTBUS_OK) {
        return 0;
    }
    OHOS::SoftBusHiDumperFuzzTest(data, size);
    OHOS::SoftBusHiDumperBusCenterFuzzTest(data, size);
    OHOS::SoftBusHiDumperConnFuzzTest(data, size);
    OHOS::SoftBusHiDumperDiscFuzzTest(data, size);
    OHOS::SoftBusHiDumperInterfaceFuzzTest(data, size);
    OHOS::SoftBusHiDumperNstackFuzzTest(data, size);
    OHOS::SoftBusHiDumperTransFuzzTest(data, size);
    SoftBusHiDumperModuleDeInit();
    return 0;
}