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
static constexpr int HIDUMPER_ARGC_NUM = 1;
static constexpr int HIDUMPER_FD = 1234;

int32_t SoftBusVarDumpCbFunc(int fd)
{
    (void)fd;
    return 0;
}

void TransSessionShowInfoFunc(int fd)
{
    (void)fd;
}

void SoftBusHiDumperFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    if (SoftBusHiDumperModuleInit() != SOFTBUS_OK) {
        return;
    }

    const char *argv1[HIDUMPER_ARGC_NUM] = { "-h" };
    const char *argv2[HIDUMPER_ARGC_NUM] = { "disc -l coapPublishInfo" };
    SoftBusDumpDispatch(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv1);
    SoftBusDumpDispatch(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv2);
}

void SoftBusHiDumperBusCenterFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    if (SoftBusHiDumperBusCenterInit() != SOFTBUS_OK) {
        return;
    }

    char dumpVar[] = "testDumpVar";
    SoftBusRegBusCenterVarDump(dumpVar, &SoftBusVarDumpCbFunc);
    const char *argv1[HIDUMPER_ARGC_NUM] = { "testDumpVar" };
    SoftBusDumpDispatch(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv1);
}

void SoftBusHiDumperConnFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    if (SoftBusConnHiDumperInit() != SOFTBUS_OK) {
        return;
    }

    char dumpVar[] = "testDumpVar";
    SoftBusRegConnVarDump(dumpVar, &SoftBusVarDumpCbFunc);
    const char *argv1[HIDUMPER_ARGC_NUM] = { "testDumpVar" };
    SoftBusDumpDispatch(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv1);
}

void SoftBusHiDumperDiscFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    if (SoftBusDiscHiDumperInit() != SOFTBUS_OK) {
        return;
    }

    char dumpVar[] = "testDumpVar";
    SoftBusRegDiscVarDump(dumpVar, &SoftBusVarDumpCbFunc);
    const char *argv1[HIDUMPER_ARGC_NUM] = { "testDumpVar" };
    SoftBusDumpDispatch(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv1);
}

void SoftBusHiDumperInterfaceFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    if (SoftBusHiDumperInit() != SOFTBUS_OK) {
        return;
    }

    const char *argv1[HIDUMPER_ARGC_NUM] = { "-h" };
    const char *argv2[HIDUMPER_ARGC_NUM] = { "conn -l lnnMacInfo" };
    SoftBusDumpProcess(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv1);
    SoftBusDumpProcess(HIDUMPER_FD, HIDUMPER_ARGC_NUM, argv2);
}

void SoftBusHiDumperNstackFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SoftBusNStackHiDumperInit();
}

void SoftBusHiDumperTransFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SetShowRegisterSessionInfosFunc(TransSessionShowInfoFunc);
    SetShowRunningSessionInfosFunc(TransSessionShowInfoFunc);
    SoftBusTransDumpHandlerInit();

    char pkgName[] = "testPackage";
    char sessionName[] = "testSession";
    SoftBusTransDumpRegisterSession(HIDUMPER_FD, pkgName, sessionName, 0, 0);
    AppInfo info;
    SoftBusTransDumpRunningSession(HIDUMPER_FD, DUMPER_LANE_BR, &info);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }

    OHOS::SoftBusHiDumperFuzzTest(data, size);
    OHOS::SoftBusHiDumperBusCenterFuzzTest(data, size);
    OHOS::SoftBusHiDumperConnFuzzTest(data, size);
    OHOS::SoftBusHiDumperDiscFuzzTest(data, size);
    OHOS::SoftBusHiDumperInterfaceFuzzTest(data, size);
    OHOS::SoftBusHiDumperNstackFuzzTest(data, size);
    OHOS::SoftBusHiDumperTransFuzzTest(data, size);

    return 0;
}