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

#include "softbushisysevt_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "fuzz_data_generator.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "legacy/softbus_hisysevt_common.h"
#include "legacy/softbus_hisysevt_connreporter.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "legacy/softbus_hisysevt_transreporter.h"

namespace OHOS {
static constexpr int32_t BUFF_MAX_LEN = 65;
int32_t ReportStatisticEvt()
{
    return 0;
}

void SoftBusRecordAuthResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusLinkType linkType = *(reinterpret_cast<const SoftBusLinkType *>(data));
    int32_t ret = 0;
    uint64_t constTime = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(ret);
    GenerateUint64(constTime);
    DataGenerator::Clear();
    AuthFailStage stage = *(reinterpret_cast<const AuthFailStage *>(data));
    SoftBusRecordAuthResult(linkType, ret, constTime, stage);
}

void SoftBusRecordBusCenterResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusLinkType linkType = *(reinterpret_cast<const SoftBusLinkType *>(data));
    uint64_t constTime = 0;
    DataGenerator::Write(data, size);
    GenerateUint64(constTime);
    DataGenerator::Clear();
    SoftBusRecordBusCenterResult(linkType, constTime);
}

void SoftBusRecordDevOnlineDurResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    uint64_t constTime = 0;
    DataGenerator::Write(data, size);
    GenerateUint64(constTime);
    DataGenerator::Clear();
    SoftBusRecordDevOnlineDurResult(constTime);
}

void SoftBusReportDevOnlineEvtFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    char udid[BUFF_MAX_LEN] = {0};
    if (memcpy_s(udid, sizeof(udid) - 1, data, size) != EOK) {
        return;
    }
    OnlineDeviceInfo info = {0};
    DataGenerator::Write(data, size);
    GenerateUint32(info.onlineDevNum);
    GenerateUint32(info.btOnlineDevNum);
    GenerateUint32(info.wifiOnlineDevNum);
    GenerateUint32(info.peerDevType);
    GenerateInt32(info.insertFileResult);
    DataGenerator::Clear();
    SoftBusReportDevOnlineEvt(&info, udid);
}

void SoftBusReportBusCenterFaultEvtFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusFaultEvtInfo info = {0};
    DataGenerator::Write(data, size);
    GenerateUint8(info.moduleType);
    GenerateUint8(info.linkType);
    GenerateFloat(info.channelQuality);
    GenerateInt32(info.errorCode);
    GenerateInt32(info.peerDevType);
    GenerateInt32(info.onLineDevNum);
    GenerateInt32(info.connNum);
    GenerateInt32(info.nightMode);
    GenerateInt32(info.wifiStatue);
    GenerateInt32(info.bleStatue);
    GenerateInt32(info.callerAppMode);
    GenerateInt32(info.subErrCode);
    GenerateInt32(info.connBrNum);
    GenerateInt32(info.connBleNum);
    GenerateBool(info.bleBradStatus);
    GenerateBool(info.bleScanStatus);
    DataGenerator::Clear();
    SoftBusReportBusCenterFaultEvt(&info);
}

void SoftBusRecordDiscoveryResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    DiscoveryStage stage = *(reinterpret_cast<const DiscoveryStage *>(data));
    AppDiscNode node = {0};
    DataGenerator::Write(data, size);
    GenerateInt32(node.appDiscCnt);
    DataGenerator::Clear();
    SoftBusRecordDiscoveryResult(stage, &node);
}

void SoftBusHiSysEvtCommonFuzzTest(const uint8_t *data, size_t size)
{
    StatisticEvtType evtType = *(reinterpret_cast<const StatisticEvtType *>(data));
    SetStatisticEvtReportFunc(evtType, ReportStatisticEvt);
    GetStatisticEvtReportFunc(evtType);
}

void SoftBusHiSysEvtTransReporterFuzzTest(const uint8_t *data, size_t size)
{
    char tmp[BUFF_MAX_LEN] = {0};
    if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
        return;
    }
    InitTransStatisticSysEvt();
    GetSoftbusRecordTimeMillis();
    SoftbusReportTransErrorEvt(SOFTBUS_ACCESS_TOKEN_DENIED);
    SoftbusReportTransInfoEvt(reinterpret_cast<const char *>(tmp));
    SoftbusRecordOpenSession(SOFTBUS_EVT_OPEN_SESSION_SUCC, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t)) {
        return 0;
    }

    OHOS::SoftBusRecordAuthResultFuzzTest(data, size);
    OHOS::SoftBusRecordBusCenterResultFuzzTest(data, size);
    OHOS::SoftBusRecordDevOnlineDurResultFuzzTest(data, size);
    OHOS::SoftBusReportDevOnlineEvtFuzzTest(data, size);
    OHOS::SoftBusReportBusCenterFaultEvtFuzzTest(data, size);
    OHOS::SoftBusRecordDiscoveryResultFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtCommonFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtTransReporterFuzzTest(data, size);

    return 0;
}