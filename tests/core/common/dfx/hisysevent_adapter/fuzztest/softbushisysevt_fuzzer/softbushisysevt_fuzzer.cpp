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
#include "softbus_error_code.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_hisysevt_common.h"
#include "softbus_hisysevt_connreporter.h"
#include "softbus_hisysevt_discreporter.h"
#include "softbus_hisysevt_transreporter.h"

namespace OHOS {
static constexpr int BUFF_MAX_LEN = 65;
int32_t ReportStatisticEvt()
{
    return 0;
}

void SoftBusRecordAuthResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusLinkType linkType = *(reinterpret_cast<const SoftBusLinkType *>(data));
    int32_t ret = *(reinterpret_cast<const int32_t *>(data));
    uint64_t constTime = *(reinterpret_cast<const uint64_t *>(data));
    AuthFailStage stage = *(reinterpret_cast<const AuthFailStage *>(data));
    SoftBusRecordAuthResult(linkType, ret, constTime, stage);
}

void SoftBusRecordBusCenterResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusLinkType linkType = *(reinterpret_cast<const SoftBusLinkType *>(data));
    uint64_t constTime = *(reinterpret_cast<const uint64_t *>(data));
    SoftBusRecordBusCenterResult(linkType, constTime);
}

void SoftBusRecordDevOnlineDurResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    uint64_t constTime = *(reinterpret_cast<const uint64_t *>(data));
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
    info.onlineDevNum = *(reinterpret_cast<const uint32_t *>(data));
    info.btOnlineDevNum = *(reinterpret_cast<const uint32_t *>(data));
    info.wifiOnlineDevNum = *(reinterpret_cast<const uint32_t *>(data));
    info.peerDevType = *(reinterpret_cast<const uint32_t *>(data));
    info.insertFileResult = *(reinterpret_cast<const int32_t *>(data));
    SoftBusReportDevOnlineEvt(&info, udid);
}

void SoftBusReportBusCenterFaultEvtFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusFaultEvtInfo info = {0};
    info.moduleType = *(reinterpret_cast<const uint8_t *>(data));
    info.linkType = *(reinterpret_cast<const uint8_t *>(data));
    info.channelQuality = *(reinterpret_cast<const float *>(data));
    info.errorCode = *(reinterpret_cast<const int32_t *>(data));
    info.peerDevType = *(reinterpret_cast<const int32_t *>(data));
    info.onLineDevNum = *(reinterpret_cast<const int32_t *>(data));
    info.connNum = *(reinterpret_cast<const int32_t *>(data));
    info.nightMode = *(reinterpret_cast<const int32_t *>(data));
    info.wifiStatue = *(reinterpret_cast<const int32_t *>(data));
    info.bleStatue = *(reinterpret_cast<const int32_t *>(data));
    info.callerAppMode = *(reinterpret_cast<const int32_t *>(data));
    info.subErrCode = *(reinterpret_cast<const int32_t *>(data));
    info.connBrNum = *(reinterpret_cast<const int32_t *>(data));
    info.connBleNum = *(reinterpret_cast<const int32_t *>(data));
    info.bleBradStatus = *(reinterpret_cast<const bool *>(data));
    info.bleScanStatus = *(reinterpret_cast<const bool *>(data));
    SoftBusReportBusCenterFaultEvt(&info);
}

void SoftBusRecordDiscoveryResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    DiscoveryStage stage = *(reinterpret_cast<const DiscoveryStage *>(data));
    AppDiscNode node = {0};
    node.appDiscCnt = *(reinterpret_cast<const int32_t *>(data));
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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
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