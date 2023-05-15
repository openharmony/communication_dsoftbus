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
    char udid[UDID_BUF_LEN] = {0};
    if (memcpy_s(udid, sizeof(udid) - 1, data, size) != EOK) {
        return;
    }
    OnlineDeviceInfo info = *(reinterpret_cast<const OnlineDeviceInfo *>(data));
    SoftBusReportDevOnlineEvt(&info, udid);
}

void SoftBusReportBusCenterFaultEvtFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    SoftBusFaultEvtInfo info = *(reinterpret_cast<const SoftBusFaultEvtInfo *>(data));
    SoftBusReportBusCenterFaultEvt(&info);
}

void SoftBusRecordDiscoveryResultFuzzTest(const uint8_t *data, size_t size)
{
    InitBusCenterDfx();
    DiscoveryStage stage = *(reinterpret_cast<const DiscoveryStage *>(data));
    AppDiscNode node = *(reinterpret_cast<const AppDiscNode *>(data));
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
    (void)data;
    (void)size;
    InitTransStatisticSysEvt();
    GetSoftbusRecordTimeMillis();
    SoftbusReportTransErrorEvt(SOFTBUS_ACCESS_TOKEN_DENIED);
    SoftbusReportTransInfoEvt(reinterpret_cast<const char *>(data));
    SoftbusRecordOpenSession(SOFTBUS_EVT_OPEN_SESSION_SUCC, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
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