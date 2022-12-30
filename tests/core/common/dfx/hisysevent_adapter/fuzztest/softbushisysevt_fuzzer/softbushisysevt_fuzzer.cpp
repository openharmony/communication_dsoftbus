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
static constexpr int TEST_PKG_NAME_MAX_LEN = 65;
static constexpr int TEST_STRING_MAX_LEN = 100;
int32_t ReportStatisticEvt()
{
    return 0;
}

void SoftBusHiSysEvtBusCenterFuzzTest(const uint8_t* data, size_t size)
{
    InitBusCenterDfx();

    LnnStatisticData statisticData = {0};
    statisticData.retCode = *(reinterpret_cast<const int32_t *>(data));
    AddStatisticDuration(&statisticData);
    AddStatisticRateOfSuccess(&statisticData);
    char tmpString[TEST_STRING_MAX_LEN] = {0};
    if (memcpy_s(tmpString, sizeof(tmpString) - 1, data, size) != EOK) {
        return;
    }
    int32_t tmpErrCode = *(reinterpret_cast<const int32_t *>(data));
    SoftBusEvtReportMsg testMsg;
    if (memset_s(&testMsg, sizeof(SoftBusEvtReportMsg), 0, sizeof(SoftBusEvtReportMsg)) != EOK) {
        return;
    }
    int32_t ret = CreateBusCenterFaultEvt(&testMsg, tmpErrCode, reinterpret_cast<ConnectionAddr *>(tmpString));
    if (ret == SOFTBUS_OK && testMsg.paramArray != nullptr) {
        ReportBusCenterFaultEvt(&testMsg);
    }
}

void SoftBusHiSysEvtCommonFuzzTest(const uint8_t* data, size_t size)
{
    StatisticEvtType evtType = *(reinterpret_cast<const StatisticEvtType *>(data));
    SetStatisticEvtReportFunc(evtType, ReportStatisticEvt);
    GetStatisticEvtReportFunc(evtType);
}

void SoftBusHiSysEvtConnReporterFuzzTest(const uint8_t* data, size_t size)
{
    InitConnStatisticSysEvt();
    SoftBusConnMedium connMedium = *(reinterpret_cast<const SoftBusConnMedium *>(data));
    SoftBusConnErrCode errCode = *(reinterpret_cast<const SoftBusConnErrCode *>(data));
    int32_t ret = SoftBusReportConnFaultEvt(connMedium, errCode);
    if (ret == SOFTBUS_OK) {
        SoftbusRecordConnInfo(connMedium, SOFTBUS_EVT_CONN_FAIL, 0);
    }
}

void SoftBusHiSysEvtDiscReporterFuzzTest(const uint8_t* data, size_t size)
{
    InitDiscStatisticSysEvt();
    uint8_t discMedium = *(reinterpret_cast<const uint8_t *>(data));
    uint32_t discParam = *(reinterpret_cast<const uint32_t *>(data));
    char tmpPkgName[TEST_PKG_NAME_MAX_LEN] = {0};
    if (memcpy_s(tmpPkgName, sizeof(tmpPkgName) - 1, data, size) != EOK) {
        return;
    }
    SoftbusRecordDiscScanTimes(discMedium);
    SoftbusRecordFirstDiscTime(discMedium, discParam);
    SoftbusRecordDiscFault(discMedium, discParam);
    SoftBusReportDiscStartupEvt(tmpPkgName);
}

void SoftBusHiSysEvtTransReporterFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    InitTransStatisticSysEvt();
    GetSoftbusRecordTimeMillis();
    SoftbusReportTransErrorEvt(SOFTBUS_ACCESS_TOKEN_DENIED);
    SoftbusRecordOpenSession(SOFTBUS_EVT_OPEN_SESSION_SUCC, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }

    OHOS::SoftBusHiSysEvtBusCenterFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtCommonFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtConnReporterFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtDiscReporterFuzzTest(data, size);
    OHOS::SoftBusHiSysEvtTransReporterFuzzTest(data, size);

    return 0;
}