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

void SoftBusHiSysEvtBusCenterFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    InitBusCenterDfx();

    LnnStatisticData statisticData = { 0 };
    AddStatisticDuration(&statisticData);
    AddStatisticRateOfSuccess(&statisticData);

    SoftBusEvtReportMsg msg;
    memset_s(&msg, sizeof(SoftBusEvtReportMsg), 0, sizeof(SoftBusEvtReportMsg));
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_WLAN;
    int32_t ret = CreateBusCenterFaultEvt(&msg, SOFTBUS_NETWORK_AUTH_TCP_ERR, &addr);
    if (ret == SOFTBUS_OK && msg.paramArray != nullptr) {
        ReportBusCenterFaultEvt(&msg);
    }
}

void SoftBusHiSysEvtCommonFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    SetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_WLAN_DURATION, ReportStatisticEvt);
    GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_WLAN_DURATION);
}

void SoftBusHiSysEvtConnReporterFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    InitConnStatisticSysEvt();
    int32_t ret = SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_CONNECT_FAIL);
    if (ret == SOFTBUS_OK) {
        SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_EVT_CONN_FAIL, 0);
    }
}

void SoftBusHiSysEvtDiscReporterFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    InitDiscStatisticSysEvt();
    SoftbusRecordDiscScanTimes(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE);
    SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, 0);
    SoftbusRecordDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, 0);
    char pkgName[] = "testPackage";
    SoftBusReportDiscStartupEvt(pkgName);
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