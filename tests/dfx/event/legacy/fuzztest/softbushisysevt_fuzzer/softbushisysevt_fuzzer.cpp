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
#include "fuzzer/FuzzedDataProvider.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "legacy/softbus_hisysevt_common.h"
#include "legacy/softbus_hisysevt_connreporter.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "legacy/softbus_hisysevt_transreporter.h"

using namespace std;

namespace OHOS {
static constexpr int32_t BUFF_MAX_LEN = 65;

#define CODE_MIN       SOFTBUS_PUBLIC_ERR_BASE
#define CODE_MAX       SOFTBUS_ERR
#define STAGE_MIN      AUTH_CONNECT_STAGE
#define STAGE_MAX      AUTH_STAGE_BUTT
#define LINK_TYPE_MIN  SOFTBUS_HISYSEVT_LINK_TYPE_BR
#define LINK_TYPE_MAX  SOFTBUS_HISYSEVT_LINK_TYPE_BUTT
#define DISC_STAGE_MIN START_DISCOVERY
#define DISC_STAGE_MAX BUSINESS_DISCOVERY
#define EVENT_TYPE_MIN SOFTBUS_STATISTIC_EVT_START
#define EVENT_TYPE_MAX SOFTBUS_STATISTIC_EVT_BUTT
#define TIME_MIN       0
#define TIME_MAX       (UINT64_MAX - 1)

class TestEnv {
public:
    TestEnv()
    {
        InitBusCenterDfx();
        isInited_ = true;
    }

    ~TestEnv()
    {
        DeinitBusCenterDfx();
        isInited_ = false;
    }

    bool IsEnvInit()
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};

int32_t ReportStatisticEvt()
{
    return 0;
}

void SoftBusRecordAuthResultFuzzTest(FuzzedDataProvider &provider)
{
    SoftBusLinkType linkType = (SoftBusLinkType)provider.ConsumeIntegralInRange<uint32_t>(LINK_TYPE_MIN,
        LINK_TYPE_MAX);
    int32_t ret = provider.ConsumeIntegralInRange<int32_t>(CODE_MIN, CODE_MAX);
    uint64_t constTime = provider.ConsumeIntegralInRange<uint64_t>(TIME_MIN, TIME_MAX);
    AuthFailStage stage = (AuthFailStage)provider.ConsumeIntegralInRange<uint32_t>(STAGE_MIN, STAGE_MAX);
    SoftBusRecordAuthResult(linkType, ret, constTime, stage);
}

void SoftBusRecordBusCenterResultFuzzTest(FuzzedDataProvider &provider)
{
    SoftBusLinkType linkType = (SoftBusLinkType)provider.ConsumeIntegralInRange<uint32_t>(LINK_TYPE_MIN,
        LINK_TYPE_MAX);
    uint64_t constTime = provider.ConsumeIntegralInRange<uint64_t>(TIME_MIN, TIME_MAX);
    SoftBusRecordBusCenterResult(linkType, constTime);
}

void SoftBusRecordDevOnlineDurResultFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t constTime = provider.ConsumeIntegralInRange<uint64_t>(TIME_MIN, TIME_MAX);
    SoftBusRecordDevOnlineDurResult(constTime);
}

void SoftBusReportDevOnlineEvtFuzzTest(FuzzedDataProvider &provider)
{
    string udid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    OnlineDeviceInfo info = {0};
    info.onlineDevNum = provider.ConsumeIntegral<uint32_t>();
    info.btOnlineDevNum = provider.ConsumeIntegral<uint32_t>();
    info.wifiOnlineDevNum = provider.ConsumeIntegral<uint32_t>();
    info.peerDevType = provider.ConsumeIntegral<uint32_t>();
    info.insertFileResult = provider.ConsumeIntegral<int32_t>();
    SoftBusReportDevOnlineEvt(&info, udid.c_str());
}

void SoftBusReportBusCenterFaultEvtFuzzTest(FuzzedDataProvider &provider)
{
    SoftBusFaultEvtInfo info = {0};
    info.moduleType = provider.ConsumeIntegral<uint8_t>();
    info.linkType = provider.ConsumeIntegral<uint8_t>();
    info.channelQuality = provider.ConsumeFloatingPoint<float>();
    info.errorCode = provider.ConsumeIntegralInRange<int32_t>(CODE_MIN, CODE_MAX);
    info.peerDevType = provider.ConsumeIntegral<int32_t>();
    info.onLineDevNum = provider.ConsumeIntegral<int32_t>();
    info.connNum = provider.ConsumeIntegral<int32_t>();
    info.nightMode = provider.ConsumeIntegral<int32_t>();
    info.wifiStatue = provider.ConsumeIntegral<int32_t>();
    info.bleStatue = provider.ConsumeIntegral<int32_t>();
    info.callerAppMode = provider.ConsumeIntegral<int32_t>();
    info.subErrCode = provider.ConsumeIntegral<int32_t>();
    info.connBrNum = provider.ConsumeIntegral<int32_t>();
    info.connBleNum = provider.ConsumeIntegral<int32_t>();
    info.bleBradStatus = provider.ConsumeBool();
    info.bleScanStatus = provider.ConsumeBool();
    SoftBusReportBusCenterFaultEvt(&info);
}

void SoftBusRecordDiscoveryResultFuzzTest(FuzzedDataProvider &provider)
{
    InitBusCenterDfx();
    DiscoveryStage stage = (DiscoveryStage)provider.ConsumeIntegralInRange<uint32_t>(DISC_STAGE_MIN, DISC_STAGE_MAX);
    AppDiscNode node = {0};
    node.appDiscCnt = provider.ConsumeIntegral<int32_t>();
    SoftBusRecordDiscoveryResult(stage, &node);
}

void SoftBusHiSysEvtCommonFuzzTest(FuzzedDataProvider &provider)
{
    StatisticEvtType evtType = (StatisticEvtType)provider.ConsumeIntegralInRange<uint32_t>(EVENT_TYPE_MIN,
        EVENT_TYPE_MAX);
    SetStatisticEvtReportFunc(evtType, ReportStatisticEvt);
    GetStatisticEvtReportFunc(evtType);
}

void SoftBusHiSysEvtTransReporterFuzzTest(FuzzedDataProvider &provider)
{
    InitTransStatisticSysEvt();
    GetSoftbusRecordTimeMillis();
    int32_t errCode = provider.ConsumeIntegralInRange<uint32_t>(CODE_MIN, CODE_MAX);
    SoftbusReportTransErrorEvt(errCode);
    string msg = provider.ConsumeRandomLengthString(BUFF_MAX_LEN);
    SoftbusReportTransInfoEvt(msg.c_str());
    bool isSucc = provider.ConsumeBool();
    SoftbusRecordOpenSession(isSucc ? SOFTBUS_EVT_OPEN_SESSION_SUCC : SOFTBUS_EVT_OPEN_SESSION_FAIL, 0);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TestEnv env;
    if (!env.IsEnvInit()) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::SoftBusRecordAuthResultFuzzTest(provider);
    OHOS::SoftBusRecordBusCenterResultFuzzTest(provider);
    OHOS::SoftBusRecordDevOnlineDurResultFuzzTest(provider);
    OHOS::SoftBusReportDevOnlineEvtFuzzTest(provider);
    OHOS::SoftBusReportBusCenterFaultEvtFuzzTest(provider);
    OHOS::SoftBusRecordDiscoveryResultFuzzTest(provider);
    OHOS::SoftBusHiSysEvtCommonFuzzTest(provider);
    OHOS::SoftBusHiSysEvtTransReporterFuzzTest(provider);

    return 0;
}