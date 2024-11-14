/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "softbusadapterhisysevent_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "softbus_error_code.h"
#include "legacy/softbus_adapter_hisysevent.h"
#include "legacy/softbus_hisysevt_connreporter.h"

namespace OHOS {
static void CreateOpenSessionCntMsg(SoftBusEvtReportMsg* msg)
{
    (void)strcpy_s(msg->evtName, SOFTBUS_HISYSEVT_NAME_LEN, "TRANS_OPEN_SESSION_CNT");
    msg->evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    msg->paramNum = SOFTBUS_EVT_PARAM_ONE;

    SoftBusEvtParam* param = &msg->paramArray[SOFTBUS_EVT_PARAM_ZERO];
    (void)strcpy_s(param->paramName, SOFTBUS_HISYSEVT_NAME_LEN, "SUCCESS_CNT");
    param->paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    param->paramValue.u32v = 0;
}

void SoftBusAdapterHiSysEventFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    int32_t tmpParam = *(reinterpret_cast<const int32_t *>(data));
    SoftBusEvtReportMsg* msg = SoftbusCreateEvtReportMsg(tmpParam);
    if (msg == nullptr) {
        return;
    }
    CreateOpenSessionCntMsg(msg);
    SoftbusWriteHisEvt(msg);
    SoftbusFreeEvtReportMsg(msg);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }

    OHOS::SoftBusAdapterHiSysEventFuzzTest(data, size);

    return 0;
}