/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SOFTBUS_HISYSEVENT_BUS_CENTER_H
#define SOFTBUS_HISYSEVENT_BUS_CENTER_H

#include <stdint.h>

#include "softbus_adapter_hisysevent.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t beginTime;
    int64_t authTime;
    int64_t endTime;
    int32_t retCode;
    ConnectionAddrType type;
} LnnStatisticData;

int32_t CreateBusCenterFaultEvt(SoftBusEvtReportMsg *msg, int32_t errorCode, ConnectionAddr *addr);
int32_t ReportBusCenterFaultEvt(SoftBusEvtReportMsg *msg);
int32_t InitBusCenterDfx(void);
int32_t AddStatisticDuration(LnnStatisticData *data);
int32_t AddStatisticRateOfSuccess(LnnStatisticData *data);

#ifdef __cplusplus
}
#endif
#endif /* SOFTBUS_HISYSEVENT_BUS_CENTER_H */
