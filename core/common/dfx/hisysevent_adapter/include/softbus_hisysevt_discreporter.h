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
#ifndef HISYSEVENT_DISC_REPORTER_H
#define HISYSEVENT_DISC_REPORTER_H

#include "softbus_adapter_hisysevent.h"

#define BEHAVIOR_EVT_DISC_START "DISC_STARTUP"
#define STATISTIC_EVT_FIRST_DISC_DURATION "FIRST_DISC_DURATION"
#define STATISTIC_EVT_SCAN_TIMES "SCAN_TIMES"
#define STATISTIC_EVT_DISC_FAULT "DISC_FAULT_EXCEPTION"

#define DISC_PARAM_DISC_PACKAGE_NAME "PACKAGE_NAME"
#define DISC_PARAM_MEDIUM "MEDIUM"
#define DISC_PARAM_MAX_DISC_DURATION "MAX_DISC_DURATION"
#define DISC_PARAM_MIN_DISC_DURATION "MIN_DISC_DURATION"
#define DISC_PARAM_AVG_DISC_DURATION "AVG_DISC_DURATION"
#define DISC_PARAM_SCAN_COUNTER "SCAN_COUNTER"
#define DISC_PARAM_ERROR_TYPE "ERROR_TYPE"
#define DISC_PARAM_ERROR_COUNTER "ERROR_COUNTER"
#define DISC_PARAM_ERROR_CODE "ERROR_CODE"

uint8_t SoftBusCreateDiscStartupEvt(SoftBusEvtReportMsg *msg, char *PackageName);
uint8_t SoftBusCreateConnDurationEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t maxConnDuration,
    uint32_t minConnDuration, int avgConnDuration);
uint8_t SoftBusCreateScanTimesEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t discDuration);
uint8_t SoftBusCreateDiscFaultEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint8_t errorType,
    uint8_t errorCode, uint32_t errorCount);

#endif /* HISYSEVENT_DISC_REPORTER_H */