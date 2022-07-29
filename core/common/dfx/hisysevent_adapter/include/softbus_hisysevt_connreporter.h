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
#ifndef HISYSEVENT_CONN_REPORTER_H
#define HISYSEVENT_CONN_REPORTER_H

#include "softbus_adapter_hisysevent.h"

#define STATISTIC_EVT_CONN_DURATION "CONN_DURATION"
#define STATISTIC_EVT_CONN_SUCC_RATE "CONN_SUCC_RATE"
#define FAULT_EVT_CONN_EXCEPTION "CONN_FAULT_EXCEPTION"

#define CONN_PARAM_MEDIUM "MEDIUM"
#define CONN_PARAM_MAX_CONN_DURATION "MAX_CONN_DURATION"
#define CONN_PARAM_MIN_CONN_DURATION "MIN_CONN_DURATION"
#define CONN_PARAM_AVG_CONN_DURATION "AVG_CONN_DURATION"
#define CONN_PARAM_CONN_SUCC_RATE "SUCC_RATE"
#define CONN_PARAM_ERROR_CODE "ERROR_CODE"
#define CONN_PARAM_DEV_ID "DEV_ID"
#define CONN_PARAM_NIGHT_MODE "NIGHT_MODE"
#define CONN_PARAM_BTSTATUS "BTSTATUS"
#define CONN_PARAM_WIFISTATUS "WIFISTATUS"
#define CONN_PARAM_CHNL_QUALITY "CHNL_QUALITY"

uint8_t SoftBusCreateConnDurationEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint32_t maxConnDuration,
    uint32_t minConnDuration, int avgConnDuration);
uint8_t SoftBusCreateConnSuccRateEvt(SoftBusEvtReportMsg *msg, uint8_t medium, float succRate);
uint8_t SoftBusCreateConnExceptionEvt(SoftBusEvtReportMsg *msg, uint8_t medium, uint8_t errorCode, char *devId,
    uint8_t nightmode);
#endif /* HISYSEVENT_CONN_REPORTER_H */