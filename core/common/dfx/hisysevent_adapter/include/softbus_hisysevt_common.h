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
#ifndef SOFTBUS_HISYSEVT_COMMON_H
#define SOFTBUS_HISYSEVT_COMMON_H
#include "softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t InitSoftbusSysEvt(void);

typedef enum {
    SOFTBUS_STATISTIC_EVT_START = 0,
    SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_CNT = SOFTBUS_STATISTIC_EVT_START,
    SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_COST,
    SOFTBUS_STATISTIC_EVT_FIRST_DISC_DURATION,
    SOFTBUS_STATISTIC_EVT_DISC_SCAN_TIMES,
    SOFTBUS_STATISTIC_EVT_DISC_FAULT,
    SOFTBUS_STATISTIC_EVT_CONN_DURATION,
    SOFTBUS_STATISTIC_EVT_CONN_SUCC_RATE,

    SOFTBUS_STATISTIC_EVT_LNN_WLAN_DURATION,
    SOFTBUS_STATISTIC_EVT_LNN_BLE_DURATION,
    SOFTBUS_STATISTIC_EVT_LNN_WLAN_RATE_SUCCESS,
    SOFTBUS_STATISTIC_EVT_LNN_BLE_RATE_SUCCESS,

    SOFTBUS_STATISTIC_EVT_BUTT,
}StatisticEvtType;

typedef int32_t(*StatisticEvtReportFunc)(void);

StatisticEvtReportFunc GetStatisticEvtReportFunc(StatisticEvtType type);

int32_t SetStatisticEvtReportFunc(StatisticEvtType type, StatisticEvtReportFunc func);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_HISYSEVT_COMMON_H */
