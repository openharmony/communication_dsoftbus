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
#include "legacy/softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define STATISTIC_EVT_FIRST_DISC_DURATION "FIRST_DISC_DURATION"
#define STATISTIC_EVT_DISCOVERY_DETAILS "DISCOVERY_DETAILS"
#define STATISTIC_EVT_DISCOVERY_BLE_RSSI "DISCOVERY_BLE_RSSI"

#define STATISTIC_EVT_CONN_DURATION "CONN_DURATION"
#define STATISTIC_EVT_PROCESS_STEP_DURATION "PROCESS_STEP_DURATION"

#define FAULT_EVT_BUS_CENTER "BUS_CENTER_FAULT_EVT"
#define STATISTIC_EVT_ONLINE_DURATION "ONLINE_DURATION"
#define STATISTIC_EVT_AUTH_KPI "AUTH_DURATION"
#define STATISTIC_EVT_LNN_DURATION "BUS_CENTER_DURATION"
#define STATISTIC_EVT_DEVICE_ONLINE "DEVICE_ONLINE_EVT"
#define STATISTIC_EVT_DEVICE_DISCOVERY "DEVICE_DISCOVERY"
#define STATISTIC_EVT_APP_DISCOVERY "APP_DISCOVERY"

typedef enum {
    SOFTBUS_STATISTIC_EVT_START = 0,
    SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_CNT = SOFTBUS_STATISTIC_EVT_START,
    SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_KPI,
    TRANSPORT_API_CALLED_INFO_STATISTIC_EVENT,
    TRANSPORT_API_CALLED_CNT_STATISTIC_EVENT,
    SOFTBUS_STATISTIC_EVT_TRANS_OPEN_SESSION_TIME_COST,
    SOFTBUS_STATISTIC_EVT_FIRST_DISC_DURATION,
    SOFTBUS_STATISTIC_EVT_DISC_BLE_RSSI,
    SOFTBUS_STATISTIC_EVT_DISC_DETAILS,
    SOFTBUS_STATISTIC_EVT_CONN_DURATION,
    SOFTBUS_STATISTIC_EVT_PROCESS_STEP_DURATION,

    SOFTBUS_STATISTIC_EVT_LNN_DURATION,
    SOFTBUS_STATISTIC_EVT_ONLINE_DURATION,
    SOFTBUS_STATISTIC_EVT_AUTH_KPI,
    SOFTBUS_STATISTIC_EVT_DEV_DISCOVERY,
    SOFTBUS_STATISTIC_EVT_APP_DISCOVERY,

    SOFTBUS_STATISTIC_EVT_BUTT,
} StatisticEvtType;

typedef int32_t(*StatisticEvtReportFunc)(void);

int32_t InitSoftbusSysEvt(void);

void DeinitSoftbusSysEvt(void);

StatisticEvtReportFunc GetStatisticEvtReportFunc(StatisticEvtType type);

int32_t SetStatisticEvtReportFunc(StatisticEvtType type, StatisticEvtReportFunc func);

int32_t GetErrorCodeEx(int32_t errorCode);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_HISYSEVT_COMMON_H */