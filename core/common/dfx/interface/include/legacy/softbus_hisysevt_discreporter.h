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
#ifndef SOFTBUS_HISYSEVT_DISCREPORTER_H
#define SOFTBUS_HISYSEVT_DISCREPORTER_H

#include "legacy/softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE = 1,
    SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,

    SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT,
} SoftBusDiscMedium;

typedef enum {
    SOFTBUS_HISYSEVT_DISC_ERRCODE_TIMEOUT = 0,
    SOFTBUS_HISYSEVT_DISCOVER_NOT_INIT,
    SOFTBUS_HISYSEVT_DISCOVER_MANAGER_INNERFUNCTION_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_MERGE_CAP_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_SET_FILTER_CAP_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_START_DISCOVER_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_STOP_DISCOVER_FAIL,
    SOFTBUS_HISYSEVT_DISCOVER_COAP_CANCEL_CAP_FAIL,
    SOFTBUS_HISYSEVT_ERR,
    SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT,
}SoftBusDiscErrCode;

typedef struct {
    uint64_t startTime;
    uint32_t repTimes;
    uint32_t devNum;
    uint32_t discTimes;
} DiscoveryStatistics;

int32_t SoftbusRecordFirstDiscTime(SoftBusDiscMedium medium, uint64_t costTime);

int32_t SoftbusRecordBleDiscDetails(char *moduleName, uint64_t duration, uint32_t repTimes, uint32_t devNum,
                                    uint32_t discTimes);

int32_t SoftbusRecordDiscBleRssi(int32_t rssi);

int32_t SoftbusReportDiscFault(SoftBusDiscMedium medium, int32_t errCode);

int32_t InitDiscStatisticSysEvt(void);

void DeinitDiscStatisticSysEvt(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_HISYSEVT_DISCREPORTER_H */