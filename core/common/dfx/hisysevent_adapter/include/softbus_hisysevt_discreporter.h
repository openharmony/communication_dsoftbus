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

#include "softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE = 0,
    SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP,

    SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT,
} SoftBusDiscMedium;

typedef enum {
    SOFTBUS_HISYSEVT_DISC_ERRCODE_TIMEOUT = 0,
    SOFTBUS_HISYSEVT_DISC_ERRCODE_BUTT,
}SoftBusDiscErrCode;

int32_t SoftbusRecordDiscScanTimes(uint8_t medium);
int32_t SoftbusRecordFirstDiscTime(uint8_t medium, uint32_t time);
int32_t SoftbusRecordDiscFault(uint8_t medium, uint32_t errCode);
int32_t InitDiscStatisticSysEvt(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_HISYSEVT_DISCREPORTER_H */