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
#ifndef HISYSEVENT_TRANS_REPORTER_H
#define HISYSEVENT_TRANS_REPORTER_H

#include <stdint.h>
#include "legacy/softbus_adapter_hisysevent.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    SOFTBUS_EVT_OPEN_SESSION_SUCC,
    SOFTBUS_EVT_OPEN_SESSION_FAIL,
} SoftBusOpenSessionStatus;

void SoftbusRecordCalledApiInfo(const char *appName, uint32_t code);

void SoftbusRecordCalledApiCnt(uint32_t code);

void SoftbusRecordOpenSessionKpi(const char *pkgName, int32_t linkType, SoftBusOpenSessionStatus isSucc, int64_t time);

void SoftbusRecordOpenSession(SoftBusOpenSessionStatus isSucc, uint32_t time);

void SoftbusReportTransErrorEvt(int32_t errcode);

void SoftbusReportTransInfoEvt(const char *infoMsg);

int32_t InitTransStatisticSysEvt(void);

void DeinitTransStatisticSysEvt(void);

int64_t GetSoftbusRecordTimeMillis(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* HISYSEVENT_TRANS_REPORTER_H */