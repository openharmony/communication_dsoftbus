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

#ifndef SOFTBUS_ADAPTER_HISYSEVENT_H
#define SOFTBUS_ADAPTER_HISYSEVENT_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_HISYSEVT_NAME_LEN  33
#define SOFTBUS_HISYSEVT_PARAM_LEN 33

typedef enum {
    SOFTBUS_EVT_PARAM_ZERO = 0,
    SOFTBUS_EVT_PARAM_ONE = 1,
    SOFTBUS_EVT_PARAM_TWO = 2,
    SOFTBUS_EVT_PARAM_THREE = 3,
    SOFTBUS_EVT_PARAM_FOUR = 4,
    SOFTBUS_EVT_PARAM_FIVE = 5,
    SOFTBUS_EVT_PARAM_SIX = 6,
    SOFTBUS_EVT_PARAM_SEVEN = 7,

    SOFTBUS_EVT_PARAM_BUTT,
} SoftBusEvtParamNum;

typedef enum {
    SOFTBUS_EVT_TYPE_FAULT = 1,
    SOFTBUS_EVT_TYPE_STATISTIC = 2,
    SOFTBUS_EVT_TYPE_SECURITY = 3,
    SOFTBUS_EVT_TYPE_BEHAVIOR = 4,

    SOFTBUS_EVT_TYPE_BUTT
} SoftBusEvtType;

typedef enum {
    SOFTBUS_EVT_LEVEL_CRITICAL,
    SOFTBUS_EVT_LEVEL_MINOR,
} SoftBusEvtLevel;

typedef enum {
    SOFTBUS_EVT_PARAMTYPE_BOOL,
    SOFTBUS_EVT_PARAMTYPE_UINT8,
    SOFTBUS_EVT_PARAMTYPE_UINT16,
    SOFTBUS_EVT_PARAMTYPE_INT32,
    SOFTBUS_EVT_PARAMTYPE_UINT32,
    SOFTBUS_EVT_PARAMTYPE_UINT64,
    SOFTBUS_EVT_PARAMTYPE_FLOAT,
    SOFTBUS_EVT_PARAMTYPE_DOUBLE,
    SOFTBUS_EVT_PARAMTYPE_STRING,

    SOFTBUS_EVT_PARAMTYPE_BUTT
} SoftBusEvtParamType;

typedef union {
    bool b;
    uint8_t u8v;
    uint16_t u16v;
    int32_t i32v;
    uint32_t u32v;
    uint64_t u64v;
    float f;
    double d;
    char str[SOFTBUS_HISYSEVT_PARAM_LEN];
}SoftbusEvtParamValue;

typedef struct {
    SoftBusEvtParamType paramType;
    char paramName[SOFTBUS_HISYSEVT_NAME_LEN];
    SoftbusEvtParamValue paramValue;
} SoftBusEvtParam;

typedef struct {
    char evtName[SOFTBUS_HISYSEVT_NAME_LEN];
    SoftBusEvtType evtType;
    uint32_t paramNum;
    SoftBusEvtParam *paramArray;
} SoftBusEvtReportMsg;

int32_t SoftbusWriteHisEvt(SoftBusEvtReportMsg* reportMsg);

SoftBusEvtReportMsg* SoftbusCreateEvtReportMsg(int32_t paramNum);

void SoftbusFreeEvtReporMsg(SoftBusEvtReportMsg* msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_ADAPTER_HISYSEVENT_H */