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
#include "legacy/softbus_adapter_hisysevent.h"

#include <securec.h>
#include <sstream>

#include "comm_log.h"
#include "hisysevent_c.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

static const char *g_domain = "DSOFTBUS";
static bool g_init_lock = false;
static SoftBusMutex g_dfx_lock;
static HiSysEventParam g_dstParam[SOFTBUS_EVT_PARAM_BUTT];

static int32_t ConvertToHisEventString(SoftBusEvtParam *srcParam, HiSysEventParam *dstParam)
{
    dstParam->t = HISYSEVENT_STRING;
    dstParam->v.s = reinterpret_cast<char *>(SoftBusCalloc(sizeof(char) * SOFTBUS_HISYSEVT_PARAM_LEN));
    if (dstParam->v.s == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "ConvertEventParam: SoftBusMalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(dstParam->v.s, SOFTBUS_HISYSEVT_PARAM_LEN, srcParam->paramValue.str) != EOK) {
        SoftBusFree(dstParam->v.s);
        COMM_LOGE(COMM_ADAPTER, "ConvertEventParam:copy string var fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertToHisEventUint32Array(SoftBusEvtParam *srcParam, HiSysEventParam *dstParam, uint32_t arraySize)
{
    dstParam->t = HISYSEVENT_UINT32_ARRAY;
    dstParam->v.array = reinterpret_cast<uint32_t *>(SoftBusCalloc(arraySize));
    if (dstParam->v.array == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "ConvertEventParam: SoftBusMalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(dstParam->v.array, arraySize, srcParam->paramValue.u32a, arraySize) != EOK) {
        SoftBusFree(dstParam->v.array);
        COMM_LOGE(COMM_ADAPTER, "ConvertEventParam:copy uint32 array var fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertEventParam(SoftBusEvtParam *srcParam, HiSysEventParam *dstParam)
{
    uint32_t arraySize = sizeof(uint32_t) * SOFTBUS_HISYSEVT_PARAM_UINT32_ARRAY_SIZE;
    switch (srcParam->paramType) {
        case SOFTBUS_EVT_PARAMTYPE_BOOL:
            dstParam->t = HISYSEVENT_BOOL;
            dstParam->v.b = srcParam->paramValue.b;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT8:
            dstParam->t = HISYSEVENT_UINT8;
            dstParam->v.ui8 = srcParam->paramValue.u8v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT16:
            dstParam->t = HISYSEVENT_UINT16;
            dstParam->v.ui16 = srcParam->paramValue.u16v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_INT32:
            dstParam->t = HISYSEVENT_INT32;
            dstParam->v.i32 = srcParam->paramValue.i32v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT32:
            dstParam->t = HISYSEVENT_UINT32;
            dstParam->v.ui32 = srcParam->paramValue.u32v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_INT64:
            dstParam->t = HISYSEVENT_INT64;
            dstParam->v.i64 = srcParam->paramValue.i64v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_UINT64:
            dstParam->t = HISYSEVENT_UINT64;
            dstParam->v.ui64 = srcParam->paramValue.u64v;
            break;
        case SOFTBUS_EVT_PARAMTYPE_FLOAT:
            dstParam->t = HISYSEVENT_FLOAT;
            dstParam->v.f = srcParam->paramValue.f;
            break;
        case SOFTBUS_EVT_PARAMTYPE_DOUBLE:
            dstParam->t = HISYSEVENT_DOUBLE;
            dstParam->v.d = srcParam->paramValue.d;
            break;
        case SOFTBUS_EVT_PARAMTYPE_STRING:
            return ConvertToHisEventString(srcParam, dstParam);
        case SOFTBUS_EVT_PARAMTYPE_UINT32_ARRAY:
            return ConvertToHisEventUint32Array(srcParam, dstParam, arraySize);
        default:
            break;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertMsgToHiSysEvent(SoftBusEvtReportMsg *msg)
{
    if (memset_s(g_dstParam, sizeof(HiSysEventParam) * SOFTBUS_EVT_PARAM_BUTT, 0,
        sizeof(HiSysEventParam) * SOFTBUS_EVT_PARAM_BUTT) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "init  g_dstParam fail");
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < msg->paramNum; i++) {
        if (strcpy_s(g_dstParam[i].name, MAX_LENGTH_OF_PARAM_NAME, msg->paramArray[i].paramName) != EOK) {
            COMM_LOGE(COMM_ADAPTER, "copy param fail");
            return SOFTBUS_ERR;
        }
        if (ConvertEventParam(&msg->paramArray[i], &g_dstParam[i]) != SOFTBUS_OK) {
            COMM_LOGE(COMM_ADAPTER, "ConvertMsgToHiSysEvent:convert param fail");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static void HiSysEventParamDeInit(uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        if (g_dstParam[i].t == HISYSEVENT_STRING && g_dstParam[i].v.s != nullptr) {
            SoftBusFree(g_dstParam[i].v.s);
            g_dstParam[i].v.s = nullptr;
        }
    }
}

static HiSysEventEventType ConvertMsgType(SoftBusEvtType type)
{
    HiSysEventEventType hiSysEvtType;
    switch (type) {
        case SOFTBUS_EVT_TYPE_FAULT:
            hiSysEvtType = HISYSEVENT_FAULT;
            break;
        case SOFTBUS_EVT_TYPE_STATISTIC:
            hiSysEvtType = HISYSEVENT_STATISTIC;
            break;
        case SOFTBUS_EVT_TYPE_SECURITY:
            hiSysEvtType = HISYSEVENT_SECURITY;
            break;
        case SOFTBUS_EVT_TYPE_BEHAVIOR:
            hiSysEvtType = HISYSEVENT_BEHAVIOR;
            break;
        default:
            hiSysEvtType = HISYSEVENT_STATISTIC;
            break;
    }
    return hiSysEvtType;
}

static void InitHisEvtMutexLock()
{
    if (SoftBusMutexInit(&g_dfx_lock, nullptr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "init HisEvtMutexLock fail");
        return;
    }
}

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SoftbusWriteHisEvt(SoftBusEvtReportMsg *reportMsg)
{
    if (reportMsg == nullptr) {
        return SOFTBUS_ERR;
    }
    if (!g_init_lock) {
        InitHisEvtMutexLock();
        g_init_lock = true;
    }
    if (SoftBusMutexLock(&g_dfx_lock) != 0) {
        COMM_LOGE(COMM_ADAPTER, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ConvertMsgToHiSysEvent(reportMsg);
    OH_HiSysEvent_Write(
        g_domain, reportMsg->evtName, ConvertMsgType(reportMsg->evtType), g_dstParam, reportMsg->paramNum);
    HiSysEventParamDeInit(reportMsg->paramNum);
    (void)SoftBusMutexUnlock(&g_dfx_lock);
    return SOFTBUS_OK;
}

void SoftbusFreeEvtReportMsg(SoftBusEvtReportMsg *msg)
{
    if (msg == nullptr) {
        return;
    }
    if (msg->paramArray != nullptr) {
        SoftBusFree(msg->paramArray);
        msg->paramArray = nullptr;
    }
    SoftBusFree(msg);
}

SoftBusEvtReportMsg *SoftbusCreateEvtReportMsg(int32_t paramNum)
{
    if (paramNum <= SOFTBUS_EVT_PARAM_ZERO || paramNum >= SOFTBUS_EVT_PARAM_BUTT) {
        COMM_LOGE(COMM_ADAPTER, "param is invalid");
        return nullptr;
    }
    SoftBusEvtReportMsg *msg = reinterpret_cast<SoftBusEvtReportMsg *>(SoftBusCalloc(sizeof(SoftBusEvtReportMsg)));
    if (msg == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "report msg is null");
        return nullptr;
    }
    msg->paramArray = reinterpret_cast<SoftBusEvtParam *>(SoftBusCalloc(sizeof(SoftBusEvtParam) * paramNum));
    if (msg->paramArray == nullptr) {
        SoftbusFreeEvtReportMsg(msg);
        return nullptr;
    }
    return msg;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */