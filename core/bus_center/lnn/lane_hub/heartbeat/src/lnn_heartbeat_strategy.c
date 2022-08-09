/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_strategy.h"

#include <securec.h>

#include "common_list.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_utils.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define HB_DEFAULT_CALLER_ID "HEARTBEAT_DEFAULT_CALLER_ID"
#define HB_GEARMODE_LIFETIME_PERMANENT (-1)

typedef struct {
    const char *callerId;
    ListNode node;
    GearMode mode;
    int64_t lifetimeStamp; // unit is milliseconds
} GearModeStorageInfo;

typedef struct {
    LnnHeartbeatType type;
    LnnHeartbeatMediumParam *param;
    ListNode gearModeList;
} LnnHeartbeatParamManager;

static SoftBusMutex g_hbStrategyMutex;
static LnnHeartbeatFsm *g_hbFsm = NULL;
static LnnHeartbeatParamManager *g_hbParamMgr[HB_MAX_TYPE_COUNT] = {0};

static int32_t SingleSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);
static int32_t FixedPeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);
static int32_t AdjustablePeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);

static LnnHeartbeatStrategyManager g_hbStrategyMgr[] = {
    [STRATEGY_HB_SEND_SINGLE] = {
        .supportType = HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_TCP_FLUSH,
        .onProcess = SingleSendStrategy,
    },
    [STRATEGY_HB_SEND_FIXED_PERIOD] = {
        .supportType = HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V1,
        .onProcess = FixedPeriodSendStrategy,
    },
    [STRATEGY_HB_SEND_ADJUSTABLE_PERIOD] = {
        .supportType = HEARTBEAT_TYPE_BLE_V0,
        .onProcess = AdjustablePeriodSendStrategy,
    },
    [STRATEGY_HB_RECV_SINGLE] = {
        .supportType = HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_TCP_FLUSH,
        .onProcess = NULL,
    },
    [STRATEGY_HB_RECV_REMOVE_REPEAT] = {
        .supportType = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1,
        .onProcess = NULL,
    },
};

static LnnHeartbeatParamManager *GetParamMgrByTypeLocked(LnnHeartbeatType type)
{
    int32_t id;

    id = LnnConvertHbTypeToId(type);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get param mgr convert type fail");
        return NULL;
    }
    return g_hbParamMgr[id];
}

static void DumpGearModeSettingList(int64_t nowTime, const ListNode *gearModeList)
{
#define HB_DUMP_GEAR_MODE_LIST_MAX_NUM 10
    int32_t dumpCount = 0;
    GearModeStorageInfo *info = NULL;

    LIST_FOR_EACH_ENTRY(info, gearModeList, GearModeStorageInfo, node) {
        dumpCount++;
        if (dumpCount > HB_DUMP_GEAR_MODE_LIST_MAX_NUM) {
            break;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "DumpGearModeSettingList count:%d [callerId=%s, cycle=%d, "
            "duration=%d, wakeupFlag=%d, lifetimeStamp=%" PRId64 ", needClean:%s]", dumpCount, info->callerId,
            info->mode.cycle, info->mode.duration, info->mode.wakeupFlag, info->lifetimeStamp,
            info->lifetimeStamp != HB_GEARMODE_LIFETIME_PERMANENT && info->lifetimeStamp <= nowTime ? "true" : "false");
    }
}

static int32_t GetGearModeFromSettingList(GearMode *mode, const ListNode *gearModeList)
{
    int64_t nowTime;
    const char *callerId = NULL;
    SoftBusSysTime times;
    GearModeStorageInfo *info = NULL;
    GearModeStorageInfo *nextInfo = NULL;

    SoftBusGetTime(&times);
    nowTime = times.sec * HB_TIME_FACTOR + times.usec / HB_TIME_FACTOR;
    DumpGearModeSettingList(nowTime, gearModeList);
    LIST_FOR_EACH_ENTRY_SAFE(info, nextInfo, gearModeList, GearModeStorageInfo, node) {
        if (info->lifetimeStamp < nowTime && info->lifetimeStamp != HB_GEARMODE_LIFETIME_PERMANENT) {
            ListDelete(&info->node);
            SoftBusFree((void *)info->callerId);
            SoftBusFree(info);
            continue;
        }
        /* Priority to send high-frequency heartbeat */
        if (mode->cycle != 0 && mode->cycle <= info->mode.cycle) {
            continue;
        }
        if (memcpy_s(mode, sizeof(GearMode), &info->mode, sizeof(GearMode)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode from setting list memcpy_s err");
            return SOFTBUS_MEM_ERR;
        }
        callerId = info->callerId;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB get Gearmode from list, id:%s, cycle:%d, duration:%d, "
        "wakeupFlag:%d", callerId, mode->cycle, mode->duration, mode->wakeupFlag);
    callerId = NULL;
    return SOFTBUS_OK;
}

static int32_t FirstSetGearModeByCallerId(const char *callerId, int64_t nowTime, ListNode *list, const GearMode *mode)
{
    GearModeStorageInfo *info = NULL;

    info = (GearModeStorageInfo *)SoftBusCalloc(sizeof(GearModeStorageInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first set Gearmode calloc storage info err");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (memcpy_s(&info->mode, sizeof(GearMode), mode, sizeof(GearMode)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first set Gearmode memcpy_s err");
        SoftBusFree(info);
        return SOFTBUS_MEM_ERR;
    }
    info->callerId = (char *)SoftBusCalloc(strlen(callerId) + 1);
    if (info->callerId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first set Gearmode malloc callerId err");
        SoftBusFree(info);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s((char *)info->callerId, strlen(callerId) + 1, callerId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB first set Gearmode strcpy_s callerId err");
        SoftBusFree((char *)info->callerId);
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    if (strcmp(callerId, HB_DEFAULT_CALLER_ID) == 0) {
        info->lifetimeStamp = HB_GEARMODE_LIFETIME_PERMANENT;
    } else {
        info->lifetimeStamp = nowTime + mode->duration * HB_TIME_FACTOR;
    }
    ListAdd(list, &info->node);
    return SOFTBUS_OK;
}

int32_t LnnGetGearModeBySpecificType(GearMode *mode, LnnHeartbeatType type)
{
    const LnnHeartbeatParamManager *paramMgr = NULL;

    if (mode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(mode, sizeof(GearMode), 0, sizeof(GearMode) != EOK)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode memset_s err");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (GetGearModeFromSettingList(mode, &paramMgr->gearModeList) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get Gearmode from setting list err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type)
{
    int64_t nowTime;
    SoftBusSysTime times;
    GearModeStorageInfo *info = NULL;
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set Gearmode lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set Gearmode get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    SoftBusGetTime(&times);
    nowTime = times.sec * HB_TIME_FACTOR + times.usec / HB_TIME_FACTOR;
    LIST_FOR_EACH_ENTRY(info, &paramMgr->gearModeList, GearModeStorageInfo, node) {
        if (strcmp(info->callerId, callerId) != 0) {
            continue;
        }
        if (memcpy_s(&info->mode, sizeof(GearMode), mode, sizeof(GearMode)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set Gearmode memcpy_s err");
            (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
            return SOFTBUS_MEM_ERR;
        }
        info->lifetimeStamp = nowTime + mode->duration * HB_TIME_FACTOR;
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_OK;
    }
    if (FirstSetGearModeByCallerId(callerId, nowTime, &paramMgr->gearModeList, mode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set Gearmode by callerId err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

static bool VisitClearUnRegistedHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)data;
    LnnHeartbeatParamManager *paramMgr = NULL;

    paramMgr = GetParamMgrByTypeLocked(eachType);
    if (paramMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB param mgr is unregisted, hbType(%d)", eachType);
        *typeSet &= ~eachType;
    }
    return true;
}

static int32_t ProcessSendOnceStrategy(LnnHeartbeatFsm *hbFsm, const LnnProcessSendOnceMsgPara *msgPara)
{
    bool isRemoved = true;
    LnnHeartbeatType registedHbType = msgPara->hbType;

    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    (void)LnnVisitHbTypeSet(VisitClearUnRegistedHbType, &registedHbType, NULL);
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    if (registedHbType < HEARTBEAT_TYPE_MIN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB send once hbType(%d) not registed", msgPara->hbType);
        return SOFTBUS_OK;
    }
    LnnRemoveSendEndMsg(hbFsm, registedHbType, &isRemoved);
    if (!isRemoved) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB send once is beginning, hbType:%d", msgPara->hbType);
        return SOFTBUS_OK;
    }
    if (LnnPostSendBeginMsgToHbFsm(hbFsm, registedHbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin fail, hbType:%d", registedHbType);
        return SOFTBUS_ERR;
    }
    if (LnnPostSendEndMsgToHbFsm(hbFsm, registedHbType, HB_SEND_ONCE_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end fail, hbType:%d", registedHbType);
        return SOFTBUS_ERR;
    }
    LnnFsmRemoveMessage(&hbFsm->fsm, EVENT_HB_CHECK_DEV_STATUS);
    if (LnnPostCheckDevStatusMsgToHbFsm(hbFsm, NULL, HB_CHECK_DELAY_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once post check msg fail, hbType:%d", registedHbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SingleSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;

    if (msgPara->strategyType != STRATEGY_HB_SEND_SINGLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB single send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ProcessSendOnceStrategy(hbFsm, msgPara) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB single send process send once fail");
        return SOFTBUS_ERR;
    }
    SoftBusFree(msgPara);
    return SOFTBUS_OK;
}

static int32_t FixedPeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    uint64_t loopDelayMillis;
    const LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;

    if (msgPara->strategyType != STRATEGY_HB_SEND_FIXED_PERIOD) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fixed period send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ProcessSendOnceStrategy(hbFsm, msgPara) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fixed period send once fail");
        return SOFTBUS_ERR;
    }
    loopDelayMillis = (uint64_t)LOW_FREQ_CYCLE * HB_TIME_FACTOR;
    if (LnnPostNextSendOnceMsgToHbFsm(hbFsm, obj, loopDelayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fixed period send loop msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AdjustablePeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    GearMode mode = {0};
    const LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;

    if (msgPara->strategyType != STRATEGY_HB_SEND_ADJUSTABLE_PERIOD) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB adjustable send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnRemoveProcessSendOnceMsg(hbFsm, msgPara->hbType, msgPara->strategyType);
    if (ProcessSendOnceStrategy(hbFsm, msgPara) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB adjustable send once fail");
        return SOFTBUS_ERR;
    }
    if (LnnGetGearModeBySpecificType(&mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB adjustable send get Gearmode err");
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR;
    if (LnnPostNextSendOnceMsgToHbFsm(hbFsm, obj, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB adjustable send loop msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t RegistParamMgrBySpecificType(LnnHeartbeatType type)
{
    LnnHeartbeatParamManager *paramMgr = NULL;

    GearMode mode = {
        .cycle = LOW_FREQ_CYCLE,
        .duration = LONG_DURATION,
        .wakeupFlag = false,
    };
    paramMgr = (LnnHeartbeatParamManager *)SoftBusCalloc(sizeof(LnnHeartbeatParamManager));
    if (paramMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist param mgr malloc paramMgr fail");
        return SOFTBUS_MALLOC_ERR;
    }
    paramMgr->type = type;
    paramMgr->param = NULL;
    ListInit(&paramMgr->gearModeList);

    if (FirstSetGearModeByCallerId(HB_DEFAULT_CALLER_ID, 0, &paramMgr->gearModeList, &mode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist param mgr set default Gearmode fail");
        SoftBusFree(paramMgr);
        return SOFTBUS_ERR;
    }
    g_hbParamMgr[LnnConvertHbTypeToId(type)] = paramMgr;
    return SOFTBUS_OK;
}

static bool VisitRegistParamMgr(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    const LnnHeartbeatParamManager *paramMgr = NULL;

    paramMgr = GetParamMgrByTypeLocked(eachType);
    if (paramMgr != NULL) {
        return true;
    }
    if (RegistParamMgrBySpecificType(eachType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist paramMgr by type(%d) err", eachType);
        return false;
    }
    return true;
}

int32_t LnnRegistParamMgrByType(LnnHeartbeatType type)
{
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist paramMgr lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    (void)LnnVisitHbTypeSet(VisitRegistParamMgr, &type, NULL);
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

static void UnRegistParamMgr(LnnHeartbeatParamManager *paramMgr)
{
    GearModeStorageInfo *item = NULL;
    GearModeStorageInfo *nextItem = NULL;

    if (paramMgr->param != NULL) {
        SoftBusFree(paramMgr->param);
        paramMgr->param = NULL;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &paramMgr->gearModeList, GearModeStorageInfo, node) {
        ListDelete(&item->node);
        if (item->callerId != NULL) {
            SoftBusFree((char *)item->callerId);
        }
        SoftBusFree(item);
    }
    ListDelInit(&paramMgr->gearModeList);
    SoftBusFree(paramMgr);
    paramMgr = NULL;
}

static bool VisitUnRegistParamMgr(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)typeSet;
    (void)data;
    LnnHeartbeatParamManager *paramMgr = NULL;

    paramMgr = GetParamMgrByTypeLocked(eachType);
    if (paramMgr == NULL) {
        return true;
    }
    UnRegistParamMgr(paramMgr);
    return true;
}

void LnnUnRegistParamMgrByType(LnnHeartbeatType type)
{
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB unRegist paramMgr lock mutex fail");
        return;
    }
    (void)LnnVisitHbTypeSet(VisitUnRegistParamMgr, &type, NULL);
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(param->type);
    if (paramMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (paramMgr->param == NULL) {
        paramMgr->param = (LnnHeartbeatMediumParam *)SoftBusCalloc(sizeof(LnnHeartbeatMediumParam));
    }
    if (paramMgr->param == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param calloc err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(paramMgr->param, sizeof(LnnHeartbeatMediumParam), param, sizeof(LnnHeartbeatMediumParam)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param memcpy_s err");
        SoftBusFree(paramMgr->param);
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = LnnHbMediumMgrSetParam(paramMgr->param);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param via mgr err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

int32_t LnnGetMediumParamBySpecificType(LnnHeartbeatMediumParam *param, LnnHeartbeatType type)
{
    const LnnHeartbeatParamManager *paramMgr = NULL;

    if (param == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(param, sizeof(LnnHeartbeatMediumParam), 0, sizeof(LnnHeartbeatMediumParam) != EOK)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get medium param memset_s err");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get medium param lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL || paramMgr->param == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get medium param get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(param, sizeof(LnnHeartbeatMediumParam), paramMgr->param, sizeof(LnnHeartbeatMediumParam)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get medium param memcpy_s err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

bool LnnIsMediumParamMgrRegisted(LnnHeartbeatType type)
{
    int32_t id;
    bool ret = false;

    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get strategy enabled status lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    id = LnnConvertHbTypeToId(type);
    if (id == HB_INVALID_TYPE_ID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get strategy enabled status convert type fail");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return false;
    }
    ret = g_hbParamMgr[id] != NULL ? true : false;
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return ret;
}

int32_t LnnGetHbStrategyManager(LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType,
    LnnHeartbeatStrategyType strategyType)
{
    if (mgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get strategy mgr invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnCheckSupportedHbType(&hbType, &g_hbStrategyMgr[strategyType].supportType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get strategy mgr type(%d) not support hbType(%d)",
            strategyType, hbType);
        return SOFTBUS_ERR;
    }
    mgr->supportType = g_hbStrategyMgr[strategyType].supportType;
    mgr->onProcess = g_hbStrategyMgr[strategyType].onProcess;
    return SOFTBUS_OK;
}

int32_t LnnStartNewHbStrategyFsm(void)
{
    LnnHeartbeatFsm *hbFsm = NULL;

    hbFsm = LnnCreateHeartbeatFsm();
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start strategy fsm create fsm fail");
        return SOFTBUS_ERR;
    }
    /* If udp heartbeat deployed, use HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V1 */
    hbFsm->hbType = HEARTBEAT_TYPE_BLE_V1;
    hbFsm->strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    if (LnnStartHeartbeatFsm(hbFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start strategy fsm start fsm fail");
        return SOFTBUS_ERR;
    }
    g_hbFsm = hbFsm;
    hbFsm = NULL;
    return SOFTBUS_OK;
}

int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    GearMode mode = {0};
    LnnCheckDevStatusMsgPara *msgPara = NULL;
    
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    msgPara = (LnnCheckDevStatusMsgPara *)SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start offline timing malloc msgPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s((char *)msgPara->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start offline timing strcpy_s networkId fail");
        SoftBusFree(msgPara);
        return SOFTBUS_ERR;
    }
    msgPara->addrType = addrType;
    msgPara->hbType = LnnConvertConnAddrTypeToHbType(addrType);
    if (LnnGetGearModeBySpecificType(&mode, msgPara->hbType) != SOFTBUS_OK) {
        SoftBusFree(msgPara);
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR + HB_CHECK_DELAY_LEN;
    return LnnPostCheckDevStatusMsgToHbFsm(g_hbFsm, msgPara, delayMillis);
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnCheckDevStatusMsgPara msgPara = {
        .hbType = LnnConvertConnAddrTypeToHbType(addrType),
        .addrType = addrType,
    };
    if (strcpy_s((char *)msgPara.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop offline timing strcpy_s networkId fail");
        return SOFTBUS_ERR;
    }
    LnnRemoveCheckDevStatusMsg(g_hbFsm, &msgPara);
    return SOFTBUS_OK;
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
{
    LnnProcessSendOnceMsgPara *msgPara = NULL;
    
    msgPara = (LnnProcessSendOnceMsgPara *)SoftBusMalloc(sizeof(LnnProcessSendOnceMsgPara));
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start heartbeat malloc msgPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    msgPara->hbType = hbType;
    msgPara->strategyType = strategyType;
    if (g_hbFsm->state == STATE_HB_NONE_INDEX) {
        LnnPostTransStateMsgToHbFsm(g_hbFsm, true);
    }
    if (LnnPostNextSendOnceMsgToHbFsm(g_hbFsm, msgPara, 0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start heartbeat fail, type:%d", hbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopHbByType(LnnHeartbeatType type)
{
    LnnRemoveProcessSendOnceMsg(g_hbFsm, HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
    return LnnPostStopMsgToHbFsm(g_hbFsm, type);
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return LnnPostTransStateMsgToHbFsm(g_hbFsm, isMasterNode);
}

int32_t LnnHbStrategyInit(void)
{
    if (SoftBusMutexInit(&g_hbStrategyMutex, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB strategy module init mutex fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegistParamMgrByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist ble strategy fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegistParamMgrByType(HEARTBEAT_TYPE_TCP_FLUSH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist udp/tcp strategy fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnHbStrategyDeinit(void)
{
    if (g_hbFsm != NULL) {
        (void)LnnStopHeartbeatFsm(g_hbFsm);
    }
    LnnUnRegistParamMgrByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1);
    LnnUnRegistParamMgrByType(HEARTBEAT_TYPE_TCP_FLUSH);
    (void)SoftBusMutexDestroy(&g_hbStrategyMutex);
}
