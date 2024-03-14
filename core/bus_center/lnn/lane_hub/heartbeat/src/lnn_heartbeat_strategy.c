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

#include "anonymizer.h"
#include "common_list.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_log.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
#include "lnn_feature_capability.h"
#include "bus_center_manager.h"

#define HB_GEARMODE_MAX_SET_CNT 100
#define HB_GEARMODE_LIFETIME_PERMANENT (-1)
#define HB_DEFAULT_CALLER_ID "HEARTBEAT_DEFAULT_CALLER_ID"

typedef struct {
    const char *callerId;
    ListNode node;
    GearMode mode;
    int64_t lifeTimestamp; // unit is milliseconds
} GearModeStorageInfo;

typedef struct {
    LnnHeartbeatType type;
    LnnHeartbeatMediumParam *param;
    int32_t gearModeCnt;
    ListNode gearModeList;
    bool isEnable;
} LnnHeartbeatParamManager;

static SoftBusMutex g_hbStrategyMutex;
static LnnHeartbeatFsm *g_hbFsm = NULL;
static LnnHeartbeatParamManager *g_hbParamMgr[HB_MAX_TYPE_COUNT] = {0};

static int32_t SingleSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);
static int32_t FixedPeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);
static int32_t AdjustablePeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj);

static LnnHeartbeatStrategyManager g_hbStrategyMgr[] = {
    [STRATEGY_HB_SEND_SINGLE] = {
        .supportType = HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3 |
            HEARTBEAT_TYPE_TCP_FLUSH,
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
        LNN_LOGD(LNN_HEART_BEAT, "DumpGearModeSettingList count=%{public}d, callerId=%{public}s, cycle=%{public}d, "
            "duration=%{public}d, wakeupFlag=%{public}d, lifeTimestamp=%{public}" PRId64 ", needClean=%{public}s",
            dumpCount, info->callerId, info->mode.cycle, info->mode.duration, info->mode.wakeupFlag,
            info->lifeTimestamp,
            info->lifeTimestamp != HB_GEARMODE_LIFETIME_PERMANENT && info->lifeTimestamp <= nowTime ? "true" : "false");
    }
}

static int32_t GetGearModeFromSettingList(GearMode *mode, const ListNode *gearModeList, int32_t *gearModeCnt)
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
        if (*gearModeCnt == 0) {
            LNN_LOGD(LNN_HEART_BEAT, "HB get Gearmode from setting list is empty");
            return SOFTBUS_NETWORK_HEARTBEAT_EMPTY_LIST;
        }
        if (info->lifeTimestamp < nowTime && info->lifeTimestamp != HB_GEARMODE_LIFETIME_PERMANENT) {
            ListDelete(&info->node);
            SoftBusFree((void *)info->callerId);
            SoftBusFree(info);
            (*gearModeCnt)--;
            continue;
        }
        /* Priority to send high-frequency heartbeat */
        if (mode->cycle != 0 && mode->cycle < info->mode.cycle) {
            continue;
        }
        if (mode->cycle == info->mode.cycle && !info->mode.wakeupFlag) {
            continue;
        }
        if (memcpy_s(mode, sizeof(GearMode), &info->mode, sizeof(GearMode)) != EOK) {
            LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode from setting list memcpy_s err");
            return SOFTBUS_MEM_ERR;
        }
        callerId = info->callerId;
    }
    if (callerId != NULL) {
        LNN_LOGD(LNN_HEART_BEAT, "HB get Gearmode from list, id=%{public}s, cycle=%{public}d, duration=%{public}d, "
        "wakeupFlag=%{public}d", callerId, mode->cycle, mode->duration, mode->wakeupFlag);
    }
    return SOFTBUS_OK;
}

static LnnHeartbeatParamManager *GetParamMgrByTypeLocked(LnnHeartbeatType type)
{
    int32_t id;

    id = LnnConvertHbTypeToId(type);
    if (id == HB_INVALID_TYPE_ID) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get param mgr convert type fail");
        return NULL;
    }
    return g_hbParamMgr[id];
}

int32_t LnnGetGearModeBySpecificType(GearMode *mode, LnnHeartbeatType type)
{
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (mode == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(mode, sizeof(GearMode), 0, sizeof(GearMode) != EOK)) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode memset_s err");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (IsListEmpty(&paramMgr->gearModeList)) {
        LNN_LOGD(LNN_HEART_BEAT, "HB get Gearmode from setting list is empty");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_NETWORK_HEARTBEAT_EMPTY_LIST;
    }
    int32_t ret = GetGearModeFromSettingList(mode, &paramMgr->gearModeList, &paramMgr->gearModeCnt);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_NETWORK_HEARTBEAT_EMPTY_LIST) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get Gearmode from setting list err");
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return ret;
}

static int32_t FirstSetGearModeByCallerId(const char *callerId, int64_t nowTime, ListNode *list, const GearMode *mode)
{
    GearModeStorageInfo *info = NULL;

    info = (GearModeStorageInfo *)SoftBusCalloc(sizeof(GearModeStorageInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB first set Gearmode calloc storage info err");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (memcpy_s(&info->mode, sizeof(GearMode), mode, sizeof(GearMode)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB first set Gearmode memcpy_s err");
        SoftBusFree(info);
        return SOFTBUS_MEM_ERR;
    }
    info->callerId = (char *)SoftBusCalloc(strlen(callerId) + 1);
    if (info->callerId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB first set Gearmode malloc callerId err");
        SoftBusFree(info);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s((char *)info->callerId, strlen(callerId) + 1, callerId) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB first set Gearmode strcpy_s callerId err");
        SoftBusFree((char *)info->callerId);
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    if (strcmp(callerId, HB_DEFAULT_CALLER_ID) == 0) {
        info->lifeTimestamp = HB_GEARMODE_LIFETIME_PERMANENT;
    } else {
        info->lifeTimestamp = nowTime + mode->duration * HB_TIME_FACTOR;
    }
    ListAdd(list, &info->node);
    return SOFTBUS_OK;
}

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode,
    LnnHeartbeatType type)
{
    int64_t nowTime;
    SoftBusSysTime times;
    GearModeStorageInfo *info = NULL;
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set Gearmode lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set Gearmode get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (paramMgr->gearModeCnt > HB_GEARMODE_MAX_SET_CNT) {
        LNN_LOGW(LNN_HEART_BEAT, "HB set Gearmode cnt exceed MAX_CNT=%{public}d", HB_GEARMODE_MAX_SET_CNT);
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
            LNN_LOGE(LNN_HEART_BEAT, "HB set Gearmode memcpy_s err");
            (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
            return SOFTBUS_MEM_ERR;
        }
        info->lifeTimestamp = nowTime + mode->duration * HB_TIME_FACTOR;
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_OK;
    }
    if (FirstSetGearModeByCallerId(callerId, nowTime, &paramMgr->gearModeList, mode) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set Gearmode by callerId err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    paramMgr->gearModeCnt++;
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

LnnHeartbeatStrategyType GetStrategyTypeByPolicy(int32_t policy)
{
    if (policy == ONCE_STRATEGY) {
        return STRATEGY_HB_SEND_SINGLE;
    }
    return STRATEGY_HB_SEND_ADJUSTABLE_PERIOD;
}

static bool VisitClearNoneSplitHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)data;

    if (eachType != HEARTBEAT_TYPE_BLE_V0 && eachType != HEARTBEAT_TYPE_BLE_V1) {
        /* only the ble heartbeat needs to be split and sent */
        *typeSet &= ~eachType;
    }
    return true;
}

static int32_t SendEachSeparately(LnnHeartbeatFsm *hbFsm, LnnProcessSendOnceMsgPara *msgPara,
    const GearMode *mode, LnnHeartbeatType registedHbType, bool isRelayV0)
{
    LNN_LOGD(LNN_HEART_BEAT, "SendEachSeparately enter, hbType=%{public}d, isRelayV0=%{public}d", registedHbType,
        isRelayV0);
    bool wakeupFlag = mode != NULL ? mode->wakeupFlag : false;
    if (LnnPostSendBeginMsgToHbFsm(hbFsm, registedHbType, wakeupFlag, msgPara, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB send once first begin fail, hbType=%{public}d", registedHbType);
        return SOFTBUS_ERR;
    }

    uint32_t i;
    uint32_t sendCnt = isRelayV0 ? 1 : HB_SEND_SEPARATELY_CNT;
    LnnHeartbeatType splitHbType = registedHbType;
    (void)LnnVisitHbTypeSet(VisitClearNoneSplitHbType, &splitHbType, NULL);
    LnnHeartbeatSendEndData endData = {
        .hbType = splitHbType,
        .wakeupFlag = wakeupFlag,
        .isRelay = msgPara->isRelay,
        .isLastEnd = false,
    };
    for (i = 1; i < sendCnt; ++i) {
        if (splitHbType < HEARTBEAT_TYPE_MIN) {
            break;
        }
        if (i == sendCnt - 1) {
            if (LnnPostSendEndMsgToHbFsm(hbFsm, &endData, i * HB_SEND_EACH_SEPARATELY_LEN) != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "HB send once end fail, hbType=%{public}d", splitHbType);
                return SOFTBUS_ERR;
            }
            msgPara->isSyncData = true;
            if (LnnPostSendBeginMsgToHbFsm(hbFsm, splitHbType, wakeupFlag, msgPara,
                i * HB_SEND_EACH_SEPARATELY_LEN) != SOFTBUS_OK) {
                msgPara->isSyncData = false;
                LNN_LOGE(LNN_HEART_BEAT, "HB send once begin fail, hbType=%{public}d", splitHbType);
                return SOFTBUS_ERR;
            }
        }
    }

    endData.hbType = registedHbType;
    endData.isLastEnd = true;
    if (LnnPostSendEndMsgToHbFsm(hbFsm, &endData, isRelayV0 ? HB_SEND_RELAY_LEN : HB_SEND_ONCE_LEN) != SOFTBUS_OK) {
        msgPara->isSyncData = false;
        LNN_LOGE(LNN_HEART_BEAT, "HB send once last end fail, hbType=%{public}d", registedHbType);
        return SOFTBUS_ERR;
    }
    msgPara->isSyncData = false;
    LNN_LOGD(LNN_HEART_BEAT, "SendEachSeparately exit");
    return SOFTBUS_OK;
}

static bool VisitClearUnRegistedHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    (void)data;

    if (!LnnIsHeartbeatEnable(eachType)) {
        LNN_LOGD(LNN_HEART_BEAT, "HB heartbeat is disabled, hbType=%{public}d", eachType);
        *typeSet &= ~eachType;
    }
    return true;
}

static int32_t ProcessSendOnceStrategy(LnnHeartbeatFsm *hbFsm, LnnProcessSendOnceMsgPara *msgPara,
    const GearMode *mode)
{
    bool isRemoved = true;
    LnnHeartbeatType registedHbType = msgPara->hbType;
    bool wakeupFlag = mode != NULL ? mode->wakeupFlag : false;
    if (GetScreenState() == SOFTBUS_SCREEN_OFF && !wakeupFlag && !msgPara->isRelay) {
        LNN_LOGW(LNN_HEART_BEAT, "screen state is off and not wakeup adv");
        return SOFTBUS_OK;
    }
    (void)LnnVisitHbTypeSet(VisitClearUnRegistedHbType, &registedHbType, NULL);
    if (registedHbType < HEARTBEAT_TYPE_MIN) {
        LNN_LOGW(LNN_HEART_BEAT, "HB send once get hbType is not available. hbType=%{public}d", msgPara->hbType);
        return SOFTBUS_OK;
    }
    LnnRemoveSendEndMsg(hbFsm, registedHbType, wakeupFlag, msgPara->isRelay, &isRemoved);
    if (!isRemoved) {
        LNN_LOGW(LNN_HEART_BEAT,
            "HB send once is beginning, hbType=%{public}d, wakeupFlag=%{public}d, isRelay=%{public}d",
            msgPara->hbType, wakeupFlag, msgPara->isRelay);
        return SOFTBUS_OK;
    }
    LnnFsmRemoveMessage(&hbFsm->fsm, EVENT_HB_SEND_ONE_BEGIN);
    bool isRelayV0 = msgPara->isRelay && registedHbType == HEARTBEAT_TYPE_BLE_V0;
    if (SendEachSeparately(hbFsm, msgPara, mode, registedHbType, isRelayV0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB send each separately fail, hbType=%{public}d", registedHbType);
        return SOFTBUS_ERR;
    }
    if (isRelayV0) {
        LNN_LOGD(LNN_HEART_BEAT, "HB send once but dont check status, hbType=%{public}d", registedHbType);
        return SOFTBUS_OK;
    }
    LnnCheckDevStatusMsgPara checkMsg = {.hbType = registedHbType, .hasNetworkId = false, .isWakeUp = wakeupFlag};
    LnnRemoveCheckDevStatusMsg(hbFsm, &checkMsg);
    if (LnnPostCheckDevStatusMsgToHbFsm(hbFsm, &checkMsg, HB_CHECK_DELAY_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB send once post check msg fail, hbType=%{public}d", registedHbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SingleSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;
    if (msgPara->strategyType != STRATEGY_HB_SEND_SINGLE) {
        LNN_LOGE(LNN_HEART_BEAT, "HB single send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ProcessSendOnceStrategy(hbFsm, msgPara, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB single send process send once fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t FixedPeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;

    if (msgPara->strategyType != STRATEGY_HB_SEND_FIXED_PERIOD) {
        LNN_LOGE(LNN_HEART_BEAT, "HB fixed period send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ProcessSendOnceStrategy(hbFsm, msgPara, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB fixed period send once fail");
        return SOFTBUS_ERR;
    }
    if (LnnPostNextSendOnceMsgToHbFsm(hbFsm, msgPara, (uint64_t)LOW_FREQ_CYCLE * HB_TIME_FACTOR) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB fixed period send loop msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AdjustablePeriodSendStrategy(LnnHeartbeatFsm *hbFsm, void *obj)
{
    int32_t ret;
    GearMode mode;
    (void)memset_s(&mode, sizeof(GearMode), 0, sizeof(GearMode));
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)obj;

    if (msgPara->hbType != HEARTBEAT_TYPE_BLE_V0 || msgPara->strategyType != STRATEGY_HB_SEND_ADJUSTABLE_PERIOD) {
        LNN_LOGE(LNN_HEART_BEAT, "HB adjustable send get invaild strategy");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnRemoveProcessSendOnceMsg(hbFsm, msgPara->hbType, msgPara->strategyType);
    ret = LnnGetGearModeBySpecificType(&mode, HEARTBEAT_TYPE_BLE_V0);
    if (ret == SOFTBUS_NETWORK_HEARTBEAT_EMPTY_LIST) {
        LNN_LOGD(LNN_HEART_BEAT, "HB adjustable period strategy is end");
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB adjustable send get Gearmode err");
        return SOFTBUS_ERR;
    }
    if (ProcessSendOnceStrategy(hbFsm, msgPara, &mode) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB adjustable send once fail");
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR;
    if (LnnPostNextSendOnceMsgToHbFsm(hbFsm, (const LnnProcessSendOnceMsgPara *)obj, delayMillis) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB adjustable send loop msg fail");
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
        LNN_LOGE(LNN_HEART_BEAT, "HB regist param mgr malloc paramMgr fail");
        return SOFTBUS_MALLOC_ERR;
    }
    paramMgr->type = type;
    paramMgr->param = NULL;
    paramMgr->isEnable = false;
    paramMgr->gearModeCnt = 0;
    ListInit(&paramMgr->gearModeList);

    if (type != HEARTBEAT_TYPE_BLE_V0 && type != HEARTBEAT_TYPE_BLE_V3) {
        if (FirstSetGearModeByCallerId(HB_DEFAULT_CALLER_ID, 0, &paramMgr->gearModeList, &mode) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "HB regist param mgr set default Gearmode fail");
            SoftBusFree(paramMgr);
            return SOFTBUS_ERR;
        }
        paramMgr->gearModeCnt++;
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
        LNN_LOGE(LNN_HEART_BEAT, "HB regist paramMgr err, type=%{public}d", eachType);
        return false;
    }
    return true;
}

int32_t LnnRegistParamMgrByType(LnnHeartbeatType type)
{
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB regist paramMgr lock mutex fail");
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
        LNN_LOGE(LNN_HEART_BEAT, "HB unRegist paramMgr lock mutex fail");
        return;
    }
    (void)LnnVisitHbTypeSet(VisitUnRegistParamMgr, &type, NULL);
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (param == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(param->type);
    if (paramMgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (paramMgr->param == NULL) {
        paramMgr->param = (LnnHeartbeatMediumParam *)SoftBusCalloc(sizeof(LnnHeartbeatMediumParam));
    }
    if (paramMgr->param == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param calloc err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(paramMgr->param, sizeof(LnnHeartbeatMediumParam), param, sizeof(LnnHeartbeatMediumParam)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param memcpy_s err");
        SoftBusFree(paramMgr->param);
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = LnnPostSetMediumParamMsgToHbFsm(g_hbFsm, paramMgr->param);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB set medium param via mgr err");
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
        LNN_LOGE(LNN_HEART_BEAT, "HB get medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memset_s(param, sizeof(LnnHeartbeatMediumParam), 0, sizeof(LnnHeartbeatMediumParam) != EOK)) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get medium param memset_s err");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get medium param lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    if (paramMgr == NULL || paramMgr->param == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get medium param get NULL paramMgr");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(param, sizeof(LnnHeartbeatMediumParam), paramMgr->param, sizeof(LnnHeartbeatMediumParam)) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get medium param memcpy_s err");
        (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

int32_t LnnGetHbStrategyManager(LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType,
    LnnHeartbeatStrategyType strategyType)
{
    if (mgr == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get strategy mgr invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnCheckSupportedHbType(&hbType, &g_hbStrategyMgr[strategyType].supportType)) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get strategy mgr not support, type=%{public}d, hbType=%{public}d",
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
        LNN_LOGE(LNN_HEART_BEAT, "HB start strategy fsm create fsm fail");
        return SOFTBUS_ERR;
    }
    /* If udp heartbeat deployed, use HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V1 */
    hbFsm->hbType = HEARTBEAT_TYPE_BLE_V1;
    hbFsm->strategyType = STRATEGY_HB_SEND_FIXED_PERIOD;
    if (LnnStartHeartbeatFsm(hbFsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB start strategy fsm start fsm fail");
        return SOFTBUS_ERR;
    }
    g_hbFsm = hbFsm;
    hbFsm = NULL;
    return SOFTBUS_OK;
}

int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    GearMode mode;
    (void)memset_s(&mode, sizeof(GearMode), 0, sizeof(GearMode));
    LnnCheckDevStatusMsgPara msgPara = {0};

    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyNetworkId = NULL;
    if (LnnIsSupportBurstFeature(networkId)) {
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGD(LNN_HEART_BEAT, "%{public}s support burst, dont't need post offline info", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    if (strcpy_s((char *)msgPara.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB start offline timing strcpy_s networkId fail");
        return SOFTBUS_ERR;
    }
    msgPara.addrType = addrType;
    msgPara.hasNetworkId = true;
    msgPara.hbType = LnnConvertConnAddrTypeToHbType(addrType);
    if (LnnGetGearModeBySpecificType(&mode, msgPara.hbType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR + HB_NOTIFY_DEV_LOST_DELAY_LEN;
    return LnnPostCheckDevStatusMsgToHbFsm(g_hbFsm, &msgPara, delayMillis);
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
        LNN_LOGE(LNN_HEART_BEAT, "HB stop offline timing strcpy_s networkId fail");
        return SOFTBUS_ERR;
    }
    msgPara.hasNetworkId = true;
    LnnRemoveCheckDevStatusMsg(g_hbFsm, &msgPara);
    return SOFTBUS_OK;
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    LNN_LOGI(LNN_HEART_BEAT, "start screen changed offline timing");
    if (networkId == NULL || addrType >= CONNECTION_ADDR_MAX) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnCheckDevStatusMsgPara msgPara = {0};
    if (strcpy_s((char *)msgPara.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB start offline timing strcpy_s networkId fail");
        return SOFTBUS_ERR;
    }
    msgPara.hasNetworkId = true;
    msgPara.hbType = LnnConvertConnAddrTypeToHbType(addrType);

    if (LnnPostScreenOffCheckDevMsgToHbFsm(g_hbFsm, &msgPara, HB_OFFLINE_PERIOD * HB_OFFLINE_TIME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "post screen off check dev msg failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnCheckDevStatusMsgPara msgPara = {
        .hbType = LnnConvertConnAddrTypeToHbType(addrType),
        .addrType = addrType,
    };
    if (strcpy_s((char *)msgPara.networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB stop offline timing strcpy_s networkId fail");
        return SOFTBUS_ERR;
    }
    msgPara.hasNetworkId = true;
    LnnRemoveScreenOffCheckStatusMsg(g_hbFsm, &msgPara);
    return SOFTBUS_OK;
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType,
    bool isRelay)
{
    LnnProcessSendOnceMsgPara msgPara = {
        .hbType = hbType,
        .isRelay = isRelay,
        .strategyType = strategyType,
    };
    if (LnnPostNextSendOnceMsgToHbFsm(g_hbFsm, &msgPara, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB start heartbeat fail, type=%{public}d", hbType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStartHeartbeat(uint64_t delayMillis)
{
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat(HB) process start delay=%{public}" PRIu64 "msec", delayMillis);
    return LnnPostStartMsgToHbFsm(g_hbFsm, delayMillis);
}

int32_t LnnStopV0HeartbeatAndNotTransState()
{
    LNN_LOGI(LNN_HEART_BEAT, "HB only stop heartbeat V0");
    if (LnnPostStopMsgToHbFsm(g_hbFsm, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB stop heartbeat by type post msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopHeartbeatByType(LnnHeartbeatType type)
{
    if (LnnPostStopMsgToHbFsm(g_hbFsm, type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB stop heartbeat by type post msg fail");
        return SOFTBUS_ERR;
    }
    LnnHbClearRecvList();
    if (type == (HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3 |
        HEARTBEAT_TYPE_TCP_FLUSH)) {
        return LnnPostTransStateMsgToHbFsm(g_hbFsm, EVENT_HB_IN_NONE_STATE);
    }
    return SOFTBUS_OK;
}

int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType type)
{
    if (type <= HEARTBEAT_TYPE_MIN || type >= HEARTBEAT_TYPE_MAX) {
        LNN_LOGE(LNN_HEART_BEAT, "HB send once get is not available, hbType=%{public}d", type);
        return SOFTBUS_ERR;
    }
    LnnHeartbeatSendEndData endData = {
        .hbType = type,
        .wakeupFlag = false,
        .isRelay = false,
        .isLastEnd = true,
    };
    if (LnnPostSendEndMsgToHbFsm(g_hbFsm, &endData, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB send once end fail, hbType=%{public}d", type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool VisitEnableHbType(LnnHeartbeatType *typeSet, LnnHeartbeatType eachType, void *data)
{
    bool *isEnable = (bool *)data;
    LnnHeartbeatParamManager *paramMgr = NULL;

    paramMgr = GetParamMgrByTypeLocked(eachType);
    if (paramMgr == NULL) {
        LNN_LOGW(LNN_HEART_BEAT, "HB enable get param mgr is NULL, hbType=%{public}d", eachType);
        return true;
    }
    paramMgr->isEnable = *isEnable;
    return true;
}

int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable)
{
    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB enable hbType lock mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    (void)LnnVisitHbTypeSet(VisitEnableHbType, &type, &isEnable);
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return SOFTBUS_OK;
}

bool LnnIsHeartbeatEnable(LnnHeartbeatType type)
{
    bool ret = false;
    LnnHeartbeatParamManager *paramMgr = NULL;

    if (SoftBusMutexLock(&g_hbStrategyMutex) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB get param regist status lock mutex fail");
        return false;
    }
    paramMgr = GetParamMgrByTypeLocked(type);
    ret = (paramMgr != NULL && paramMgr->isEnable) ? true : false;
    (void)SoftBusMutexUnlock(&g_hbStrategyMutex);
    return ret;
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return LnnPostTransStateMsgToHbFsm(g_hbFsm, isMasterNode ? EVENT_HB_AS_MASTER_NODE : EVENT_HB_AS_NORMAL_NODE);
}

int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type)
{
    return LnnPostUpdateSendInfoMsgToHbFsm(g_hbFsm, type);
}

int32_t LnnHbStrategyInit(void)
{
    if (SoftBusMutexInit(&g_hbStrategyMutex, NULL) != 0) {
        LNN_LOGE(LNN_HEART_BEAT, "HB strategy module init mutex fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegistParamMgrByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB regist ble strategy fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegistParamMgrByType(HEARTBEAT_TYPE_TCP_FLUSH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB regist udp/tcp strategy fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnHbStrategyDeinit(void)
{
    if (g_hbFsm != NULL) {
        (void)LnnStopHeartbeatFsm(g_hbFsm);
    }
    LnnUnRegistParamMgrByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3);
    LnnUnRegistParamMgrByType(HEARTBEAT_TYPE_TCP_FLUSH);
    (void)SoftBusMutexDestroy(&g_hbStrategyMutex);
}
