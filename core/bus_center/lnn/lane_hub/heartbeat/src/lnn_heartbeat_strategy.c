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
#include <string.h>

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_fsm.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_utils.h"

#define HB_INVALID_UID (-1)

typedef struct {
    int32_t callingUid;
    GearMode gearMode;
    HeartbeatPolicy policy[HB_IMPL_TYPE_MAX];
    SoftBusMutex lock;
} LnnHeartbeatStrategy;

static LnnHeartbeatStrategy g_strategy = {
    .policy[HB_IMPL_TYPE_BLE] = {
        .implPolicy = NULL,
    },
};

static int32_t HbMonitorInit(void)
{
    if (SoftBusMutexInit(&g_strategy.lock, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB monitor init mutex fail!");
        return SOFTBUS_ERR;
    }
    g_strategy.gearMode.modeCycle = LOW_FREQ_CYCLE;
    g_strategy.gearMode.modeDuration = LONG_DURATION;
    g_strategy.gearMode.wakeupFlag = false;
    g_strategy.callingUid = HB_INVALID_UID;
    return SOFTBUS_OK;
}

static void HbMonitorDeinit(void)
{
    uint8_t i;
    for (i = 0; i < HB_IMPL_TYPE_MAX; i++) {
        if (g_strategy.policy[i].implPolicy != NULL) {
            SoftBusFree(g_strategy.policy[i].implPolicy);
            g_strategy.policy[i].implPolicy = NULL;
        }
    }
    SoftBusMutexDestroy(&g_strategy.lock);
}

static int32_t ResetHeartbeatParam(int32_t callingUid, GearMode mode, const HeartbeatImplPolicy *implPolicy)
{
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB reset param lock mutex fail!");
        return SOFTBUS_ERR;
    }

    if (g_strategy.callingUid == HB_INVALID_UID || g_strategy.callingUid == callingUid) {
        g_strategy.gearMode = mode;
    } else {
        if (g_strategy.gearMode.modeCycle <= mode.modeCycle) {
            g_strategy.gearMode.modeCycle = mode.modeCycle;
        }
        if (g_strategy.gearMode.modeDuration >= mode.modeDuration) {
            g_strategy.gearMode.modeDuration = mode.modeDuration;
        }
    }

    if (implPolicy != NULL) {
        HeartbeatImplPolicy *tmpImplPolicy = (HeartbeatImplPolicy *)SoftBusCalloc(sizeof(HeartbeatImplPolicy));
        if (tmpImplPolicy == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB calloc tmpImplPolicy err");
            (void)SoftBusMutexUnlock(&g_strategy.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        tmpImplPolicy->type = implPolicy->type;
        tmpImplPolicy->info = implPolicy->info;
        g_strategy.policy[implPolicy->type].implPolicy = tmpImplPolicy;
        tmpImplPolicy = NULL;
    }
    (void)SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t ShiftLNNGear(const char *pkgName, int32_t callingUid, const char *targetNetworkId,
    GearMode mode, const HeartbeatImplPolicy *implPolicy)
{
    NodeInfo *nodeInfo = NULL;

    if (pkgName == NULL || callingUid <= HB_INVALID_UID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB shift gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (targetNetworkId != NULL) {
        nodeInfo = LnnGetNodeInfoById(targetNetworkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB shift gear get node info fail");
            return SOFTBUS_ERR;
        }
        if (!LnnIsNodeOnline(nodeInfo)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB target networkId has offline");
            return SOFTBUS_ERR;
        }
    }
    if (ResetHeartbeatParam(callingUid, mode, implPolicy) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB reset gearMode param fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetHeartbeatGearMode(GearMode *mode)
{
    if (mode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get gearMode invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get gearMode lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    *mode = g_strategy.gearMode;
    (void)SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetHeartbeatImplPolicy(LnnHeartbeatImplType type, HeartbeatImplPolicy *implPolicy)
{
    if (implPolicy == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get impl policy lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_strategy.policy[type].implPolicy == NULL) {
        (void)SoftBusMutexUnlock(&g_strategy.lock);
        return SOFTBUS_ERR;
    }
    *implPolicy = *g_strategy.policy[type].implPolicy;
    (void)SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    uint64_t delayMillis;
    GearMode gearMode;

    if (networkId == NULL || addrType != CONNECTION_ADDR_BLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB offline timing get invalid param: %d", addrType);
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    delayMillis = (uint64_t)gearMode.modeCycle * HB_TIME_FACTOR + HB_ENABLE_DELAY_LEN;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "heartbeat(HB) start offline countdown");
    if (LnnHbProcessDeviceLost(networkId, addrType, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyMasterNodeChanged(const char *masterUdid, int32_t weight)
{
    (void)weight;
    char localUdid[UDID_BUF_LEN] = {0};

    if (masterUdid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB notify master node changed get local udid err");
        return SOFTBUS_ERR;
    }
    if (strcmp(masterUdid, localUdid) == 0) {
        return LnnPostMsgToHbFsm(EVENT_HB_AS_MASTER_NODE, NULL);
    }
    return LnnPostMsgToHbFsm(EVENT_HB_AS_NORMAL_NODE, NULL);
}

int32_t LnnStartHeartbeatDelay(void)
{
    uint64_t delayMillis;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) process start.");
    if (LnnRemoveHbFsmMsg(EVENT_HB_START, 0, NULL) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (LnnRemoveHbFsmMsg(EVENT_HB_STOP, 0, NULL) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (LnnHbFsmStart(STATE_HB_MASTER_NODE_INDEX, 0) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    delayMillis = (uint64_t)g_strategy.gearMode.modeDuration * HB_TIME_FACTOR;
    if (LnnHbFsmStop(delayMillis) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnStopHeartbeatNow(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) process stop.");
    (void)LnnHbFsmStop(0);
}

int32_t LnnInitHeartbeat(void)
{
    if (LnnHbMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB manager init fail");
        return SOFTBUS_ERR;
    }
    if (LnnHbFsmInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsm init fail");
        return SOFTBUS_ERR;
    }
    if (HbMonitorInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB monitor init fail!");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHbFsmDeinit();
    HbMonitorDeinit();
    LnnHbMgrDeinit();
}
