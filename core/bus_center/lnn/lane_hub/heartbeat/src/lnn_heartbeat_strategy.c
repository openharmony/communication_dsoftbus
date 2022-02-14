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

#define BEAT_INVALID_UID (-1)

typedef struct {
    int32_t callingUid;
    GearMode gearMode;
    HeartbeatPolicy beatPolicy[LNN_BEAT_IMPL_TYPE_MAX];
    SoftBusMutex lock;
} LnnHeartbeatStrategy;

static LnnHeartbeatStrategy g_strategy = {
    .beatPolicy[LNN_BEAT_IMPL_TYPE_BLE] = {
        .implPolicy = NULL,
    },
};

static int32_t HeartbeatMonitorInit(void)
{
    if (SoftBusMutexInit(&g_strategy.lock, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mutex init fail!");
        return SOFTBUS_ERR;
    }

    g_strategy.gearMode.modeCycle = LOW_FREQ_CYCLE;
    g_strategy.gearMode.modeDuration = LONG_DURATION;
    g_strategy.gearMode.wakeupFlag = false;
    g_strategy.callingUid = BEAT_INVALID_UID;
    return SOFTBUS_OK;
}

static int32_t HeartbeatMonitorDeinit(void)
{
    uint8_t i;
    for (i = 0; i < LNN_BEAT_IMPL_TYPE_MAX; i++) {
        if (g_strategy.beatPolicy[i].implPolicy != NULL) {
            SoftBusFree(g_strategy.beatPolicy[i].implPolicy);
            g_strategy.beatPolicy[i].implPolicy = NULL;
        }
    }
    if (SoftBusMutexDestroy(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "mutex deinit fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ResetHeartbeatParam(int32_t callingUid, GearMode mode, const HeartbeatImplPolicy *implPolicy)
{
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    if (g_strategy.callingUid == BEAT_INVALID_UID || g_strategy.callingUid == callingUid) {
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat malloc err");
            return SOFTBUS_MALLOC_ERR;
        }
        tmpImplPolicy->type = implPolicy->type;
        tmpImplPolicy->info = implPolicy->info;
        g_strategy.beatPolicy[implPolicy->type].implPolicy = tmpImplPolicy;
        tmpImplPolicy = NULL;
    }
    SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t ShiftLNNGear(const char *pkgName, int32_t callingUid, const char *targetNetworkId,
    GearMode mode, const HeartbeatImplPolicy *implPolicy)
{
    if (pkgName == NULL || callingUid <= BEAT_INVALID_UID) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (targetNetworkId != NULL) {
        NodeInfo *nodeInfo = NULL;
        nodeInfo = LnnGetNodeInfoById(targetNetworkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get node info fail");
            return SOFTBUS_ERR;
        }
        if (!LnnIsNodeOnline(nodeInfo)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat target networdid offline");
            return SOFTBUS_ERR;
        }
    }

    if (ResetHeartbeatParam(callingUid, mode, implPolicy) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reset gear mode param fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetHeartbeatGearMode(GearMode *mode)
{
    if (mode == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    *mode = g_strategy.gearMode;
    SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t LnnGetHeartbeatImplPolicy(LnnHeartbeatImplType type, HeartbeatImplPolicy *implPolicy)
{
    if (implPolicy == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_strategy.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_strategy.beatPolicy[type].implPolicy == NULL) {
        SoftBusMutexUnlock(&g_strategy.lock);
        return SOFTBUS_ERR;
    }
    *implPolicy = *g_strategy.beatPolicy[type].implPolicy;
    SoftBusMutexUnlock(&g_strategy.lock);
    return SOFTBUS_OK;
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL || addrType != CONNECTION_ADDR_BLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat invalid param: %d", addrType);
        return SOFTBUS_INVALID_PARAM;
    }

    GearMode gearMode;
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)gearMode.modeCycle * HEARTBEAT_TIME_FACTOR + HEARTBEAT_ENABLE_DELAY_LEN;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "beat start offline countdown");
    return LnnHeartbeatNodeOffline(networkId, addrType, delayMillis);
}

int32_t LnnNotifyMasterNodeChanged(const char *masterUdid, int32_t weight)
{
    (void)weight;
    char localUdid[UDID_BUF_LEN] = {0};
    if (masterUdid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    if (strcmp(masterUdid, localUdid) == 0) {
        return LnnPostMsgToBeatFsm(EVENT_BEAT_AS_MASTER_NODE, NULL);
    }
    return LnnPostMsgToBeatFsm(EVENT_BEAT_AS_NORMAL_NODE, NULL);
}

int32_t LnnStartHeartbeatDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat fsm start");
    (void)LnnRemoveBeatFsmMsg(EVENT_BEAT_START, 0, NULL);
    (void)LnnRemoveBeatFsmMsg(EVENT_BEAT_STOP, 0, NULL);
    if (LnnHeartbeatFsmStart(STATE_BEAT_MASTER_NODE_INDEX, 0) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    uint64_t delayMillis = (uint64_t)g_strategy.gearMode.modeDuration * HEARTBEAT_TIME_FACTOR;
    if (LnnHeartbeatFsmStop(delayMillis) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnStopHeartbeat(void)
{
    (void)LnnHeartbeatFsmStop(0);
}

int32_t LnnInitHeartbeat(void)
{
    if (LnnHeartbeatMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat manager init fail");
        return SOFTBUS_ERR;
    }

    if (LnnHeartbeatFsmInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat fsm init fail");
        return SOFTBUS_ERR;
    }

    if (HeartbeatMonitorInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat monitor init fail!");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHeartbeatFsmDeinit();
    if (HeartbeatMonitorDeinit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat monitor deinit fail");
    }
    LnnHeartbeatMgrDeinit();
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lnn heartbeat deinit done");
}
