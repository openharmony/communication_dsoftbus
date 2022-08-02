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

#include "auth_interface.h"
#include "bus_center_event.h"
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
    .policy[HB_IMPL_TYPE_BLE] = {.implPolicy = NULL},
};

static int32_t HbMonitorInit(void)
{
    if (SoftBusMutexInit(&g_strategy.lock, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB monitor init mutex fail!");
        return SOFTBUS_ERR;
    }
    g_strategy.gearMode.cycle = LOW_FREQ_CYCLE;
    g_strategy.gearMode.duration = LONG_DURATION;
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

int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB shift gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    (void)targetNetworkId;
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
    /* heartbeat dont support WLAN/ETH/BR medium type yet, so dont take the dev offline */
    if (networkId == NULL || addrType == CONNECTION_ADDR_WLAN || addrType == CONNECTION_ADDR_ETH ||
        addrType == CONNECTION_ADDR_BR) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB offline timing get invalid param, addrType:%d", addrType);
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    delayMillis = (uint64_t)gearMode.cycle * HB_TIME_FACTOR + HB_ENABLE_DELAY_LEN;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "heartbeat(HB) start offline countdown");
    if (LnnHbProcessDeviceLost(networkId, addrType, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LnnHeartbeatMasterNodeChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NODE_MASTER_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bad input");
        return;
    }
    LnnMasterNodeChangedEvent *masterNodeChangeEvent = (LnnMasterNodeChangedEvent *)info;

    int32_t ret = LnnPostMsgToHbFsm(
        masterNodeChangeEvent->isMasterNode ? EVENT_HB_AS_MASTER_NODE : EVENT_HB_AS_NORMAL_NODE, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(
            SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "notify master node change to heartbeat module failed. ret=%d", ret);
    }
}

static void HbOnGroupChanged(void)
{
    int32_t ret = LnnPostMsgToHbFsm(EVENT_HB_UPDATE_DEVICE_INFO, NULL);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HbOnGroupCreated post msg ret %d", ret);
}

static void HbOnGroupCreated(const char *groupId)
{
    (void)groupId;
    HbOnGroupChanged();
}

static void HbOnGroupDeleted(const char *groupId)
{
    (void)groupId;
    HbOnGroupChanged();
}

static VerifyCallback g_verifyCb = {
    .onGroupCreated = HbOnGroupCreated,
    .onGroupDeleted = HbOnGroupDeleted,
};

int32_t LnnStartHeartbeatDelay(void)
{
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

    AuthRegCallback(HEARTBEAT_MONITOR, &g_verifyCb);
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
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, LnnHeartbeatMasterNodeChangeEventHandler) !=
        SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB monitor regist event fail!");
        return SOFTBUS_ERR;
    }
    AuthRegCallback(HEARTBEAT_MONITOR, &g_verifyCb);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHbFsmDeinit();
    HbMonitorDeinit();
    LnnHbMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, LnnHeartbeatMasterNodeChangeEventHandler);
}
