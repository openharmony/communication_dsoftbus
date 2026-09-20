/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "perception_advertiser.h"

#include <stdatomic.h>
#include <stdbool.h>

#include "broadcast_scheduler.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "perception_const.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

typedef enum {
    PERCEPTION_ADV_MSG_RECOVER_LOW = 0,
} PerceptionAdvMessageType;

typedef enum {
    PERCEPTION_ADV_FREQ_LOW = 0,
    PERCEPTION_ADV_FREQ_HIGH,
} PerceptionAdvFreqState;

typedef struct {
    SoftBusMutex opLock;
    atomic_bool isAdvertising;
    int32_t bcId;
    PerceptionType currentType;
    PerceptionAdvParam currentParam;
} PerceptionAdvertiserContext;

static PerceptionAdvertiserContext g_advCtx;
static SoftBusHandler g_advHandler = { NULL, NULL, NULL };
static atomic_bool g_advInited = false;

static void PerceptionOnStartBroadcastingCallback(int32_t bcId, int32_t status)
{
    if (status != (int32_t)SOFTBUS_BC_STATUS_SUCCESS) {
        atomic_store(&g_advCtx.isAdvertising, false);
        LNN_LOGE(LNN_STATE, "perception adv start fail, bcId=%{public}d, status=%{public}d", bcId, status);
        return;
    }
    atomic_store(&g_advCtx.isAdvertising, true);
    LNN_LOGI(LNN_STATE, "perception adv physically started, bcId=%{public}d", bcId);
}

static void PerceptionOnStopBroadcastingCallback(int32_t bcId, int32_t status)
{
    atomic_store(&g_advCtx.isAdvertising, false);
    LNN_LOGI(LNN_STATE, "perception adv physically stopped, bcId=%{public}d, status=%{public}d", bcId, status);
}

static void PerceptionOnSetBroadcastingCallback(int32_t bcId, int32_t status)
{
    (void)bcId;
    (void)status;
}

static const BroadcastCallback g_advCallback = {
    .OnStartBroadcastingCallback = PerceptionOnStartBroadcastingCallback,
    .OnStopBroadcastingCallback = PerceptionOnStopBroadcastingCallback,
    .OnSetBroadcastingCallback = PerceptionOnSetBroadcastingCallback,
};

static int32_t ValidateAdvParam(const PerceptionAdvParam *param)
{
    if (param == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (param->customDataLen > PERCEPTION_CUSTOM_DATA_MAX_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static bool ValidateAdvType(PerceptionType type)
{
    return type >= PERCEPTION_TYPE_COLLABORATIVE_WAKE && type < PERCEPTION_TYPE_BUTT;
}

static void FreePacketPayload(BroadcastPacket *packet)
{
    if (packet == NULL) {
        return;
    }
    SoftBusFree(packet->bcData.payload);
    packet->bcData.payload = NULL;
    SoftBusFree(packet->rspData.payload);
    packet->rspData.payload = NULL;
    SoftBusFree(packet->uuidData.payload);
    packet->uuidData.payload = NULL;
}

static int32_t BuildAdvPacket(PerceptionType type, const PerceptionAdvParam *param, BroadcastPacket *packet)
{
    (void)memset_s(packet, sizeof(BroadcastPacket), 0, sizeof(BroadcastPacket));

    int32_t ret = PerceptionBuildAdvDataPacked(&type, param, 1, packet);
    if (ret != SOFTBUS_OK) {
        FreePacketPayload(packet);
        return ret;
    }
    return SOFTBUS_OK;
}

static void BuildBcParam(BroadcastParam *bcParam, PerceptionAdvFreqState freq)
{
    (void)memset_s(bcParam, sizeof(BroadcastParam), 0, sizeof(BroadcastParam));
    int32_t interval = (freq == PERCEPTION_ADV_FREQ_HIGH) ? PERCEPTION_HIGH_INTERVAL : PERCEPTION_NORMAL_INTERVAL;
    bcParam->minInterval = interval;
    bcParam->maxInterval = interval;
    bcParam->advType = SOFTBUS_BC_ADV_NONCONN_IND;
    bcParam->advFilterPolicy = SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
    bcParam->ownAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    bcParam->peerAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    bcParam->txPower = 0;
    bcParam->isSupportRpa = false;
}

static void CacheParam(PerceptionType type, const PerceptionAdvParam *param)
{
    g_advCtx.currentType = type;
    (void)memset_s(g_advCtx.currentParam.customData, PERCEPTION_CUSTOM_DATA_MAX_LEN, 0, PERCEPTION_CUSTOM_DATA_MAX_LEN);
    if (param->customDataLen > 0) {
        (void)memcpy_s(
            g_advCtx.currentParam.customData, PERCEPTION_CUSTOM_DATA_MAX_LEN, param->customData, param->customDataLen);
    }
    g_advCtx.currentParam.customDataLen = param->customDataLen;
}

static int32_t AcquireAdvLock(void)
{
    if (!atomic_load(&g_advInited)) {
        LNN_LOGE(LNN_STATE, "perception adv not inited");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_advCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception adv opLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsAdvHandlerReady(void)
{
    return g_advHandler.looper != NULL && g_advHandler.looper->PostMessageDelay != NULL &&
        g_advHandler.looper->RemoveMessage != NULL;
}

static void RemoveRecoverLowMessage(void)
{
    if (!IsAdvHandlerReady()) {
        return;
    }
    g_advHandler.looper->RemoveMessage(g_advHandler.looper, &g_advHandler, PERCEPTION_ADV_MSG_RECOVER_LOW);
}

static SoftBusMessage *CreateRecoverLowMessage(void)
{
    if (!IsAdvHandlerReady()) {
        LNN_LOGW(LNN_STATE, "adv handler not ready, skip recover-low message");
        return NULL;
    }
    SoftBusMessage *msg = MallocMessage();
    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "malloc recover-low message fail");
        return NULL;
    }
    msg->what = PERCEPTION_ADV_MSG_RECOVER_LOW;
    msg->handler = &g_advHandler;
    msg->FreeMessage = NULL;
    return msg;
}

static void PostPreparedRecoverLowMessage(SoftBusMessage *msg)
{
    RemoveRecoverLowMessage();
    g_advHandler.looper->PostMessageDelay(g_advHandler.looper, msg, PERCEPTION_HIGH_DURATION_MS);
}

static int32_t PostRecoverLowMessage(void)
{
    SoftBusMessage *msg = CreateRecoverLowMessage();
    if (msg == NULL) {
        return IsAdvHandlerReady() ? SOFTBUS_MEM_ERR : SOFTBUS_LOOPER_ERR;
    }
    PostPreparedRecoverLowMessage(msg);
    return SOFTBUS_OK;
}

static int32_t SwitchAdvFreq(PerceptionAdvFreqState freq)
{
    BroadcastParam bcParam;
    BuildBcParam(&bcParam, freq);
    int32_t ret = SchedulerSetBroadcastParam(g_advCtx.bcId, &bcParam);
    return ret;
}

static void ClearAdvState(void)
{
    atomic_store(&g_advCtx.isAdvertising, false);
    g_advCtx.currentType = PERCEPTION_TYPE_BUTT;
    (void)memset_s(&g_advCtx.currentParam, sizeof(PerceptionAdvParam), 0, sizeof(PerceptionAdvParam));
}

static int32_t StopAndClearAdv(void)
{
    int32_t ret = SOFTBUS_OK;
    if (g_advCtx.bcId != PERCEPTION_INVALID_BC_ID) {
        ret = SchedulerStopBroadcast(g_advCtx.bcId);
    }
    ClearAdvState();
    return ret;
}

static void HandleAdvMessage(SoftBusMessage *msg)
{
    if (msg == NULL || msg->what != PERCEPTION_ADV_MSG_RECOVER_LOW) {
        LNN_LOGW(LNN_STATE, "perception adv handle invalid msg");
        return;
    }
    if (SoftBusMutexLock(&g_advCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception adv handle msg lock fail");
        return;
    }
    if (atomic_load(&g_advCtx.isAdvertising)) {
        LNN_LOGI(LNN_STATE, "high frequency window expired, recover to low");
        int32_t ret = SwitchAdvFreq(PERCEPTION_ADV_FREQ_LOW);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "recover low fail, ret=%{public}d", ret);
        }
    }
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
}

static int32_t DoStartBroadcast(PerceptionType type, const PerceptionAdvParam *param, PerceptionAdvFreqState freq)
{
    CacheParam(type, param);
    BroadcastPacket packet;
    int32_t ret = BuildAdvPacket(type, param, &packet);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "build adv packet fail, ret=%{public}d", ret);
        return ret;
    }
    BroadcastParam bcParam;
    BuildBcParam(&bcParam, freq);

    ret = SchedulerStartBroadcast(g_advCtx.bcId, BC_TYPE_PERCEPTION, &bcParam, &packet);
    FreePacketPayload(&packet);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "start broadcast fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAdvDataLocked(PerceptionType type, const PerceptionAdvParam *param)
{
    CacheParam(type, param);
    BroadcastPacket packet;
    int32_t ret = BuildAdvPacket(type, param, &packet);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "build adv packet fail, ret=%{public}d", ret);
        return ret;
    }
    ret = SchedulerSetBroadcastData(g_advCtx.bcId, &packet);
    FreePacketPayload(&packet);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "update broadcast data fail, ret=%{public}d", ret);
    }
    return ret;
}

int32_t PerceptionAdvStart(PerceptionType type, const PerceptionAdvParam *param)
{
    int32_t ret = ValidateAdvParam(param);
    if (!ValidateAdvType(type) || ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "start adv invalid param, type=%{public}d ret=%{public}d", (int32_t)type, ret);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = AcquireAdvLock();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (atomic_load(&g_advCtx.isAdvertising)) {
        ret = UpdateAdvDataLocked(type, param);
    } else {
        ret = DoStartBroadcast(type, param, PERCEPTION_ADV_FREQ_LOW);
    }
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
    return ret;
}

int32_t PerceptionAdvSetHighFreq(PerceptionType type, const PerceptionAdvParam *param)
{
    int32_t ret = ValidateAdvParam(param);
    if (!ValidateAdvType(type) || ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "set high freq invalid param, type=%{public}d ret=%{public}d", (int32_t)type, ret);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = AcquireAdvLock();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!atomic_load(&g_advCtx.isAdvertising)) {
        ret = DoStartBroadcast(type, param, PERCEPTION_ADV_FREQ_HIGH);
    } else {
        ret = UpdateAdvDataLocked(type, param);
        if (ret == SOFTBUS_OK) {
            ret = SwitchAdvFreq(PERCEPTION_ADV_FREQ_HIGH);
        }
    }
    if (ret == SOFTBUS_OK) {
        (void)PostRecoverLowMessage();
    }
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
    LNN_LOGI(LNN_STATE, "perception adv set high freq, ret=%{public}d", ret);
    return ret;
}

int32_t PerceptionAdvStop(void)
{
    int32_t ret = AcquireAdvLock();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!atomic_load(&g_advCtx.isAdvertising)) {
        LNN_LOGW(LNN_STATE, "perception adv already stopped");
        (void)SoftBusMutexUnlock(&g_advCtx.opLock);
        return SOFTBUS_OK;
    }
    RemoveRecoverLowMessage();
    ret = StopAndClearAdv();
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
    LNN_LOGI(LNN_STATE, "perception adv stop, ret=%{public}d", ret);
    return ret;
}

void PerceptionAdvOnBtStateChanged(bool isBtOn)
{
    if (!atomic_load(&g_advInited)) {
        LNN_LOGW(LNN_STATE, "perception adv bt state change but not inited");
        return;
    }
    if (SoftBusMutexLock(&g_advCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception adv bt state change lock fail");
        return;
    }
    PerceptionType type = g_advCtx.currentType;
    PerceptionAdvParam param = g_advCtx.currentParam;
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
    if (!isBtOn) {
        RemoveRecoverLowMessage();
        atomic_store(&g_advCtx.isAdvertising, false);
        LNN_LOGI(LNN_STATE, "perception adv bt off, physical stopped, desired state retained");
    } else if (type != PERCEPTION_TYPE_BUTT) {
        int32_t ret = DoStartBroadcast(type, &param, PERCEPTION_ADV_FREQ_LOW);
        LNN_LOGI(LNN_STATE, "perception adv recover on bt on, ret=%{public}d", ret);
    }
}

int32_t PerceptionAdvertiserInit(void)
{
    if (atomic_load(&g_advInited)) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_advCtx.opLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception adv init opLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ClearAdvState();
    g_advCtx.bcId = PERCEPTION_INVALID_BC_ID;

    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (looper == NULL || looper->PostMessageDelay == NULL || looper->RemoveMessage == NULL) {
        LNN_LOGE(LNN_INIT, "default looper unavailable, perception adv init fail");
        return SOFTBUS_LOOPER_ERR;
    }
    g_advHandler.looper = looper;
    g_advHandler.HandleMessage = HandleAdvMessage;

    int32_t bcId = PERCEPTION_INVALID_BC_ID;
    int32_t ret = SchedulerRegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_PERCEPTION, &bcId, &g_advCallback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register perception broadcaster fail, ret=%{public}d", ret);
        (void)SoftBusMutexDestroy(&g_advCtx.opLock);
        return ret;
    }
    g_advCtx.bcId = bcId;
    atomic_store(&g_advInited, true);
    LNN_LOGI(LNN_INIT, "perception advertiser init ok, bcId=%{public}d", bcId);
    return SOFTBUS_OK;
}

void PerceptionAdvertiserDeinit(void)
{
    if (!atomic_load(&g_advInited)) {
        return;
    }
    if (SoftBusMutexLock(&g_advCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception adv deinit opLock fail, abort (state retained)");
        return;
    }
    atomic_store(&g_advInited, false);
    int32_t bcId = g_advCtx.bcId;
    g_advCtx.bcId = PERCEPTION_INVALID_BC_ID;
    ClearAdvState();
    if (bcId != PERCEPTION_INVALID_BC_ID) {
        (void)SchedulerUnregisterBroadcaster(bcId);
    }
    (void)SoftBusMutexUnlock(&g_advCtx.opLock);
    LNN_LOGI(LNN_INIT, "perception advertiser deinit ok (persistent resources retained)");
}
