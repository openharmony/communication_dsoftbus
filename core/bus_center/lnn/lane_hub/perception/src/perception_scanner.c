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
#include "perception_scanner.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "broadcast_scheduler.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_perception.h"
#include "message_handler.h"
#include "perception_const.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_broadcast_manager.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define PERCEPTION_SCAN_FILTER_MAX_NUM 2
#define PERCEPTION_SCAN_TO_SH_DELAY_MS 3000

typedef struct {
    SoftBusMutex opLock;
    atomic_int listenerId;
    PerceptionType activeType;
    atomic_bool isScanning;
} PerceptionScannerContext;

static PerceptionScannerContext g_scanCtx;
static atomic_bool g_scanInited = false;
static atomic_bool g_isScreenOn = true;

static void FreePerceptionScanFilterArray(BcScanFilter *filter, uint8_t filterNum)
{
    if (filter == NULL) {
        return;
    }
    while (filterNum-- > 0) {
        SoftBusFree((filter + filterNum)->address);
        SoftBusFree((filter + filterNum)->deviceName);
        SoftBusFree((filter + filterNum)->serviceData);
        SoftBusFree((filter + filterNum)->serviceDataMask);
        SoftBusFree((filter + filterNum)->manufactureData);
        SoftBusFree((filter + filterNum)->manufactureDataMask);
        SoftBusFree((filter + filterNum)->serviceUuidData);
        SoftBusFree((filter + filterNum)->serviceUuidDataMask);
    }
    SoftBusFree(filter);
}

static void BuildScanParams(BcScanParams *param)
{
    (void)memset_s(param, sizeof(BcScanParams), 0, sizeof(BcScanParams));
    param->scanType = SOFTBUS_BC_SCAN_TYPE_PASSIVE;
    param->scanPhy = SOFTBUS_BC_SCAN_PHY_1M;
    param->scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL;
    if (atomic_load(&g_isScreenOn)) {
        param->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10;
        param->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10;
    } else {
        param->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2_FAST;
        param->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2_FAST;
    }
}

static void PerceptionSwitchScanToSH(void *para)
{
    int32_t listenerId = *(int32_t *)para;
    SoftBusFree(para);

    LpBroadcastParam lpAdvParam;
    (void)memset_s(&lpAdvParam, sizeof(LpBroadcastParam), 0, sizeof(LpBroadcastParam));
    lpAdvParam.bcHandle = -1;

    LpScanParam lpScanParam;
    (void)memset_s(&lpScanParam, sizeof(LpScanParam), 0, sizeof(LpScanParam));
    lpScanParam.listenerId = listenerId;
    BuildScanParams(&lpScanParam.scanParam);

    if (!BroadcastSetAdvDeviceParam(SOFTBUS_PERCEPTION_TYPE, &lpAdvParam, &lpScanParam)) {
        LNN_LOGE(LNN_STATE, "perception sink scan filter to SH failed, listenerId=%{public}d", listenerId);
        return;
    }

    if (BroadcastSetScanReportChannelToLpDevice(listenerId, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception switch scan report channel to SH failed, listenerId=%{public}d", listenerId);
        return;
    }
    LNN_LOGI(LNN_STATE, "scan sunk to SH, listenerId=%{public}d", listenerId);
}

static void PerceptionOnStartScanCallback(int32_t listenerId, int32_t status)
{
    if (listenerId != atomic_load(&g_scanCtx.listenerId)) {
        LNN_LOGW(LNN_STATE, "perception scan start callback listenerId mismatch");
        return;
    }
    if (status != (int32_t)SOFTBUS_BC_STATUS_SUCCESS) {
        atomic_store(&g_scanCtx.isScanning, false);
        LNN_LOGE(LNN_STATE, "perception scan start callback fail, status=%{public}d", status);
        return;
    }
    atomic_store(&g_scanCtx.isScanning, true);
    int32_t *para = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (para != NULL) {
        *para = listenerId;
        SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
        int32_t ret =
            LnnAsyncCallbackDelayHelper(looper, PerceptionSwitchScanToSH, para, PERCEPTION_SCAN_POST_START_DELAY_MS);
        if (ret != SOFTBUS_OK) {
            SoftBusFree(para);
        }
    }
    LNN_LOGI(LNN_STATE, "perception scan physically started");
}

static void PerceptionOnStopScanCallback(int32_t listenerId, int32_t status)
{
    if (listenerId != atomic_load(&g_scanCtx.listenerId)) {
        LNN_LOGW(LNN_STATE, "perception scan stop callback listenerId mismatch");
        return;
    }
    atomic_store(&g_scanCtx.isScanning, false);
    LNN_LOGI(LNN_STATE, "perception scan physically stopped, status=%{public}d", status);
}

static const ScanCallback g_scanCallback = {
    .OnStartScanCallback = PerceptionOnStartScanCallback,
    .OnStopScanCallback = PerceptionOnStopScanCallback,
    .OnReportScanDataCallback = NULL,
};

static int32_t EnsureScanFilterLocked(void)
{
    BcScanFilter *filter = NULL;
    uint8_t filterNum = 0;
    int32_t ret = PerceptionBuildScanFilterPacked(&filter, &filterNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "build perception scan filter fail, ret=%{public}d", ret);
        return ret;
    }
    if (filter == NULL || filterNum == 0 || filterNum > PERCEPTION_SCAN_FILTER_MAX_NUM) {
        FreePerceptionScanFilterArray(filter, filterNum);
        LNN_LOGE(LNN_STATE, "perception scan filter invalid, filterNum=%{public}u", (uint32_t)filterNum);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SchedulerSetScanFilter(atomic_load(&g_scanCtx.listenerId), filter, filterNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "set perception scan filter fail, ret=%{public}d (filter released)", ret);
        FreePerceptionScanFilterArray(filter, filterNum);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AcquireScanLock(void)
{
    if (!atomic_load(&g_scanInited)) {
        LNN_LOGE(LNN_STATE, "perception scan not inited");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_scanCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception scan opLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static uint32_t PerceptionCycleToSeconds(PerceptionCycle cycle)
{
    switch (cycle) {
        case PERCEPTION_CYCLE_LOW:
            return PERCEPTION_CYCLE_LOW_SEC;
        case PERCEPTION_CYCLE_MEDIUM:
            return PERCEPTION_CYCLE_MEDIUM_SEC;
        case PERCEPTION_CYCLE_HIGH:
            return PERCEPTION_CYCLE_HIGH_SEC;
        default:
            return 0;
    }
}

int32_t PerceptionScanStart(PerceptionType type, PerceptionCycle cycle)
{
    if (type < PERCEPTION_TYPE_COLLABORATIVE_WAKE || type >= PERCEPTION_TYPE_BUTT) {
        LNN_LOGE(LNN_STATE, "perception scan start invalid type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    (void)PerceptionSyncCyclePacked(type, PerceptionCycleToSeconds(cycle));
    int32_t ret = AcquireScanLock();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    g_scanCtx.activeType = type;
    if (atomic_load(&g_scanCtx.isScanning)) {
        LNN_LOGW(LNN_STATE, "perception scan already started");
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return SOFTBUS_OK;
    }
    ret = EnsureScanFilterLocked();
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return ret;
    }
    BcScanParams param;
    BuildScanParams(&param);
    ret = SchedulerStartScan(atomic_load(&g_scanCtx.listenerId), &param);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "start perception scan fail, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return ret;
    }
    LNN_LOGI(LNN_STATE, "perception scan start ok, listenerId=%{public}d", atomic_load(&g_scanCtx.listenerId));
    (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
    (void)PerceptionSyncStatePacked(PERCEPTION_STATE_START);
    return SOFTBUS_OK;
}

int32_t PerceptionScanStop(void)
{
    int32_t ret = AcquireScanLock();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!atomic_load(&g_scanCtx.isScanning)) {
        LNN_LOGW(LNN_STATE, "perception scan already stopped");
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return SOFTBUS_OK;
    }
    g_scanCtx.activeType = PERCEPTION_TYPE_BUTT;
    ret = SchedulerStopScan(atomic_load(&g_scanCtx.listenerId));
    atomic_store(&g_scanCtx.isScanning, false);
    (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
    LNN_LOGI(LNN_STATE, "perception scan stop, ret=%{public}d", ret);
    (void)PerceptionSyncStatePacked(PERCEPTION_STATE_STOP);
    return ret;
}

int32_t PerceptionScanGetDeviceList(PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count)
{
    if (list == NULL || count == NULL) {
        LNN_LOGE(LNN_STATE, "perception scan get device list invalid param, type=%{public}d", (int32_t)type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (!atomic_load(&g_scanCtx.isScanning)) {
        LNN_LOGE(LNN_STATE, "perception scan not started, type=%{public}d", (int32_t)type);
        return SOFTBUS_PERCEPTION_SCAN_NOT_START;
    }
    return PerceptionGetDeviceInfoListPacked(type, list, count);
}

static int32_t PerceptionScanRecoverOnBtOnLocked(void)
{
    int32_t ret = EnsureScanFilterLocked();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    BcScanParams param;
    BuildScanParams(&param);
    ret = SchedulerStartScan(atomic_load(&g_scanCtx.listenerId), &param);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

void PerceptionScanOnScreenStateChanged(bool isScreenOn)
{
    if (!atomic_load(&g_scanInited)) {
        return;
    }
    atomic_store(&g_isScreenOn, isScreenOn);
    if (!atomic_load(&g_scanCtx.isScanning)) {
        return;
    }
    if (SoftBusMutexLock(&g_scanCtx.opLock) != SOFTBUS_OK) {
        return;
    }
    (void)SchedulerStopScan(atomic_load(&g_scanCtx.listenerId));
    BcScanParams param;
    BuildScanParams(&param);
    (void)SchedulerStartScan(atomic_load(&g_scanCtx.listenerId), &param);
    (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
    LNN_LOGI(LNN_STATE, "perception scan params updated for screen %{public}s", isScreenOn ? "on" : "off");
}

void PerceptionScanOnBtStateChanged(bool isBtOn)
{
    if (!atomic_load(&g_scanInited)) {
        LNN_LOGW(LNN_STATE, "perception scan bt state change but not inited");
        return;
    }
    if (SoftBusMutexLock(&g_scanCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "perception scan bt state change lock fail");
        return;
    }
    if (!isBtOn) {
        atomic_store(&g_scanCtx.isScanning, false);
        LNN_LOGI(LNN_STATE, "perception scan bt off, physical stopped, desired state retained");
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return;
    }
    if (g_scanCtx.activeType == PERCEPTION_TYPE_BUTT) {
        (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
        return;
    }
    int32_t ret = PerceptionScanRecoverOnBtOnLocked();
    (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
    LNN_LOGI(LNN_STATE, "perception scan recover on bt on, ret=%{public}d", ret);
}

int32_t PerceptionScannerInit(void)
{
    if (atomic_load(&g_scanInited)) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_scanCtx.opLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception scan init opLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    atomic_store(&g_scanCtx.isScanning, false);
    g_scanCtx.activeType = PERCEPTION_TYPE_BUTT;
    atomic_store(&g_scanCtx.listenerId, PERCEPTION_INVALID_LISTENER_ID);
    int32_t listenerId = PERCEPTION_INVALID_LISTENER_ID;
    int32_t ret =
        SchedulerRegisterScanListener(BROADCAST_PROTOCOL_BLE, SRV_TYPE_PERCEPTION, &listenerId, &g_scanCallback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register perception scan listener fail, ret=%{public}d", ret);
        (void)SoftBusMutexDestroy(&g_scanCtx.opLock);
        return ret;
    }
    atomic_store(&g_scanCtx.listenerId, listenerId);
    atomic_store(&g_scanInited, true);
    LNN_LOGI(LNN_INIT, "perception scanner init ok, listenerId=%{public}d", listenerId);
    return SOFTBUS_OK;
}

void PerceptionScannerDeinit(void)
{
    if (!atomic_load(&g_scanInited)) {
        return;
    }
    if (SoftBusMutexLock(&g_scanCtx.opLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "perception scan deinit opLock fail, abort (state retained)");
        return;
    }
    atomic_store(&g_scanInited, false);
    atomic_store(&g_scanCtx.isScanning, false);
    g_scanCtx.activeType = PERCEPTION_TYPE_BUTT;
    int32_t listenerId = atomic_load(&g_scanCtx.listenerId);
    if (listenerId != PERCEPTION_INVALID_LISTENER_ID) {
        (void)SchedulerStopScan(listenerId);
        (void)SchedulerUnregisterListener(listenerId);
    }
    atomic_store(&g_scanCtx.listenerId, PERCEPTION_INVALID_LISTENER_ID);
    (void)SoftBusMutexUnlock(&g_scanCtx.opLock);
    LNN_LOGI(LNN_INIT, "perception scanner deinit ok (persistent resources retained)");
}
