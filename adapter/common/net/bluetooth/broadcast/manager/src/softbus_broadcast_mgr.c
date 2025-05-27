/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <unistd.h>

#include "broadcast_dfx_event.h"
#include "disc_log.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_ble_gatt_public.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_broadcast_manager.h"
#include "softbus_broadcast_mgr_utils.h"
#include "softbus_broadcast_utils.h"
#include "softbus_error_code.h"
#include "softbus_event.h"
#include "legacy/softbus_hidumper_bc_mgr.h"
#include "softbus_utils.h"

#define BC_WAIT_TIME_MS                  50
#define BC_WAIT_TIME_SEC                 1
#define BC_DFX_REPORT_NUM                4
#define MAX_BLE_ADV_NUM                  7
#define MGR_TIME_THOUSAND_MULTIPLIER     1000LL
#define BC_WAIT_TIME_MICROSEC            (BC_WAIT_TIME_MS * MGR_TIME_THOUSAND_MULTIPLIER)
#define MAX_FILTER_SIZE                  32
#define REGISTER_INFO_MANAGER            "registerInfoMgr"

typedef struct {
    bool isAdapterScanCbReg;
    int32_t adapterScannerId;
} AdapterScannerControl;

static int32_t RegisterInfoDump(int fd);

typedef struct {
    bool isUsed;
    bool isAdvertising;
    bool isStarted;
    bool isDisabled;
    BaseServiceType srvType;
    int32_t adapterBcId;
    int32_t advHandle;
    int32_t minInterval;
    int32_t maxInterval;
    SoftBusCond cond;
    SoftBusCond pauseCond;
    BroadcastCallback *bcCallback;
    int64_t time;
} BroadcastManager;

typedef enum {
    SCAN_FREQ_LOW_POWER,
    SCAN_FREQ_P2_60_3000,
    SCAN_FREQ_P2_30_1500,
    SCAN_FREQ_P10_30_300,
    SCAN_FREQ_P25_60_240,
    SCAN_FREQ_P50_30_60,
    SCAN_FREQ_P75_30_40,
    SCAN_FREQ_P100_1000_1000,
    SCAN_FREQ_BUTT,
} ScanFreq;

typedef struct {
    bool isUsed;
    bool isFliterChanged;
    bool isScanning;
    uint8_t filterSize;
    BaseServiceType srvType;
    int32_t adapterScanId;
    BcScanParams param;
    ScanFreq freq;
    BcScanFilter *filter;
    uint8_t *deleted;
    uint8_t deleteSize;
    uint8_t *added;
    uint8_t addSize;
    ScanCallback *scanCallback;
} ScanManager;

static volatile bool g_mgrInit = false;
static volatile bool g_mgrLockInit = false;
static SoftBusMutex g_bcLock = { 0 };
static SoftBusMutex g_scanLock = { 0 };
static int32_t g_btStateListenerId = -1;

static int32_t g_bcMaxNum = 0;
static int32_t g_bcCurrentNum = 0;
static int32_t g_bcOverMaxNum = 0;
static DiscEventExtra g_bcManagerExtra[BC_NUM_MAX] = { 0 };
static BroadcastManager g_bcManager[BC_NUM_MAX];
static ScanManager g_scanManager[SCAN_NUM_MAX];
static bool g_firstSetIndex[MAX_FILTER_SIZE + 1] = {false};

static AdapterScannerControl g_AdapterStatusControl[GATT_SCAN_MAX_NUM] = {
    {
        .adapterScannerId = -1,
        .isAdapterScanCbReg = false
    },
    {
        .adapterScannerId = -1,
        .isAdapterScanCbReg = false
    },
    {
        .adapterScannerId = -1,
        .isAdapterScanCbReg = false
    },
    {
        .adapterScannerId = -1,
        .isAdapterScanCbReg = false
    }
 };

// Global variable for specifying an interface type {@link SoftbusMediumType}.
static uint32_t g_interfaceId = BROADCAST_MEDIUM_TYPE_BLE;
static SoftbusBroadcastMediumInterface *g_interface[MEDIUM_NUM_MAX];

static inline bool CheckMediumIsValid(SoftbusMediumType interfaceId)
{
    return interfaceId >= 0 && interfaceId < BROADCAST_MEDIUM_TYPE_BUTT;
}

int32_t RegisterBroadcastMediumFunction(SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface)
{
    DISC_LOGI(DISC_BROADCAST, "register type=%{public}d", type);
    DISC_CHECK_AND_RETURN_RET_LOGE(type >= 0 && type < BROADCAST_MEDIUM_TYPE_BUTT, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "type is invalid!");
    DISC_CHECK_AND_RETURN_RET_LOGE(interface != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "interface is nullptr");

    g_interface[type] = (SoftbusBroadcastMediumInterface *)interface;
    return SOFTBUS_OK;
}

static void ReleaseScanIdx(int32_t listenerId)
{
    if (g_scanManager[listenerId].added != NULL) {
        SoftBusFree(g_scanManager[listenerId].added);
        g_scanManager[listenerId].added = NULL;
    }
    g_scanManager[listenerId].addSize = 0;

    if (g_scanManager[listenerId].deleted != NULL) {
        SoftBusFree(g_scanManager[listenerId].deleted);
        g_scanManager[listenerId].deleted = NULL;
    }
    g_scanManager[listenerId].deleteSize = 0;
}

static void BcBtStateChanged(int32_t listenerId, int32_t state)
{
    DISC_CHECK_AND_RETURN_LOGE(CheckMediumIsValid(g_interfaceId), DISC_BROADCAST, "bad id");
    (void)listenerId;
    if (state != SOFTBUS_BC_BT_STATE_TURN_OFF) {
        return;
    }
    DISC_LOGI(DISC_BROADCAST, "receive bt turn off event, start reset broadcast mgr state..");

    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (!bcManager->isUsed || bcManager->adapterBcId == -1 || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        SoftBusMutexUnlock(&g_bcLock);
        (void)g_interface[g_interfaceId]->StopBroadcasting(bcManager->adapterBcId);
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");
        if (bcManager->isAdvertising) {
            g_bcCurrentNum--;
        }
        bcManager->isAdvertising = false;
        bcManager->isStarted = false;
        bcManager->time = 0;
        SoftBusCondBroadcast(&bcManager->cond);
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnStopBroadcastingCallback((int32_t)managerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    }

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_scanLock) == SOFTBUS_OK, DISC_BROADCAST, "scanLock mutex error");

        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || scanManager->adapterScanId == -1 || !scanManager->isScanning ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnStopScanCallback == NULL) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        (void)g_interface[g_interfaceId]->StopScan(scanManager->adapterScanId);
        for (uint32_t i = 0; i < scanManager->filterSize; i++) {
            g_firstSetIndex[scanManager->filter[i].filterIndex] = false;
            scanManager->filter[i].filterIndex = 0;
        }
        ReleaseScanIdx(managerId);
        scanManager->isFliterChanged = true;
        scanManager->isScanning = false;
        ScanCallback callback = *(scanManager->scanCallback);
        SoftBusMutexUnlock(&g_scanLock);
        callback.OnStopScanCallback((int32_t)managerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    }
}

static SoftBusBtStateListener g_softbusBcBtStateLister = {
    .OnBtStateChanged = BcBtStateChanged,
    .OnBtAclStateChanged = NULL,
};

static int32_t BcManagerLockInit(void)
{
    DISC_LOGI(DISC_BROADCAST, "init enter");
    if (g_mgrLockInit) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_bcLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "bcLock init failed");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_scanLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "scanLock init failed");
        (void)SoftBusMutexDestroy(&g_bcLock);
        return SOFTBUS_NO_INIT;
    }
    g_mgrLockInit = true;
    return SOFTBUS_OK;
}

static void DelayReportBroadcast(void *para)
{
    DiscEventExtra extra = { 0 };
    for (int32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (g_bcManagerExtra[managerId].isOn == 1) {
            extra.startTime = g_bcManagerExtra[managerId].startTime;
            extra.advHandle = g_bcManagerExtra[managerId].advHandle;
            extra.serverType = g_bcManagerExtra[managerId].serverType;
            extra.minInterval = g_bcManagerExtra[managerId].minInterval;
            extra.maxInterval = g_bcManagerExtra[managerId].maxInterval;
            extra.bcOverMaxCnt = g_bcOverMaxNum;
            DISC_LOGI(DISC_BROADCAST, "startTime=%{public}" PRId64 ", advHandle=%{public}d, serverType=%{public}s, "
                "minInterval=%{public}d, maxInterval=%{public}d, bcOverMaxCnt=%{public}d", extra.startTime,
                extra.advHandle, extra.serverType, extra.minInterval, extra.maxInterval, extra.bcOverMaxCnt);
            DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BROADCAST, extra);
        }
    }
 
    g_bcMaxNum = 0;
    g_bcOverMaxNum = 0;
    memset_s(g_bcManagerExtra, sizeof(g_bcManagerExtra), 0, sizeof(g_bcManagerExtra));
    if (BleAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayReportBroadcast, NULL,
        DELAY_TIME_DEFAULT) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "DelayReportBroadcast failed, due to async callback fail");
    }
}

int32_t InitBroadcastMgr(void)
{
    DISC_LOGI(DISC_BROADCAST, "init enter");
    if (g_mgrInit) {
        DISC_LOGD(DISC_BROADCAST, "mgr already inited");
        return SOFTBUS_OK;
    }
    int32_t ret = BcManagerLockInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "lock init failed");

    SoftbusBleAdapterInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->Init != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    ret = g_interface[g_interfaceId]->Init();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    ret = SoftBusAddBtStateListener(&g_softbusBcBtStateLister, &g_btStateListenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "add bt state listener failed");
    g_mgrInit = true;

    if (BleAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), DelayReportBroadcast, NULL,
        DELAY_TIME_DEFAULT) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "looper init failed");
    }
    SoftBusRegBcMgrVarDump((char *)REGISTER_INFO_MANAGER, &RegisterInfoDump);
    return SOFTBUS_OK;
}

static bool CheckLockIsInit(SoftBusMutex *lock)
{
    if (SoftBusMutexLock(lock) != SOFTBUS_OK) {
        return false;
    }
    SoftBusMutexUnlock(lock);
    return true;
}

static int32_t CheckBroadcastingParam(const BroadcastParam *param, const BroadcastPacket *packet)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param packet");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet->bcData.payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "invalid param payload");
    return SOFTBUS_OK;
}

int32_t DeInitBroadcastMgr(void)
{
    DISC_LOGI(DISC_BROADCAST, "deinit enter");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_interface[g_interfaceId] != NULL, SOFTBUS_OK, DISC_BROADCAST, "already deinit");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DeInit != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    if (CheckLockIsInit(&g_bcLock)) {
        (void)SoftBusMutexDestroy(&g_bcLock);
    }
    if (CheckLockIsInit(&g_scanLock)) {
        (void)SoftBusMutexDestroy(&g_scanLock);
    }
    g_mgrLockInit = false;
    g_mgrInit = false;
    int32_t ret;
    if (g_btStateListenerId != -1) {
        ret = SoftBusRemoveBtStateListener(g_btStateListenerId);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "RemoveBtStateListener failed");
        g_btStateListenerId = -1;
    }

    ret = g_interface[g_interfaceId]->DeInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");
    g_interface[g_interfaceId] = NULL;
    SoftbusBleAdapterDeInit();
    return SOFTBUS_OK;
}

static char *GetSrvType(BaseServiceType srvType)
{
    if ((int32_t)srvType < 0 || (int32_t)srvType >= (int32_t)(sizeof(g_srvTypeMap)/sizeof(SrvTypeMap))) {
        return (char *)"invalid service";
    }
    return g_srvTypeMap[srvType].service;
}

static void ReportCurrentBroadcast(bool startBcResult)
{
    DiscEventExtra extra = { 0 };
    for (int32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (g_bcManager[managerId].isAdvertising) {
            extra.startTime = g_bcManager[managerId].time;
            extra.advHandle = g_bcManager[managerId].advHandle;
            extra.serverType = GetSrvType(g_bcManager[managerId].srvType);
            extra.minInterval = g_bcManager[managerId].minInterval;
            extra.maxInterval = g_bcManager[managerId].maxInterval;
            if (startBcResult) {
                extra.currentNum = g_bcCurrentNum;
            }
            DISC_LOGI(DISC_BROADCAST, "startTime=%{public}" PRId64 ", advHandle=%{public}d, serverType=%{public}s, "
                "minInterval=%{public}d, maxInterval=%{public}d", extra.startTime,
                extra.advHandle, extra.serverType, extra.minInterval, extra.maxInterval);
            DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BROADCAST, extra);
        }
    }
}
 
static void UpdateBcMaxExtra(void)
{
    if (g_bcCurrentNum > BC_DFX_REPORT_NUM) {
        ReportCurrentBroadcast(true);
    }
 
    if (g_bcCurrentNum < g_bcMaxNum) {
        return;
    }
 
    g_bcMaxNum = g_bcCurrentNum;
    memset_s(g_bcManagerExtra, sizeof(g_bcManagerExtra), 0, sizeof(g_bcManagerExtra));
    for (int32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (g_bcManager[managerId].isAdvertising) {
            g_bcManagerExtra[managerId].isOn = 1;
            g_bcManagerExtra[managerId].startTime = g_bcManager[managerId].time;
            g_bcManagerExtra[managerId].advHandle = g_bcManager[managerId].advHandle;
            g_bcManagerExtra[managerId].serverType = GetSrvType(g_bcManager[managerId].srvType);
            g_bcManagerExtra[managerId].minInterval = g_bcManager[managerId].minInterval;
            g_bcManagerExtra[managerId].maxInterval = g_bcManager[managerId].maxInterval;
        }
    }
}

static void BcStartBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    static uint32_t callCount = 0;
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK,
            DISC_BROADCAST, "mutex error, adapterBcId=%{public}d", adapterBcId);

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        if (!bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStartBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            DISC_LOGE(DISC_BROADCAST, "bcManager not available, adapterBcId=%{public}d, managerId=%{public}u",
                adapterBcId, managerId);
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d,"
            "callCount=%{public}u", GetSrvType(bcManager->srvType), managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            if (!bcManager->isAdvertising) {
                g_bcCurrentNum++;
            }
            bcManager->isAdvertising = true;
            UpdateBcMaxExtra();
            SoftBusCondSignal(&bcManager->cond);
        }
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnStartBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcStopBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK,
            DISC_BROADCAST, "mutex error, adapterBcId=%{public}d", adapterBcId);

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        if (!bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            DISC_LOGE(DISC_BROADCAST, "bcManager not available, adapterBcId=%{public}d, managerId=%{public}u",
                adapterBcId, managerId);
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            if (bcManager->isAdvertising) {
                g_bcCurrentNum--;
            }
            bcManager->isAdvertising = false;
            bcManager->time = 0;
            SoftBusCondSignal(&bcManager->cond);
        }
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnStopBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcUpdateBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter update bc cb enter");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnUpdateBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnUpdateBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter set bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnSetBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d,"
            "callCount=%{public}u", GetSrvType(bcManager->srvType), managerId, adapterBcId, status, callCount++);
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnSetBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingParamCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter set bc param cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d,"
            "status=%{public}d, callCount=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        SoftBusMutexUnlock(&g_bcLock);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcEnableBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter enable bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d,"
            "status=%{public}d, callCount=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isDisabled = false;
            SoftBusCondSignal(&bcManager->pauseCond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcDisableBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter disable bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d,"
            "status=%{public}d, callCount=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isDisabled = true;
            SoftBusCondSignal(&bcManager->pauseCond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static SoftbusBroadcastCallback g_softbusBcBleCb = {
    .OnStartBroadcastingCallback = BcStartBroadcastingCallback,
    .OnStopBroadcastingCallback = BcStopBroadcastingCallback,
    .OnUpdateBroadcastingCallback = BcUpdateBroadcastingCallback,
    .OnSetBroadcastingCallback = BcSetBroadcastingCallback,
    .OnSetBroadcastingParamCallback = BcSetBroadcastingParamCallback,
    .OnDisableBroadcastingCallback = BcDisableBroadcastingCallback,
    .OnEnableBroadcastingCallback = BcEnableBroadcastingCallback,
};

static void BcOnStartScanCallback(int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter on start scan cb");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->adapterScanId != adapterScanId || !scanManager->isUsed || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnStartScanCallback == NULL) {
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, "
            "status=%{public}d", GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = true;
        }

        scanManager->scanCallback->OnStartScanCallback((int32_t)managerId, status);
    }
}

static void BcStopScanCallback(int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter stop scan cb");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->adapterScanId != adapterScanId || !scanManager->isUsed || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnStopScanCallback == NULL) {
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, "
            "status=%{public}d", GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = false;
        }

        scanManager->scanCallback->OnStopScanCallback((int32_t)managerId, status);
    }
}

static int32_t BuildBcInfoCommon(const SoftBusBcScanResult *reportData, BroadcastReportInfo *bcInfo)
{
    bcInfo->eventType = reportData->eventType;
    bcInfo->dataStatus = reportData->dataStatus;
    bcInfo->primaryPhy = reportData->primaryPhy;
    bcInfo->secondaryPhy = reportData->secondaryPhy;
    bcInfo->advSid = reportData->advSid;
    bcInfo->txPower = reportData->txPower;
    bcInfo->rssi = reportData->rssi;
    bcInfo->addrType = reportData->addrType;

    int32_t ret = memcpy_s(bcInfo->addr.addr, BC_ADDR_MAC_LEN, reportData->addr.addr, SOFTBUS_ADDR_MAC_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_MEM_ERR, DISC_BROADCAST, "memcpy addr failed");

    ret = memcpy_s(bcInfo->localName, BC_LOCAL_NAME_LEN_MAX, reportData->localName, SOFTBUS_LOCAL_NAME_LEN_MAX);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_MEM_ERR, DISC_BROADCAST, "memcpy localName failed");

    return SOFTBUS_OK;
}

static bool CheckManufactureIsMatch(const BcScanFilter *filter, const BroadcastPayload *bcData)
{
    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter->manufactureDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BROADCAST, "payload is too short");
        return false;
    }
    if (filter->manufactureId != bcData->id) {
        DISC_LOGD(DISC_BROADCAST, "manufacture id not match");
        return false;
    }
    for (uint32_t i = 0; i < filterLen; i++) {
        if ((filter->manufactureData[i] & filter->manufactureDataMask[i]) !=
            (bcData->payload[i] & filter->manufactureDataMask[i])) {
            return false;
        }
    }
    return true;
}

static bool CheckServiceIsMatch(const BcScanFilter *filter, const BroadcastPayload *bcData)
{
    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter->serviceDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BROADCAST, "payload is too short");
        return false;
    }
    if (filter->serviceUuid != bcData->id) {
        DISC_LOGD(DISC_BROADCAST, "serviceUuid not match");
        return false;
    }
    for (uint32_t i = 0; i < filterLen; i++) {
        if ((filter->serviceData[i] & filter->serviceDataMask[i]) !=
            (bcData->payload[i] & filter->serviceDataMask[i])) {
            return false;
        }
    }
    return true;
}

static bool CheckScanResultDataIsMatch(const uint32_t managerId, BroadcastPayload *bcData)
{
    if (bcData->type != BC_DATA_TYPE_SERVICE && bcData->type != BC_DATA_TYPE_MANUFACTURER) {
        DISC_LOGE(DISC_BROADCAST, "not support type, type=%{public}d", bcData->type);
        return false;
    }

    uint8_t filterSize = g_scanManager[managerId].filterSize;
    for (uint8_t i = 0; i < filterSize; i++) {
        BcScanFilter filter = g_scanManager[managerId].filter[i];
        if (bcData->type == BC_DATA_TYPE_SERVICE && CheckServiceIsMatch(&filter, bcData)) {
            return true;
        }
        if (bcData->type == BC_DATA_TYPE_MANUFACTURER && CheckManufactureIsMatch(&filter, bcData)) {
            return true;
        }
    }
    return false;
}

static void DumpSoftbusData(const char *description, uint16_t len, const uint8_t *data)
{
    DISC_CHECK_AND_RETURN_LOGE(description != NULL, DISC_BROADCAST, "description is nullptr");
    DISC_CHECK_AND_RETURN_LOGD(len != 0, DISC_BROADCAST, "description=%{public}s, len is 0", description);
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_BROADCAST, "description=%{public}s, data is nullptr", description);

    int32_t hexLen = HEXIFY_LEN(len);
    char *softbusData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
    DISC_CHECK_AND_RETURN_LOGE(softbusData != NULL, DISC_BROADCAST, "desc=%{public}s, malloc failed", description);

    (void)ConvertBytesToHexString(softbusData, hexLen, data, len);
    DISC_LOGD(DISC_BROADCAST, "description=%{public}s, softbusData=%{public}s", description, softbusData);

    SoftBusFree(softbusData);
}

static void ReleaseBroadcastReportInfo(BroadcastReportInfo *bcInfo)
{
    SoftBusFree(bcInfo->packet.bcData.payload);
    SoftBusFree(bcInfo->packet.rspData.payload);
}

static int32_t BuildBcPayload(int32_t maxPayloadLen, const SoftbusBroadcastPayload *srcData, BroadcastPayload *dstData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcData->payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "broadcast payload is nullptr");

    dstData->type = (BroadcastDataType)srcData->type;
    dstData->id = srcData->id;

    if (srcData->payloadLen > maxPayloadLen) {
        DISC_LOGW(DISC_BROADCAST, "payloadLen=%{public}d is too long", srcData->payloadLen);
    }
    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;
    dstData->payload = (uint8_t *)SoftBusCalloc(bcDataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");

    if (memcpy_s(dstData->payload, bcDataLen, srcData->payload, bcDataLen) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy payload failed");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }
    dstData->payloadLen = bcDataLen;

    return SOFTBUS_OK;
}

static int32_t BuildBroadcastPacket(const SoftbusBroadcastData *softbusBcData, BroadcastPacket *packet)
{
    packet->isSupportFlag = softbusBcData->isSupportFlag;
    packet->flag = softbusBcData->flag;

    // 2.1. Build broadcast payload.
    int32_t maxPayloadLen = (softbusBcData->isSupportFlag) ? BC_DATA_MAX_LEN : (BC_DATA_MAX_LEN + BC_FLAG_LEN);

    int32_t ret = BuildBcPayload(maxPayloadLen, &(softbusBcData->bcData), &(packet->bcData));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_BC_MGR_BUILD_ADV_PACKT_FAIL,
        DISC_BROADCAST, "build broadcast payload failed");

    DumpSoftbusData("scan result bcData", softbusBcData->bcData.payloadLen, softbusBcData->bcData.payload);

    // 2.2. Build broadcast response payload.
    if (softbusBcData->rspData.payload == NULL) {
        packet->rspData.payload = NULL;
        DISC_LOGD(DISC_BROADCAST, "no rspData");
    } else {
        maxPayloadLen = RSP_DATA_MAX_LEN;
        ret = BuildBcPayload(maxPayloadLen, &(softbusBcData->rspData), &(packet->rspData));
        if (ret != SOFTBUS_OK) {
            SoftBusFree(packet->bcData.payload);
            DISC_LOGE(DISC_BROADCAST, "build broadcast rsp payload failed");
            return SOFTBUS_BC_MGR_BUILD_RSP_PACKT_FAIL;
        }
        DumpSoftbusData("scan result rspData", softbusBcData->rspData.payloadLen, softbusBcData->rspData.payload);
    }
    return SOFTBUS_OK;
}

static int32_t BuildBroadcastReportInfo(const SoftBusBcScanResult *reportData, BroadcastReportInfo *bcInfo)
{
    // 1. Build BroadcastReportInfo from SoftBusBcScanResult except BroadcastPacket.
    int32_t ret = BuildBcInfoCommon(reportData, bcInfo);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "build broadcast common info failed");

    // 2. Build BroadcastPacket.
    ret = BuildBroadcastPacket(&(reportData->data), &(bcInfo->packet));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "build broadcast packet failed");

    return SOFTBUS_OK;
}

static bool CheckScanResultDataIsMatchApproach(const uint32_t managerId, BroadcastPayload *bcData)
{
    if (bcData->payload == NULL) {
        return false;
    }
    DISC_CHECK_AND_RETURN_RET_LOGD(bcData->type == BC_DATA_TYPE_SERVICE, false, DISC_BROADCAST,
        "type dismatch, type=%{public}d", bcData->type);

    uint8_t filterSize = g_scanManager[managerId].filterSize;
    for (uint8_t i = 0; i < filterSize; i++) {
        BcScanFilter filter = g_scanManager[managerId].filter[i];
        if (CheckServiceIsMatch(&filter, bcData)) {
            return true;
        }
    }
    return false;
}

static void BcReportScanDataCallback(int32_t adapterScanId, const SoftBusBcScanResult *reportData)
{
    DISC_LOGD(DISC_BROADCAST, "enter report scan cb");
    DISC_CHECK_AND_RETURN_LOGE(reportData != NULL, DISC_BROADCAST, "reportData is nullptr");

    BroadcastReportInfo bcInfo;
    int32_t ret = BuildBroadcastReportInfo(reportData, &bcInfo);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "build bc report info failed");

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (SoftBusMutexLock(&g_scanLock) != 0) {
            ReleaseBroadcastReportInfo(&bcInfo);
            return;
        }
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->filter == NULL ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnReportScanDataCallback == NULL ||
            scanManager->adapterScanId != adapterScanId ||
            !(CheckScanResultDataIsMatch(managerId, &(bcInfo.packet.bcData)) ||
            (scanManager->srvType == SRV_TYPE_APPROACH &&
            CheckScanResultDataIsMatchApproach(managerId, &(bcInfo.packet.rspData))))) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }

        DISC_LOGD(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d",
            GetSrvType(scanManager->srvType), managerId, adapterScanId);
        ScanCallback callback = *(scanManager->scanCallback);
        SoftBusMutexUnlock(&g_scanLock);
        callback.OnReportScanDataCallback((int32_t)managerId, &bcInfo);
    }
    ReleaseBroadcastReportInfo(&bcInfo);
}

static void BcScanStateChanged(int32_t resultCode, bool isStartScan)
{
    DISC_LOGD(DISC_BROADCAST, "enter scan state change");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_scanLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnScanStateChanged == NULL) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        DISC_LOGD(DISC_BROADCAST,
            "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, isStartScan=%{public}d",
            GetSrvType(scanManager->srvType), managerId, scanManager->adapterScanId, isStartScan);
        ScanCallback callback = *(scanManager->scanCallback);
        SoftBusMutexUnlock(&g_scanLock);
        callback.OnScanStateChanged(resultCode, isStartScan);
    }
}

static int32_t ConvertBroadcastUuid(const SoftbusBroadcastUuid *uuid, BroadcastUuid *bcUuid)
{
    bcUuid->uuidLen = uuid->uuidLen;
    bcUuid->uuid = (int8_t *)SoftBusCalloc(bcUuid->uuidLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(bcUuid->uuid != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");
    if (memcpy_s(bcUuid->uuid, bcUuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy error");
        SoftBusFree(bcUuid->uuid);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void BcLpDeviceInfoCallback(const SoftbusBroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    DISC_LOGD(DISC_BROADCAST, "enter lp cb");
    BroadcastUuid bcUuid = {0};
    int32_t ret = ConvertBroadcastUuid(uuid, &bcUuid);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "convert broadcast Uuid failed");

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnLpDeviceInfoCallback == NULL) {
            continue;
        }

        scanManager->scanCallback->OnLpDeviceInfoCallback(&bcUuid, type, data, dataSize);
        break;
    }
    SoftBusFree(bcUuid.uuid);
}

static SoftbusScanCallback g_softbusBcBleScanCb = {
    .OnStartScanCallback = BcOnStartScanCallback,
    .OnStopScanCallback = BcStopScanCallback,
    .OnReportScanDataCallback = BcReportScanDataCallback,
    .OnScanStateChanged = BcScanStateChanged,
    .OnLpDeviceInfoCallback = BcLpDeviceInfoCallback,
};

static bool IsSrvTypeValid(BaseServiceType srvType)
{
    return srvType >= 0 && srvType < SRV_TYPE_BUTT;
}

static int32_t InitializeBroadcaster(
    int32_t *bcId, int32_t adapterBcId, BaseServiceType srvType, const BroadcastCallback *cb)
{
    int32_t ret = SOFTBUS_OK;
    int32_t managerId;

    for (managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (!g_bcManager[managerId].isUsed) {
            break;
        }
    }
    if (managerId == BC_NUM_MAX) {
        DISC_LOGE(DISC_BROADCAST, "no available adv manager");
        return SOFTBUS_BC_MGR_REG_NO_AVAILABLE_BC_ID;
    }
    DISC_LOGI(DISC_BROADCAST,
        "srvType=%{public}s, bcId=%{public}d, adapterBcId=%{public}d", GetSrvType(srvType), managerId, adapterBcId);

    *bcId = managerId;
    ret = SoftBusCondInit(&g_bcManager[managerId].cond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "cond Init failed");
        return ret;
    }
    ret = SoftBusCondInit(&g_bcManager[managerId].pauseCond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "pauseCond Init failed");
        return ret;
    }
    g_bcManager[managerId].srvType = srvType;
    g_bcManager[managerId].adapterBcId = adapterBcId;
    g_bcManager[managerId].isUsed = true;
    g_bcManager[managerId].isAdvertising = false;
    g_bcManager[managerId].isDisabled = false;
    g_bcManager[managerId].time = 0;
    g_bcManager[managerId].bcCallback = (BroadcastCallback *)cb;

    return SOFTBUS_OK;
}

int32_t RegisterBroadcaster(BaseServiceType srvType, int32_t *bcId, const BroadcastCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter register bc, callCount=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterBcId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BROADCAST, "bad srvType");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcId != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param bcId");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterBroadcaster != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    ret = g_interface[g_interfaceId]->RegisterBroadcaster(&adapterBcId, &g_softbusBcBleCb);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    ret = InitializeBroadcaster(bcId, adapterBcId, srvType, cb);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static bool CheckBcIdIsValid(int32_t bcId)
{
    if (bcId < 0 || bcId >= BC_NUM_MAX || !g_bcManager[bcId].isUsed) {
        DISC_LOGE(DISC_BROADCAST, "invalid param bcId=%{public}d", bcId);
        return false;
    }
    return true;
}

int32_t UnRegisterBroadcaster(int32_t bcId)
{
    DISC_LOGI(DISC_BROADCAST, "enter unRegister bc");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterBroadcaster != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        DISC_LOGE(DISC_BROADCAST, "bcId is invalid");
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_bcManager[bcId].isAdvertising) {
        SoftBusMutexUnlock(&g_bcLock);
        (void)g_interface[g_interfaceId]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
        SoftBusMutexLock(&g_bcLock);
    }
    ret = g_interface[g_interfaceId]->UnRegisterBroadcaster(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    g_bcManager[bcId].srvType = -1;
    g_bcManager[bcId].adapterBcId = -1;
    g_bcManager[bcId].isUsed = false;
    g_bcManager[bcId].isAdvertising = false;
    g_bcManager[bcId].isDisabled = false;
    g_bcManager[bcId].time = 0;
    SoftBusCondDestroy(&g_bcManager[bcId].cond);
    SoftBusCondDestroy(&g_bcManager[bcId].pauseCond);
    g_bcManager[bcId].bcCallback = NULL;

    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static int32_t GetSrvTypeIndex(BaseServiceType srvType)
{
    if (srvType == SRV_TYPE_LP_BURST || srvType == SRV_TYPE_LP_HB) {
        return CHANEL_LP;
    } else if (srvType == SRV_TYPE_CONN || srvType == SRV_TYPE_TRANS_MSG || srvType == SRV_TYPE_AUTH_CONN ||
        srvType == SRV_TYPE_APPROACH || srvType == SRV_TYPE_OH_APPROACH || srvType == SRV_TYPE_VLINK ||
        srvType == SRV_TYPE_FAST_OFFLINE) {
        return CHANEL_STEADY;
    } else if (srvType == SRV_TYPE_SHARE || srvType == SRV_TYPE_TOUCH) {
        return CHANEL_SHARE;
    } else if (srvType == SRV_TYPE_HB || srvType == SRV_TYPE_DIS || srvType == SRV_TYPE_OOP) {
        return CHANEL_UNSTEADY;
    }
    return CHANEL_UNKNOW;
}

static int32_t RegisterScanListenerForChannel(int32_t channel, int32_t *adapterScanId, const ScanCallback *cb)
{
    int32_t ret;
    if (g_AdapterStatusControl[channel].isAdapterScanCbReg) {
        *adapterScanId = g_AdapterStatusControl[channel].adapterScannerId;
        DISC_LOGI(DISC_BROADCAST, "service is already registered channel=%{public}d", channel);
        return SOFTBUS_OK;
    }
    ret = g_interface[g_interfaceId]->RegisterScanListener(adapterScanId, &g_softbusBcBleScanCb);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed");
    g_AdapterStatusControl[channel].isAdapterScanCbReg = true;
    g_AdapterStatusControl[channel].adapterScannerId = *adapterScanId;
    DISC_LOGI(DISC_BROADCAST, "channel %{public}d register scan listener", channel);
    return SOFTBUS_OK;
}

static int32_t RegisterScanListenerSub(
    BaseServiceType srvType, int32_t *adapterScanId, const ScanCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId),
        SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    int32_t channel = GetSrvTypeIndex(srvType);
    switch (channel) {
        case CHANEL_LP:
        case CHANEL_STEADY:
        case CHANEL_SHARE:
        case CHANEL_UNSTEADY:
            return RegisterScanListenerForChannel(channel, adapterScanId, cb);
        default:
            DISC_LOGI(DISC_BROADCAST, "no server type channel srvType=%{public}s",
                GetSrvType(srvType));
            return SOFTBUS_TRANS_MSG_START_SCAN_FAIL;
    }
}

static bool CheckSrvRegistered(BaseServiceType srvType)
{
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            continue;
        }
        if (g_scanManager[managerId].srvType == srvType) {
            DISC_LOGE(DISC_BROADCAST, "service is registered, srvType=%{public}s", GetSrvType(srvType));
            return true;
        }
    }
    return false;
}

int32_t RegisterScanListener(BaseServiceType srvType, int32_t *listenerId, const ScanCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGD(DISC_BROADCAST, "enter callCount=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterScanId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BROADCAST, "bad srvType");
    DISC_CHECK_AND_RETURN_RET_LOGE(listenerId != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid listenerId");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param cb");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterScanListener != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(!CheckSrvRegistered(srvType), SOFTBUS_BC_MGR_REG_DUP,
        DISC_BROADCAST, "already registered");
    ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    ret = RegisterScanListenerSub(srvType, &adapterScanId, cb);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        DISC_LOGE(DISC_BROADCAST, "register listerner failed");
        return ret;
    }

    int32_t managerId;
    for (managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            break;
        }
    }
    if (managerId == SCAN_NUM_MAX) {
        DISC_LOGE(DISC_BROADCAST, "no available scanner");
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_REG_NO_AVAILABLE_LISN_ID;
    }
    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, listenerId=%{public}d, adapterScanId=%{public}d",
              GetSrvType(srvType), managerId, adapterScanId);
    *listenerId = managerId;
    g_scanManager[managerId].srvType = srvType;
    g_scanManager[managerId].adapterScanId = adapterScanId;
    g_scanManager[managerId].isUsed = true;
    g_scanManager[managerId].isFliterChanged = true;
    g_scanManager[managerId].isScanning = false;
    g_scanManager[managerId].freq = SCAN_FREQ_LOW_POWER;
    g_scanManager[managerId].scanCallback = (ScanCallback *)cb;

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

static bool CheckScanIdIsValid(int32_t listenerId)
{
    if (listenerId < 0 || listenerId >= SCAN_NUM_MAX || !g_scanManager[listenerId].isUsed) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId=%{public}d", listenerId);
        return false;
    }
    return true;
}

static void ReleaseBcScanFilter(int listenerId)
{
    DISC_LOGD(DISC_BROADCAST, "enter release scan filter");
    BcScanFilter *filter = g_scanManager[listenerId].filter;
    if (filter == NULL) {
        return;
    }
    uint8_t filterSize = g_scanManager[listenerId].filterSize;
    while (filterSize-- > 0) {
        SoftBusFree((filter + filterSize)->address);
        SoftBusFree((filter + filterSize)->deviceName);
        SoftBusFree((filter + filterSize)->serviceData);
        SoftBusFree((filter + filterSize)->serviceDataMask);
        SoftBusFree((filter + filterSize)->manufactureData);
        SoftBusFree((filter + filterSize)->manufactureDataMask);
    }
    SoftBusFree(filter);
    g_scanManager[listenerId].filterSize = 0;
    g_scanManager[listenerId].filter = NULL;
}

static bool CheckNeedUnRegisterScanListener(int32_t listenerId)
{
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (managerId != listenerId && g_scanManager[managerId].adapterScanId == adapterScanId &&
            g_scanManager[managerId].isScanning) {
            return false;
        }
    }
    return true;
}

static bool CheckNeedUpdateScan(int32_t listenerId, int32_t *liveListenerId)
{
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (managerId != listenerId && g_scanManager[managerId].adapterScanId == adapterScanId &&
            g_scanManager[managerId].isScanning) {
            *liveListenerId = managerId;
            return true;
        }
    }
    return false;
}

static int32_t CopyScanFilterServiceInfo(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    dstFilter->serviceUuid = srcFilter->serviceUuid;
    dstFilter->serviceDataLength = srcFilter->serviceDataLength;
    if (srcFilter->serviceData != NULL && srcFilter->serviceDataLength > 0) {
        dstFilter->serviceData = (uint8_t *)SoftBusCalloc(dstFilter->serviceDataLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->serviceData != NULL &&
            memcpy_s(dstFilter->serviceData, dstFilter->serviceDataLength,
            srcFilter->serviceData, srcFilter->serviceDataLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter serviceData failed");
    }
    if (srcFilter->serviceDataMask != NULL && srcFilter->serviceDataLength > 0) {
        dstFilter->serviceDataMask = (uint8_t *)SoftBusCalloc(dstFilter->serviceDataLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->serviceDataMask != NULL &&
            memcpy_s(dstFilter->serviceDataMask, dstFilter->serviceDataLength,
            srcFilter->serviceDataMask, srcFilter->serviceDataLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter serviceDataMask failed");
    }
    return SOFTBUS_OK;
}

static int32_t CopySoftBusBcScanFilter(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    if (srcFilter->address != NULL) {
        uint32_t addressLength = strlen((char *)srcFilter->address) + 1;
        dstFilter->address = (int8_t *)SoftBusCalloc(addressLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->address != NULL &&
            memcpy_s(dstFilter->address, addressLength, srcFilter->address, addressLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter address failed");
    }

    if (srcFilter->deviceName != NULL) {
        uint32_t deviceNameLength = strlen((char *)srcFilter->deviceName) + 1;
        dstFilter->deviceName = (int8_t *)SoftBusCalloc(deviceNameLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->deviceName != NULL &&
            memcpy_s(dstFilter->deviceName, deviceNameLength, srcFilter->deviceName, deviceNameLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter deviceName failed");
    }

    int ret = CopyScanFilterServiceInfo(srcFilter, dstFilter);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    dstFilter->manufactureId = srcFilter->manufactureId;
    dstFilter->manufactureDataLength = srcFilter->manufactureDataLength;
    if (srcFilter->manufactureData != NULL && srcFilter->manufactureDataLength > 0) {
        dstFilter->manufactureData = (uint8_t *)SoftBusCalloc(dstFilter->manufactureDataLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->manufactureData != NULL &&
            memcpy_s(dstFilter->manufactureData, dstFilter->manufactureDataLength,
            srcFilter->manufactureData, srcFilter->manufactureDataLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter manufactureData failed");
    }
    if (srcFilter->manufactureDataMask != NULL && srcFilter->manufactureDataLength > 0) {
        dstFilter->manufactureDataMask = (uint8_t *)SoftBusCalloc(dstFilter->manufactureDataLength);
        DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter->manufactureDataMask != NULL &&
            memcpy_s(dstFilter->manufactureDataMask, dstFilter->manufactureDataLength,
            srcFilter->manufactureDataMask, srcFilter->manufactureDataLength) == EOK,
            SOFTBUS_MEM_ERR, DISC_BROADCAST, "copy filter manufactureDataMask failed");
    }
    if (srcFilter->filterIndex == 0) {
        DISC_LOGW(DISC_BROADCAST, "invaild filterIndex");
    }
    dstFilter->filterIndex = srcFilter->filterIndex;
    dstFilter->advIndReport = srcFilter->advIndReport;
    return SOFTBUS_OK;
}

static int32_t CovertSoftBusBcScanFilters(const BcScanFilter *filter, uint8_t size, SoftBusBcScanFilter *adapterFilter)
{
    while (size-- > 0) {
        int32_t ret = CopySoftBusBcScanFilter(filter + size, adapterFilter + size);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "copy filter failed");
    }
    return SOFTBUS_OK;
}

static void ReleaseSoftBusBcScanFilter(SoftBusBcScanFilter *filter, int32_t size)
{
    if (filter != NULL) {
        while (size-- > 0) {
            if ((filter + size)->address != NULL) {
                SoftBusFree((filter + size)->address);
            }
            if ((filter + size)->deviceName != NULL) {
                SoftBusFree((filter + size)->deviceName);
            }
            if ((filter + size)->serviceData != NULL) {
                SoftBusFree((filter + size)->serviceData);
            }
            if ((filter + size)->serviceDataMask != NULL) {
                SoftBusFree((filter + size)->serviceDataMask);
            }
            if ((filter + size)->manufactureData != NULL) {
                SoftBusFree((filter + size)->manufactureData);
            }
            if ((filter + size)->manufactureDataMask != NULL) {
                SoftBusFree((filter + size)->manufactureDataMask);
            }
        }
        SoftBusFree(filter);
    }
}

static int32_t CombineSoftbusBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    DISC_LOGD(DISC_BROADCAST, "enter combine scan filters");
    uint8_t size = 0;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || (!scanManager->isScanning && managerId != listenerId) ||
            scanManager->adapterScanId != g_scanManager[listenerId].adapterScanId) {
            continue;
        }

        size += scanManager->filterSize;
    }
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");
    *filterSize = size;

    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || (!scanManager->isScanning && managerId != listenerId) ||
            scanManager->adapterScanId != g_scanManager[listenerId].adapterScanId) {
            continue;
        }

        uint8_t currentSize = g_scanManager[managerId].filterSize;
        BcScanFilter *filter = g_scanManager[managerId].filter;
        size = size - currentSize;
        int32_t ret = CovertSoftBusBcScanFilters(filter, currentSize, *adapterFilter + size);
        if (ret != SOFTBUS_OK) {
            ReleaseSoftBusBcScanFilter(*adapterFilter, size);
            *adapterFilter = NULL;
            DISC_LOGE(DISC_BROADCAST, "convert bc scan filters failed");
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetScanFiltersForOneListener(int32_t listenerId, SoftBusBcScanFilter **adapterFilter,
    int32_t *filterSize)
{
    if (g_scanManager[listenerId].filterSize == 0) {
        DISC_LOGE(DISC_BROADCAST, "adapterFilter couldn't assemble");
        return SOFTBUS_DISCOVER_BLE_END_SCAN_FAIL;
    }
    uint8_t size = g_scanManager[listenerId].filterSize;
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");
    *filterSize = size;
    BcScanFilter *filter = g_scanManager[listenerId].filter;
    int32_t ret = CovertSoftBusBcScanFilters(filter, size, *adapterFilter);
    if (ret != SOFTBUS_OK) {
        ReleaseSoftBusBcScanFilter(*adapterFilter, size);
        *adapterFilter = NULL;
        DISC_LOGE(DISC_BROADCAST, "convert bc scan filters failed");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DeleteFilterByIndex(int32_t listenerId, SoftBusBcScanFilter **adapterFilter,
    SoftBusBcScanParams *adapterParam, int32_t filterSize)
{
    DISC_LOGI(DISC_BROADCAST, "enter delete filter by index, listenerId=%{public}d, size=%{public}d",
        listenerId, g_scanManager[listenerId].deleteSize);
    int32_t ret;
    uint8_t size = g_scanManager[listenerId].deleteSize;
    DISC_CHECK_AND_RETURN_RET_LOGE(size != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "size is 0");
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST,
        "memory allocation failed");
    for (int i = 0; i < size; i++) {
        int filterIndex = g_scanManager[listenerId].deleted[i];
        DISC_CHECK_AND_RETURN_RET_LOGE(filterIndex != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid index!");
        (*adapterFilter + i)->filterIndex = filterIndex;
        ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
            *adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_DELETE);
        if (ret == SOFTBUS_OK) {
            g_firstSetIndex[filterIndex] = false;
        }
    }

    return ret;
}

static int32_t GetAddFiltersByIndex(int32_t listenerId, SoftBusBcScanFilter **adapterFilter)
{
    DISC_LOGI(DISC_BROADCAST, "enter add filter by index, listenerId=%{public}d, size=%{public}d",
        listenerId, g_scanManager[listenerId].addSize);

    int32_t ret;
    uint8_t size = g_scanManager[listenerId].addSize;
    DISC_CHECK_AND_RETURN_RET_LOGE(size != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "size is 0");
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    for (int i = 0; i < size; i++) {
        int addIndex = g_scanManager[listenerId].added[i];
        BcScanFilter *tempFilter = &(g_scanManager[listenerId].filter[addIndex]);
        if (tempFilter->filterIndex == 0) {
            DISC_LOGE(DISC_BROADCAST, "invalid index");
            return SOFTBUS_INVALID_PARAM;
        }
        ret = CopySoftBusBcScanFilter(tempFilter, (*adapterFilter) + i);
    }

    return ret;
}

static int32_t GetModifyFiltersByIndex(int32_t listenerId, SoftBusBcScanFilter **adapterFilter)
{
    DISC_LOGI(DISC_BROADCAST, "enter Modify filter by index, listenerId=%{public}d, addSize=%{public}d",
        listenerId, g_scanManager[listenerId].addSize);
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].addSize != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "addSize is 0");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].deleteSize != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "deleteSize is 0");

    int32_t ret;
    uint8_t size = g_scanManager[listenerId].addSize;
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    for (int i = 0; i < size; i++) {
        uint8_t addIndex = g_scanManager[listenerId].added[i];
        uint8_t deleteIndex = g_scanManager[listenerId].deleted[i];
        int replaceIndex = g_scanManager[listenerId].filter[addIndex].filterIndex;
        g_firstSetIndex[replaceIndex] = false;
        BcScanFilter *tempFilter = &(g_scanManager[listenerId].filter[addIndex]);
        tempFilter->filterIndex = deleteIndex;
        if (tempFilter->filterIndex == 0) {
            DISC_LOGE(DISC_BROADCAST, "invalid index");
            return SOFTBUS_INVALID_PARAM;
        }
        ret = CopySoftBusBcScanFilter(tempFilter, (*adapterFilter) + i);
    }

    return ret;
}

static int32_t GetBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    return CombineSoftbusBcScanFilters(listenerId, adapterFilter, filterSize);
}

static void DumpBcScanFilter(const SoftBusBcScanFilter *nativeFilter, uint8_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BROADCAST, "invalid param nativeFilter");
    DISC_CHECK_AND_RETURN_LOGE(filterSize != 0, DISC_BROADCAST, "filterSize is 0");

    while (filterSize-- > 0) {
        int32_t len = (nativeFilter + filterSize)->serviceDataLength;
        if (len > 0) {
            DumpSoftbusData("service data", len, (nativeFilter + filterSize)->serviceData);
            DumpSoftbusData("service dataMask", len, (nativeFilter + filterSize)->serviceDataMask);
        } else {
            len = (nativeFilter + filterSize)->manufactureDataLength;
            if (len <= 0) {
                continue;
            }
            DumpSoftbusData("manufacture data", len, (nativeFilter + filterSize)->manufactureData);
            DumpSoftbusData("manufacture dataMask", len, (nativeFilter + filterSize)->manufactureDataMask);
        }
    }
}

static void BuildSoftBusBcScanParams(const BcScanParams *param, SoftBusBcScanParams *adapterParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter scan param");
    (void)memset_s(adapterParam, sizeof(SoftBusBcScanParams), 0x0, sizeof(SoftBusBcScanParams));

    // convert params
    adapterParam->scanInterval = param->scanInterval;
    adapterParam->scanWindow = param->scanWindow;
    adapterParam->scanType = param->scanType;
    adapterParam->scanPhy = param->scanPhy;
    adapterParam->scanFilterPolicy = param->scanFilterPolicy;
}

static void GetScanIntervalAndWindow(int32_t freq, SoftBusBcScanParams *adapterParam)
{
    if (freq == SCAN_FREQ_P2_60_3000) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    }
    if (freq == SCAN_FREQ_P2_30_1500) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2_FAST;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2_FAST;
    }
    if (freq == SCAN_FREQ_P10_30_300) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10;
    }
    if (freq == SCAN_FREQ_P25_60_240) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P25;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P25;
    }
    if (freq == SCAN_FREQ_P50_30_60) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P50;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P50;
    }
    if (freq == SCAN_FREQ_P75_30_40) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P75;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P75;
    }
    if (freq == SCAN_FREQ_P100_1000_1000) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P100;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P100;
    }
}

static void CheckScanFreq(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    int32_t maxFreq = g_scanManager[listenerId].freq;

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->adapterScanId != adapterScanId) {
            continue;
        }
        maxFreq = (maxFreq > (int32_t)(scanManager->freq)) ? maxFreq : (int32_t)(scanManager->freq);
    }

    GetScanIntervalAndWindow(maxFreq, adapterParam);
}

static int32_t CheckAndStopScan(int32_t listenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    int32_t liveListenerId = -1;
    int32_t ret;
    bool needUpdate = CheckNeedUpdateScan(listenerId, &liveListenerId);
    if (!needUpdate) {
        DISC_LOGI(DISC_BROADCAST, "call stop scan, adapterId=%{public}d", g_scanManager[listenerId].adapterScanId);
        ret = g_interface[g_interfaceId]->StopScan(g_scanManager[listenerId].adapterScanId);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
            return ret;
        }
    } else {
        int32_t filterSize = 0;
        SoftBusBcScanFilter *adapterFilter = NULL;
        g_scanManager[listenerId].isScanning = false;
        ret = GetScanFiltersForOneListener(listenerId, &adapterFilter, &filterSize);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "get bc scan filters failed");
        DumpBcScanFilter(adapterFilter, filterSize);
        SoftBusBcScanParams adapterParam;
        BuildSoftBusBcScanParams(&(g_scanManager[listenerId].param), &adapterParam);
        CheckScanFreq(liveListenerId, &adapterParam);
        ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, &adapterParam,
            adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_DELETE);

        ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].isScanning = true;
            g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
            return ret;
        }
        g_scanManager[listenerId].isScanning = false;
    }
    return SOFTBUS_OK;
}

int32_t UnRegisterScanListener(int32_t listenerId)
{
    DISC_LOGI(DISC_BROADCAST, "enter unregister scan, listenerId=%{public}d", listenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterScanListener != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    if (!CheckScanIdIsValid(listenerId)) {
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    if (g_scanManager[listenerId].isScanning) {
        ret = CheckAndStopScan(listenerId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "stop scan failed");
            SoftBusMutexUnlock(&g_scanLock);
            return ret;
        }
    }
    if (CheckNeedUnRegisterScanListener(listenerId)) {
        for (uint32_t index = 0; index < GATT_SCAN_MAX_NUM; ++index) {
            if (adapterScanId == g_AdapterStatusControl[index].adapterScannerId) {
                g_AdapterStatusControl[index].adapterScannerId = -1;
                g_AdapterStatusControl[index].isAdapterScanCbReg = false;
            }
        }
        ret = g_interface[g_interfaceId]->UnRegisterScanListener(adapterScanId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
            SoftBusMutexUnlock(&g_scanLock);
            return ret;
        }
    }
    DISC_LOGD(DISC_BROADCAST, "srvType=%{public}s", GetSrvType(g_scanManager[listenerId].srvType));
    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].srvType = -1;
    g_scanManager[listenerId].adapterScanId = -1;
    g_scanManager[listenerId].isUsed = false;
    g_scanManager[listenerId].isFliterChanged = false;
    g_scanManager[listenerId].freq = SCAN_FREQ_LOW_POWER;
    g_scanManager[listenerId].scanCallback = NULL;
    g_scanManager[listenerId].isScanning = false;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

static void ConvertBcParams(const BroadcastParam *srcParam, SoftbusBroadcastParam *dstParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter covert bc param");
    dstParam->minInterval = srcParam->minInterval;
    dstParam->maxInterval = srcParam->maxInterval;
    dstParam->advType = srcParam->advType;
    dstParam->advFilterPolicy = srcParam->advFilterPolicy;
    dstParam->ownAddrType = srcParam->ownAddrType;
    dstParam->peerAddrType = srcParam->peerAddrType;
    if (memcpy_s(dstParam->peerAddr.addr, SOFTBUS_ADDR_MAC_LEN, srcParam->peerAddr.addr, BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy peerAddr failed");
        return;
    }
    dstParam->channelMap = srcParam->channelMap;
    dstParam->duration = srcParam->duration;
    dstParam->txPower = srcParam->txPower;
    dstParam->isSupportRpa = srcParam->isSupportRpa;
    if (memcpy_s(dstParam->ownIrk, SOFTBUS_IRK_LEN, srcParam->ownIrk, BC_IRK_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy ownIrk failed");
        return;
    }
    if (memcpy_s(dstParam->ownUdidHash, SOFTBUS_UDID_HASH_LEN, srcParam->ownUdidHash, BC_UDID_HASH_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy ownUdidHash failed");
        return;
    }
    if (memcpy_s(dstParam->localAddr.addr, BC_ADDR_MAC_LEN, srcParam->localAddr.addr,
        BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy localAddr failed");
        return;
    }
}

static void DumpBroadcastPacket(const BroadcastPayload *bcData, const BroadcastPayload *rspData)
{
    if (bcData->payloadLen != 0 && bcData->payload != NULL) {
        DumpSoftbusData("BroadcastPayload bcData", bcData->payloadLen, bcData->payload);
    }
    if (rspData->payloadLen != 0 && rspData->payload != NULL) {
        DumpSoftbusData("BroadcastPayload rspData", rspData->payloadLen, rspData->payload);
    }
}

static int32_t SoftBusCondWaitSec(int64_t sec, int32_t bcId, SoftBusMutex *mutex)
{
    SoftBusSysTime absTime = {0};
    int32_t ret = SoftBusGetTime(&absTime);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "softbus get time failed");

    absTime.sec += sec;
    if (SoftBusCondWait(&g_bcManager[bcId].cond, mutex, &absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "wait timeout");
        return SOFTBUS_TIMOUT;
    }
    return SOFTBUS_OK;
}

static int32_t SoftbusPauseCondWaitSec(int64_t sec, int32_t bcId, SoftBusMutex *mutex)
{
    SoftBusSysTime absTime = {0};
    int32_t ret = SoftBusGetTime(&absTime);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "softbus get time failed");

    absTime.sec += sec;
    if (SoftBusCondWait(&g_bcManager[bcId].pauseCond, mutex, &absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "wait timeout");
        return SOFTBUS_TIMOUT;
    }
    return SOFTBUS_OK;
}

static int32_t BuildSoftbusBcPayload(int32_t maxPayloadLen, const BroadcastPayload *srcData,
    SoftbusBroadcastPayload *dstData)
{
    dstData->type = (SoftbusBcDataType)srcData->type;
    dstData->id = srcData->id;
    dstData->payloadLen = srcData->payloadLen;
    if (srcData->payloadLen > maxPayloadLen) {
        DISC_LOGW(DISC_BROADCAST, "payloadLen is too long! payloadLen=%{public}d", srcData->payloadLen);
    }
    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;

    dstData->payload = (uint8_t *)SoftBusCalloc(bcDataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");

    if (memcpy_s(dstData->payload, bcDataLen, srcData->payload, bcDataLen) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy_s error");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void ReleaseSoftbusBroadcastData(SoftbusBroadcastData *softbusBcData)
{
    DISC_LOGD(DISC_BROADCAST, "enter release bc data");
    SoftBusFree(softbusBcData->bcData.payload);
    SoftBusFree(softbusBcData->rspData.payload);
}

static int32_t BuildSoftbusBroadcastData(const BroadcastPacket *packet, SoftbusBroadcastData *softbusBcData)
{
    softbusBcData->isSupportFlag = packet->isSupportFlag;
    softbusBcData->flag = packet->flag;

    // 1. Build broadcast paylod.
    int32_t maxPayloadLen = (packet->isSupportFlag) ? BC_DATA_MAX_LEN : (BC_DATA_MAX_LEN + BC_FLAG_LEN);
    int32_t ret = BuildSoftbusBcPayload(maxPayloadLen, &(packet->bcData), &(softbusBcData->bcData));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "BuildSoftbusBcPayload failed");

    // 2. Build response broadcast paylod.
    if (packet->rspData.payload != NULL) {
        maxPayloadLen = RSP_DATA_MAX_LEN;
        ret = BuildSoftbusBcPayload(maxPayloadLen, &(packet->rspData), &(softbusBcData->rspData));
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "convert rspData failed");
            SoftBusFree(softbusBcData->bcData.payload);
            return ret;
        }
    } else {
        softbusBcData->rspData.payload = NULL;
        softbusBcData->rspData.payloadLen = 0;
    }
    return SOFTBUS_OK;
}

static int64_t MgrGetSysTime(void)
{
    SoftBusSysTime absTime = {0};
    SoftBusGetTime(&absTime);
    int64_t time = absTime.sec * MGR_TIME_THOUSAND_MULTIPLIER * MGR_TIME_THOUSAND_MULTIPLIER + absTime.usec;
    return time;
}

static void StartBroadcastingWaitSignal(int32_t bcId, SoftBusMutex *mutex)
{
    DISC_CHECK_AND_RETURN_LOGE(mutex != NULL, DISC_BROADCAST, "invalid param");
    DISC_CHECK_AND_RETURN_LOGE(CheckMediumIsValid(g_interfaceId), DISC_BROADCAST, "bad id");
    if (SoftBusCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex) == SOFTBUS_OK) {
        return;
    }
    DISC_LOGW(DISC_BROADCAST, "wait signal failed, srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "call StopBroadcast", GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    SoftBusMutexUnlock(mutex);
    int32_t ret = g_interface[g_interfaceId]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
    DISC_LOGW(DISC_BROADCAST, "StopBroadcasting ret=%{public}d", ret);
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(mutex) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");
    ret = SoftBusCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex);
    DISC_LOGW(DISC_BROADCAST, "wait signal ret=%{public}d", ret);
    g_bcManager[bcId].isAdvertising = false;
}

static int32_t DisableBroadcastingWaitSignal(int32_t bcId, SoftBusMutex *mutex)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(mutex != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId),
        SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    if (SoftbusPauseCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    DISC_LOGW(DISC_BROADCAST, "wait signal failed, srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "call enableBroadcast", GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    SoftBusMutexUnlock(mutex);
    int32_t ret = g_interface[g_interfaceId]->EnableBroadcasting(g_bcManager[bcId].adapterBcId);
    DISC_LOGW(DISC_BROADCAST, "EnableBroadcasting ret=%{public}d", ret);
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(mutex) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BROADCAST, "bcLock mutex error");
    ret = SoftbusPauseCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex);
    DISC_LOGW(DISC_BROADCAST, "wait signal ret=%{public}d", ret);
    g_bcManager[bcId].isDisabled = false;

    return SOFTBUS_BC_MGR_WAIT_COND_FAIL;
}

static int32_t CheckInterface(bool isStart)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    if (isStart) {
        DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartBroadcasting != NULL,
            SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    } else {
        DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopBroadcasting != NULL,
            SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    }
    return SOFTBUS_OK;
}

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    static uint32_t callCount = 0;
    int32_t ret = CheckInterface(true);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        DISC_BROADCAST, "interface check failed, bcId=%{public}d", bcId);
    ret = CheckBroadcastingParam(param, packet);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "check param failed");
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST,
        "mutex error, bcId=%{public}d", bcId);
    if (!CheckBcIdIsValid(bcId) || g_bcManager[bcId].bcCallback == NULL ||
        g_bcManager[bcId].bcCallback->OnStartBroadcastingCallback == NULL) {
        SoftBusMutexUnlock(&g_bcLock);
        DISC_LOGE(DISC_BROADCAST, "invalid bcId, bcId=%{public}d", bcId);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    if (g_bcManager[bcId].isAdvertising && !g_bcManager[bcId].isStarted) {
        DISC_LOGW(DISC_BROADCAST, "wait condition managerId=%{public}d", bcId);
        StartBroadcastingWaitSignal(bcId, &g_bcLock);
    }

    DumpBroadcastPacket(&(packet->bcData), &(packet->rspData));
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "build SoftbusBroadcastData failed, bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    SoftbusBroadcastParam adapterParam;
    ConvertBcParams(param, &adapterParam);
    DISC_LOGI(DISC_BROADCAST, "start service srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "callCount=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId,
        g_bcManager[bcId].adapterBcId, callCount++);
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->StartBroadcasting(g_bcManager[bcId].adapterBcId, &adapterParam, &softbusBcData);
    g_bcManager[bcId].time = MgrGetSysTime();
    g_bcManager[bcId].minInterval = adapterParam.minInterval;
    g_bcManager[bcId].maxInterval = adapterParam.maxInterval;
    int32_t advHandle = 0;
    (void)BroadcastGetBroadcastHandle(bcId, &advHandle);
    g_bcManager[bcId].advHandle = advHandle;
    if (g_bcCurrentNum >= MAX_BLE_ADV_NUM) {
        g_bcOverMaxNum++;
    }
    if (ret != SOFTBUS_OK) {
        callback.OnStartBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        ReportCurrentBroadcast(false);
        ReleaseSoftbusBroadcastData(&softbusBcData);
        return ret;
    }

    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "lock failed");
    g_bcManager[bcId].isStarted = true;
    g_bcManager[bcId].isDisabled = false;
    SoftBusMutexUnlock(&g_bcLock);
    ReleaseSoftbusBroadcastData(&softbusBcData);
    return SOFTBUS_OK;
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    DISC_LOGI(DISC_BROADCAST, "enter update bc");
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invald param");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invald packet");

    int32_t ret = SetBroadcastingData(bcId, packet);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "set data failed");

    ret = SetBroadcastingParam(bcId, param);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "set param failed");

    return SOFTBUS_OK;
}

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter set bc data, bcId=%{public}d, callCount=%{public}u", bcId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param packet");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetBroadcastingData != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId) || g_bcManager[bcId].bcCallback == NULL ||
        g_bcManager[bcId].bcCallback->OnSetBroadcastingCallback == NULL) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }
    DISC_LOGI(DISC_BROADCAST, "replace BroadcastPacket srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "callCount=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId,
        callCount++);
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "build SoftbusBroadcastData failed");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->SetBroadcastingData(g_bcManager[bcId].adapterBcId, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        callback.OnSetBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        ReleaseSoftbusBroadcastData(&softbusBcData);
        return ret;
    }

    ReleaseSoftbusBroadcastData(&softbusBcData);
    return SOFTBUS_OK;
}

int32_t DisableBroadcasting(int32_t bcId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DisableBroadcasting != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    if (!g_bcManager[bcId].isAdvertising || g_bcManager[bcId].isDisabled) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is already disabled", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }

    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->DisableBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t EnableBroadcasting(int32_t bcId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->EnableBroadcasting != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    if (!g_bcManager[bcId].isAdvertising && !g_bcManager[bcId].isDisabled) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is already enabled", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }

    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->EnableBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t PerformSetBroadcastingParam(int32_t bcId, SoftbusBroadcastParam *softbusBcParam)
{
    int32_t ret = DisableBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed during disabling");

    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "lock failed");
    DISC_LOGW(DISC_BROADCAST, "wait pausecondition managerId=%{public}d", bcId);
    ret = DisableBroadcastingWaitSignal(bcId, &g_bcLock);
    SoftBusMutexUnlock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "wait pausecondition fail managerId=%{public}d", bcId);

    if (g_bcManager[bcId].isDisabled) {
        ret = g_interface[g_interfaceId]->SetBroadcastingParam(g_bcManager[bcId].adapterBcId, softbusBcParam);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed during setting param");
            return ret;
        }
    }

    ret = EnableBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed during enabling");

    return SOFTBUS_OK;
}

int32_t SetBroadcastingParam(int32_t bcId, const BroadcastParam *param)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter set bc Param, bcId=%{public}d, callCount=%{public}u", bcId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetBroadcastingParam != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }
    DISC_LOGI(DISC_BROADCAST, "replace BroadcastParam srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "callCount=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId,
        callCount++);
    SoftbusBroadcastParam softbusBcParam = {};
    ConvertBcParams(param, &softbusBcParam);
    SoftBusMutexUnlock(&g_bcLock);

    return PerformSetBroadcastingParam(bcId, &softbusBcParam);
}

int32_t StopBroadcasting(int32_t bcId)
{
    int32_t ret = CheckInterface(false);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        DISC_BROADCAST, "interface check failed, bcId=%{public}d", bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckBcIdIsValid(bcId), SOFTBUS_BC_MGR_INVALID_BC_ID,
        DISC_BROADCAST, "bad bcId, bcId=%{public}d", bcId);

    int64_t time = MgrGetSysTime();
    if (time - g_bcManager[bcId].time < BC_WAIT_TIME_MICROSEC) {
        int64_t diffTime = g_bcManager[bcId].time + BC_WAIT_TIME_MICROSEC - time;
        DISC_LOGW(DISC_BROADCAST, "wait %{public}d us", (int32_t)diffTime);
        usleep(diffTime);
    }

    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_BROADCAST, "mutex error, bcId=%{public}d", bcId);

    if (!g_bcManager[bcId].isStarted) {
        DISC_LOGW(DISC_BROADCAST, "bcId is not start, bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_OK;
    }
    if (g_bcManager[bcId].bcCallback == NULL || g_bcManager[bcId].bcCallback->OnStopBroadcastingCallback == NULL) {
        DISC_LOGE(DISC_BROADCAST, "bc callback is null, bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }

    DISC_LOGI(DISC_BROADCAST, "stop srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d",
        GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        callback.OnStopBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BROADCAST, "lock failed");
    g_bcManager[bcId].isStarted = false;
    SoftBusMutexUnlock(&g_bcLock);
    callback.OnStopBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static int32_t GetScanFreq(uint16_t scanInterval, uint16_t scanWindow)
{
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P2 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P2) {
        return SCAN_FREQ_P2_60_3000;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P2_FAST && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P2_FAST) {
        return SCAN_FREQ_P2_30_1500;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P10 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P10) {
        return SCAN_FREQ_P10_30_300;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P25 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P25) {
        return SCAN_FREQ_P25_60_240;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P50 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P50) {
        return SCAN_FREQ_P50_30_60;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P75 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P75) {
        return SCAN_FREQ_P75_30_40;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100) {
        return SCAN_FREQ_P100_1000_1000;
    }
    return SCAN_FREQ_LOW_POWER;
}

static int32_t PerformNormalStartScan(int32_t listenerId, SoftBusBcScanParams *adapterParam, uint32_t *callCount)
{
    int32_t ret = 0;
    int32_t filterSize = 0;
    SoftBusBcScanFilter *adapterFilter = NULL;

    ret = GetBcScanFilters(listenerId, &adapterFilter, &filterSize);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK && filterSize > 0, SOFTBUS_BC_MGR_START_SCAN_NO_FILTER,
        DISC_BROADCAST, "no filter");
    DumpBcScanFilter(adapterFilter, filterSize);

    DISC_LOGI(DISC_BROADCAST, "start service srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d, "
        "interval=%{public}hu, window=%{public}hu, callCount=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId,
        g_scanManager[listenerId].adapterScanId, adapterParam->scanInterval,
        adapterParam->scanWindow, (*callCount)++);
    ret = g_interface[g_interfaceId]->StartScan(g_scanManager[listenerId].adapterScanId, adapterParam,
        adapterFilter, filterSize);
    g_scanManager[listenerId].isFliterChanged = false;
    ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
    if (ret != SOFTBUS_OK) {
        g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t CheckNotScaning(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    SoftBusBcScanFilter *adapterFilter = NULL;
    int32_t filterSize = 0;
    int32_t ret = 0;
    if (g_scanManager[listenerId].addSize > 0) {
        GetAddFiltersByIndex(listenerId, &adapterFilter);
        ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId,
            adapterParam, adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_ADD);
        ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
        adapterFilter = NULL;
    }
    if (g_scanManager[listenerId].deleteSize > 0) {
        DeleteFilterByIndex(listenerId, &adapterFilter, adapterParam, filterSize);
        ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
        adapterFilter = NULL;
    }
    return ret;
}

static int32_t CheckChannelScan(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    SoftBusBcScanFilter *adapterFilter = NULL;
    int32_t filterSize = 0;
    int32_t ret = 0;
    if (g_scanManager[listenerId].isFliterChanged) {
        if (g_scanManager[listenerId].isScanning) {
            DISC_LOGI(DISC_BROADCAST, "listenerId=%{public}d, srvType=%{public}s, ", listenerId,
                GetSrvType(g_scanManager[listenerId].srvType));
            if (g_scanManager[listenerId].addSize == 0 && g_scanManager[listenerId].deleteSize == 0) {
                DISC_LOGI(DISC_BROADCAST, "same filter and scanning, just change params. srvType=%{public}s,"
                    "listenerId=%{public}d, adapterId=%{public}d, interval=%{public}hu, window=%{public}hu",
                    GetSrvType(g_scanManager[listenerId].srvType), listenerId,
                    g_scanManager[listenerId].adapterScanId, adapterParam->scanInterval,
                    adapterParam->scanWindow);
                ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
                    NULL, 0, SOFTBUS_SCAN_FILTER_CMD_NONE);
                DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_INVALID_PARAM,
                    DISC_BROADCAST, "call from adapter failed");
                return ret;
            }
            if (g_scanManager[listenerId].addSize == g_scanManager[listenerId].deleteSize) {
                DISC_LOGI(DISC_BROADCAST, "modify filter");
                GetModifyFiltersByIndex(listenerId, &adapterFilter);
                ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
                    adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_MODIFY);
                ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
                adapterFilter = NULL;
            } else {
                ret = CheckNotScaning(listenerId, adapterParam);
            }
            if (ret != SOFTBUS_OK) {
                DISC_LOGE(DISC_BROADCAST, "call from adapter failed, ret=%{public}d", ret);
                return ret;
            }
            DISC_LOGI(DISC_BROADCAST, "modify service srvType=%{public}s, listenerId=%{public}d,"
                "adapterId=%{public}d, interval=%{public}hu, window=%{public}hu",
                GetSrvType(g_scanManager[listenerId].srvType), listenerId,
                g_scanManager[listenerId].adapterScanId, adapterParam->scanInterval,
                adapterParam->scanWindow);
        } else {
            DISC_LOGI(DISC_BROADCAST, "channel is scanning, add filter");
            ret = GetScanFiltersForOneListener(listenerId, &adapterFilter, &filterSize);
            DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "get bc scan filters failed");
            ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
                adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_ADD);
            ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
            if (ret != SOFTBUS_OK) {
                DISC_LOGE(DISC_BROADCAST, "call from adapter failed, ret=%{public}d", ret);
                return ret;
            }
        }
        return ret;
    }
    ret = g_interface[g_interfaceId]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
        NULL, 0, SOFTBUS_SCAN_FILTER_CMD_NONE);
    return ret;
}

static int32_t StartScanSub(int32_t listenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].filterSize != 0, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "filter size is 0, need to set filter");
    static uint32_t callCount = 0;
    SoftBusBcScanParams adapterParam;
    BuildSoftBusBcScanParams(&g_scanManager[listenerId].param, &adapterParam);
    CheckScanFreq(listenerId, &adapterParam);
    
    bool isChannelScanning = false;
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;

    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (g_scanManager[managerId].adapterScanId != adapterScanId) {
            continue;
        }
        if (g_scanManager[managerId].isScanning) {
            isChannelScanning = true;
            break;
        }
    }
    if (!isChannelScanning) {
        goto NORMAL_START_SCAN;
    }

    return CheckChannelScan(listenerId, &adapterParam);

NORMAL_START_SCAN:
    DISC_LOGI(DISC_BROADCAST, "not scanning just start scan. listenerId=%{public}d", listenerId);
    // channel have stop. normal run scan
    return PerformNormalStartScan(listenerId, &adapterParam, &callCount);
}

static int32_t GetFilterIndex(uint8_t *index)
{
    for (int i = 1; i <= MAX_FILTER_SIZE; i++) {
        if (!g_firstSetIndex[i]) {
            g_firstSetIndex[i] = true;
            *index = i;
            return SOFTBUS_OK;
        }
    }
    DISC_LOGI(DISC_BROADCAST, "no index available");
    return SOFTBUS_INVALID_PARAM;
}

int32_t StartScan(int32_t listenerId, const BcScanParams *param)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter start scan, listenerId=%{public}d, callCount=%{public}u", listenerId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartScan != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId, listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    g_scanManager[listenerId].param = *param;
    g_scanManager[listenerId].freq = GetScanFreq(param->scanInterval, param->scanWindow);

    if (!g_scanManager[listenerId].isScanning) {
        for (int i = 0; i < g_scanManager[listenerId].filterSize; i++) {
            if (g_scanManager[listenerId].filter[i].filterIndex != 0) {
                continue;
            }
            ret = GetFilterIndex(&g_scanManager[listenerId].filter[i].filterIndex);
            if (ret != SOFTBUS_OK) {
                DISC_LOGE(DISC_BROADCAST, "no available index");
                SoftBusMutexUnlock(&g_scanLock);
                return ret;
            }
            DISC_LOGI(DISC_BROADCAST, "add filter filterIndex = %{public}d",
                g_scanManager[listenerId].filter[i].filterIndex);
        }
    }

    ret = StartScanSub(listenerId);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    ReleaseScanIdx(listenerId);
    g_scanManager[listenerId].isScanning = true;
    g_scanManager[listenerId].isFliterChanged = false;
    g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t StopScan(int32_t listenerId)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter stop scan, listenerId=%{public}d, callCount=%{public}u", listenerId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopScan != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId, listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }
    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d, callCount=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId, callCount);
    if (!g_scanManager[listenerId].isScanning) {
        DISC_LOGI(DISC_BROADCAST, "listenerId is not scanning. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_OK;
    }

    ret = CheckAndStopScan(listenerId);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    for (int i = 0; i < g_scanManager[listenerId].filterSize; ++i) {
        g_firstSetIndex[g_scanManager[listenerId].filter[i].filterIndex] = false;
        g_scanManager[listenerId].filter[i].filterIndex = 0;
    }
    ReleaseScanIdx(listenerId);
    g_scanManager[listenerId].isFliterChanged = true;
    g_scanManager[listenerId].isScanning = false;
    g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

bool CompareSameFilter(BcScanFilter *srcFilter, BcScanFilter *dstFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcFilter != NULL, false, DISC_BROADCAST, "left filter is null");
    DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter != NULL, false, DISC_BROADCAST, "right filter is null");

    return srcFilter->advIndReport == dstFilter->advIndReport &&
        srcFilter->serviceUuid == dstFilter->serviceUuid &&
        srcFilter->serviceDataLength == dstFilter->serviceDataLength &&
        srcFilter->manufactureId == dstFilter->manufactureId &&
        srcFilter->manufactureDataLength == dstFilter->manufactureDataLength &&
        ((srcFilter->serviceData != NULL && dstFilter->serviceData != NULL &&
        srcFilter->serviceDataMask != NULL && dstFilter->serviceDataMask != NULL &&
        memcmp(srcFilter->serviceData, dstFilter->serviceData, srcFilter->serviceDataLength) == 0 &&
        memcmp(srcFilter->serviceDataMask, dstFilter->serviceDataMask, srcFilter->serviceDataLength) == 0) ||
        (srcFilter->serviceData == NULL && dstFilter->serviceData == NULL &&
        srcFilter->serviceDataMask == NULL && dstFilter->serviceDataMask == NULL)) &&
        ((srcFilter->manufactureData != NULL && dstFilter->manufactureData != NULL &&
        srcFilter->manufactureDataMask != NULL && dstFilter->manufactureDataMask != NULL &&
        memcmp(srcFilter->manufactureData, dstFilter->manufactureData, srcFilter->manufactureDataLength) == 0 &&
        memcmp(srcFilter->manufactureDataMask, dstFilter->manufactureDataMask,
            srcFilter->manufactureDataLength) == 0) ||
        (srcFilter->manufactureData == NULL && dstFilter->manufactureData == NULL &&
        srcFilter->manufactureDataMask == NULL && dstFilter->manufactureDataMask == NULL));
}

static int32_t CompareFilterAndGetIndex(int32_t listenerId, BcScanFilter *filter, uint8_t filterNum)
{
    ReleaseScanIdx(listenerId);

    g_scanManager[listenerId].added = (uint8_t *)SoftBusCalloc(filterNum * sizeof(uint8_t));
    g_scanManager[listenerId].addSize = 0;
    g_scanManager[listenerId].deleted = (uint8_t *)SoftBusCalloc(g_scanManager[listenerId].filterSize *
        sizeof(uint8_t));
    g_scanManager[listenerId].deleteSize = 0;

    for (int i = 0; i < g_scanManager[listenerId].filterSize; i++) {
        bool isSameFilter = false;
        for (int j = 0; j < filterNum; j++) {
            if (CompareSameFilter(&g_scanManager[listenerId].filter[i], &filter[j])) {
                filter[j].filterIndex = g_scanManager[listenerId].filter[i].filterIndex;
                DISC_LOGI(DISC_BROADCAST, "same filter, equal index=%{public}d",
                    g_scanManager[listenerId].filter[i].filterIndex);
                isSameFilter = true;
                break;
            }
        }
        if (!isSameFilter) {
            g_scanManager[listenerId].deleted[g_scanManager[listenerId].deleteSize++] =
                g_scanManager[listenerId].filter[i].filterIndex;
            DISC_LOGI(DISC_BROADCAST, "old filter del index, filterIndex=%{public}d",
                g_scanManager[listenerId].filter[i].filterIndex);
        }
    }

    for (int i = 0; i < filterNum; i++) {
        if (filter[i].filterIndex == 0) {
            if (GetFilterIndex(&filter[i].filterIndex) == SOFTBUS_OK) {
                g_scanManager[listenerId].added[g_scanManager[listenerId].addSize++] = i;
                DISC_LOGI(DISC_BROADCAST, "new filter add index, filterIndex=%{public}d", filter[i].filterIndex);
            } else {
                DISC_LOGI(DISC_BROADCAST, "filter add index failed");
                return SOFTBUS_INVALID_PARAM;
            }
        }
    }
    return SOFTBUS_OK;
}

int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    DISC_LOGI(DISC_BROADCAST, "enter set scan filter, filterNum=%{public}d", filterNum);
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "param is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterNum != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filterNum is 0");
    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    BcScanFilter *filter = (BcScanFilter *)scanFilter;
    if (g_scanManager[listenerId].isScanning) {
        ret = CompareFilterAndGetIndex(listenerId, filter, filterNum);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "set scan filter failed");
            SoftBusMutexUnlock(&g_scanLock);
            return SOFTBUS_INVALID_PARAM;
        }
    } else {
        if (g_scanManager[listenerId].filterSize != 0) {
            for (int i = 0; i < g_scanManager[listenerId].filterSize; i++) {
                DISC_LOGI(DISC_BROADCAST, "not scanning, just release index, filterIndex=%{public}d",
                    g_scanManager[listenerId].filter[i].filterIndex);
                g_firstSetIndex[g_scanManager[listenerId].filter[i].filterIndex] = false;
            }
        }

        if (filterNum > 0) {
            for (int i = 0; i < filterNum; i++) {
                GetFilterIndex(&filter[i].filterIndex);
                DISC_LOGI(DISC_BROADCAST, "add filter index, filterIndex=%{public}d",
                    filter[i].filterIndex);
            }
        }
    }

    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].filter = (BcScanFilter *)scanFilter;
    g_scanManager[listenerId].filterSize = filterNum;
    // Need to reset scanner when filter changed.
    g_scanManager[listenerId].isFliterChanged = true;
    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d",
              GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId);
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t GetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum)
{
    DISC_LOGD(DISC_BROADCAST, "enter get scan filter");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid scanFilter");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterNum != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid filterNum");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    *scanFilter = g_scanManager[listenerId].filter;
    *filterNum = g_scanManager[listenerId].filterSize;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t QueryBroadcastStatus(int32_t bcId, int32_t *status)
{
    DISC_LOGI(DISC_BROADCAST, "enter query bc status");
    (void)bcId;
    (void)status;
    return SOFTBUS_OK;
}

bool BroadcastIsLpDeviceAvailable(void)
{
    DISC_LOGI(DISC_BROADCAST, "enter lp available");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), false, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->IsLpDeviceAvailable != NULL,
        false, DISC_BROADCAST, "function is nullptr");

    return g_interface[g_interfaceId]->IsLpDeviceAvailable();
}

bool BroadcastSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter set adv dev param");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcParam != NULL, false, DISC_BROADCAST, "invalid param bcParam");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanParam != NULL, false, DISC_BROADCAST, "invalid param scanParam");
    DISC_CHECK_AND_RETURN_RET_LOGE(type < SOFTBUS_UNKNOW_TYPE && type >= SOFTBUS_HEARTBEAT_TYPE,
        false, DISC_BROADCAST, "invalid app type");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), false, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetAdvFilterParam != NULL,
        false, DISC_BROADCAST, "function is nullptr");

    SoftBusLpBroadcastParam bcDstParam = {0};
    SoftBusLpScanParam scanDstParam = {0};

    bcDstParam.advHandle = bcParam->bcHandle;
    ConvertBcParams(&bcParam->bcParam, &bcDstParam.advParam);

    int32_t ret = BuildSoftbusBroadcastData(&bcParam->packet, &bcDstParam.advData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, DISC_BROADCAST, "build SoftbusBroadcastData failed");

    BuildSoftBusBcScanParams(&scanParam->scanParam, &scanDstParam.scanParam);
    BcScanFilter *scanFilter = NULL;
    uint8_t filterNum = 0;
    ret = GetScanFilter(scanParam->listenerId, &scanFilter, &filterNum);
    if (ret != SOFTBUS_OK || scanFilter == NULL || filterNum == 0) {
        DISC_LOGE(DISC_BROADCAST, "get listenerId filters failed, listenerId=%{public}d", scanParam->listenerId);
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    scanDstParam.filter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * (filterNum));
    if (scanDstParam.filter == NULL) {
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    scanDstParam.filterSize = filterNum;
    ret = CovertSoftBusBcScanFilters(scanFilter, filterNum, scanDstParam.filter);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "convert bc scan filters failed");
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        ReleaseSoftBusBcScanFilter(scanDstParam.filter, filterNum);
        return false;
    }
    DISC_LOGI(DISC_BROADCAST, "set adv dev param, bcId=%{public}d, listenerId=%{public}d",
        bcParam->bcHandle, scanParam->listenerId);
    ret = g_interface[g_interfaceId]->SetAdvFilterParam(type, &bcDstParam, &scanDstParam);
    ReleaseSoftbusBroadcastData(&bcDstParam.advData);
    ReleaseSoftBusBcScanFilter(scanDstParam.filter, filterNum);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret, false, DISC_BROADCAST, "call from adapter failed");
    return true;
}

int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    DISC_LOGD(DISC_BROADCAST, "enter get bc handle");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->GetBroadcastHandle != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckBcIdIsValid(bcId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bcId is invalid");

    int32_t ret = g_interface[g_interfaceId]->GetBroadcastHandle(g_bcManager[bcId].adapterBcId, bcHandle);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t BroadcastEnableSyncDataToLpDevice(void)
{
    DISC_LOGI(DISC_BROADCAST, "enter enable sync");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->EnableSyncDataToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[g_interfaceId]->EnableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    return SOFTBUS_OK;
}

int32_t BroadcastDisableSyncDataToLpDevice(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DisableSyncDataToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[g_interfaceId]->DisableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    return SOFTBUS_OK;
}

int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetScanReportChannelToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    ret = g_interface[g_interfaceId]->SetScanReportChannelToLpDevice(g_scanManager[listenerId].adapterScanId, enable);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t BroadcastSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle)
{
    DISC_LOGI(DISC_BROADCAST, "enter set lp adv param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetLpDeviceParam != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[g_interfaceId]->SetLpDeviceParam(duration, maxExtAdvEvents, window, interval, bcHandle);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    return SOFTBUS_OK;
}

static int32_t RegisterInfoDump(int fd)
{
    SOFTBUS_DPRINTF(fd, "\n---------------------------Register Broadcaster Info-------------------------\n");
    SOFTBUS_DPRINTF(fd, "max broadcaster num                   : %d\n", BC_NUM_MAX);
    SOFTBUS_DPRINTF(fd, "isAdvertising : 0 - false, 1 - true\n\n");
    int32_t managerId;
    for (managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (!g_bcManager[managerId].isUsed) {
            continue;
        }
        BroadcastManager *bcManager = &g_bcManager[managerId];
        SOFTBUS_DPRINTF(fd, "managerId : %d, ", managerId);
        SOFTBUS_DPRINTF(fd, "adapterBcId : %d, ", bcManager->adapterBcId);
        SOFTBUS_DPRINTF(fd, "isAdvertising : %d, ", bcManager->isAdvertising);
        SOFTBUS_DPRINTF(fd, "serviceType : %s\n", GetSrvType(bcManager->srvType));
    }

    SOFTBUS_DPRINTF(fd, "\n---------------------------Register Listener Info----------------------------\n");
    SOFTBUS_DPRINTF(fd, "max listener num                      : %d\n", SCAN_NUM_MAX);
    SOFTBUS_DPRINTF(fd, "freq : 0 - low power, 1 - 60/3000, 2 - 30/1500, 3 - 30/300, 4 - 60/240, 5 - 30/60, "
        "6 - 30/40, 7 - 1000/1000\n");
    SOFTBUS_DPRINTF(fd, "isFliterChanged/isScanning : 0 - false, 1 - true\n\n");
    for (managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            continue;
        }
        ScanManager *scanManager = &g_scanManager[managerId];
        SOFTBUS_DPRINTF(fd, "managerId : %d, ", managerId);
        SOFTBUS_DPRINTF(fd, "adapterScanId : %d, ", scanManager->adapterScanId);
        SOFTBUS_DPRINTF(fd, "isFliterChanged : %d, ", scanManager->isFliterChanged);
        SOFTBUS_DPRINTF(fd, "isScanning : %d, ", scanManager->isScanning);
        SOFTBUS_DPRINTF(fd, "scan freq: %d, ", scanManager->freq);
        SOFTBUS_DPRINTF(fd, "serviceType : %s\n", GetSrvType(scanManager->srvType));
    }
    return SOFTBUS_OK;
}
