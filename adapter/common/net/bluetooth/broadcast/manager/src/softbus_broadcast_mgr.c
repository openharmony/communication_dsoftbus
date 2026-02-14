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
#include "g_enhance_adapter_func.h"
#include "g_enhance_adapter_func_pack.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_ble_gatt_public.h"
#include "softbus_broadcast_manager.h"
#include "softbus_broadcast_mgr_utils.h"
#include "softbus_broadcast_utils.h"
#include "softbus_error_code.h"
#include "softbus_event.h"
#include "legacy/softbus_hidumper_bc_mgr.h"
#include "softbus_utils.h"
#include "softbus_conn_async_helper.h"


#define BC_WAIT_TIME_MS                  50
#define BC_WAIT_TIME_SEC                 1
#define WAIT_ADV_HANDLE_TIME_SEC         3

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
    bool isDisableCb;
    BaseServiceType srvType;
    int32_t adapterBcId;
    int32_t advHandle;
    int32_t minInterval;
    int32_t maxInterval;
    SoftBusCond cond;
    SoftBusCond enableCond;
    SoftBusCond disableCond;
    SoftBusCond setParamCond;
    BroadcastCallback *bcCallback;
    int64_t time;
    BroadcastProtocol protocol;
} BroadcastManager;

typedef enum {
    SCAN_FREQ_LOW_POWER,
    SCAN_FREQ_P2_60_3000,
    SCAN_FREQ_P2_30_1500,
    SCAN_FREQ_P10_30_300,
    SCAN_FREQ_P25_60_240,
    SCAN_FREQ_P50_30_60,
    SCAN_FREQ_P50_60_120,
    SCAN_FREQ_P75_30_40,
    SCAN_FREQ_P100_1000_1000,
    SCAN_FREQ_P10_400_40_LONG_RANGE,
    SCAN_FREQ_P100_30_30_LONG_RANGE,
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
    BroadcastProtocol protocol;
} ScanManager;

typedef struct {
    int32_t adapterBcId;
    BaseServiceType srvType;
    BroadcastProtocol protocol;
} BroadcastOptions;

static volatile bool g_mgrInit = false;
static volatile bool g_mgrLockInit = false;
static SoftBusMutex g_bcLock = { 0 };
static SoftBusMutex g_scanLock = { 0 };
static int32_t g_btStateListenerId = -1;
static int32_t g_sleStateListenerId = -1;

static int32_t g_bcMaxNum = 0;
static int32_t g_bcCurrentNum = 0;
static int32_t g_bcOverMaxNum = 0;
static DiscEventBcManagerExtra g_bcManagerExtra[BC_NUM_MAX] = { 0 };
static BroadcastManager g_bcManager[BC_NUM_MAX] = { 0 };
static ScanManager g_scanManager[SCAN_NUM_MAX] = { 0 };
static bool g_firstSetIndex[MAX_FILTER_SIZE + 1] = {false};

static AdapterScannerControl g_AdapterStatusControl[GATT_SCAN_MAX_NUM] = {
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
    { .adapterScannerId = -1, .isAdapterScanCbReg = false},
};

static SoftbusBroadcastMediumInterface *g_interface[MEDIUM_NUM_MAX];

static inline bool CheckProtocolIsValid(BroadcastProtocol interfaceId)
{
    return interfaceId >= 0 && interfaceId < BROADCAST_PROTOCOL_BUTT;
}

int32_t RegisterBroadcastMediumFunction(BroadcastProtocol type, const SoftbusBroadcastMediumInterface *interface)
{
    DISC_LOGI(DISC_BROADCAST, "register type=%{public}d", type);
    DISC_CHECK_AND_RETURN_RET_LOGE(type >= 0 && type < BROADCAST_PROTOCOL_BUTT, SOFTBUS_INVALID_PARAM,
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

static void HandleOnStateOff(int32_t timer, void *arg)
{
    BroadcastProtocol protocol = *(BroadcastProtocol *)arg;
    SoftBusFree(arg);
    DISC_CHECK_AND_RETURN_LOGE(CheckProtocolIsValid(protocol), DISC_BROADCAST, "type is invalid");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (!bcManager->isUsed || bcManager->adapterBcId == -1 || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL || protocol != bcManager->protocol) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        SoftBusMutexUnlock(&g_bcLock);
        (void)g_interface[protocol]->StopBroadcasting(bcManager->adapterBcId);
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");
        if (protocol == BROADCAST_PROTOCOL_BLE && bcManager->isAdvertising) {
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
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnStopScanCallback == NULL ||
            protocol != scanManager->protocol) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        (void)g_interface[protocol]->StopScan(scanManager->adapterScanId);
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

static void BcBtStateChanged(int32_t listenerId, int32_t state)
{
    (void)listenerId;
    if (state != SOFTBUS_BC_BT_STATE_TURN_OFF) {
        return;
    }
    DISC_LOGI(DISC_BROADCAST, "receive bt turn off event, start reset broadcast mgr state..");
    BroadcastProtocol *protocol = SoftBusCalloc(sizeof(BroadcastProtocol));
    DISC_CHECK_AND_RETURN_LOGE(protocol != NULL, DISC_BROADCAST, "malloc protocol failed");
    *protocol = BROADCAST_PROTOCOL_BLE;
    HandleOnStateOff(0, protocol);
}

static void SleStateChanged(int32_t state)
{
    if (state != SOFTBUS_SLE_STATE_TURN_OFF) {
        return;
    }
    DISC_LOGI(DISC_BROADCAST, "receive sle turn off event, start reset broadcast mgr state..");

    BroadcastProtocol *protocol = SoftBusCalloc(sizeof(BroadcastProtocol));
    DISC_CHECK_AND_RETURN_LOGE(protocol != NULL, DISC_BROADCAST, "malloc protocol failed");
    *protocol = BROADCAST_PROTOCOL_SLE;
    ConnAsync *sync = ConnAsyncGetInstance();
    DISC_CHECK_AND_RETURN_LOGE(sync != NULL, DISC_BROADCAST, "get sync failed");
    int32_t ret = ConnAsyncCall(sync, HandleOnStateOff, (void *)protocol, 0);
    if (ret < 0) {
        SoftBusFree(protocol);
        DISC_LOGE(DISC_BROADCAST, "post state change to looper failed, err=%{public}d", ret);
        return;
    }
}

static SoftBusBtStateListener g_softbusBcBtStateLister = {
    .OnBtStateChanged = BcBtStateChanged,
    .OnBtAclStateChanged = NULL,
};

static SoftBusSleStateListener g_softbusSleStateListener = {
    .onSleStateChanged = SleStateChanged,
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
    (void)para;
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

void SoftbusBleAdapterInitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (pfnAdapterEnhanceFuncList->softbusBleAdapterInit == NULL) {
        DISC_LOGE(DISC_BROADCAST, "go open source func");
        return SoftbusBleAdapterInit();
    }
    return pfnAdapterEnhanceFuncList->softbusBleAdapterInit();
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

    SoftbusBleAdapterInitPacked();
    SoftbusSleAdapterInitPacked();
    for (BroadcastProtocol i = 0; i < BROADCAST_PROTOCOL_BUTT; ++i) {
        if (g_interface[i] != NULL && g_interface[i]->Init != NULL) {
            ret = g_interface[i]->Init();
            DISC_LOGI(DISC_BROADCAST, "init protocol=%{public}d, ret=%{public}d", i, ret);
        } else {
            DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not register", i);
        }
    }

    ret = SoftBusAddBtStateListener(&g_softbusBcBtStateLister, &g_btStateListenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "add bt state listener failed");

    ret = SoftBusAddSleStateListenerPacked(&g_softbusSleStateListener, &g_sleStateListenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "add sle state listener failed");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(lock != NULL, false, DISC_BROADCAST, "lock is nullptr");

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

void SoftbusBleAdapterDeInitPacked(void)
{
    AdapterEnhanceFuncList *pfnAdapterEnhanceFuncList = AdapterEnhanceFuncListGet();
    if (pfnAdapterEnhanceFuncList->softbusBleAdapterDeInit == NULL) {
        DISC_LOGE(DISC_BROADCAST, "go open source func");
        return SoftbusBleAdapterDeInit();
    }
    return pfnAdapterEnhanceFuncList->softbusBleAdapterDeInit();
}

int32_t DeInitBroadcastMgr(void)
{
    DISC_LOGI(DISC_BROADCAST, "deinit enter");

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

    if (g_sleStateListenerId != -1) {
        SoftBusRemoveSleStateListenerPacked(g_sleStateListenerId);
        g_sleStateListenerId = -1;
    }

    for (BroadcastProtocol i = 0; i < BROADCAST_PROTOCOL_BUTT; ++i) {
        if (g_interface[i] != NULL && g_interface[i]->DeInit != NULL) {
            ret = g_interface[i]->DeInit();
            DISC_LOGI(DISC_BROADCAST, "deInit protocol=%{public}d, ret=%{public}d", i, ret);
            g_interface[i] = NULL;
        } else {
            DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not register", i);
        }
    }
    SoftbusBleAdapterDeInit();
    SoftbusSleAdapterDeInitPacked();
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
            extra.startTime = (uint64_t)g_bcManager[managerId].time;
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
            g_bcManagerExtra[managerId].startTime = (uint64_t)g_bcManager[managerId].time;
            g_bcManagerExtra[managerId].advHandle = g_bcManager[managerId].advHandle;
            g_bcManagerExtra[managerId].serverType = GetSrvType(g_bcManager[managerId].srvType);
            g_bcManagerExtra[managerId].minInterval = g_bcManager[managerId].minInterval;
            g_bcManagerExtra[managerId].maxInterval = g_bcManager[managerId].maxInterval;
        }
    }
}

static void BcStartBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    static uint32_t callCount = 0;
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK,
            DISC_BROADCAST, "mutex error, adapterBcId=%{public}d", adapterBcId);

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId) {
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
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, bcId=%{public}d, status=%{public}d,"
            "c=%{public}u", GetSrvType(bcManager->srvType), managerId, adapterBcId, status, callCount++);
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

static void BcStopBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK,
            DISC_BROADCAST, "mutex error, adapterBcId=%{public}d", adapterBcId);

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId) {
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
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            if (bcManager->isAdvertising) {
                g_bcCurrentNum--;
            }
            bcManager->isAdvertising = false;
            bcManager->time = 0;
            SoftBusCondSignal(&bcManager->cond);
        } else {
            DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, mId=%{public}u, BcId=%{public}d, sta=%{public}d",
                GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        }
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnStopBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcUpdateBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter update bc cb enter");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId ||
            !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnUpdateBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, BcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnUpdateBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter set bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId || !bcManager->isUsed ||
            bcManager->bcCallback == NULL || bcManager->bcCallback->OnSetBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, BcId=%{public}d, status=%{public}d,"
            "c=%{public}u", GetSrvType(bcManager->srvType), managerId, adapterBcId, status, callCount++);
        BroadcastCallback callback = *(bcManager->bcCallback);
        SoftBusMutexUnlock(&g_bcLock);
        callback.OnSetBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingParamCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter set bc param cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, BcId=%{public}d,"
            "status=%{public}d, c=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            SoftBusCondSignal(&bcManager->setParamCond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcEnableBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter enable bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, BcId=%{public}d,"
            "status=%{public}d, c=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isDisabled = false;
            SoftBusCondSignal(&bcManager->enableCond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcDisableBroadcastingCallback(BroadcastProtocol protocol, int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter disable bc cb");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->protocol != protocol || bcManager->adapterBcId != adapterBcId || !bcManager->isUsed) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        static uint32_t callCount = 0;
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, BcId=%{public}d,"
            "status=%{public}d, c=%{public}u", GetSrvType(bcManager->srvType),
            managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isDisabled = true;
            bcManager->isDisableCb = true;
            SoftBusCondSignal(&bcManager->disableCond);
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

static void BcOnStartScanCallback(BroadcastProtocol protocol, int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter on start scan cb");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->protocol != protocol || scanManager->adapterScanId != adapterScanId || !scanManager->isUsed ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnStartScanCallback == NULL) {
            continue;
        }
        DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, ScanId=%{public}d, "
            "status=%{public}d", GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = true;
        }

        scanManager->scanCallback->OnStartScanCallback((int32_t)managerId, status);
    }
}

static void BcStopScanCallback(BroadcastProtocol protocol, int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BROADCAST, "enter stop scan cb");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->protocol != protocol || scanManager->adapterScanId != adapterScanId || !scanManager->isUsed ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnStopScanCallback == NULL) {
            continue;
        }
        
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = false;
        } else {
            DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}u, ScanId=%{public}d, "
                "status=%{public}d", GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
        }

        scanManager->scanCallback->OnStopScanCallback((int32_t)managerId, status);
    }
}

static int32_t BuildBcInfoCommon(const SoftBusBcScanResult *reportData, BroadcastReportInfo *bcInfo)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(reportData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "reportData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bcInfo is nullptr");

    bcInfo->eventType = reportData->eventType;
    bcInfo->dataStatus = reportData->dataStatus;
    bcInfo->primaryPhy = reportData->primaryPhy;
    bcInfo->secondaryPhy = reportData->secondaryPhy;
    bcInfo->advSid = reportData->advSid;
    bcInfo->txPower = reportData->txPower;
    bcInfo->rssi = reportData->rssi;
    bcInfo->addrType = reportData->addrType;

    errno_t ret = memcpy_s(bcInfo->addr.addr, BC_ADDR_MAC_LEN, reportData->addr.addr, SOFTBUS_ADDR_MAC_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, DISC_BROADCAST, "memcpy addr failed");

    ret = memcpy_s(bcInfo->localName, BC_LOCAL_NAME_LEN_MAX, reportData->localName, SOFTBUS_LOCAL_NAME_LEN_MAX);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, DISC_BROADCAST, "memcpy localName failed");

    ret = memcpy_s(bcInfo->advDevName, sizeof(bcInfo->advDevName),
        reportData->advDevName, sizeof(reportData->advDevName));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, DISC_BROADCAST, "memcpy advName failed");

    return SOFTBUS_OK;
}

static bool CheckManufactureIsMatch(const BcScanFilter *filter, const BroadcastPayload *bcData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(filter != NULL, false, DISC_BROADCAST, "filter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcData != NULL, false, DISC_BROADCAST, "bcData is nullptr");

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
    DISC_CHECK_AND_RETURN_RET_LOGE(filter != NULL, false, DISC_BROADCAST, "filter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcData != NULL, false, DISC_BROADCAST, "bcData is nullptr");

    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter->serviceDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BROADCAST, "payload is too short");
        return false;
    }
    if (filter->serviceId != bcData->id) {
        DISC_LOGD(DISC_BROADCAST, "serviceId not match");
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

static bool CheckServiceUuidIsMatch(const BcScanFilter *filter, const BroadcastPayload *bcData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(filter != NULL, false, DISC_BROADCAST, "filter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcData != NULL, false, DISC_BROADCAST, "bcData is nullptr");

    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter->serviceUuidDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BROADCAST, "payload is too short");
        return false;
    }
    
    if (filter->serviceUuidId != bcData->id) {
        DISC_LOGD(DISC_BROADCAST, "serviceUuid not match");
        return false;
    }

    for (uint32_t i = 0; i < filterLen; i++) {
        if ((filter->serviceUuidData[i] & filter->serviceUuidDataMask[i]) !=
            (bcData->payload[i] & filter->serviceUuidDataMask[i])) {
            return false;
        }
    }
    return true;
}

static bool CheckScanResultDataIsMatch(const uint32_t managerId, BroadcastPayload *bcData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(bcData != NULL, false, DISC_BROADCAST, "bcData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGD(bcData->payload != NULL, false, DISC_BROADCAST, "payload is nullptr");

    if (bcData->type != BC_DATA_TYPE_SERVICE && bcData->type != BC_DATA_TYPE_MANUFACTURER &&
        bcData->type != BC_DATA_TYPE_SERVICE_UUID) {
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
        if (bcData->type == BC_DATA_TYPE_SERVICE_UUID && CheckServiceUuidIsMatch(&filter, bcData)) {
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
    DISC_CHECK_AND_RETURN_LOGE(bcInfo != NULL, DISC_BROADCAST, "bcInfo is nullptr");

    SoftBusFree(bcInfo->packet.bcData.payload);
    SoftBusFree(bcInfo->packet.rspData.payload);
    SoftBusFree(bcInfo->packet.uuidData.payload);
}

static int32_t BuildBcPayload(const SoftbusBroadcastPayload *srcData, BroadcastPayload *dstData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "srcData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "dstData is nullptr");

    if (srcData->payload == NULL) {
        DISC_LOGD(DISC_BROADCAST, "payload is null, skip");
        return SOFTBUS_OK;
    }

    dstData->type = (BroadcastDataType)srcData->type;
    dstData->id = srcData->id;

    dstData->payloadLen = srcData->payloadLen;
    dstData->payload = (uint8_t *)SoftBusCalloc(dstData->payloadLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");

    if (memcpy_s(dstData->payload, dstData->payloadLen, srcData->payload, dstData->payloadLen) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy payload failed");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BuildBroadcastPacket(const SoftbusBroadcastData *softbusBcData, BroadcastPacket *packet)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(softbusBcData != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "softbusBcData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "packet is nullptr");

    packet->isSupportFlag = softbusBcData->isSupportFlag;
    packet->flag = softbusBcData->flag;

    // 2.1. Build broadcast payload.
    int32_t ret = BuildBcPayload(&(softbusBcData->bcData), &(packet->bcData));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_BC_MGR_BUILD_ADV_PACKT_FAIL,
        DISC_BROADCAST, "build broadcast payload failed");

    DumpSoftbusData("scan result bcData", softbusBcData->bcData.payloadLen, softbusBcData->bcData.payload);

    // 2.2. Build broadcast response payload.
    ret = BuildBcPayload(&(softbusBcData->rspData), &(packet->rspData));
    if (ret != SOFTBUS_OK) {
        SoftBusFree(packet->bcData.payload);
        DISC_LOGE(DISC_BROADCAST, "build broadcast rsp payload failed");
        return SOFTBUS_BC_MGR_BUILD_RSP_PACKT_FAIL;
    }
    DumpSoftbusData("scan result rspData", softbusBcData->rspData.payloadLen, softbusBcData->rspData.payload);

    ret = BuildBcPayload(&(softbusBcData->uuidData), &(packet->uuidData));
    if (ret != SOFTBUS_OK) {
        SoftBusFree(packet->bcData.payload);
        SoftBusFree(packet->rspData.payload);
        DISC_LOGE(DISC_BROADCAST, "build broadcast uuid payload failed");
        return SOFTBUS_BC_MGR_BUILD_UUID_PACKT_FAIL;
    }
    DumpSoftbusData("scan result uuidData", softbusBcData->uuidData.payloadLen, softbusBcData->uuidData.payload);
    return SOFTBUS_OK;
}

static int32_t BuildBroadcastReportInfo(const SoftBusBcScanResult *reportData, BroadcastReportInfo *bcInfo)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(reportData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "reportData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bcInfo is nullptr");
    errno_t result = memcpy_s(bcInfo->localName, sizeof(bcInfo->localName),
        reportData->localName, sizeof(reportData->localName));
    DISC_CHECK_AND_RETURN_RET_LOGE(result == EOK, SOFTBUS_MEM_ERR, DISC_BROADCAST,
        "cpy localName failed, ret=%{public}d", result);

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
    DISC_CHECK_AND_RETURN_RET_LOGE(bcData != NULL, false, DISC_BROADCAST, "bcData is nullptr");
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

static void BcReportScanDataCallback(BroadcastProtocol protocol,
    int32_t adapterScanId, const SoftBusBcScanResult *reportData)
{
    DISC_LOGD(DISC_BROADCAST, "enter report scan cb");
    DISC_CHECK_AND_RETURN_LOGE(reportData != NULL, DISC_BROADCAST, "reportData is nullptr");

    BroadcastReportInfo bcInfo;
    memset_s(&bcInfo, sizeof(bcInfo), 0, sizeof(bcInfo));
    int32_t ret = BuildBroadcastReportInfo(reportData, &bcInfo);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "build bc report info failed");
    bool isFindMatchFiter = false;
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (SoftBusMutexLock(&g_scanLock) != 0) {
            ReleaseBroadcastReportInfo(&bcInfo);
            return;
        }
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->protocol != protocol || !scanManager->isUsed || !scanManager->isScanning ||
            scanManager->filter == NULL || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnReportScanDataCallback == NULL ||
            scanManager->adapterScanId != adapterScanId ||
            !(CheckScanResultDataIsMatch(managerId, &(bcInfo.packet.bcData)) ||
            CheckScanResultDataIsMatch(managerId, &(bcInfo.packet.uuidData)) ||
            (scanManager->srvType == SRV_TYPE_APPROACH &&
            CheckScanResultDataIsMatchApproach(managerId, &(bcInfo.packet.rspData))))) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        isFindMatchFiter = true;
        DISC_LOGD(DISC_BROADCAST, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d",
            GetSrvType(scanManager->srvType), managerId, adapterScanId);
        ScanCallback callback = *(scanManager->scanCallback);
        SoftBusMutexUnlock(&g_scanLock);
        callback.OnReportScanDataCallback((int32_t)managerId, &bcInfo);
    }
    if (!isFindMatchFiter) {
        DISC_LOGD(DISC_BROADCAST, "not find matched filter, adapterScanId=%{public}d", adapterScanId);
    }
    ReleaseBroadcastReportInfo(&bcInfo);
}

static void BcScanStateChanged(BroadcastProtocol protocol, int32_t resultCode, bool isStartScan)
{
    DISC_LOGD(DISC_BROADCAST, "enter scan state change");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_scanLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "mutex error");

        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->protocol != protocol || scanManager->isUsed || !scanManager->isScanning ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnScanStateChanged == NULL) {
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
    DISC_CHECK_AND_RETURN_RET_LOGE(uuid != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "uuid is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcUuid != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bcUuid is nullptr");

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

static void BcLpDeviceInfoCallback(BroadcastProtocol protocol,
    const SoftbusBroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    DISC_LOGD(DISC_BROADCAST, "enter lp cb");
    DISC_CHECK_AND_RETURN_LOGE(uuid != NULL, DISC_BROADCAST, "uuid is nullptr");

    BroadcastUuid bcUuid = {0};
    int32_t ret = ConvertBroadcastUuid(uuid, &bcUuid);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BROADCAST, "convert broadcast Uuid failed");

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->protocol != protocol || !scanManager->isUsed || scanManager->scanCallback == NULL ||
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

static int32_t InitializeBroadcaster(int32_t *bcId, BroadcastOptions *options, const BroadcastCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(bcId != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bcId is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "cb is nullptr");

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
    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, bcId=%{public}d, adapterBcId=%{public}d",
        GetSrvType(options->srvType), managerId, options->adapterBcId);

    *bcId = managerId;
    ret = SoftBusCondInit(&g_bcManager[managerId].cond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "cond Init failed");
        return ret;
    }
    ret = SoftBusCondInit(&g_bcManager[managerId].enableCond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "enableCond Init failed");
        return ret;
    }
    ret = SoftBusCondInit(&g_bcManager[managerId].disableCond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "disableCond Init failed");
        return ret;
    }
    ret = SoftBusCondInit(&g_bcManager[managerId].setParamCond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "setParamCond Init failed");
        return ret;
    }
    g_bcManager[managerId].srvType = options->srvType;
    g_bcManager[managerId].adapterBcId = options->adapterBcId;
    g_bcManager[managerId].isUsed = true;
    g_bcManager[managerId].isAdvertising = false;
    g_bcManager[managerId].isDisabled = false;
    g_bcManager[managerId].isDisableCb = false;
    g_bcManager[managerId].time = 0;
    g_bcManager[managerId].bcCallback = (BroadcastCallback *)cb;
    g_bcManager[managerId].protocol = options->protocol;

    return SOFTBUS_OK;
}

int32_t RegisterBroadcaster(BroadcastProtocol protocol,
    BaseServiceType srvType, int32_t *bcId, const BroadcastCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "enter register bc, c=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterBcId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BROADCAST, "bad srvType");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcId != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param bcId");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckProtocolIsValid(protocol), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol]->RegisterBroadcaster != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    ret = g_interface[protocol]->RegisterBroadcaster(&adapterBcId, &g_softbusBcBleCb);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    BroadcastOptions options = {
        .adapterBcId = adapterBcId,
        .srvType = srvType,
        .protocol = protocol,
    };
    ret = InitializeBroadcaster(bcId, &options, cb);
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
    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        DISC_LOGE(DISC_BROADCAST, "bcId is invalid");
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;

    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->UnRegisterBroadcaster == NULL) {
        DISC_LOGE(DISC_BROADCAST, "not found or not register protocol=%{public}d", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_bcManager[bcId].isAdvertising) {
        SoftBusMutexUnlock(&g_bcLock);
        (void)g_interface[protocol]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
        SoftBusMutexLock(&g_bcLock);
    }
    ret = g_interface[protocol]->UnRegisterBroadcaster(g_bcManager[bcId].adapterBcId);
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
    SoftBusCondDestroy(&g_bcManager[bcId].enableCond);
    SoftBusCondDestroy(&g_bcManager[bcId].disableCond);
    SoftBusCondDestroy(&g_bcManager[bcId].setParamCond);
    g_bcManager[bcId].bcCallback = NULL;
    g_bcManager[bcId].protocol = BROADCAST_PROTOCOL_BUTT;

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
    } else if (srvType == SRV_TYPE_HB || srvType == SRV_TYPE_DIS || srvType == SRV_TYPE_OOP ||
        srvType == SRV_TYPE_SD || srvType == SRV_TYPE_COLLABORATION) {
        return CHANEL_UNSTEADY;
    } else if (srvType == SRV_TYPE_D2D_PAGING) {
        return CHANEL_SLE_D2D_PAGING;
    } else if (srvType == SRV_TYPE_D2D_GROUP_TALKIE) {
        return CHANEL_SLE_D2D_TALKIE;
    }
    return CHANEL_UNKNOW;
}

static int32_t RegisterScanListenerForChannel(BroadcastProtocol protocol,
    int32_t channel, int32_t *adapterScanId, const ScanCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterScanId != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterScanId is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "cb is nullptr");

    int32_t ret;
    if (g_AdapterStatusControl[channel].isAdapterScanCbReg) {
        *adapterScanId = g_AdapterStatusControl[channel].adapterScannerId;
        DISC_LOGI(DISC_BROADCAST, "service is already registered channel=%{public}d", channel);
        return SOFTBUS_OK;
    }
    ret = g_interface[protocol]->RegisterScanListener(adapterScanId, &g_softbusBcBleScanCb);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed");
    g_AdapterStatusControl[channel].isAdapterScanCbReg = true;
    g_AdapterStatusControl[channel].adapterScannerId = *adapterScanId;
    DISC_LOGI(DISC_BROADCAST, "channel %{public}d register scan listener", channel);
    return SOFTBUS_OK;
}

static int32_t RegisterScanListenerSub(
    BroadcastProtocol protocol, BaseServiceType srvType, int32_t *adapterScanId, const ScanCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterScanId != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterScanId is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "cb is nullptr");
    int32_t channel = GetSrvTypeIndex(srvType);
    switch (channel) {
        case CHANEL_LP:
        case CHANEL_STEADY:
        case CHANEL_SHARE:
        case CHANEL_UNSTEADY:
        case CHANEL_SLE_D2D_PAGING:
        case CHANEL_SLE_D2D_TALKIE:
            return RegisterScanListenerForChannel(protocol, channel, adapterScanId, cb);
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

int32_t RegisterScanListener(BroadcastProtocol protocol,
    BaseServiceType srvType, int32_t *listenerId, const ScanCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGD(DISC_BROADCAST, "enter c=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterScanId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BROADCAST, "bad srvType");
    DISC_CHECK_AND_RETURN_RET_LOGE(listenerId != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid listenerId");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param cb");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckProtocolIsValid(protocol), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol]->RegisterScanListener != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(!CheckSrvRegistered(srvType), SOFTBUS_BC_MGR_REG_DUP,
        DISC_BROADCAST, "already registered");
    ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    ret = RegisterScanListenerSub(protocol, srvType, &adapterScanId, cb);
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
    g_scanManager[managerId].protocol = protocol;

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
        SoftBusFree((filter + filterSize)->serviceUuidData);
        SoftBusFree((filter + filterSize)->serviceUuidDataMask);
    }
    SoftBusFree(filter);
    g_scanManager[listenerId].filterSize = 0;
    g_scanManager[listenerId].filter = NULL;
}

static bool CheckNeedUnRegisterScanListener(int32_t listenerId)
{
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (managerId != listenerId && g_scanManager[managerId].adapterScanId == adapterScanId &&
            g_scanManager[managerId].isScanning && g_scanManager[managerId].protocol == protocol) {
            return false;
        }
    }
    return true;
}

static bool CheckNeedUpdateScan(int32_t listenerId, int32_t *liveListenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(liveListenerId != NULL, false, DISC_BROADCAST, "liveListenerId is nullptr");

    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (managerId != listenerId && g_scanManager[managerId].adapterScanId == adapterScanId &&
            g_scanManager[managerId].isScanning && g_scanManager[managerId].protocol == protocol) {
            *liveListenerId = managerId;
            return true;
        }
    }
    return false;
}

static int32_t DupData(uint8_t *srcData, uint32_t srcDataLen, uint8_t **outData)
{
    if (srcData != NULL && srcDataLen > 0) {
        uint8_t *dupData = (uint8_t *)SoftBusCalloc(srcDataLen);
        DISC_CHECK_AND_RETURN_RET_LOGE(dupData != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "calloc failed");
        (void)memcpy_s(dupData, srcDataLen, srcData, srcDataLen);
        *outData = dupData;
    }
    
    return SOFTBUS_OK;
}

static int32_t CopyScanFilterServiceInfo(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "srcFilter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "dstFilter is nullptr");

    dstFilter->serviceId = srcFilter->serviceId;
    dstFilter->serviceDataLength = srcFilter->serviceDataLength;
    
    int32_t ret = DupData(srcFilter->serviceData, srcFilter->serviceDataLength, &dstFilter->serviceData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "dup serviceData failed, ret=%{public}d", ret);

    ret = DupData(srcFilter->serviceDataMask, srcFilter->serviceDataLength, &dstFilter->serviceDataMask);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "dup serviceDataMask failed, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t CopyScanFilterServiceUuid(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    dstFilter->serviceUuid = srcFilter->serviceUuid;
    dstFilter->serviceUuidMask = srcFilter->serviceUuidMask;
    dstFilter->serviceUuidLength = srcFilter->serviceUuidLength;

    dstFilter->serviceUuidId = srcFilter->serviceUuidId;
    dstFilter->serviceUuidDataLength = srcFilter->serviceUuidDataLength;
    int32_t ret = DupData(srcFilter->serviceUuidData, srcFilter->serviceUuidDataLength, &dstFilter->serviceUuidData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        DISC_BROADCAST, "dup serviceUuidData failed, ret=%{public}d", ret);

    ret = DupData(srcFilter->serviceUuidDataMask, srcFilter->serviceUuidDataLength, &dstFilter->serviceUuidDataMask);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "dup serviceUuidDataMask failed, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t CopyScanFilterManufacture(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    dstFilter->manufactureId = srcFilter->manufactureId;
    dstFilter->manufactureDataLength = srcFilter->manufactureDataLength;
    
    int32_t ret = DupData(srcFilter->manufactureData, srcFilter->manufactureDataLength, &dstFilter->manufactureData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        DISC_BROADCAST, "dup manufactureData failed,ret=%{public}d", ret);
    
    ret = DupData(srcFilter->manufactureDataMask, srcFilter->manufactureDataLength, &dstFilter->manufactureDataMask);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "dup manufactureDataMask failed, ret=%{public}d", ret);
    return SOFTBUS_OK;
}

static int32_t CopySoftBusBcScanFilter(const BcScanFilter *srcFilter, SoftBusBcScanFilter *dstFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "srcFilter is NULL");
    DISC_CHECK_AND_RETURN_RET_LOGE(dstFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "dstFilter is NULL");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "cpy service data failed=%{public}d", ret);
    ret = CopyScanFilterServiceUuid(srcFilter, dstFilter);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "cpy service uuid failed=%{public}d", ret);

    ret = CopyScanFilterManufacture(srcFilter, dstFilter);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "cpy manufacture failed=%{public}d", ret);
    if (srcFilter->filterIndex == 0) {
        DISC_LOGD(DISC_BROADCAST, "invaild filterIndex");
    }
    dstFilter->filterIndex = srcFilter->filterIndex;
    dstFilter->advIndReport = srcFilter->advIndReport;
    return SOFTBUS_OK;
}

static int32_t CovertSoftBusBcScanFilters(const BcScanFilter *filter, uint8_t size, SoftBusBcScanFilter *adapterFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(filter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");

    while (size-- > 0) {
        int32_t ret = CopySoftBusBcScanFilter(filter + size, adapterFilter + size);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "copy filter failed");
    }
    return SOFTBUS_OK;
}

static void ReleaseSoftBusBcScanFilter(SoftBusBcScanFilter *filter, int32_t size)
{
    DISC_CHECK_AND_RETURN_LOGE(filter != NULL, DISC_BROADCAST, "filter is nullptr");

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
            if ((filter + size)->serviceUuidData != NULL) {
                SoftBusFree((filter + size)->serviceUuidData);
            }
            if ((filter + size)->serviceUuidDataMask != NULL) {
                SoftBusFree((filter + size)->serviceUuidDataMask);
            }
        }
        SoftBusFree(filter);
    }
}

static int32_t CombineSoftbusBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    DISC_LOGD(DISC_BROADCAST, "enter combine scan filters");
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterSize != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filterSize is nullptr");

    uint8_t size = 0;
    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || (!scanManager->isScanning && managerId != listenerId) ||
            scanManager->adapterScanId != g_scanManager[listenerId].adapterScanId ||
            scanManager->protocol != protocol) {
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
            scanManager->adapterScanId != g_scanManager[listenerId].adapterScanId ||
            scanManager->protocol != protocol) {
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
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterSize != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filterSize is nullptr");

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
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterParam != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterParam is nullptr");
    ScanManager *scanManager = &g_scanManager[listenerId];
    DISC_LOGI(DISC_BROADCAST, "enter delete filter by index, listenerId=%{public}d, size=%{public}d",
        listenerId, scanManager->deleteSize);
    int32_t ret;
    uint8_t size = scanManager->deleteSize;
    DISC_CHECK_AND_RETURN_RET_LOGE(size != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "size is 0");
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST,
        "memory allocation failed");
    for (int i = 0; i < size; i++) {
        int filterIndex = scanManager->deleted[i];
        if (filterIndex == 0) {
            DISC_LOGE(DISC_BROADCAST, "invalid index");
            ReleaseSoftBusBcScanFilter(*adapterFilter, size);
            *adapterFilter = NULL;
            return SOFTBUS_INVALID_PARAM;
        }
        (*adapterFilter + i)->filterIndex = filterIndex;
        BroadcastProtocol protocol = scanManager->protocol;
        ret = g_interface[protocol]->SetScanParams(scanManager->adapterScanId, adapterParam,
            *adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_DELETE);
        g_firstSetIndex[filterIndex] = false;
    }

    return ret;
}

static int32_t GetAddFiltersByIndex(int32_t listenerId, SoftBusBcScanFilter **adapterFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_LOGI(DISC_BROADCAST, "enter add filter by index, listenerId=%{public}d, size=%{public}d",
        listenerId, g_scanManager[listenerId].addSize);

    int32_t ret;
    uint8_t size = g_scanManager[listenerId].addSize;
    DISC_CHECK_AND_RETURN_RET_LOGE(size != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "size is 0");
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST,
        "memory allocation failed");
    for (int i = 0; i < size; i++) {
        int addIndex = g_scanManager[listenerId].added[i];
        BcScanFilter *tempFilter = &(g_scanManager[listenerId].filter[addIndex]);
        if (tempFilter->filterIndex == 0) {
            DISC_LOGE(DISC_BROADCAST, "invalid index");
            ReleaseSoftBusBcScanFilter(*adapterFilter, size);
            *adapterFilter = NULL;
            return SOFTBUS_INVALID_PARAM;
        }
        ret = CopySoftBusBcScanFilter(tempFilter, (*adapterFilter) + i);
    }

    return ret;
}

static int32_t GetModifyFiltersByIndex(int32_t listenerId, SoftBusBcScanFilter **adapterFilter)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_LOGI(DISC_BROADCAST, "enter Modify filter by index, listenerId=%{public}d, addSize=%{public}d",
        listenerId, g_scanManager[listenerId].addSize);
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].addSize != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "addSize is 0");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].deleteSize != 0, SOFTBUS_INVALID_PARAM, DISC_BROADCAST,
        "deleteSize is 0");

    int32_t ret;
    uint8_t size = g_scanManager[listenerId].addSize;
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    DISC_CHECK_AND_RETURN_RET_LOGE(*adapterFilter != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST,
        "memory allocation failed");
    for (int i = 0; i < size; i++) {
        uint8_t addIndex = g_scanManager[listenerId].added[i];
        uint8_t deleteIndex = g_scanManager[listenerId].deleted[i];
        int replaceIndex = g_scanManager[listenerId].filter[addIndex].filterIndex;
        g_firstSetIndex[replaceIndex] = false;
        BcScanFilter *tempFilter = &(g_scanManager[listenerId].filter[addIndex]);
        tempFilter->filterIndex = deleteIndex;
        if (tempFilter->filterIndex == 0) {
            DISC_LOGE(DISC_BROADCAST, "invalid index");
            ReleaseSoftBusBcScanFilter(*adapterFilter, size);
            *adapterFilter = NULL;
            return SOFTBUS_INVALID_PARAM;
        }
        ret = CopySoftBusBcScanFilter(tempFilter, (*adapterFilter) + i);
    }

    return ret;
}

static int32_t GetBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterFilter != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterFilter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterSize != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filterSize is nullptr");
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
    DISC_CHECK_AND_RETURN_LOGE(param != NULL, DISC_BROADCAST, "param is nullptr");
    DISC_CHECK_AND_RETURN_LOGE(adapterParam != NULL, DISC_BROADCAST, "adapterParam is nullptr");
    (void)memset_s(adapterParam, sizeof(SoftBusBcScanParams), 0x0, sizeof(SoftBusBcScanParams));

    // convert params
    adapterParam->scanInterval = param->scanInterval;
    adapterParam->scanWindow = param->scanWindow;
    adapterParam->scanType = param->scanType;
    adapterParam->scanPhy = param->scanPhy;
    adapterParam->scanFilterPolicy = param->scanFilterPolicy;
    adapterParam->frameType = param->frameType;
}

static void GetScanIntervalAndWindow(int32_t freq, SoftBusBcScanParams *adapterParam)
{
    DISC_CHECK_AND_RETURN_LOGE(adapterParam != NULL, DISC_BROADCAST, "adapterParam is nullptr");

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
    if (freq == SCAN_FREQ_P50_60_120) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_120_P50;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_60_P50;
    }
    if (freq == SCAN_FREQ_P75_30_40) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P75;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P75;
    }
    if (freq == SCAN_FREQ_P100_1000_1000) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P100;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P100;
    }
    if (freq == SCAN_FREQ_P10_400_40_LONG_RANGE) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10_LONG_RANGE;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10_LONG_RANGE;
    }
    if (freq == SCAN_FREQ_P100_30_30_LONG_RANGE) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P100_LONG_RANGE;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P100_LONG_RANGE;
    }
}

static void CheckScanFreq(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    DISC_CHECK_AND_RETURN_LOGE(adapterParam != NULL, DISC_BROADCAST, "adapterParam is nullptr");

    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    int32_t maxFreq = g_scanManager[listenerId].freq;
    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->adapterScanId != adapterScanId ||
            protocol != scanManager->protocol) {
            continue;
        }
        maxFreq = (maxFreq > (int32_t)(scanManager->freq)) ? maxFreq : (int32_t)(scanManager->freq);
    }

    GetScanIntervalAndWindow(maxFreq, adapterParam);
}

static int32_t CheckAndStopScan(BroadcastProtocol protocol, int32_t listenerId)
{
    int32_t liveListenerId = -1;
    int32_t ret;
    ScanManager *scanManager = &g_scanManager[listenerId];
    bool needUpdate = CheckNeedUpdateScan(listenerId, &liveListenerId);
    if (!needUpdate) {
        DISC_LOGD(DISC_BROADCAST, "stop scanId=%{public}d", g_scanManager[listenerId].adapterScanId);
        for (int i = 0; i < scanManager->deleteSize; i++) {
            int filterIndex = scanManager->deleted[i];
            g_firstSetIndex[filterIndex] = false;
        }
        ret = g_interface[protocol]->StopScan(g_scanManager[listenerId].adapterScanId);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
            return ret;
        }
    } else {
        int32_t filterSize = 0;
        SoftBusBcScanFilter *adapterFilter = NULL;
        g_scanManager[listenerId].isScanning = false;
        SoftBusBcScanParams adapterParam;
        BuildSoftBusBcScanParams(&(g_scanManager[listenerId].param), &adapterParam);
        CheckScanFreq(liveListenerId, &adapterParam);
        if (scanManager->deleteSize > 0) {
            DeleteFilterByIndex(listenerId, &adapterFilter, &adapterParam, scanManager->deleteSize);
            ReleaseSoftBusBcScanFilter(adapterFilter, scanManager->deleteSize);
            adapterFilter = NULL;
        }
        ret = GetScanFiltersForOneListener(listenerId, &adapterFilter, &filterSize);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "get bc scan filters failed");
        DumpBcScanFilter(adapterFilter, filterSize);
        ret = g_interface[protocol]->SetScanParams(g_scanManager[listenerId].adapterScanId, &adapterParam,
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

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    if (!CheckScanIdIsValid(listenerId)) {
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }
    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->UnRegisterScanListener == NULL) {
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    if (g_scanManager[listenerId].isScanning) {
        ret = CheckAndStopScan(protocol, listenerId);
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
        SoftBusMutexUnlock(&g_scanLock);
        ret = g_interface[protocol]->UnRegisterScanListener(adapterScanId);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");
        ret = SoftBusMutexLock(&g_scanLock);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "mutex error");
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
    g_scanManager[listenerId].protocol = BROADCAST_PROTOCOL_BUTT;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

static void ConvertBcParams(BroadcastProtocol protocol,
    const BroadcastParam *srcParam, SoftbusBroadcastParam *dstParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter covert bc param");
    DISC_CHECK_AND_RETURN_LOGE(srcParam != NULL, DISC_BROADCAST, "srcParam is nullptr");
    DISC_CHECK_AND_RETURN_LOGE(dstParam != NULL, DISC_BROADCAST, "dstParam is nullptr");

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
    dstParam->linkRole = srcParam->linkRole;
    dstParam->frameType = srcParam->frameType;
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
    DISC_CHECK_AND_RETURN_LOGE(bcData != NULL, DISC_BROADCAST, "bcData is nullptr");
    DISC_CHECK_AND_RETURN_LOGE(rspData != NULL, DISC_BROADCAST, "rspData is nullptr");

    if (bcData->payloadLen != 0 && bcData->payload != NULL) {
        DumpSoftbusData("BroadcastPayload bcData", bcData->payloadLen, bcData->payload);
    }
    if (rspData->payloadLen != 0 && rspData->payload != NULL) {
        DumpSoftbusData("BroadcastPayload rspData", rspData->payloadLen, rspData->payload);
    }
}

static int32_t SoftBusCondWaitSec(int64_t sec, int32_t bcId, SoftBusMutex *mutex)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(mutex != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "mutex is nullptr");

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

static int32_t SoftbusPauseCondWaitSec(int64_t sec, int32_t bcId, SoftBusMutex *mutex, SoftBusCond *cond)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(mutex != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "mutex is nullptr");

    SoftBusSysTime absTime = {0};
    int32_t ret = SoftBusGetTime(&absTime);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "softbus get time failed");

    absTime.sec += sec;
    if (SoftBusCondWait(cond, mutex, &absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "wait timeout");
        return SOFTBUS_TIMOUT;
    }
    return SOFTBUS_OK;
}

static int32_t BuildSoftbusBcPayload(const BroadcastPayload *srcData, SoftbusBroadcastPayload *dstData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "srcData is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "dstData is nullptr");

    dstData->type = (SoftbusBcDataType)srcData->type;
    dstData->id = srcData->id;
    dstData->payloadLen = srcData->payloadLen;

    dstData->payload = (uint8_t *)SoftBusCalloc(dstData->payloadLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST, "malloc failed");

    if (memcpy_s(dstData->payload, dstData->payloadLen, srcData->payload, srcData->payloadLen) != EOK) {
        DISC_LOGE(DISC_BROADCAST, "memcpy_s error");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void ReleaseSoftbusBroadcastData(SoftbusBroadcastData *softbusBcData)
{
    DISC_LOGD(DISC_BROADCAST, "enter release bc data");
    DISC_CHECK_AND_RETURN_LOGE(softbusBcData != NULL, DISC_BROADCAST, "softbusBcData is nullptr");
    SoftBusFree(softbusBcData->bcData.payload);
    SoftBusFree(softbusBcData->rspData.payload);
}

static int32_t BuildSoftbusBroadcastData(BroadcastProtocol protocol,
    const BroadcastPacket *packet, SoftbusBroadcastData *softbusBcData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "packet is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(softbusBcData != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "softbusBcData is nullptr");

    softbusBcData->isSupportFlag = packet->isSupportFlag;
    softbusBcData->flag = packet->flag;

    // 1. Build broadcast paylod.
    int32_t ret = BuildSoftbusBcPayload(&(packet->bcData), &(softbusBcData->bcData));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "BuildSoftbusBcPayload failed");

    // 2. Build response broadcast paylod.
    if (packet->rspData.payload != NULL) {
        ret = BuildSoftbusBcPayload(&(packet->rspData), &(softbusBcData->rspData));
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

static void StartBroadcastingWaitSignal(int32_t bcId, SoftBusMutex *mutex, int64_t sec)
{
    DISC_CHECK_AND_RETURN_LOGE(mutex != NULL, DISC_BROADCAST, "invalid param");
    DISC_CHECK_AND_RETURN_LOGE(CheckProtocolIsValid(g_bcManager[bcId].protocol), DISC_BROADCAST, "bad id");
    if (SoftBusCondWaitSec(sec, bcId, mutex) == SOFTBUS_OK) {
        return;
    }
    DISC_LOGW(DISC_BROADCAST, "wait failed, srvType=%{public}s, bcId=%{public}d",
        GetSrvType(g_bcManager[bcId].srvType), bcId);
    SoftBusMutexUnlock(mutex);
    int32_t ret = g_interface[g_bcManager[bcId].protocol]->StopBroadcasting(g_bcManager[bcId].adapterBcId);

    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(mutex) == SOFTBUS_OK, DISC_BROADCAST, "bcLock mutex error");
    ret = SoftBusCondWaitSec(sec, bcId, mutex);
    if (ret != SOFTBUS_OK) {
        DISC_LOGW(DISC_BROADCAST, "wait stop failed=%{public}d", ret);
    }

    g_bcManager[bcId].isAdvertising = false;
}

static int32_t DisableBroadcastingWaitSignal(int32_t bcId, SoftBusMutex *mutex)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(mutex != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckProtocolIsValid(g_bcManager[bcId].protocol),
        SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    if (SoftbusPauseCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex, &g_bcManager[bcId].disableCond) == SOFTBUS_OK) {
        g_bcManager[bcId].isDisableCb = false;
        return SOFTBUS_OK;
    }
    DISC_LOGW(DISC_BROADCAST, "wait signal failed, srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "call enableBroadcast", GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    SoftBusMutexUnlock(mutex);
    int32_t ret = g_interface[g_bcManager[bcId].protocol]->EnableBroadcasting(g_bcManager[bcId].adapterBcId);
    DISC_LOGW(DISC_BROADCAST, "EnableBroadcasting ret=%{public}d", ret);
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(mutex) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, DISC_BROADCAST, "bcLock mutex error");
    ret = SoftbusPauseCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex, &g_bcManager[bcId].enableCond);
    DISC_LOGW(DISC_BROADCAST, "wait signal ret=%{public}d", ret);
    g_bcManager[bcId].isDisabled = false;
    g_bcManager[bcId].isAdvertising = true;
    return SOFTBUS_BC_MGR_WAIT_COND_FAIL;
}

static int32_t SetBroadcastingParamWaitSignal(int32_t bcId, SoftBusMutex *mutex)
{
    if (SoftbusPauseCondWaitSec(BC_WAIT_TIME_SEC, bcId, mutex, &g_bcManager[bcId].setParamCond) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_BC_MGR_WAIT_COND_FAIL;
}

static int32_t CheckInterface(BroadcastProtocol protocol, bool isStart)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckProtocolIsValid(protocol), SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "bad id");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    if (isStart) {
        DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol]->StartBroadcasting != NULL,
            SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    } else {
        DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol]->StopBroadcasting != NULL,
            SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
    }
    return SOFTBUS_OK;
}

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    static uint32_t callCount = 0;

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST,
        "mutex error, bcId=%{public}d", bcId);
    if (!CheckBcIdIsValid(bcId) || g_bcManager[bcId].bcCallback == NULL ||
        g_bcManager[bcId].bcCallback->OnStartBroadcastingCallback == NULL) {
        SoftBusMutexUnlock(&g_bcLock);
        DISC_LOGE(DISC_BROADCAST, "invalid bcId, bcId=%{public}d", bcId);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }

    BroadcastProtocol protocol = g_bcManager[bcId].protocol;
    if (CheckInterface(protocol, true) != SOFTBUS_OK || CheckBroadcastingParam(param, packet) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_bcLock);
        DISC_LOGE(DISC_BROADCAST, "invalid param, bcId=%{public}d", bcId);
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_bcManager[bcId].isAdvertising && !g_bcManager[bcId].isStarted) {
        StartBroadcastingWaitSignal(bcId, &g_bcLock, BC_WAIT_TIME_SEC);
    }

    DumpBroadcastPacket(&(packet->bcData), &(packet->rspData));
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(protocol, packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "build SoftbusBroadcastData failed, bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    SoftbusBroadcastParam adapterParam;
    ConvertBcParams(protocol, param, &adapterParam);
    DISC_LOGI(DISC_BROADCAST, "start bc srvType=%{public}s, bcId=%{public}d, "
        "c=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId, callCount++);
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[protocol]->StartBroadcasting(g_bcManager[bcId].adapterBcId, &adapterParam, &softbusBcData);
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
    g_bcManager[bcId].isDisableCb = false;
    SoftBusMutexUnlock(&g_bcLock);
    ReleaseSoftbusBroadcastData(&softbusBcData);
    return SOFTBUS_OK;
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
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
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param packet");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId) || g_bcManager[bcId].bcCallback == NULL ||
        g_bcManager[bcId].bcCallback->OnSetBroadcastingCallback == NULL) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;
    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->SetBroadcastingData == NULL) {
        DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not registered", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "replace bc srvType=%{public}s, bcId=%{public}d,"
        "c=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId, callCount++);
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(protocol, packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "build SoftbusBroadcastData failed");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[protocol]->SetBroadcastingData(g_bcManager[bcId].adapterBcId, &softbusBcData);
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
    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;

    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->DisableBroadcasting == NULL) {
        DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not registered", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_bcManager[bcId].isAdvertising || g_bcManager[bcId].isDisabled) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is already disabled", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }

    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[protocol]->DisableBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    g_bcManager[bcId].isAdvertising = false;
    g_bcManager[bcId].isDisabled = true;
    SoftBusMutexUnlock(&g_bcLock);

    return SOFTBUS_OK;
}

int32_t EnableBroadcasting(int32_t bcId)
{
    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;

    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->EnableBroadcasting == NULL) {
        DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not registered", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    if (!g_bcManager[bcId].isAdvertising && !g_bcManager[bcId].isDisabled) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is already enabled", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }

    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[protocol]->EnableBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    g_bcManager[bcId].isAdvertising = true;
    g_bcManager[bcId].isDisabled = false;
    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

int32_t PerformSetBroadcastingParam(int32_t bcId, SoftbusBroadcastParam *softbusBcParam)
{
    int32_t ret = DisableBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed during disabling");

    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "lock failed");
    DISC_LOGD(DISC_BROADCAST, "managerId=%{public}d, isDisableCb=%{public}d",
        bcId, g_bcManager[bcId].isDisableCb);
    if (!g_bcManager[bcId].isDisableCb) {
        ret = DisableBroadcastingWaitSignal(bcId, &g_bcLock);
        SoftBusMutexUnlock(&g_bcLock);
        DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
            "wait pausecondition fail managerId=%{public}d", bcId);
    } else {
        SoftBusMutexUnlock(&g_bcLock);
    }

    if (g_bcManager[bcId].isDisabled) {
        ret = g_interface[g_bcManager[bcId].protocol]->SetBroadcastingParam(g_bcManager[bcId].adapterBcId,
            softbusBcParam);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "call from adapter failed during setting param");
            return ret;
        }
        ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "lock failed");
        ret = SetBroadcastingParamWaitSignal(bcId, &g_bcLock);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BROADCAST, "wait set broadcasting param fail managerId=%{public}d", bcId);
        }
        SoftBusMutexUnlock(&g_bcLock);
    }

    ret = EnableBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
        "call from adapter failed during enabling");

    return SOFTBUS_OK;
}

int32_t SetBroadcastingParam(int32_t bcId, const BroadcastParam *param)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;

    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->SetBroadcastingParam == NULL) {
        DISC_LOGE(DISC_BROADCAST, "protocol=%{public}d is not registered", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BROADCAST, "bcId=%{public}d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BROADCAST, "replace param srvType=%{public}s, bcId=%{public}d, "
        "c=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId, callCount++);
    SoftbusBroadcastParam softbusBcParam = {};
    ConvertBcParams(protocol, param, &softbusBcParam);
    g_bcManager[bcId].isDisableCb = false;
    SoftBusMutexUnlock(&g_bcLock);

    return PerformSetBroadcastingParam(bcId, &softbusBcParam);
}

int32_t StopBroadcasting(int32_t bcId)
{
    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_BROADCAST, "mutex error, bcId=%{public}d", bcId);
    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;

    if (!CheckProtocolIsValid(protocol) || CheckInterface(protocol, false) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BROADCAST, "interface check failed, bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    int64_t time = MgrGetSysTime();
    if (time - g_bcManager[bcId].time < BC_WAIT_TIME_MICROSEC) {
        int64_t diffTime = g_bcManager[bcId].time + BC_WAIT_TIME_MICROSEC - time;
        DISC_LOGW(DISC_BROADCAST, "wait %{public}d us", (int32_t)diffTime);
        usleep(diffTime);
    }

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

    DISC_LOGI(DISC_BROADCAST, "stop srvType=%{public}s, bcId=%{public}d", GetSrvType(g_bcManager[bcId].srvType), bcId);
    BroadcastCallback callback = *(g_bcManager[bcId].bcCallback);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[protocol]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
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
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_120_P50 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_60_P50) {
        return SCAN_FREQ_P50_60_120;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P75 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P75) {
        return SCAN_FREQ_P75_30_40;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100) {
        return SCAN_FREQ_P100_1000_1000;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P10_LONG_RANGE &&
        scanWindow == SOFTBUS_BC_SCAN_WINDOW_P10_LONG_RANGE) {
        return SCAN_FREQ_P10_400_40_LONG_RANGE;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100_LONG_RANGE &&
        scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100_LONG_RANGE) {
        return SCAN_FREQ_P100_30_30_LONG_RANGE;
    }
    return SCAN_FREQ_LOW_POWER;
}

static int32_t PerformNormalStartScan(BroadcastProtocol protocol,
    int32_t listenerId, SoftBusBcScanParams *adapterParam, uint32_t *callCount)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterParam != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterParam is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(callCount != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "c is nullptr");

    int32_t ret = 0;
    int32_t filterSize = 0;
    SoftBusBcScanFilter *adapterFilter = NULL;

    ret = GetBcScanFilters(listenerId, &adapterFilter, &filterSize);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK && filterSize > 0, SOFTBUS_BC_MGR_START_SCAN_NO_FILTER,
        DISC_BROADCAST, "no filter");
    DumpBcScanFilter(adapterFilter, filterSize);

    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}d, scanId=%{public}d,"
        "(%{public}hu, %{public}hu), c=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId,
        g_scanManager[listenerId].adapterScanId, adapterParam->scanInterval,
        adapterParam->scanWindow, (*callCount)++);
    ret = g_interface[protocol]->StartScan(g_scanManager[listenerId].adapterScanId, adapterParam,
        adapterFilter, filterSize);
    ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
    if (ret != SOFTBUS_OK) {
        g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BROADCAST, "call from adapter failed");
        return ret;
    }
    g_scanManager[listenerId].isFliterChanged = false;
    return SOFTBUS_OK;
}

static int32_t CheckNotScaning(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterParam != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterParam is nullptr");

    SoftBusBcScanFilter *adapterFilter = NULL;
    int32_t filterSize = 0;
    int32_t ret = 0;
    if (g_scanManager[listenerId].addSize > 0) {
        GetAddFiltersByIndex(listenerId, &adapterFilter);
        ret = g_interface[g_scanManager[listenerId].protocol]->SetScanParams(g_scanManager[listenerId].adapterScanId,
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

static int32_t ProcessFliterChanged(int32_t listenerId, SoftBusBcScanParams *adapterParam,
    SoftBusBcScanFilter *adapterFilter, int32_t filterSize)
{
    int32_t ret = -1;
    ScanManager *scanManager = &g_scanManager[listenerId];
    BroadcastProtocol protocol = scanManager->protocol;
    if (scanManager->isScanning) {
        DISC_LOGI(DISC_BROADCAST, "lId=%{public}d, srvType=%{public}s", listenerId,
            GetSrvType(scanManager->srvType));
        if (scanManager->addSize == 0 && scanManager->deleteSize == 0) {
            DISC_LOGI(DISC_BROADCAST, "scanId=%{public}d (%{public}hu, %{public}hu)",
                scanManager->adapterScanId, adapterParam->scanInterval, adapterParam->scanWindow);
            ret = g_interface[protocol]->SetScanParams(scanManager->adapterScanId, adapterParam,
                NULL, 0, SOFTBUS_SCAN_FILTER_CMD_NONE);
            DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_INVALID_PARAM,
                DISC_BROADCAST, "call from adapter failed");
            return ret;
        }
        if (scanManager->addSize == scanManager->deleteSize) {
            DISC_LOGI(DISC_BROADCAST, "modify filter");
            GetModifyFiltersByIndex(listenerId, &adapterFilter);
            ret = g_interface[protocol]->SetScanParams(scanManager->adapterScanId, adapterParam,
                adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_MODIFY);
            ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
            adapterFilter = NULL;
        } else {
            ret = CheckNotScaning(listenerId, adapterParam);
        }
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
            ret, DISC_BROADCAST, "call from adapter failed, ret=%{public}d", ret);
        DISC_LOGI(DISC_BROADCAST, "modify service srvType=%{public}s, listenerId=%{public}d,"
            "adapterId=%{public}d, interval=%{public}hu, window=%{public}hu",
            GetSrvType(scanManager->srvType), listenerId, scanManager->adapterScanId,
            adapterParam->scanInterval, adapterParam->scanWindow);
    } else {
        DISC_LOGD(DISC_BROADCAST, "sanId=%{public}d, add filter", scanManager->adapterScanId);
        ret = GetScanFiltersForOneListener(listenerId, &adapterFilter, &filterSize);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "get bc scan filters failed");
        ret = g_interface[protocol]->SetScanParams(scanManager->adapterScanId, adapterParam,
            adapterFilter, filterSize, SOFTBUS_SCAN_FILTER_CMD_ADD);
        ReleaseSoftBusBcScanFilter(adapterFilter, filterSize);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
            DISC_BROADCAST, "call from adapter failed, ret=%{public}d", ret);
    }
    return ret;
}

static int32_t CheckChannelScan(BroadcastProtocol protocol, int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(adapterParam != NULL, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "adapterParam is nullptr");

    SoftBusBcScanFilter *adapterFilter = NULL;
    int32_t filterSize = 0;
    int32_t ret = 0;
    if (g_scanManager[listenerId].isFliterChanged) {
        return ProcessFliterChanged(listenerId, adapterParam, adapterFilter, filterSize);
    }
    ret = g_interface[protocol]->SetScanParams(g_scanManager[listenerId].adapterScanId, adapterParam,
        NULL, 0, SOFTBUS_SCAN_FILTER_CMD_NONE);
    return ret;
}

static int32_t StartScanSub(int32_t listenerId, BroadcastProtocol protocol)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].filterSize != 0, SOFTBUS_INVALID_PARAM,
        DISC_BROADCAST, "filter size is 0, need to set filter");
    static uint32_t callCount = 0;
    SoftBusBcScanParams adapterParam;
    BuildSoftBusBcScanParams(&g_scanManager[listenerId].param, &adapterParam);
    CheckScanFreq(listenerId, &adapterParam);
    
    bool isChannelScanning = false;
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;

    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (g_scanManager[managerId].adapterScanId != adapterScanId ||
            protocol != g_scanManager[managerId].protocol) {
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
    if (protocol == BROADCAST_PROTOCOL_SLE) {
        DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[protocol]->StopScan != NULL,
            SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");
        int32_t ret = g_interface[protocol]->StopScan(g_scanManager[listenerId].adapterScanId);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST,
            "stop sle scan falied, err=%{public}d", ret);
        return PerformNormalStartScan(protocol, listenerId, &adapterParam, &callCount);
    }
    return CheckChannelScan(protocol, listenerId, &adapterParam);

NORMAL_START_SCAN:
    DISC_LOGD(DISC_BROADCAST, "start scan lId=%{public}d", listenerId);
    // channel have stop. normal run scan
    return PerformNormalStartScan(protocol, listenerId, &adapterParam, &callCount);
}

static int32_t GetFilterIndex(uint8_t *index)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(index != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "index is nullptr");

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
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId, listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }
    DISC_LOGI(DISC_BROADCAST, "start scan, lId=%{public}d, srvType=%{public}s, c=%{public}u",
        listenerId, GetSrvType(g_scanManager[listenerId].srvType), callCount++);

    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;

    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL || g_interface[protocol]->StartScan == NULL) {
        DISC_LOGE(DISC_BROADCAST, "interface check failed, listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
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
            DISC_LOGD(DISC_BROADCAST, "add filter filterIndex = %{public}d",
                g_scanManager[listenerId].filter[i].filterIndex);
        }
    }

    ret = StartScanSub(listenerId, protocol);
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
    DISC_LOGD(DISC_BROADCAST, "enter stop scan, listenerId=%{public}d, c=%{public}u", listenerId, callCount++);
    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");
    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId, listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    BroadcastProtocol protocol = g_scanManager[listenerId].protocol;
    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL || g_interface[protocol]->StopScan == NULL) {
        DISC_LOGE(DISC_BROADCAST, "not found or not register protocol=%{public}d", protocol);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }
    DISC_LOGI(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}d, scanId=%{public}d, c=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId, callCount);
    if (!g_scanManager[listenerId].isScanning) {
        DISC_LOGI(DISC_BROADCAST, "listenerId is not scanning. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_OK;
    }

    ret = CheckAndStopScan(protocol, listenerId);
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
        srcFilter->serviceId == dstFilter->serviceId &&
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
    DISC_CHECK_AND_RETURN_RET_LOGE(filter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "filter is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(!((filterNum <= 0) || (filterNum > MAX_FILTER_SIZE)),
        SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param filterNum");

    ReleaseScanIdx(listenerId);

    g_scanManager[listenerId].added = (uint8_t *)SoftBusCalloc(filterNum * sizeof(uint8_t));
    DISC_CHECK_AND_RETURN_RET_LOGE(g_scanManager[listenerId].added != NULL, SOFTBUS_MALLOC_ERR, DISC_BROADCAST,
        "memory allocation failed");
    g_scanManager[listenerId].addSize = 0;
    g_scanManager[listenerId].deleted = (uint8_t *)SoftBusCalloc(g_scanManager[listenerId].filterSize *
        sizeof(uint8_t));
    if (g_scanManager[listenerId].deleted == NULL) {
        DISC_LOGI(DISC_BROADCAST, "memory allocation failed");
        ReleaseScanIdx(listenerId);
        return SOFTBUS_MALLOC_ERR;
    }
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
                ReleaseScanIdx(listenerId);
                return SOFTBUS_INVALID_PARAM;
            }
        }
    }
    return SOFTBUS_OK;
}

int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    DISC_LOGD(DISC_BROADCAST, "set scan filter, filterNum=%{public}d", filterNum);
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "param is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(!((filterNum == 0) || (filterNum > MAX_FILTER_SIZE)),
        SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "invalid param filterNum");
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
                DISC_LOGD(DISC_BROADCAST, "not scanning, just release index, filterIndex=%{public}d",
                    g_scanManager[listenerId].filter[i].filterIndex);
                g_firstSetIndex[g_scanManager[listenerId].filter[i].filterIndex] = false;
            }
        }

        if (filterNum > 0) {
            for (int i = 0; i < filterNum; i++) {
                GetFilterIndex(&filter[i].filterIndex);
                DISC_LOGD(DISC_BROADCAST, "add filter index, filterIndex=%{public}d",
                    filter[i].filterIndex);
            }
        }
    }

    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].filter = (BcScanFilter *)scanFilter;
    g_scanManager[listenerId].filterSize = filterNum;
    // Need to reset scanner when filter changed.
    g_scanManager[listenerId].isFliterChanged = true;
    DISC_LOGD(DISC_BROADCAST, "srvType=%{public}s, lId=%{public}d, aId=%{public}d",
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
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL,
        false, DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->IsLpDeviceAvailable != NULL,
        false, DISC_BROADCAST, "function is nullptr");

    return g_interface[BROADCAST_PROTOCOL_BLE]->IsLpDeviceAvailable();
}

bool BroadcastSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam)
{
    DISC_LOGD(DISC_BROADCAST, "enter set adv dev param");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcParam != NULL, false, DISC_BROADCAST, "invalid param bcParam");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanParam != NULL, false, DISC_BROADCAST, "invalid param scanParam");
    DISC_CHECK_AND_RETURN_RET_LOGE(type < SOFTBUS_UNKNOW_TYPE && type >= SOFTBUS_HEARTBEAT_TYPE,
        false, DISC_BROADCAST, "invalid app type");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL,
        false, DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->SetAdvFilterParam != NULL,
        false, DISC_BROADCAST, "function is nullptr");

    SoftBusLpBroadcastParam bcDstParam = {0};
    SoftBusLpScanParam scanDstParam = {0};

    bcDstParam.advHandle = bcParam->bcHandle;
    ConvertBcParams(BROADCAST_PROTOCOL_BLE, &bcParam->bcParam, &bcDstParam.advParam);

    int32_t ret = BuildSoftbusBroadcastData(BROADCAST_PROTOCOL_BLE, &bcParam->packet, &bcDstParam.advData);
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
    DISC_LOGI(DISC_BROADCAST, "bcId=%{public}d, Id=%{public}d",
        bcParam->bcHandle, scanParam->listenerId);
    ret = g_interface[BROADCAST_PROTOCOL_BLE]->SetAdvFilterParam(type, &bcDstParam, &scanDstParam);
    ReleaseSoftbusBroadcastData(&bcDstParam.advData);
    ReleaseSoftBusBcScanFilter(scanDstParam.filter, filterNum);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret, false, DISC_BROADCAST, "call from adapter failed");
    return true;
}

int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    DISC_LOGD(DISC_BROADCAST, "enter get bc handle");
    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckBcIdIsValid(bcId)) {
        DISC_LOGE(DISC_BROADCAST, "bcId is invalid");
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }
    BroadcastProtocol protocol = g_bcManager[bcId].protocol;
    if (!CheckProtocolIsValid(protocol) || g_interface[protocol] == NULL ||
        g_interface[protocol]->GetBroadcastHandle == NULL) {
        DISC_LOGE(DISC_BROADCAST, "protocol =%{public}d is not registered", protocol);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusMutexUnlock(&g_bcLock);

    ret = g_interface[protocol]->GetBroadcastHandle(g_bcManager[bcId].adapterBcId, bcHandle);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "call from adapter failed");
    return SOFTBUS_OK;
}

int32_t BroadcastEnableSyncDataToLpDevice(void)
{
    DISC_LOGI(DISC_BROADCAST, "enter enable sync");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->EnableSyncDataToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[BROADCAST_PROTOCOL_BLE]->EnableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    return SOFTBUS_OK;
}

int32_t BroadcastDisableSyncDataToLpDevice(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->DisableSyncDataToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[BROADCAST_PROTOCOL_BLE]->DisableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BROADCAST, "call from adapter failed");

    return SOFTBUS_OK;
}

int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->SetScanReportChannelToLpDevice != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BROADCAST, "mutex error");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BROADCAST, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    ScanManager manager = g_scanManager[listenerId];
    ret = g_interface[BROADCAST_PROTOCOL_BLE]->SetScanReportChannelToLpDevice(manager.adapterScanId, enable);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
        DISC_BROADCAST, "interface is nullptr");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[BROADCAST_PROTOCOL_BLE]->SetLpDeviceParam != NULL,
        SOFTBUS_BC_MGR_FUNC_NULL, DISC_BROADCAST, "function is nullptr");

    int32_t ret = g_interface[BROADCAST_PROTOCOL_BLE]->SetLpDeviceParam(duration,
        maxExtAdvEvents, window, interval, bcHandle);
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
