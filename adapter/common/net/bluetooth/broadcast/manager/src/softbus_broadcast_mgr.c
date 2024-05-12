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

#include "disc_log.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_ble_gatt.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_broadcast_manager.h"
#include "softbus_broadcast_utils.h"
#include "softbus_errcode.h"
#include "softbus_hidumper_bc_mgr.h"
#include "softbus_utils.h"

#define BC_WAIT_TIME_MILLISEC 50
#define BC_WAIT_TIME_SEC 2
#define MGR_TIME_THOUSAND_MULTIPLIER 1000LL
#define BC_WAIT_TIME_MICROSEC (BC_WAIT_TIME_MILLISEC * MGR_TIME_THOUSAND_MULTIPLIER)

static volatile bool g_mgrInit = false;
static volatile bool g_mgrLockInit = false;
static SoftBusMutex g_bcLock = {0};
static SoftBusMutex g_scanLock = {0};

static int32_t g_adapterScannerId = -1;
static int32_t g_adapterLpScannerId = -1;
static int32_t g_btStateListenerId = -1;
static volatile bool g_isScanCbReg = false;
static volatile bool g_isLpScanCbReg = false;

#define REGISTER_INFO_MANAGER "registerInfoMgr"
static int32_t RegisterInfoDump(int fd);

typedef struct {
    BaseServiceType srvType;
    int32_t adapterBcId;
    bool isUsed;
    bool isAdvertising;
    int64_t time;
    SoftBusCond cond;
    BroadcastCallback *bcCallback;
} BroadcastManager;

typedef enum {
    SCAN_FREQ_LOW_POWER,
    SCAN_FREQ_P2_60_3000,
    SCAN_FREQ_P2_30_1500,
    SCAN_FREQ_P10_30_300,
    SCAN_FREQ_P25_60_240,
    SCAN_FREQ_P100_1000_1000,
    SCAN_FREQ_BUTT,
} ScanFreq;

typedef struct {
    BaseServiceType srvType;
    int32_t adapterScanId;
    bool isUsed;
    bool isNeedReset;
    bool isScanning;
    BcScanParams param;
    ScanFreq freq;
    BcScanFilter *filter;
    uint8_t filterSize;
    ScanCallback *scanCallback;
} ScanManager;

static BroadcastManager g_bcManager[BC_NUM_MAX];
static ScanManager g_scanManager[SCAN_NUM_MAX];

// Global variable for specifying an interface type {@link SoftbusMediumType}.
static uint32_t g_interfaceId = BROADCAST_MEDIUM_TYPE_BLE;
static SoftbusBroadcastMediumInterface *g_interface[MEDIUM_NUM_MAX];

static inline bool CheckMediumIsValid(SoftbusMediumType interfaceId)
{
    return interfaceId >= 0 && interfaceId < BROADCAST_MEDIUM_TYPE_BUTT;
}

int32_t RegisterBroadcastMediumFunction(SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface)
{
    DISC_LOGI(DISC_BLE, "enter, register type=%{public}d.", type);
    DISC_CHECK_AND_RETURN_RET_LOGE(type >= 0 && type < BROADCAST_MEDIUM_TYPE_BUTT, SOFTBUS_INVALID_PARAM, DISC_BLE,
                                   "type is invalid!");
    DISC_CHECK_AND_RETURN_RET_LOGE(interface != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "interface is null!");

    g_interface[type] = (SoftbusBroadcastMediumInterface *)interface;
    return SOFTBUS_OK;
}

static void BcBtStateChanged(int32_t listenerId, int32_t state)
{
    DISC_CHECK_AND_RETURN_LOGE(CheckMediumIsValid(g_interfaceId), DISC_BLE, "invalid id!");
    (void)listenerId;
    if (state != SOFTBUS_BC_BT_STATE_TURN_OFF) {
        return;
    }
    DISC_LOGI(DISC_BLE, "receive bt turn off event, start reset broadcast mgr state...");

    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bcLock) == SOFTBUS_OK, DISC_BLE, "bcLock mutex err!");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (!bcManager->isUsed || bcManager->adapterBcId == -1 || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        (void)g_interface[g_interfaceId]->StopBroadcasting(bcManager->adapterBcId);
        bcManager->isAdvertising = false;
        bcManager->time = 0;
        SoftBusCondBroadcast(&bcManager->cond);

        SoftBusMutexUnlock(&g_bcLock);
        bcManager->bcCallback->OnStopBroadcastingCallback((int32_t)managerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    }

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_scanLock) == SOFTBUS_OK, DISC_BLE, "scanLock mutex err!");

        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || scanManager->adapterScanId == -1 || !scanManager->isScanning ||
            scanManager->scanCallback == NULL || scanManager->scanCallback->OnStopScanCallback == NULL) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        (void)g_interface[g_interfaceId]->StopScan(scanManager->adapterScanId);
        scanManager->isScanning = false;

        SoftBusMutexUnlock(&g_scanLock);
        scanManager->scanCallback->OnStopScanCallback((int32_t)managerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    }
}

static SoftBusBtStateListener g_softbusBcBtStateLister = {
    .OnBtStateChanged = BcBtStateChanged,
    .OnBtAclStateChanged = NULL,
};

static int32_t BcManagerLockInit(void)
{
    DISC_LOGI(DISC_BLE, "enter.");
    if (g_mgrLockInit) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_bcLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "g_bcLock init failed");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_scanLock, NULL) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "g_scanLock init failed");
        (void)SoftBusMutexDestroy(&g_bcLock);
        return SOFTBUS_NO_INIT;
    }
    g_mgrLockInit = true;
    return SOFTBUS_OK;
}

int32_t InitBroadcastMgr(void)
{
    DISC_LOGI(DISC_BLE, "enter.");
    if (g_mgrInit) {
        DISC_LOGD(DISC_BLE, "mgr already init.");
        return SOFTBUS_OK;
    }
    int32_t ret = BcManagerLockInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "lock init fail!");

    SoftbusBleAdapterInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->Init != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    ret = g_interface[g_interfaceId]->Init();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    ret = SoftBusAddBtStateListener(&g_softbusBcBtStateLister);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret != SOFTBUS_ERR, ret, DISC_BLE, "add bt state listener fail!");
    g_btStateListenerId = ret;
    g_mgrInit = true;

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
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param packet!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet->bcData.payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE,
                                   "invalid param payload!");
    return SOFTBUS_OK;
}

int32_t DeInitBroadcastMgr(void)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGW(g_interface[g_interfaceId] != NULL, SOFTBUS_OK, DISC_BLE, "already deinit!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DeInit != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

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
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "RemoveBtStateListener fail!");
        g_btStateListenerId = -1;
    }

    ret = g_interface[g_interfaceId]->DeInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");
    g_interface[g_interfaceId] = NULL;
    return SOFTBUS_OK;
}

static char *GetSrvType(BaseServiceType srvType)
{
    if ((int32_t)srvType < 0 || (int32_t)srvType >= (int32_t)(sizeof(g_srvTypeMap)/sizeof(SrvTypeMap))) {
        return (char *)"invalid service";
    }
    return g_srvTypeMap[srvType].service;
}

static void BcStartBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. adapterBcId=%{public}d", adapterBcId);
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "mutex err!");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStartBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d,"
            "callCount=%{public}u", GetSrvType(bcManager->srvType), managerId, adapterBcId, status, callCount++);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isAdvertising = true;
            SoftBusCondSignal(&bcManager->cond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        bcManager->bcCallback->OnStartBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcStopBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. adapterBcId=%{public}d, callCount=%{public}u", adapterBcId, callCount++);
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "mutex err!");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isAdvertising = false;
            bcManager->time = 0;
            SoftBusCondSignal(&bcManager->cond);
        }
        SoftBusMutexUnlock(&g_bcLock);
        bcManager->bcCallback->OnStopBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcUpdateBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "mutex err!");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnUpdateBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        SoftBusMutexUnlock(&g_bcLock);
        bcManager->bcCallback->OnUpdateBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_bcLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "mutex err!");

        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnSetBroadcastingCallback == NULL) {
            SoftBusMutexUnlock(&g_bcLock);
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterBcId=%{public}d, status=%{public}d",
            GetSrvType(bcManager->srvType), managerId, adapterBcId, status);
        SoftBusMutexUnlock(&g_bcLock);
        bcManager->bcCallback->OnSetBroadcastingCallback((int32_t)managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static SoftbusBroadcastCallback g_softbusBcBleCb = {
    .OnStartBroadcastingCallback = BcStartBroadcastingCallback,
    .OnStopBroadcastingCallback = BcStopBroadcastingCallback,
    .OnUpdateBroadcastingCallback = BcUpdateBroadcastingCallback,
    .OnSetBroadcastingCallback = BcSetBroadcastingCallback,
};

static void BcOnStartScanCallback(int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->adapterScanId != adapterScanId || !scanManager->isUsed || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnStartScanCallback == NULL) {
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, status=%{public}d",
            GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = true;
        }

        scanManager->scanCallback->OnStartScanCallback((int32_t)managerId, status);
    }
}

static void BcStopScanCallback(int32_t adapterScanId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (scanManager->adapterScanId != adapterScanId || !scanManager->isUsed || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnStopScanCallback == NULL) {
            continue;
        }
        DISC_LOGI(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, status=%{public}d",
            GetSrvType(scanManager->srvType), managerId, adapterScanId, status);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_MEM_ERR, DISC_BLE, "memcpy addr fail!");

    ret = memcpy_s(bcInfo->localName, BC_LOCAL_NAME_LEN_MAX, reportData->localName, SOFTBUS_LOCAL_NAME_LEN_MAX);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_MEM_ERR, DISC_BLE, "memcpy localName fail!");

    return SOFTBUS_OK;
}

static bool CheckManufactureIsMatch(const BcScanFilter *filter, const BroadcastPayload *bcData)
{
    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter->manufactureDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BLE, "payload is too short!");
        return false;
    }
    if (filter->manufactureId != bcData->id) {
        DISC_LOGD(DISC_BLE, "manufactureId not match!");
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
        DISC_LOGD(DISC_BLE, "payload is too short!");
        return false;
    }
    if (filter->serviceUuid != bcData->id) {
        DISC_LOGD(DISC_BLE, "serviceUuid not match!");
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
        DISC_LOGE(DISC_BLE, "not support type. type=%{public}d", bcData->type);
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
    DISC_CHECK_AND_RETURN_LOGE(description != NULL, DISC_BLE, "description is null!");
    DISC_CHECK_AND_RETURN_LOGE(len != 0, DISC_BLE, "description=%{public}s, len is 0!", description);
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_BLE, "description=%{public}s, data is null!", description);

    int32_t hexLen = HEXIFY_LEN(len);
    char *softbusData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
    DISC_CHECK_AND_RETURN_LOGE(softbusData != NULL, DISC_BLE, "description=%{public}s, malloc failed!", description);

    (void)ConvertBytesToHexString(softbusData, hexLen, data, len);
    DISC_LOGD(DISC_BLE, "description=%{public}s, softbusData=%{public}s", description, softbusData);

    SoftBusFree(softbusData);
}

static void ReleaseBroadcastReportInfo(BroadcastReportInfo *bcInfo)
{
    SoftBusFree(bcInfo->packet.bcData.payload);
    SoftBusFree(bcInfo->packet.rspData.payload);
}

static int32_t BuildBcPayload(int32_t maxPayloadLen, const SoftbusBroadcastPayload *srcData, BroadcastPayload *dstData)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(srcData->payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE,
                                   "broadcast payload is null!");

    dstData->type = (BroadcastDataType)srcData->type;
    dstData->id = srcData->id;
    dstData->payloadLen = srcData->payloadLen;

    if (srcData->payloadLen > maxPayloadLen) {
        DISC_LOGW(DISC_BLE, "payloadLen=%{public}d is too long!", srcData->payloadLen);
    }
    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;
    dstData->payload = (uint8_t *)SoftBusCalloc(bcDataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BLE, "malloc failed!");

    if (memcpy_s(dstData->payload, bcDataLen, srcData->payload, bcDataLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy payload fail");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }

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
        DISC_BLE, "build broadcast payload failed!");

    DumpSoftbusData("scan result bcData", softbusBcData->bcData.payloadLen, softbusBcData->bcData.payload);

    // 2.2. Build broadcast response payload.
    if (softbusBcData->rspData.payload == NULL) {
        packet->rspData.payload = NULL;
        DISC_LOGD(DISC_BLE, "no rspData!");
    } else {
        maxPayloadLen = RSP_DATA_MAX_LEN;
        ret = BuildBcPayload(maxPayloadLen, &(softbusBcData->rspData), &(packet->rspData));
        if (ret != SOFTBUS_OK) {
            SoftBusFree(packet->bcData.payload);
            DISC_LOGE(DISC_BLE, "build broadcast rsp payload failed!");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "build broadcast common info failed!");

    // 2. Build BroadcastPacket.
    ret = BuildBroadcastPacket(&(reportData->data), &(bcInfo->packet));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "build broadcast packet failed!");

    return SOFTBUS_OK;
}

static bool CheckScanResultDataIsMatchApproach(const uint32_t managerId, BroadcastPayload *bcData)
{
    if (bcData->payload == NULL) {
        return false;
    }
    DISC_CHECK_AND_RETURN_RET_LOGD(bcData->type == BC_DATA_TYPE_SERVICE, false, DISC_BLE,
                                   "type dismatch. type=%{public}d", bcData->type);

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
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_LOGE(reportData != NULL, DISC_BLE, "reportData is null!");

    BroadcastReportInfo bcInfo;
    int32_t ret = BuildBroadcastReportInfo(reportData, &bcInfo);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "BuildBroadcastReportInfo fail!");

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

        DISC_LOGD(DISC_BLE, "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d",
                  GetSrvType(scanManager->srvType), managerId, adapterScanId);
        SoftBusMutexUnlock(&g_scanLock);
        scanManager->scanCallback->OnReportScanDataCallback((int32_t)managerId, &bcInfo);
    }
    ReleaseBroadcastReportInfo(&bcInfo);
}

static void BcScanStateChanged(int32_t resultCode, bool isStartScan)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        int32_t ret = SoftBusMutexLock(&g_scanLock);
        DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "mutex err!");

        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->scanCallback == NULL ||
            scanManager->scanCallback->OnScanStateChanged == NULL) {
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }
        DISC_LOGD(DISC_BLE,
            "srvType=%{public}s, managerId=%{public}u, adapterScanId=%{public}d, isStartScan=%{public}d",
            GetSrvType(scanManager->srvType), managerId, scanManager->adapterScanId, isStartScan);
        SoftBusMutexUnlock(&g_scanLock);
        scanManager->scanCallback->OnScanStateChanged(resultCode, isStartScan);
    }
}

static int32_t ConvertBroadcastUuid(const SoftbusBroadcastUuid *uuid, BroadcastUuid *bcUuid)
{
    bcUuid->uuidLen = uuid->uuidLen;
    bcUuid->uuid = (int8_t *)SoftBusCalloc(bcUuid->uuidLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(bcUuid->uuid != NULL, SOFTBUS_MALLOC_ERR, DISC_BLE, "malloc failed!");
    if (memcpy_s(bcUuid->uuid, bcUuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy_s err!");
        SoftBusFree(bcUuid->uuid);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void BcLpDeviceInfoCallback(const SoftbusBroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    DISC_LOGD(DISC_BLE, "enter.");
    BroadcastUuid bcUuid = {0};
    int32_t ret = ConvertBroadcastUuid(uuid, &bcUuid);
    DISC_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, DISC_BLE, "ConvertBroadcastUuid failed!");

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

int32_t RegisterBroadcaster(BaseServiceType srvType, int32_t *bcId, const BroadcastCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. callCount=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterBcId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BLE, "srvType invalid!");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcId != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param bcId!");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterBroadcaster != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");
    ret = g_interface[g_interfaceId]->RegisterBroadcaster(&adapterBcId, &g_softbusBcBleCb);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    int32_t managerId;
    for (managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (!g_bcManager[managerId].isUsed) {
            break;
        }
    }
    if (managerId == BC_NUM_MAX) {
        DISC_LOGE(DISC_BLE, "no available adv manager");
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_REG_NO_AVAILABLE_BC_ID;
    }
    DISC_LOGD(DISC_BLE,
        "srvType=%{public}s, bcId=%{public}d, adapterBcId=%{public}d", GetSrvType(srvType), managerId, adapterBcId);

    *bcId = managerId;
    ret = SoftBusCondInit(&g_bcManager[managerId].cond);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "SoftBusCondInit failed!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    g_bcManager[managerId].srvType = srvType;
    g_bcManager[managerId].adapterBcId = adapterBcId;
    g_bcManager[managerId].isUsed = true;
    g_bcManager[managerId].isAdvertising = false;
    g_bcManager[managerId].time = 0;
    g_bcManager[managerId].bcCallback = (BroadcastCallback *)cb;
    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static bool CheckBcIdIsValid(int32_t bcId)
{
    if (bcId < 0 || bcId >= BC_NUM_MAX || !g_bcManager[bcId].isUsed) {
        DISC_LOGE(DISC_BLE, "invalid param bcId=%{public}d", bcId);
        return false;
    }
    return true;
}

int32_t UnRegisterBroadcaster(int32_t bcId)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterBroadcaster != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckBcIdIsValid(bcId)) {
        DISC_LOGE(DISC_BLE, "bcId is invalid");
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
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    g_bcManager[bcId].srvType = -1;
    g_bcManager[bcId].adapterBcId = -1;
    g_bcManager[bcId].isUsed = false;
    g_bcManager[bcId].isAdvertising = false;
    g_bcManager[bcId].time = 0;
    SoftBusCondDestroy(&g_bcManager[bcId].cond);
    g_bcManager[bcId].bcCallback = NULL;

    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static int32_t RegisterScanListenerSub(BaseServiceType srvType, int32_t *adapterScanId, const ScanCallback *cb)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    int32_t ret;

    if (srvType == SRV_TYPE_SH_BURST || srvType == SRV_TYPE_SH_HB) {
        if (g_isLpScanCbReg) {
            *adapterScanId = g_adapterLpScannerId;
            DISC_LOGE(DISC_BLE, "service is already registered. srvType=%{public}s", GetSrvType(srvType));
            return SOFTBUS_OK;
        }
        ret = g_interface[g_interfaceId]->RegisterScanListener(adapterScanId, &g_softbusBcBleScanCb);
        DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

        g_isLpScanCbReg = true;
        g_adapterLpScannerId = *adapterScanId;
        return SOFTBUS_OK;
    }

    if (g_isScanCbReg) {
        *adapterScanId = g_adapterScannerId;
        return SOFTBUS_OK;
    }
    DISC_LOGD(DISC_BLE, "register scan listener");
    ret = g_interface[g_interfaceId]->RegisterScanListener(adapterScanId, &g_softbusBcBleScanCb);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    g_isScanCbReg = true;
    g_adapterScannerId = *adapterScanId;
    return SOFTBUS_OK;
}

static bool CheckSrvRegistered(BaseServiceType srvType)
{
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            continue;
        }
        if (g_scanManager[managerId].srvType == srvType) {
            DISC_LOGE(DISC_BLE, "service is registered. srvType=%{public}s", GetSrvType(srvType));
            return true;
        }
    }
    return false;
}

int32_t RegisterScanListener(BaseServiceType srvType, int32_t *listenerId, const ScanCallback *cb)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. callCount=%{public}u", callCount++);
    int32_t ret = SOFTBUS_OK;
    int32_t adapterScanId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(IsSrvTypeValid(srvType), SOFTBUS_BC_MGR_INVALID_SRV, DISC_BLE, "srvType invalid!");
    DISC_CHECK_AND_RETURN_RET_LOGE(listenerId != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param listenerId!");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterScanListener != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(!CheckSrvRegistered(srvType), SOFTBUS_BC_MGR_REG_DUP,
                                   DISC_BLE, "already registered!");
    ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    ret = RegisterScanListenerSub(srvType, &adapterScanId, cb);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        DISC_LOGE(DISC_BLE, "register listerner failed!");
        return ret;
    }

    int32_t managerId;
    for (managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            break;
        }
    }
    if (managerId == SCAN_NUM_MAX) {
        DISC_LOGE(DISC_BLE, "no available scanner");
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_REG_NO_AVAILABLE_LISN_ID;
    }
    DISC_LOGD(DISC_BLE, "srvType=%{public}s, listenerId=%{public}d, adapterScanId=%{public}d",
              GetSrvType(srvType), managerId, adapterScanId);
    *listenerId = managerId;
    g_scanManager[managerId].srvType = srvType;
    g_scanManager[managerId].adapterScanId = adapterScanId;
    g_scanManager[managerId].isUsed = true;
    g_scanManager[managerId].isNeedReset = true;
    g_scanManager[managerId].isScanning = false;
    g_scanManager[managerId].freq = SCAN_FREQ_LOW_POWER;
    g_scanManager[managerId].scanCallback = (ScanCallback *)cb;

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

static bool CheckScanIdIsValid(int32_t listenerId)
{
    if (listenerId < 0 || listenerId >= SCAN_NUM_MAX || !g_scanManager[listenerId].isUsed) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId=%{public}d", listenerId);
        return false;
    }
    return true;
}

static void ReleaseBcScanFilter(int listenerId)
{
    DISC_LOGD(DISC_BLE, "enter.");
    BcScanFilter *filter = g_scanManager[listenerId].filter;
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

static void CovertSoftBusBcScanFilters(const BcScanFilter *filter, uint8_t size, SoftBusBcScanFilter *adapterFilter)
{
    while (size-- > 0) {
        (adapterFilter + size)->address = (filter + size)->address;
        (adapterFilter + size)->deviceName = (filter + size)->deviceName;
        (adapterFilter + size)->serviceUuid = (filter + size)->serviceUuid;
        (adapterFilter + size)->serviceDataLength = (filter + size)->serviceDataLength;
        (adapterFilter + size)->serviceData = (filter + size)->serviceData;
        (adapterFilter + size)->serviceDataMask = (filter + size)->serviceDataMask;
        (adapterFilter + size)->manufactureId = (filter + size)->manufactureId;
        (adapterFilter + size)->manufactureDataLength = (filter + size)->manufactureDataLength;
        (adapterFilter + size)->manufactureData = (filter + size)->manufactureData;
        (adapterFilter + size)->manufactureDataMask = (filter + size)->manufactureDataMask;
        (adapterFilter + size)->advIndReport = (filter + size)->advIndReport;
    }
}

static void CombineSoftbusBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t size = 0;
    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || (!scanManager->isScanning && managerId != listenerId) ||
            scanManager->adapterScanId != g_scanManager[listenerId].adapterScanId) {
            scanManager->isNeedReset = false;
            continue;
        }

        scanManager->isNeedReset = true;
        size += scanManager->filterSize;
    }
    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    if (*adapterFilter == NULL) {
        DISC_LOGE(DISC_BLE, "malloc failed!");
        return;
    }
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
        CovertSoftBusBcScanFilters(filter, currentSize, *adapterFilter + size);
    }
}

static void GetBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    CombineSoftbusBcScanFilters(listenerId, adapterFilter, filterSize);
}

static void DumpBcScanFilter(const SoftBusBcScanFilter *nativeFilter, uint8_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE, "invalid param nativeFilter!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize != 0, DISC_BLE, "filterSize is 0!");

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
    DISC_LOGD(DISC_BLE, "enter.");
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
    if (freq == SCAN_FREQ_P100_1000_1000) {
        adapterParam->scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P100;
        adapterParam->scanWindow = SOFTBUS_BC_SCAN_WINDOW_P100;
    }
}

static void CheckScanFreq(int32_t listenerId, SoftBusBcScanParams *adapterParam)
{
    static int32_t scanFreq = SCAN_FREQ_LOW_POWER;
    static int32_t scanLpFreq = SCAN_FREQ_LOW_POWER;

    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    int32_t maxFreq = g_scanManager[listenerId].freq;

    if (adapterScanId == g_adapterLpScannerId) {
        if (maxFreq != scanLpFreq) {
            DISC_LOGD(DISC_BLE, "lp freq need to update.");
            scanLpFreq = maxFreq;
            g_scanManager[listenerId].isNeedReset = true;
        }
        return;
    }

    for (uint32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        ScanManager *scanManager = &g_scanManager[managerId];
        if (!scanManager->isUsed || !scanManager->isScanning || scanManager->adapterScanId != adapterScanId) {
            continue;
        }
        maxFreq = (maxFreq > (int32_t)(scanManager->freq)) ? maxFreq : (int32_t)(scanManager->freq);
    }
    if (scanFreq != maxFreq) {
        g_scanManager[listenerId].isNeedReset = true;
        scanFreq = maxFreq;
        DISC_LOGD(DISC_BLE, "need to update.");
    }
    GetScanIntervalAndWindow(scanFreq, adapterParam);
}

static int32_t CheckAndStopScan(int32_t listenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    int32_t liveListenerId = -1;
    int32_t ret;
    bool needUpdate = CheckNeedUpdateScan(listenerId, &liveListenerId);
    if (!needUpdate) {
        DISC_LOGI(DISC_BLE, "call stop scan");
        ret = g_interface[g_interfaceId]->StopScan(g_scanManager[listenerId].adapterScanId);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BLE, "call from adapter fail!");
            return ret;
        }
    } else {
        int32_t filterSize = 0;
        SoftBusBcScanFilter *adapterFilter = NULL;
        g_scanManager[listenerId].isScanning = false;
        GetBcScanFilters(liveListenerId, &adapterFilter, &filterSize);
        DumpBcScanFilter(adapterFilter, filterSize);
        SoftBusBcScanParams adapterParam;
        BuildSoftBusBcScanParams(&(g_scanManager[listenerId].param), &adapterParam);
        CheckScanFreq(liveListenerId, &adapterParam);
        ret = g_interface[g_interfaceId]->StopScan(g_scanManager[listenerId].adapterScanId);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BLE, "call from adapter fail!");
            SoftBusFree(adapterFilter);
            return ret;
        }
        DISC_LOGI(DISC_BLE, "start scan adapterId=%{public}d, interval=%{public}hu, window=%{public}hu",
            g_scanManager[listenerId].adapterScanId, adapterParam.scanInterval, adapterParam.scanWindow);
        ret = g_interface[g_interfaceId]->StartScan(g_scanManager[listenerId].adapterScanId, &adapterParam,
                                                    adapterFilter, filterSize);
        SoftBusFree(adapterFilter);
        if (ret != SOFTBUS_OK) {
            g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
            DISC_LOGE(DISC_BLE, "call from adapter fail!");
            return ret;
        }
    }
    return SOFTBUS_OK;
}

int32_t UnRegisterScanListener(int32_t listenerId)
{
    DISC_LOGI(DISC_BLE, "enter. listenerId=%{public}d", listenerId);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterScanListener != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");
    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");
    if (!CheckScanIdIsValid(listenerId)) {
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;
    if (g_scanManager[listenerId].isScanning) {
        ret = CheckAndStopScan(listenerId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "stop scan fail!");
            SoftBusMutexUnlock(&g_scanLock);
            return ret;
        }
    }
    if (CheckNeedUnRegisterScanListener(listenerId)) {
        if (adapterScanId == g_adapterLpScannerId) {
            g_isLpScanCbReg = false;
            g_adapterLpScannerId = -1;
        }
        if (adapterScanId == g_adapterScannerId) {
            g_isScanCbReg = false;
            g_adapterScannerId = -1;
        }
        ret = g_interface[g_interfaceId]->UnRegisterScanListener(adapterScanId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "call from adapter fail!");
            SoftBusMutexUnlock(&g_scanLock);
            return ret;
        }
    }
    DISC_LOGD(DISC_BLE, "srvType=%{public}s", GetSrvType(g_scanManager[listenerId].srvType));
    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].srvType = -1;
    g_scanManager[listenerId].adapterScanId = -1;
    g_scanManager[listenerId].isUsed = false;
    g_scanManager[listenerId].isNeedReset = true;
    g_scanManager[listenerId].freq = SCAN_FREQ_LOW_POWER;
    g_scanManager[listenerId].scanCallback = NULL;
    g_scanManager[listenerId].isScanning = false;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

static void ConvertBcParams(const BroadcastParam *srcParam, SoftbusBroadcastParam *dstParam)
{
    DISC_LOGD(DISC_BLE, "enter.");
    dstParam->minInterval = srcParam->minInterval;
    dstParam->maxInterval = srcParam->maxInterval;
    dstParam->advType = srcParam->advType;
    dstParam->advFilterPolicy = srcParam->advFilterPolicy;
    dstParam->ownAddrType = srcParam->ownAddrType;
    dstParam->peerAddrType = srcParam->peerAddrType;
    if (memcpy_s(dstParam->peerAddr.addr, SOFTBUS_ADDR_MAC_LEN, srcParam->peerAddr.addr, BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy peerAddr fail");
        return;
    }
    dstParam->channelMap = srcParam->channelMap;
    dstParam->duration = srcParam->duration;
    dstParam->txPower = srcParam->txPower;
    dstParam->isSupportRpa = srcParam->isSupportRpa;
    if (memcpy_s(dstParam->ownIrk, SOFTBUS_IRK_LEN, srcParam->ownIrk, BC_IRK_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy ownIrk fail");
        return;
    }
    if (memcpy_s(dstParam->ownUdidHash, SOFTBUS_UDID_HASH_LEN, srcParam->ownUdidHash, BC_UDID_HASH_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy ownUdidHash fail");
        return;
    }
    if (memcpy_s(dstParam->localAddr.addr, BC_ADDR_MAC_LEN, srcParam->localAddr.addr,
        BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy localAddr fail");
        return;
    }
}

static void DumpBroadcastPacket(const BroadcastPayload *bcData, const BroadcastPayload *rspData)
{
    DumpSoftbusData("BroadcastPayload bcData", bcData->payloadLen, bcData->payload);
    DumpSoftbusData("BroadcastPayload rspData", rspData->payloadLen, rspData->payload);
}

static int32_t SoftBusCondWaitTwoSec(int32_t bcId, SoftBusMutex *mutex)
{
    SoftBusSysTime absTime = {0};
    int32_t ret = SoftBusGetTime(&absTime);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "softbus get time failed");

    absTime.sec += BC_WAIT_TIME_SEC;
    if (SoftBusCondWait(&g_bcManager[bcId].cond, mutex, &absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "wait timeout");
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
        DISC_LOGW(DISC_BLE, "payloadLen is too long! payloadLen=%{public}d", srcData->payloadLen);
    }
    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;

    dstData->payload = (uint8_t *)SoftBusCalloc(bcDataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BLE, "malloc failed!");

    if (memcpy_s(dstData->payload, bcDataLen, srcData->payload, bcDataLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy_s err!");
        SoftBusFree(dstData->payload);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void ReleaseSoftbusBroadcastData(SoftbusBroadcastData *softbusBcData)
{
    DISC_LOGD(DISC_BLE, "enter.");
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "BuildSoftbusBcPayload fail!");

    // 2. Build response broadcast paylod.
    if (packet->rspData.payload != NULL) {
        maxPayloadLen = RSP_DATA_MAX_LEN;
        ret = BuildSoftbusBcPayload(maxPayloadLen, &(packet->rspData), &(softbusBcData->rspData));
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "convert rspData failed!");
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

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. bcId=%{public}d, callCount=%{public}u", bcId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartBroadcasting != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");
    int32_t ret = CheckBroadcastingParam(param, packet);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "check param failed!");
    ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");
    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }
    if (g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "wait condition managerId=%{public}d", bcId);
        if (SoftBusCondWaitTwoSec(bcId, &g_bcLock) != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "SoftBusCondWaitTwoSec failed");
            SoftBusMutexUnlock(&g_bcLock);
            return SOFTBUS_BC_MGR_WAIT_COND_FAIL;
        }
    }

    DumpBroadcastPacket(&(packet->bcData), &(packet->rspData));
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Build SoftbusBroadcastData failed!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    SoftbusBroadcastParam adapterParam;
    ConvertBcParams(param, &adapterParam);
    DISC_LOGI(DISC_BLE, "start service srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d,"
        "callCount=%{public}u", GetSrvType(g_bcManager[bcId].srvType), bcId,
        g_bcManager[bcId].adapterBcId, callCount++);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->StartBroadcasting(g_bcManager[bcId].adapterBcId, &adapterParam, &softbusBcData);
    g_bcManager[bcId].time = MgrGetSysTime();
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnStartBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        ReleaseSoftbusBroadcastData(&softbusBcData);
        return ret;
    }
    ReleaseSoftbusBroadcastData(&softbusBcData);
    return SOFTBUS_OK;
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invald param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invald param packet!");

    int ret = StopBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "StopBroadcasting fail");

    return StartBroadcasting(bcId, param, packet);
}

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. bcId=%{public}d, callCount=%{public}u", bcId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param packet!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetBroadcastingData != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_INVALID_BC_ID;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "bcId=%{public}d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_BC_MGR_NOT_BROADCASTING;
    }

    DISC_LOGI(DISC_BLE, "replace BroadcastPacket srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d",
              GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Build SoftbusBroadcastData failed!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->SetBroadcastingData(g_bcManager[bcId].adapterBcId, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnSetBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        ReleaseSoftbusBroadcastData(&softbusBcData);
        return ret;
    }

    ReleaseSoftbusBroadcastData(&softbusBcData);
    return SOFTBUS_OK;
}

int32_t StopBroadcasting(int32_t bcId)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. bcId=%{public}d, callCount=%{public}u", bcId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopBroadcasting != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckBcIdIsValid(bcId), SOFTBUS_BC_MGR_INVALID_BC_ID, DISC_BLE, "invalid bcId");

    int64_t time = MgrGetSysTime();
    if (time - g_bcManager[bcId].time < BC_WAIT_TIME_MICROSEC) {
        int64_t diffTime = g_bcManager[bcId].time + BC_WAIT_TIME_MICROSEC - time;
        DISC_LOGW(DISC_BLE, "wait %{public}d us", (int32_t)diffTime);
        usleep(diffTime);
    }

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "bcId is not advertising. bcId=%{public}d", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_OK;
    }

    DISC_LOGI(DISC_BLE, "stop service srvType=%{public}s, bcId=%{public}d, adapterId=%{public}d",
              GetSrvType(g_bcManager[bcId].srvType), bcId, g_bcManager[bcId].adapterBcId);
    SoftBusMutexUnlock(&g_bcLock);
    ret = g_interface[g_interfaceId]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnStopBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return ret;
    }

    g_bcManager[bcId].bcCallback->OnStopBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
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
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100) {
        return SCAN_FREQ_P100_1000_1000;
    }
    return SCAN_FREQ_LOW_POWER;
}

static bool NeedUpdateScan(int32_t listenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), false, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopScan != NULL, false, DISC_BLE, "function is null!");
    bool isNeedReset = false;
    bool isScanning = false;
    int32_t adapterScanId = g_scanManager[listenerId].adapterScanId;

    for (int32_t managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (g_scanManager[managerId].adapterScanId != adapterScanId) {
            continue;
        }
        if (g_scanManager[managerId].isNeedReset) {
            isNeedReset = true;
        }
        if (g_scanManager[managerId].isScanning) {
            isScanning = true;
        }
    }
    if (!isScanning) {
        return true;
    }
    if (!isNeedReset) {
        DISC_LOGD(DISC_BLE, "no need reset");
        return false;
    }
    int32_t ret = g_interface[g_interfaceId]->StopScan(adapterScanId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return false;
    }
    return true;
}

static int32_t StartScanSub(int32_t listenerId)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    static uint32_t callCount = 0;
    SoftBusBcScanParams adapterParam;
    BuildSoftBusBcScanParams(&g_scanManager[listenerId].param, &adapterParam);

    CheckScanFreq(listenerId, &adapterParam);

    int32_t filterSize = 0;
    SoftBusBcScanFilter *adapterFilter = NULL;

    if (!NeedUpdateScan(listenerId)) {
        DISC_LOGD(DISC_BLE, "no need update scan");
        return SOFTBUS_OK;
    }
    DISC_LOGD(DISC_BLE, "need update scan");
    GetBcScanFilters(listenerId, &adapterFilter, &filterSize);
    DISC_CHECK_AND_RETURN_RET_LOGE(filterSize > 0, SOFTBUS_BC_MGR_START_SCAN_NO_FILTER, DISC_BLE, "fitersize is 0!");
    DumpBcScanFilter(adapterFilter, filterSize);

    DISC_LOGI(DISC_BLE, "start service srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d,"
        "interval=%{public}hu, window=%{public}hu, callCount=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId,
        adapterParam.scanInterval, adapterParam.scanWindow, callCount++);
    int32_t ret = g_interface[g_interfaceId]->StartScan(g_scanManager[listenerId].adapterScanId, &adapterParam,
        adapterFilter, filterSize);
    SoftBusFree(adapterFilter);
    if (ret != SOFTBUS_OK) {
        g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t StartScan(int32_t listenerId, const BcScanParams *param)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. listenerId=%{public}d, callCount=%{public}u", listenerId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartScan != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    g_scanManager[listenerId].param = *param;
    g_scanManager[listenerId].freq = GetScanFreq(param->scanInterval, param->scanWindow);

    ret = StartScanSub(listenerId);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    g_scanManager[listenerId].isScanning = true;
    g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t StopScan(int32_t listenerId)
{
    static uint32_t callCount = 0;
    DISC_LOGI(DISC_BLE, "enter. listenerId=%{public}d, callCount=%{public}u", listenerId, callCount++);
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopScan != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }
    DISC_LOGI(DISC_BLE, "srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d, callCount=%{public}u",
        GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId, callCount);
    if (!g_scanManager[listenerId].isScanning) {
        DISC_LOGI(DISC_BLE, "listenerId is not scanning. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_OK;
    }

    ret = CheckAndStopScan(listenerId);
    if (ret != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    g_scanManager[listenerId].isScanning = false;
    g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "param is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterNum != 0, SOFTBUS_INVALID_PARAM, DISC_BLE, "filterNum is 0!");
    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].filter = (BcScanFilter *)scanFilter;
    g_scanManager[listenerId].filterSize = filterNum;
    g_scanManager[listenerId].isNeedReset = true;
    DISC_LOGI(DISC_BLE, "srvType=%{public}s, listenerId=%{public}d, adapterId=%{public}d",
              GetSrvType(g_scanManager[listenerId].srvType), listenerId, g_scanManager[listenerId].adapterScanId);
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t GetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param scanFilter!");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterNum != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param filterNum!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId. listenerId=%{public}d", listenerId);
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
    DISC_LOGI(DISC_BLE, "enter.");
    (void)bcId;
    (void)status;
    return SOFTBUS_OK;
}

bool BroadcastIsLpDeviceAvailable(void)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), false, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->IsLpDeviceAvailable != NULL,
                                   false, DISC_BLE, "function is null!");

    return g_interface[g_interfaceId]->IsLpDeviceAvailable();
}

bool BroadcastSetAdvDeviceParam(SensorHubServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcParam != NULL, false, DISC_BLE, "invalid param bcParam!");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanParam != NULL, false, DISC_BLE, "invalid param scanParam!");
    DISC_CHECK_AND_RETURN_RET_LOGE(type < SOFTBUS_UNKNOW_TYPE && type >= SOFTBUS_HEARTBEAT_TYPE,
        false, DISC_BLE, "invalid app type!");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), false, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetAdvFilterParam != NULL,
                                   false, DISC_BLE, "function is null!");

    SoftBusLpBroadcastParam bcDstParam = {0};
    SoftBusLpScanParam scanDstParam = {0};

    bcDstParam.advHandle = bcParam->bcHandle;
    ConvertBcParams(&bcParam->bcParam, &bcDstParam.advParam);

    int32_t ret = BuildSoftbusBroadcastData(&bcParam->packet, &bcDstParam.advData);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, DISC_BLE, "Build SoftbusBroadcastData failed!");

    BuildSoftBusBcScanParams(&scanParam->scanParam, &scanDstParam.scanParam);
    BcScanFilter *scanFilter = NULL;
    uint8_t filterNum = 0;
    ret = GetScanFilter(scanParam->listenerId, &scanFilter, &filterNum);
    if (ret != SOFTBUS_OK || scanFilter == NULL || filterNum == 0) {
        DISC_LOGE(DISC_BLE, "get listenerId filters failed! listenerId=%{public}d", scanParam->listenerId);
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    scanDstParam.filter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * (filterNum));
    if (scanDstParam.filter == NULL) {
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    scanDstParam.filterSize = filterNum;
    CovertSoftBusBcScanFilters(scanFilter, filterNum, scanDstParam.filter);

    ret = g_interface[g_interfaceId]->SetAdvFilterParam(type, &bcDstParam, &scanDstParam);
    if (!ret) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusFree(scanDstParam.filter);
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    ReleaseSoftbusBroadcastData(&bcDstParam.advData);
    SoftBusFree(scanDstParam.filter);
    return true;
}

int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->GetBroadcastHandle != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->GetBroadcastHandle(g_bcManager[bcId].adapterBcId, bcHandle);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t BroadcastEnableSyncDataToLpDevice(void)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->EnableSyncDataToLpDevice != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->EnableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

int32_t BroadcastDisableSyncDataToLpDevice(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DisableSyncDataToLpDevice != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->DisableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetScanReportChannelToLpDevice != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId. listenerId=%{public}d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_BC_MGR_INVALID_LISN_ID;
    }

    ret = g_interface[g_interfaceId]->SetScanReportChannelToLpDevice(g_scanManager[listenerId].adapterScanId, enable);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t BroadcastSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
                               int32_t interval, int32_t bcHandle)
{
    DISC_LOGI(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(CheckMediumIsValid(g_interfaceId), SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid id!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_BC_MGR_NO_FUNC_REGISTERED,
                                   DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetLpDeviceParam != NULL,
                                   SOFTBUS_BC_MGR_FUNC_NULL, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->SetLpDeviceParam(duration, maxExtAdvEvents, window, interval, bcHandle);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

static int32_t RegisterInfoDump(int fd)
{
    SOFTBUS_DPRINTF(fd, "\n---------------------------Register Broadcaster Info-------------------------\n");
    SOFTBUS_DPRINTF(fd, "max broadcaster num                   : %d\n", BC_NUM_MAX);
    int32_t managerId;
    for (managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        if (!g_bcManager[managerId].isUsed) {
            continue;
        }
        BroadcastManager *bcManager = &g_bcManager[managerId];
        SOFTBUS_DPRINTF(fd, "managerId                             : %d\n", managerId);
        SOFTBUS_DPRINTF(fd, "serviceType                           : %s\n", GetSrvType(bcManager->srvType));
        SOFTBUS_DPRINTF(fd, "adapterBcId                           : %d\n", bcManager->adapterBcId);
        SOFTBUS_DPRINTF(fd, "isAdvertising(0 - false, 1 - true)    : %d\n\n", bcManager->isAdvertising);
    }

    SOFTBUS_DPRINTF(fd, "\n---------------------------Register Listener Info----------------------------\n");
    SOFTBUS_DPRINTF(fd, "max listener num                      : %d\n", SCAN_NUM_MAX);
    for (managerId = 0; managerId < SCAN_NUM_MAX; managerId++) {
        if (!g_scanManager[managerId].isUsed) {
            continue;
        }
        ScanManager *scanManager = &g_scanManager[managerId];
        SOFTBUS_DPRINTF(fd, "managerId                             : %d\n", managerId);
        SOFTBUS_DPRINTF(fd, "serviceType                           : %s\n", GetSrvType(scanManager->srvType));
        SOFTBUS_DPRINTF(fd, "adapterScanId                         : %d\n", scanManager->adapterScanId);
        SOFTBUS_DPRINTF(fd, "isNeedReset(0 - false, 1 - true)      : %d\n", scanManager->isNeedReset);
        SOFTBUS_DPRINTF(fd, "isScanning(0 - false, 1 - true)       : %d\n", scanManager->isScanning);
        SOFTBUS_DPRINTF(fd, "scan freq(0 - low power, 1 - 60/3000, 2 - 30/300, 3 - 60/240, 4 - 1000/1000,\n");
        SOFTBUS_DPRINTF(fd, "                                      : %d\n\n", scanManager->freq);
    }
    return SOFTBUS_OK;
}
