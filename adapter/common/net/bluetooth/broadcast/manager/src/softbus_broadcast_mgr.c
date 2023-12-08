/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <stdint.h>

#include "securec.h"

#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_ble_gatt.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_broadcast_manager.h"
#include "softbus_broadcast_utils.h"
#include "softbus_errcode.h"
#include "softbus_log_old.h"
#include "softbus_utils.h"

#define BC_WAIT_TIME_SEC 2

static volatile bool g_mgrLockInit = false;
static SoftBusMutex g_bcLock = {0};
static SoftBusMutex g_scanLock = {0};

typedef struct {
    BaseServiceType srvType;
    int32_t adapterBcId;
    bool isUsed;
    bool isAdvertising;
    SoftBusCond cond;
    BroadcastCallback *bcCallback;
} BroadcastManager;

typedef enum {
    SCAN_FREQ_LOW_POWER,
    SCAN_FREQ_P2_60_3000,
    SCAN_FREQ_P10_60_600,
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

int32_t RegisterBroadcastMediumFunction(SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface)
{
    DISC_LOGD(DISC_BLE, "enter, register type = %d.", type);
    DISC_CHECK_AND_RETURN_RET_LOGE(interface != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "interface is null!");

    g_interface[type] = (SoftbusBroadcastMediumInterface *)interface;
    return SOFTBUS_OK;
}

static int32_t BcManagerLockInit(void)
{
    DISC_LOGD(DISC_BLE, "enter.");
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
    DISC_LOGD(DISC_BLE, "enter.");
    int32_t ret = BcManagerLockInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "lock init fail!");
    
    SoftbusBleAdapterInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->Init != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");
    ret = g_interface[g_interfaceId]->Init();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

static bool CheckLockIsInit(SoftBusMutex *lock)
{
    if (SoftBusMutexLock(lock) != 0) {
        return false;
    }
    SoftBusMutexUnlock(lock);
    return true;
}

int32_t DeInitBroadcastMgr(void)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DeInit != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->DeInit();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    if (CheckLockIsInit(&g_bcLock)) {
        (void)SoftBusMutexDestroy(&g_bcLock);
    }
    if (CheckLockIsInit(&g_scanLock)) {
        (void)SoftBusMutexDestroy(&g_scanLock);
    }
    g_mgrLockInit = false;
    return SOFTBUS_OK;
}

static void BcStartBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStartBroadcastingCallback == NULL) {
            continue;
        }
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterBcId = %d, status = %d", bcManager->srvType,
                  managerId, adapterBcId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isAdvertising = true;
            SoftBusCondSignal(&bcManager->cond);
        }

        bcManager->bcCallback->OnStartBroadcastingCallback(managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcStopBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnStopBroadcastingCallback == NULL) {
            continue;
        }
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterBcId = %d, status = %d", bcManager->srvType,
            managerId, adapterBcId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            bcManager->isAdvertising = false;
            SoftBusCondSignal(&bcManager->cond);
        }

        bcManager->bcCallback->OnStopBroadcastingCallback(managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcUpdateBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnUpdateBroadcastingCallback == NULL) {
            continue;
        }
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterBcId = %d, status = %d", bcManager->srvType,
            managerId, adapterBcId, status);

        bcManager->bcCallback->OnUpdateBroadcastingCallback(managerId, status);
        break; // The broadcast channel cannot be multiplexed.
    }
}

static void BcSetBroadcastingCallback(int32_t adapterBcId, int32_t status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    for (uint32_t managerId = 0; managerId < BC_NUM_MAX; managerId++) {
        BroadcastManager *bcManager = &g_bcManager[managerId];
        if (bcManager->adapterBcId != adapterBcId || !bcManager->isUsed || bcManager->bcCallback == NULL ||
            bcManager->bcCallback->OnSetBroadcastingCallback == NULL) {
            continue;
        }
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterBcId = %d, status = %d", bcManager->srvType,
                  managerId, adapterBcId, status);

        bcManager->bcCallback->OnSetBroadcastingCallback(managerId, status);
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
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterScanId = %d, status = %d", scanManager->srvType,
                  managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = true;
        }

        scanManager->scanCallback->OnStartScanCallback(managerId, status);
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
        DISC_LOGD(DISC_BLE, "srvType = %d, managerId = %u, adapterScanId = %d, status = %d", scanManager->srvType,
                  managerId, adapterScanId, status);
        if (status == SOFTBUS_BC_STATUS_SUCCESS) {
            scanManager->isScanning = false;
        }

        scanManager->scanCallback->OnStopScanCallback(managerId, status);
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

    if (memcpy_s(bcInfo->addr.addr, BC_ADDR_MAC_LEN, reportData->addr.addr, BC_ADDR_MAC_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "ConvertScanResult memcpy addr fail");
        return SOFTBUS_MEM_ERR;
    }

    for (int32_t i = 0; i < BC_LOCAL_NAME_LEN_MAX; i++) {
        bcInfo->localName[i] = reportData->localName[i];
    }
    return SOFTBUS_OK;
}

static bool CheckManufactureIsMatch(const BcScanFilter filter, BroadcastPayload *bcData)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter.manufactureDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGD(DISC_BLE, "payload is too short!");
        return false;
    }
    if (filter.manufactureId != bcData->id) {
        DISC_LOGD(DISC_BLE, "manufactureId not match!");
        return false;
    }
    for (uint32_t i = 0; i < filterLen; i++) {
        if ((filter.manufactureData[i] & filter.manufactureDataMask[i]) !=
            (bcData->payload[i] & filter.manufactureDataMask[i])) {
            DISC_LOGE(DISC_BLE, "not match! i = %u", i);
            return false;
        }
    }
    return true;
}

static bool CheckServiceIsMatch(const BcScanFilter filter, BroadcastPayload *bcData)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t dataLen = bcData->payloadLen;
    uint32_t filterLen = filter.serviceDataLength;
    if ((uint32_t)dataLen < filterLen) {
        DISC_LOGW(DISC_BLE, "payload is too short!");
        return false;
    }
    if (filter.serviceUuid != bcData->id) {
        DISC_LOGW(DISC_BLE, "serviceUuid not match!");
        return false;
    }
    for (uint32_t i = 0; i < filterLen; i++) {
        if ((filter.serviceData[i] & filter.serviceDataMask[i]) != (bcData->payload[i] & filter.serviceDataMask[i])) {
            DISC_LOGW(DISC_BLE, "not match! i = %u", i);
            return false;
        }
    }
    return true;
}

static bool CheckScanResultDataIsMatch(const uint32_t managerId, BroadcastPayload *bcData)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t filterSize = g_scanManager[managerId].filterSize;
    for (uint8_t i = 0; i < filterSize; i++) {
        BcScanFilter filter = g_scanManager[managerId].filter[i];
        if (bcData->type == BC_DATA_TYPE_SERVICE) {
            DISC_LOGD(DISC_BLE, "check service filter");
            if (CheckServiceIsMatch(filter, bcData)) {
                return true;
            }
        } else if (bcData->type == BC_DATA_TYPE_MANUFACTURER) {
            DISC_LOGD(DISC_BLE, "check manufacture filter");
            if (CheckManufactureIsMatch(filter, bcData)) {
                return true;
            }
        } else {
            DISC_LOGE(DISC_BLE, "not support type %u", bcData->type);
            return false;
        }
    }
    return false;
}

static void DumpSoftbusData(const char *description, uint16_t len, uint8_t *data)
{
    DISC_CHECK_AND_RETURN_LOGE(description != NULL, DISC_BLE, "data is null!");
    DISC_CHECK_AND_RETURN_LOGE(len != 0, DISC_BLE, "len is 0!");
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_BLE, "data is null!");

    int32_t hexLen = HEXIFY_LEN(len);
    char *softbusData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
    DISC_CHECK_AND_RETURN_LOGE(softbusData != NULL, DISC_BLE, "malloc failed!");

    (void)ConvertBytesToHexString(softbusData, hexLen, data, len);
    DISC_LOGI(DISC_BLE, "%s softbusData:%s", description, softbusData);

    SoftBusFree(softbusData);
}

static void ReleaseBroadcastReportInfo(BroadcastReportInfo *bcInfo)
{
    DISC_LOGD(DISC_BLE, "enter.");
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

    dstData->payload = (uint8_t *)SoftBusCalloc(maxPayloadLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(dstData->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BLE, "malloc failed!");

    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "build broadcast payload failed!");

    DumpSoftbusData("scan result bcData:", softbusBcData->bcData.payloadLen, softbusBcData->bcData.payload);

    // 2.2. Build broadcast response payload.
    if (softbusBcData->rspData.payload == NULL) {
        packet->rspData.payload = NULL;
        DISC_LOGW(DISC_BLE, "no rspData!");
    } else {
        maxPayloadLen = RSP_DATA_MAX_LEN;
        ret = BuildBcPayload(maxPayloadLen, &(softbusBcData->rspData), &(packet->rspData));
        if (ret != SOFTBUS_OK) {
            SoftBusFree(packet->bcData.payload);
            DISC_LOGE(DISC_BLE, "build broadcast rsp payload failed!");
            return SOFTBUS_ERR;
        }
        DumpSoftbusData("scan result rspData:", softbusBcData->rspData.payloadLen, softbusBcData->rspData.payload);
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
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "build broadcast BroadcastPacket failed!");

    return SOFTBUS_OK;
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
            !CheckScanResultDataIsMatch(managerId, &(bcInfo.packet.bcData))) {
                DISC_LOGE(DISC_BLE, "not match managerId %d.", managerId);
            SoftBusMutexUnlock(&g_scanLock);
            continue;
        }

        DISC_LOGD(DISC_BLE, "service srvType = %d, managerId = %u, adapterScanId = %d",
                  scanManager->srvType, managerId, adapterScanId);
        SoftBusMutexUnlock(&g_scanLock);
        scanManager->scanCallback->OnReportScanDataCallback(managerId, &bcInfo);
    }
    ReleaseBroadcastReportInfo(&bcInfo);
}

static SoftbusScanCallback g_softbusBcBleScanCb = {
    .OnStartScanCallback = BcOnStartScanCallback,
    .OnStopScanCallback = BcStopScanCallback,
    .OnReportScanDataCallback = BcReportScanDataCallback,
};

int32_t RegisterBroadcaster(BaseServiceType srvType, int32_t *bcId, const BroadcastCallback *cb)
{
    DISC_LOGD(DISC_BLE, "enter.");
    int32_t ret = 0;
    int32_t adapterBcId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(bcId != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param bcId!");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterBroadcaster != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

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
        return SOFTBUS_ERR;
    }
    DISC_LOGD(DISC_BLE, "BaseServiceType = %d, managerId = %d, adapterBcId = %d", srvType, managerId, adapterBcId);

    *bcId = managerId;
    g_bcManager[managerId].srvType = srvType;
    g_bcManager[managerId].adapterBcId = adapterBcId;
    g_bcManager[managerId].isUsed = true;
    g_bcManager[managerId].isAdvertising = false;
    SoftBusCondInit(&g_bcManager[managerId].cond);
    g_bcManager[managerId].bcCallback = (BroadcastCallback *)cb;
    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static bool CheckBcIdIsValid(int32_t bcId)
{
    if (bcId < 0 || bcId >= BC_NUM_MAX || !g_bcManager[bcId].isUsed) {
        DISC_LOGE(DISC_BLE, "invalid param bcId = %d", bcId);
        return false;
    }
    return true;
}

int32_t UnRegisterBroadcaster(int32_t bcId)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterBroadcaster != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckBcIdIsValid(bcId)) {
        DISC_LOGE(DISC_BLE, "bcId is invalid");
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_INVALID_PARAM;
    }

    ret = g_interface[g_interfaceId]->UnRegisterBroadcaster(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    if (g_bcManager[bcId].isAdvertising) {
        ret = StopBroadcasting(bcId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "stop broadcasting fail!");
            SoftBusMutexUnlock(&g_bcLock);
            return ret;
        }
    }
    g_bcManager[bcId].srvType = -1;
    g_bcManager[bcId].adapterBcId = -1;
    g_bcManager[bcId].isUsed = false;
    g_bcManager[bcId].isAdvertising = false;
    SoftBusCondDestroy(&g_bcManager[bcId].cond);
    g_bcManager[bcId].bcCallback = NULL;

    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

int32_t RegisterScanListener(BaseServiceType srvType, int32_t *listenerId, const ScanCallback *cb)
{
    DISC_LOGD(DISC_BLE, "enter.");
    int32_t ret = 0;
    int32_t adapterScanId = -1;
    DISC_CHECK_AND_RETURN_RET_LOGE(listenerId != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param listenerId!");
    DISC_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param cb!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->RegisterScanListener != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    ret = g_interface[g_interfaceId]->RegisterScanListener(&adapterScanId, &g_softbusBcBleScanCb);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_scanLock);
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
        return SOFTBUS_ERR;
    }
    DISC_LOGD(DISC_BLE, "BaseServiceType = %d, managerId = %d, adapterScanId = %d", srvType, managerId, adapterScanId);
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
        DISC_LOGE(DISC_BLE, "invalid param listenerId = %d", listenerId);
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

int32_t UnRegisterScanListener(int32_t listenerId)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->UnRegisterScanListener != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_INVALID_PARAM;
    }

    ret = g_interface[g_interfaceId]->UnRegisterScanListener(g_scanManager[listenerId].adapterScanId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    if (g_scanManager[listenerId].isScanning) {
        ret = StopScan(listenerId);
        if (ret != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "stop scan fail!");
            SoftBusMutexUnlock(&g_scanLock);
            return ret;
        }
    }
    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].srvType = -1;
    g_scanManager[listenerId].adapterScanId = -1;
    g_scanManager[listenerId].isUsed = false;
    g_scanManager[listenerId].isNeedReset = true;
    g_scanManager[listenerId].freq = SCAN_FREQ_BUTT;
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
    if (memcpy_s(dstParam->peerAddr.addr, BC_ADDR_MAC_LEN, srcParam->peerAddr.addr, BC_ADDR_MAC_LEN) != EOK) {
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
}

static void DumpBroadcastPacket(const BroadcastPayload *bcData, const BroadcastPayload *rspData)
{
    DumpSoftbusData("BroadcastPayload bcData:", bcData->payloadLen, bcData->payload);
    DumpSoftbusData("BroadcastPayload rspData:", rspData->payloadLen, rspData->payload);
}

static int32_t SoftBusCondWaitTwoSec(int32_t bcId, SoftBusMutex *mutex)
{
    SoftBusSysTime absTime = {0};
    if (SoftBusGetTime(&absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "softbus get time failed");
        return SOFTBUS_ERR;
    }

    absTime.sec += BC_WAIT_TIME_SEC;
    if (SoftBusCondWait(&g_bcManager[bcId].cond, mutex, &absTime) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "wait timeout");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BuildSoftbusBcPayload(int32_t maxPayloadLen, const BroadcastPayload *srcData,
                                     SoftbusBroadcastPayload *dstData)
{
    dstData->type = (SoftbusBcDataType)srcData->type;
    dstData->id = srcData->id;
    dstData->payloadLen = srcData->payloadLen;

    int32_t bcDataLen = (srcData->payloadLen > maxPayloadLen) ? maxPayloadLen : srcData->payloadLen;

    dstData->payload = (uint8_t *)SoftBusCalloc(maxPayloadLen);
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

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param packet!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet->bcData.payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE,
                                   "invalid param payload!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartBroadcasting != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");
    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_ERR;
    }
    if (g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "wait condition managerId: %d", bcId);
        if (SoftBusCondWaitTwoSec(bcId, &g_bcLock) != SOFTBUS_OK) {
            DISC_LOGE(DISC_BLE, "SoftBusCondWaitTwoSec failed");
            SoftBusMutexUnlock(&g_bcLock);
            return SOFTBUS_ERR;
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
    DISC_LOGD(DISC_BLE, "start service srvType = %d, managerId = %d, adapterId = %d",
              g_bcManager[bcId].srvType, bcId, g_bcManager[bcId].adapterBcId);
    ret = g_interface[g_interfaceId]->StartBroadcasting(g_bcManager[bcId].adapterBcId, &adapterParam, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnStartBroadcastingCallback(bcId, SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        ReleaseSoftbusBroadcastData(&softbusBcData);
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invald param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invald param packet!");

    int ret = StopBroadcasting(bcId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "StopBroadcasting fail");
    
    return StartBroadcasting(bcId, param, packet);
}

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(packet != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param packet!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetBroadcastingData != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_ERR;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "managerId = %d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_ERR;
    }

    DISC_LOGD(DISC_BLE, "replace BroadcastPacket srvType = %d, managerId = %d, adapterId = %d",
              g_bcManager[bcId].srvType, bcId, g_bcManager[bcId].adapterBcId);
    SoftbusBroadcastData softbusBcData = {0};
    ret = BuildSoftbusBroadcastData(packet, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Build SoftbusBroadcastData failed!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    ret = g_interface[g_interfaceId]->SetBroadcastingData(g_bcManager[bcId].adapterBcId, &softbusBcData);
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnSetBroadcastingCallback(bcId, SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        ReleaseSoftbusBroadcastData(&softbusBcData);
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    ReleaseSoftbusBroadcastData(&softbusBcData);
    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

int32_t StopBroadcasting(int32_t bcId)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopBroadcasting != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_bcLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckBcIdIsValid(bcId)) {
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_ERR;
    }

    if (!g_bcManager[bcId].isAdvertising) {
        DISC_LOGW(DISC_BLE, "managerId = %d is not advertising", bcId);
        SoftBusMutexUnlock(&g_bcLock);
        return SOFTBUS_ERR;
    }

    DISC_LOGD(DISC_BLE, "stop service srvType = %d, managerId = %d, adapterId = %d",
              g_bcManager[bcId].srvType, bcId, g_bcManager[bcId].adapterBcId);
    ret = g_interface[g_interfaceId]->StopBroadcasting(g_bcManager[bcId].adapterBcId);
    if (ret != SOFTBUS_OK) {
        g_bcManager[bcId].bcCallback->OnStopBroadcastingCallback(bcId, SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_bcLock);
        return ret;
    }

    g_bcManager[bcId].bcCallback->OnStopBroadcastingCallback(bcId, SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_bcLock);
    return SOFTBUS_OK;
}

static int32_t GetScanFreq(uint16_t scanInterval, uint16_t scanWindow)
{
    DISC_LOGD(DISC_BLE, "enter.");
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P2 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P2) {
        return SCAN_FREQ_P2_60_3000;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P10 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P10) {
        return SCAN_FREQ_P10_60_600;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P25 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P25) {
        return SCAN_FREQ_P25_60_240;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100) {
        return SCAN_FREQ_P100_1000_1000;
    }
    return SCAN_FREQ_LOW_POWER;
}

static void DumpBcScanFilter(SoftBusBcScanFilter *nativeFilter, uint8_t filterSize)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE, "invalid param nativeFilter!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize != 0, DISC_BLE, "filterSize is 0!");

    while (filterSize-- > 0) {
        int32_t len = (nativeFilter + filterSize)->serviceDataLength;
        if (len > 0) {
            DumpSoftbusData("service data:", len, (nativeFilter + filterSize)->serviceData);
            DumpSoftbusData("service dataMask:", len, (nativeFilter + filterSize)->serviceDataMask);
        } else {
            len = (nativeFilter + filterSize)->manufactureDataLength;
            if (len <= 0) {
                continue;
            }
            DumpSoftbusData("manufacture data:", len, (nativeFilter + filterSize)->manufactureData);
            DumpSoftbusData("manufacture dataMask:", len, (nativeFilter + filterSize)->manufactureDataMask);
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

static void CovertSoftBusBcScanFilters(const BcScanFilter *filter, uint8_t filterSize,
                                       SoftBusBcScanFilter *adapterFilter)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t size = filterSize;

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
    }
}

static void BuildSoftBusBcScanFilters(int32_t listenerId, SoftBusBcScanFilter **adapterFilter, int32_t *filterSize)
{
    DISC_LOGD(DISC_BLE, "enter.");
    uint8_t size = g_scanManager[listenerId].filterSize;
    BcScanFilter *filter = g_scanManager[listenerId].filter;

    *adapterFilter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * size);
    if (*adapterFilter == NULL) {
        return;
    }
    *filterSize = size;

    CovertSoftBusBcScanFilters(filter, size, *adapterFilter);
}

int32_t StartScan(int32_t listenerId, const BcScanParams *param)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StartScan != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId: %d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_ERR;
    }
    g_scanManager[listenerId].param = *param;
    g_scanManager[listenerId].freq = GetScanFreq(param->scanInterval, param->scanWindow);
    
    SoftBusBcScanParams adapterParam;
    BuildSoftBusBcScanParams(param, &adapterParam);

    int32_t filterSize;
    SoftBusBcScanFilter *adapterFilter = NULL;
    BuildSoftBusBcScanFilters(listenerId, &adapterFilter, &filterSize);
    DumpBcScanFilter(adapterFilter, filterSize);

    ret = g_interface[g_interfaceId]->StartScan(g_scanManager[listenerId].adapterScanId, &adapterParam,
                                                adapterFilter, filterSize);
    SoftBusFree(adapterFilter);
    if (ret != SOFTBUS_OK) {
        g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    g_scanManager[listenerId].isScanning = true;
    g_scanManager[listenerId].scanCallback->OnStartScanCallback(listenerId, SOFTBUS_BC_STATUS_SUCCESS);

    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t StopScan(int32_t listenerId)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->StopScan != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId: %d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_ERR;
    }
    if (!g_scanManager[listenerId].isScanning) {
        DISC_LOGI(DISC_BLE, "listenerId %d is not scanning", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_OK;
    }

    ret = g_interface[g_interfaceId]->StopScan(g_scanManager[listenerId].adapterScanId);
    if (ret != SOFTBUS_OK) {
        g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, SOFTBUS_BC_STATUS_FAIL);
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        SoftBusMutexUnlock(&g_scanLock);
        return ret;
    }

    g_scanManager[listenerId].isScanning = false;
    g_scanManager[listenerId].scanCallback->OnStopScanCallback(listenerId, SOFTBUS_BC_STATUS_SUCCESS);

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
        DISC_LOGE(DISC_BLE, "invalid param listenerId: %d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_ERR;
    }

    ReleaseBcScanFilter(listenerId);
    g_scanManager[listenerId].filter = (BcScanFilter *)scanFilter;
    g_scanManager[listenerId].filterSize = filterNum;
    g_scanManager[listenerId].isNeedReset = true;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t GetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanFilter != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param scanFilter!");
    DISC_CHECK_AND_RETURN_RET_LOGE(filterNum != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "invalid param filterNum!");
    DISC_CHECK_AND_RETURN_RET_LOGE((listenerId >= 0 && listenerId < SCAN_NUM_MAX), SOFTBUS_INVALID_PARAM, DISC_BLE,
                                   "invalid param scanFilter!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    *scanFilter = g_scanManager[listenerId].filter;
    *filterNum = g_scanManager[listenerId].filterSize;
    SoftBusMutexUnlock(&g_scanLock);
    return SOFTBUS_OK;
}

int32_t QueryBroadcastStatus(int32_t bcId, int32_t *status)
{
    DISC_LOGD(DISC_BLE, "enter.");
    (void)bcId;
    (void)status;
    return SOFTBUS_OK;
}

bool BroadcastIsLpDeviceAvailable(void)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, false, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->IsLpDeviceAvailable != NULL,
                                   false, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->IsLpDeviceAvailable();
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return false;
    }
    return true;
}

bool BroadcastSetAdvDeviceParam(const LpBroadcastParam *bcParam, const LpScanParam *scanParam)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(bcParam != NULL, false, DISC_BLE, "invalid param bcParam!");
    DISC_CHECK_AND_RETURN_RET_LOGE(scanParam != NULL, false, DISC_BLE, "invalid param scanParam!");
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
    ret = GetScanFilter(scanParam->listenerId, &filters, &filterNum);
    if (ret != SOFTBUS_OK || scanFilter == NULL || filterNum == 0) {
        DISC_LOGE(DISC_BLE, "get listenerId [%d] filters failed!", scanParam->listenerId);
        ReleaseSoftbusBroadcastData(&bcDstParam.advData);
        return false;
    }
    scanDstParam.filter = (SoftBusBcScanFilter *)SoftBusCalloc(sizeof(SoftBusBcScanFilter) * (filterNum));
    scanDstParam.filterSize = filterNum;
    CovertSoftBusBcScanFilters(scanFilter, filterNum, scanDstParam.filter);

    ret = g_interface[g_interfaceId]->SetAdvFilterParam(&bcDstParam, &scanDstParam);
    if (ret != SOFTBUS_OK) {
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
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->GetBroadcastHandle != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->GetBroadcastHandle(g_bcManager[bcId].adapterBcId, bcHandle);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "call from adapter fail!");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t BroadcastEnableSyncDataToLpDevice(void)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->EnableSyncDataToLpDevice != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->EnableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

int32_t BroadcastDisableSyncDataToLpDevice(void)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->DisableSyncDataToLpDevice != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->DisableSyncDataToLpDevice();
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}

int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetScanReportChannelToLpDevice != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = SoftBusMutexLock(&g_scanLock);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, DISC_BLE, "mutex err!");

    if (!CheckScanIdIsValid(listenerId)) {
        DISC_LOGE(DISC_BLE, "invalid param listenerId: %d", listenerId);
        SoftBusMutexUnlock(&g_scanLock);
        return SOFTBUS_ERR;
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
    DISC_LOGD(DISC_BLE, "enter.");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId] != NULL, SOFTBUS_ERR, DISC_BLE, "interface is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(g_interface[g_interfaceId]->SetLpDeviceParam != NULL,
                                   SOFTBUS_ERR, DISC_BLE, "function is null!");

    int32_t ret = g_interface[g_interfaceId]->SetLpDeviceParam(duration, maxExtAdvEvents, window, interval, bcHandle);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_BLE, "call from adapter fail!");

    return SOFTBUS_OK;
}
