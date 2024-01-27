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

#include "softbus_ble_gatt.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_type.h"
#include "softbus_error_code.h"
#include "softbus_ble_utils.h"
#include "disc_log.h"
#include <stdatomic.h>
#include <string.h>

#define GATT_ADV_MAX_NUM       16
#define GATT_SCAN_MAX_NUM      2
#define LP_BT_UUID             "43d4a49f-604d-45b5-9302-4ddbbfd538fd"
#define LP_DELIVERY_MODE_REPLY 0xF0
#define LP_ADV_DURATION_MS     0
#define SCAN_CHANNEL_0         0
#define SCAN_CHANNEL_1         1

static atomic_bool g_init = false;
static atomic_bool g_bcCbReg = false;
static SoftBusMutex g_advLock = { 0 };
static SoftBusMutex g_scannerLock = { 0 };

typedef struct {
    int32_t advId;
    bool isUsed;
    bool isAdvertising;
    SoftbusBroadcastCallback *advCallback;
} AdvChannel;

typedef struct {
    int32_t scannerId;
    bool isUsed;
    bool isScanning;
    SoftbusScanCallback *scanCallback;
} ScanChannel;

static AdvChannel g_advChannel[GATT_ADV_MAX_NUM];
static ScanChannel g_scanChannel[GATT_SCAN_MAX_NUM];

static int32_t Init(void)
{
    if (g_init) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already inited");
        return SOFTBUS_OK;
    }
    g_init = true;
    if (SoftBusMutexInit(&g_advLock, NULL) != SOFTBUS_OK) {
        g_init = false;
        DISC_LOGE(DISC_BLE_ADAPTER, "g_advLock init failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_scannerLock, NULL) != SOFTBUS_OK) {
        SoftBusMutexDestroy(&g_advLock);
        g_init = false;
        DISC_LOGE(DISC_BLE_ADAPTER, "g_scannerLock init failed");
        return SOFTBUS_ERR;
    }
    DISC_LOGI(DISC_BLE_ADAPTER, "init success");
    return SOFTBUS_OK;
}

static int32_t DeInit(void)
{
    if (!g_init) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already deinited");
        return SOFTBUS_OK;
    }
    g_init = false;
    SoftBusMutexDestroy(&g_advLock);
    SoftBusMutexDestroy(&g_scannerLock);
    DISC_LOGI(DISC_BLE_ADAPTER, "deinit success");
    return SOFTBUS_OK;
}

static void WrapperAdvEnableCallback(int advId, int status)
{
    int32_t ret = BtStatusToSoftBus((BtStatus)status);
    for (uint8_t channelId = 0; channelId < GATT_ADV_MAX_NUM; channelId++) {
        if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}u, bt-advId=%{public}d", channelId, advId);
            continue;
        }
        AdvChannel *advChannel = &g_advChannel[channelId];
        if (advChannel->advId != advId || !advChannel->isUsed) {
            SoftBusMutexUnlock(&g_advLock);
            continue;
        }
        advChannel->isAdvertising = (ret == SOFTBUS_BC_STATUS_SUCCESS);
        if (!advChannel->isAdvertising) {
            advChannel->advId = -1;
        }
        DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}u, bt-advId=%{public}d, status=%{public}d", channelId, advId, ret);
        SoftBusMutexUnlock(&g_advLock);
        if (advChannel->advCallback != NULL && advChannel->advCallback->OnStartBroadcastingCallback != NULL) {
            advChannel->advCallback->OnStartBroadcastingCallback(channelId, ret);
        }
        break;
    }
}

static void WrapperAdvDisableCallback(int advId, int status)
{
    int32_t ret = BtStatusToSoftBus((BtStatus)status);
    for (uint8_t channelId = 0; channelId < GATT_ADV_MAX_NUM; channelId++) {
        if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}u, bt-advId=%{public}d", channelId, advId);
            continue;
        }
        AdvChannel *advChannel = &g_advChannel[channelId];
        if (advChannel->advId != advId || !advChannel->isUsed) {
            SoftBusMutexUnlock(&g_advLock);
            continue;
        }
        advChannel->isAdvertising = false;
        advChannel->advId = -1;
        DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}u, bt-advId=%{public}d, status=%{public}d", channelId, advId, ret);
        SoftBusMutexUnlock(&g_advLock);
        if (advChannel->advCallback != NULL && advChannel->advCallback->OnStopBroadcastingCallback != NULL) {
            advChannel->advCallback->OnStopBroadcastingCallback(channelId, ret);
        }
        break;
    }
}

static void WrapperAdvSetDataCallback(int advId, int status)
{
    int32_t ret = BtStatusToSoftBus((BtStatus)status);
    for (uint32_t channelId = 0; channelId < GATT_ADV_MAX_NUM; channelId++) {
        if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}u, bt-advId=%{public}d", channelId, advId);
            continue;
        }
        AdvChannel *advChannel = &g_advChannel[channelId];
        if (advChannel->advId != advId || !advChannel->isUsed) {
            SoftBusMutexUnlock(&g_advLock);
            continue;
        }
        DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}u, bt-advId=%{public}d, status=%{public}d", channelId, advId, ret);
        SoftBusMutexUnlock(&g_advLock);
        if (advChannel->advCallback != NULL && advChannel->advCallback->OnSetBroadcastingCallback != NULL) {
            advChannel->advCallback->OnSetBroadcastingCallback(channelId, ret);
        }
        break;
    }
}

static void WrapperAdvUpdateDataCallback(int advId, int status)
{
    int32_t ret = BtStatusToSoftBus((BtStatus)status);
    for (uint32_t channelId = 0; channelId < GATT_ADV_MAX_NUM; channelId++) {
        if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}u, bt-advId=%{public}d", channelId, advId);
            continue;
        }
        AdvChannel *advChannel = &g_advChannel[channelId];
        if (advChannel->advId != advId || !advChannel->isUsed) {
            SoftBusMutexUnlock(&g_advLock);
            continue;
        }
        DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}u, bt-advId=%{public}d, status=%{public}d", channelId, advId, ret);
        SoftBusMutexUnlock(&g_advLock);
        if (advChannel->advCallback != NULL && advChannel->advCallback->OnUpdateBroadcastingCallback != NULL) {
            advChannel->advCallback->OnUpdateBroadcastingCallback(channelId, ret);
        }
        break;
    }
}

static BtGattCallbacks g_softbusGattCb = {
    .advEnableCb = WrapperAdvEnableCallback,
    .advDisableCb = WrapperAdvDisableCallback,
    .advDataCb = WrapperAdvSetDataCallback,
    .advUpdateCb = WrapperAdvUpdateDataCallback,
};

static int32_t RegisterAdvCallback(int32_t *advId, const SoftbusBroadcastCallback *cb)
{
    if (advId == NULL || cb == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    for (uint8_t channelId = 0; channelId < GATT_ADV_MAX_NUM; channelId++) {
        if (g_advChannel[channelId].isUsed) {
            continue;
        }
        if (!g_bcCbReg) {
            if (BleGattRegisterCallbacks(&g_softbusGattCb) != OHOS_BT_STATUS_SUCCESS) {
                DISC_LOGE(DISC_BLE_ADAPTER, "register failed, advId=%{public}u", channelId);
                SoftBusMutexUnlock(&g_advLock);
                return SOFTBUS_ERR;
            }
            g_bcCbReg = true;
        }
        g_advChannel[channelId].advId = -1;
        g_advChannel[channelId].isUsed = true;
        g_advChannel[channelId].isAdvertising = false;
        g_advChannel[channelId].advCallback = (SoftbusBroadcastCallback *)cb;
        *advId = channelId;
        DISC_LOGI(DISC_BLE_ADAPTER, "register success, advId=%{public}u", channelId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_OK;
    }
    DISC_LOGE(DISC_BLE_ADAPTER, "no available adv channel");
    SoftBusMutexUnlock(&g_advLock);
    return SOFTBUS_ERR;
}

static int32_t UnRegisterAdvCallback(int32_t advId)
{
    if (advId < 0 || advId >= GATT_ADV_MAX_NUM) {
        DISC_LOGE(DISC_BLE_ADAPTER, "invalid advId=%{public}d", advId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, advId=%{public}d", advId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!g_advChannel[advId].isUsed) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already unregistered, advId=%{public}d, bt-advId=%{public}d", advId,
            g_advChannel[advId].advId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_OK;
    }
    DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}d, bt-advId=%{public}d", advId, g_advChannel[advId].advId);
    g_advChannel[advId].advId = -1;
    g_advChannel[advId].isUsed = false;
    g_advChannel[advId].isAdvertising = false;
    g_advChannel[advId].advCallback = NULL;
    SoftBusMutexUnlock(&g_advLock);
    return SOFTBUS_OK;
}

static void WrapperScanResultCallback(uint8_t channelId, BtScanResultData *data)
{
    if (data == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scan result data is null, scannerId=%{public}u", channelId);
        return;
    }
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}u", channelId);
        return;
    }
    ScanChannel *scanChannel = &g_scanChannel[channelId];
    if (!scanChannel->isUsed || !scanChannel->isScanning) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used, scannerId=%{public}u, bt-scannerId=%{public}d", channelId,
            scanChannel->scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return;
    }
    SoftBusBcScanResult scanResult = {};
    BtScanResultToSoftbus(data, &scanResult);

    if (ParseScanResult(data->advData, data->advLen, &scanResult) != SOFTBUS_OK) {
        SoftBusFree(scanResult.data.bcData.payload);
        SoftBusFree(scanResult.data.rspData.payload);
        SoftBusMutexUnlock(&g_scannerLock);
        return;
    }
    SoftBusMutexUnlock(&g_scannerLock);
    if (scanChannel->scanCallback != NULL && scanChannel->scanCallback->OnReportScanDataCallback != NULL) {
        scanChannel->scanCallback->OnReportScanDataCallback(channelId, &scanResult);
    }
    SoftBusFree(scanResult.data.bcData.payload);
    SoftBusFree(scanResult.data.rspData.payload);
}

static void WrapperScanStateChangeCallback(uint8_t channelId, int32_t resultCode, bool isStartScan)
{
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}u", channelId);
        return;
    }
    ScanChannel *scanChannel = &g_scanChannel[channelId];
    if (!scanChannel->isUsed) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used, scannerId=%{public}u, bt-scannerId=%{public}d", channelId,
            scanChannel->scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return;
    }
    DISC_LOGD(DISC_BLE_ADAPTER,
        "scannerId=%{public}d, bt-scannerId=%{public}d, resultCode=%{public}d, isStartScan=%{public}d", channelId,
        scanChannel->scannerId, resultCode, isStartScan);
    SoftBusMutexUnlock(&g_scannerLock);
    if (scanChannel->scanCallback != NULL && scanChannel->scanCallback->OnScanStateChanged != NULL) {
        scanChannel->scanCallback->OnScanStateChanged(resultCode, isStartScan);
    }
}

static void WrapperLpDeviceInfoCallback(uint8_t channelId, BtUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}u", channelId);
        return;
    }
    ScanChannel *scanChannel = &g_scanChannel[channelId];
    if (!scanChannel->isUsed) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used, scannerId=%{public}u, bt-scannerId=%{public}d", channelId,
            scanChannel->scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return;
    }
    SoftBusMutexUnlock(&g_scannerLock);
    if (scanChannel->scanCallback != NULL && scanChannel->scanCallback->OnLpDeviceInfoCallback != NULL) {
        SoftbusBroadcastUuid bcUuid;
        bcUuid.uuid = (uint8_t *)uuid->uuid;
        bcUuid.uuidLen = (uint8_t)uuid->uuidLen;
        scanChannel->scanCallback->OnLpDeviceInfoCallback(&bcUuid, type, data, dataSize);
    }
}

static void WrapperScanResultCallback0(BtScanResultData *data)
{
    WrapperScanResultCallback(SCAN_CHANNEL_0, data);
}

static void WrapperScanResultCallback1(BtScanResultData *data)
{
    WrapperScanResultCallback(SCAN_CHANNEL_1, data);
}

static void WrapperScanStateChangeCallback0(int32_t resultCode, bool isStartScan)
{
    WrapperScanStateChangeCallback(SCAN_CHANNEL_0, resultCode, isStartScan);
}

static void WrapperScanStateChangeCallback1(int32_t resultCode, bool isStartScan)
{
    WrapperScanStateChangeCallback(SCAN_CHANNEL_1, resultCode, isStartScan);
}

static void WrapperLpDeviceInfoCallback0(BtUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    WrapperLpDeviceInfoCallback(SCAN_CHANNEL_0, uuid, type, data, dataSize);
}

static void WrapperLpDeviceInfoCallback1(BtUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    WrapperLpDeviceInfoCallback(SCAN_CHANNEL_1, uuid, type, data, dataSize);
}

static BleScanCallbacks g_softbusBleScanCb[GATT_SCAN_MAX_NUM] = {
    {
        .scanResultCb = WrapperScanResultCallback0,
        .scanStateChangeCb = WrapperScanStateChangeCallback0,
        .lpDeviceInfoCb = WrapperLpDeviceInfoCallback0,
    },
    {
        .scanResultCb = WrapperScanResultCallback1,
        .scanStateChangeCb = WrapperScanStateChangeCallback1,
        .lpDeviceInfoCb = WrapperLpDeviceInfoCallback1,
    }
};

static BleScanCallbacks *GetAdapterScanCallback(uint8_t channelId)
{
    return &g_softbusBleScanCb[channelId];
}

static int32_t RegisterScanCallback(int32_t *scannerId, const SoftbusScanCallback *cb)
{
    if (scannerId == NULL || cb == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scan param is null");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    for (uint8_t channelId = 0; channelId < GATT_SCAN_MAX_NUM; channelId++) {
        if (g_scanChannel[channelId].isUsed) {
            continue;
        }
        if (BleRegisterScanCallbacks(GetAdapterScanCallback(channelId),
            &g_scanChannel[channelId].scannerId) != OHOS_BT_STATUS_SUCCESS) {
            DISC_LOGE(DISC_BLE_ADAPTER, "register callback failed, scannerId=%{public}u", channelId);
            SoftBusMutexUnlock(&g_scannerLock);
            return SOFTBUS_ERR;
        }
        g_scanChannel[channelId].isUsed = true;
        g_scanChannel[channelId].isScanning = false;
        g_scanChannel[channelId].scanCallback = (SoftbusScanCallback *)cb;
        *scannerId = channelId;
        DISC_LOGI(DISC_BLE_ADAPTER, "scannerId=%{public}u, bt-scannerId=%{public}d", channelId,
            g_scanChannel[channelId].scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_OK;
    }
    DISC_LOGE(DISC_BLE_ADAPTER, "no available scan channel");
    SoftBusMutexUnlock(&g_scannerLock);
    return SOFTBUS_ERR;
}

static int32_t UnRegisterScanCallback(int32_t scannerId)
{
    if (scannerId < 0 || scannerId >= GATT_SCAN_MAX_NUM) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scannerId is invalid=%{public}d", scannerId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}u", scannerId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!g_scanChannel[scannerId].isUsed) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already unregistered, scannerId=%{public}d, bt-scannerId=%{public}d", scannerId,
            g_scanChannel[scannerId].scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_OK;
    }
    int ret = BleDeregisterScanCallbacks(g_scanChannel[scannerId].scannerId);
    DISC_LOGI(DISC_BLE_ADAPTER, "scannerId=%{public}d, bt-scannerId=%{public}d, result=%{public}d",
        scannerId, g_scanChannel[scannerId].scannerId, ret);
    g_scanChannel[scannerId].scannerId = -1;
    g_scanChannel[scannerId].isUsed = false;
    g_scanChannel[scannerId].isScanning = false;
    g_scanChannel[scannerId].scanCallback = NULL;
    SoftBusMutexUnlock(&g_scannerLock);
    return SOFTBUS_OK;
}

static bool CheckAdvChannelInUsed(int32_t advId)
{
    if (advId < 0 || advId >= GATT_ADV_MAX_NUM) {
        DISC_LOGE(DISC_BLE_ADAPTER, "invalid advId=%{public}d", advId);
        return false;
    }
    if (!g_advChannel[advId].isUsed) {
        DISC_LOGE(DISC_BLE_ADAPTER, "advId=%{public}d, bt-advId=%{public}d", advId, g_advChannel[advId].advId);
        return false;
    }
    return true;
}

static int32_t StartBleAdv(int32_t advId, int *btAdvId, const SoftbusBroadcastParam *param,
    const SoftbusBroadcastData *data)
{
    BleAdvParams advParam = {};
    SoftbusAdvParamToBt(param, &advParam);
    StartAdvRawData advRawData = {};
    advRawData.advData = (unsigned char *)AssembleAdvData(data, (uint16_t *)&advRawData.advDataLen);
    if (advRawData.advData == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "assemble adv data failed, advId=%{public}d, bt-advId=%{public}d", advId, *btAdvId);
        return SOFTBUS_ERR;
    }
    advRawData.rspDataLen = 0;
    advRawData.rspData = NULL;
    if (data->rspData.payloadLen > 0 && data->rspData.payload != NULL) {
        advRawData.rspData = (unsigned char *)AssembleRspData(&data->rspData, (uint16_t *)&advRawData.rspDataLen);
        if (advRawData.rspData == NULL) {
            SoftBusFree(advRawData.advData);
            DISC_LOGE(DISC_BLE_ADAPTER, "assemble rsp data failed, advId=%{public}d, bt-advId=%{public}d",
                advId, *btAdvId);
            return SOFTBUS_ERR;
        }
    }
    int ret = BleStartAdvEx(btAdvId, advRawData, advParam);
    SoftBusFree(advRawData.advData);
    SoftBusFree(advRawData.rspData);
    return (ret == OHOS_BT_STATUS_SUCCESS) ? SOFTBUS_OK : SOFTBUS_ERR;
}

static int32_t StartAdv(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data)
{
    if (param == NULL || data == NULL || data->bcData.payloadLen == 0 || data->bcData.payload == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "invalid adv param, advId=%{public}d", advId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, advId=%{public}d", advId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv is not in used, advId=%{public}d", advId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int32_t btAdvId = g_advChannel[advId].advId;
    if (g_advChannel[advId].isAdvertising) {
        DISC_LOGE(DISC_BLE_ADAPTER, "already started, advId=%{public}d, bt-advId=%{public}d", advId, btAdvId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    g_advChannel[advId].isAdvertising = true;
    SoftBusMutexUnlock(&g_advLock);
    int32_t ret = StartBleAdv(advId, &btAdvId, param, data);
    DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}d, bt-advId=%{public}d, ret=%{public}d", advId, btAdvId, ret);
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, advId=%{public}d, btAdvId=%{public}d", advId, btAdvId);
        return SOFTBUS_LOCK_ERR;
    }
    g_advChannel[advId].advId = btAdvId;
    g_advChannel[advId].isAdvertising = (ret == SOFTBUS_OK);
    SoftBusMutexUnlock(&g_advLock);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t StopAdv(int32_t advId)
{
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}d", advId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv is not in used, advId=%{public}d", advId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int32_t btAdvId = g_advChannel[advId].advId;
    if (!g_advChannel[advId].isAdvertising) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already stopped, advId=%{public}d, bt-advId=%{public}d", advId, btAdvId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_OK;
    }
    g_advChannel[advId].isAdvertising = false;
    SoftBusMutexUnlock(&g_advLock);
    int ret = BleStopAdv(btAdvId);
    DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}d, bt-advId=%{public}d, ret=%{public}d", advId, btAdvId, ret);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetAdvData(int32_t advId, const SoftbusBroadcastData *data)
{
    if (data == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "data is null, advId=%{public}d", advId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}d", advId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv is not in used, advId=%{public}d", advId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int32_t btAdvId = g_advChannel[advId].advId;
    if (!g_advChannel[advId].isAdvertising) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv is not advertising, advId=%{public}d, bt-advId=%{public}d",
            advId, btAdvId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    SoftBusMutexUnlock(&g_advLock);
    StartAdvRawData advRawData = {};
    advRawData.advData = (unsigned char *)AssembleAdvData(data, (uint16_t *)&advRawData.advDataLen);
    if (advRawData.advData == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "assemble adv data failed, advId=%{public}d, bt-advId=%{public}d",
            advId, btAdvId);
        return SOFTBUS_ERR;
    }
    advRawData.rspDataLen = 0;
    advRawData.rspData = NULL;
    if (data->rspData.payloadLen > 0 && data->rspData.payload != NULL) {
        advRawData.rspData = (unsigned char *)AssembleRspData(&data->rspData, (uint16_t *)&advRawData.rspDataLen);
        if (advRawData.rspData == NULL) {
            SoftBusFree(advRawData.advData);
            DISC_LOGE(DISC_BLE_ADAPTER, "assemble rsp data failed, advId=%{public}d, bt-advId=%{public}d",
                advId, btAdvId);
            return SOFTBUS_ERR;
        }
    }
    int32_t ret = BtStatusToSoftBus(BleSetAdvData(btAdvId, advRawData));
    DISC_LOGI(DISC_BLE_ADAPTER, "advId=%{public}d, bt-advId=%{public}d, ret=%{public}d", advId, btAdvId, ret);
    SoftBusFree(advRawData.advData);
    SoftBusFree(advRawData.rspData);
    return ret;
}

static int32_t UpdateAdvData(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data)
{
    if (StopAdv(advId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "update adv data failed, advId=%{public}d", advId);
        return SOFTBUS_ERR;
    }
    DISC_LOGI(DISC_BLE_ADAPTER, "update adv data, advId=%{public}d", advId);
    return StartAdv(advId, param, data);
}

static bool CheckScanChannelInUsed(int32_t scannerId)
{
    if (scannerId < 0 || scannerId >= GATT_SCAN_MAX_NUM) {
        DISC_LOGE(DISC_BLE_ADAPTER, "invalid scannerId=%{public}d", scannerId);
        return false;
    }
    if (!g_scanChannel[scannerId].isUsed) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scannerId=%{public}d, bt-scannerId=%{public}d", scannerId,
            g_scanChannel[scannerId].scannerId);
        return false;
    }
    return true;
}

static int32_t StartScan(int32_t scannerId, const SoftBusBcScanParams *param, const SoftBusBcScanFilter *scanFilter,
    int32_t filterSize)
{
    if (param == NULL || scanFilter == NULL || filterSize <= 0) {
        DISC_LOGE(DISC_BLE_ADAPTER, "invalid param, scannerId=%{public}d", scannerId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}d", scannerId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(scannerId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used, scannerId=%{public}d", scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_ERR;
    }
    int32_t btScannerId = g_scanChannel[scannerId].scannerId;
    if (g_scanChannel[scannerId].isScanning) {
        DISC_LOGE(DISC_BLE_ADAPTER, "already scanning, scannerId=%{public}d, bt-scannerId=%{public}d",
            scannerId, btScannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_ERR;
    }
    g_scanChannel[scannerId].isScanning = true;
    SoftBusMutexUnlock(&g_scannerLock);
    BleScanNativeFilter *nativeFilter =
        (BleScanNativeFilter *)SoftBusCalloc(sizeof(BleScanNativeFilter) * filterSize);
    if (nativeFilter == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc filter failed, scannerId=%{public}d, bt-scannerId=%{public}d",
            scannerId, btScannerId);
        return SOFTBUS_MALLOC_ERR;
    }
    SoftbusFilterToBt(nativeFilter, scanFilter, filterSize);
    DumpBleScanFilter(nativeFilter, filterSize);
    BleScanConfigs scanConfig = {};
    scanConfig.scanMode = GetBtScanMode(param->scanInterval, param->scanWindow);
    scanConfig.phy = (int)param->scanPhy;
    int ret = BleStartScanEx(btScannerId, &scanConfig, nativeFilter, (uint32_t)filterSize);
    FreeBtFilter(nativeFilter, filterSize);
    DISC_LOGD(DISC_BLE_ADAPTER, "scannerId=%{public}d, bt-scannerId=%{public}d, ret=%{public}d",
        scannerId, btScannerId, ret);
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}d, bt-scannerId=%{public}d",
            scannerId, btScannerId);
        return SOFTBUS_LOCK_ERR;
    }
    g_scanChannel[scannerId].isScanning = (ret == OHOS_BT_STATUS_SUCCESS);
    SoftBusMutexUnlock(&g_scannerLock);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t StopScan(int32_t scannerId)
{
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}d", scannerId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(scannerId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used=%{public}d", scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_ERR;
    }
    int32_t btScannerId = g_scanChannel[scannerId].scannerId;
    if (!g_scanChannel[scannerId].isScanning) {
        DISC_LOGI(DISC_BLE_ADAPTER, "already stopped, scannerId=%{public}d, bt-scannerId=%{public}d",
            scannerId, btScannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_OK;
    }
    g_scanChannel[scannerId].isScanning = false;
    SoftBusMutexUnlock(&g_scannerLock);
    int ret = BleStopScan(btScannerId);
    DISC_LOGD(DISC_BLE_ADAPTER, "stop scan, scannerId=%{public}d, bt-scannerId=%{public}d, ret=%{public}d",
        scannerId, btScannerId, ret);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsLpAvailable(void)
{
    bool ret = IsLpDeviceAvailable();
    if (!ret) {
        DISC_LOGW(DISC_BLE_ADAPTER, "is lp available, ret=%{public}d", ret);
    }
    return ret;
}

static bool SetLpParam(const SoftBusLpBroadcastParam *bcParam, const SoftBusLpScanParam *scanParam)
{
    BleScanConfigs scanConfig = {};
    scanConfig.scanMode = GetBtScanMode(scanParam->scanParam.scanInterval, scanParam->scanParam.scanWindow);
    BtLpDeviceParam lpParam = {};
    lpParam.scanConfig = &scanConfig;
    lpParam.rawData.advData = (unsigned char *)AssembleAdvData(&bcParam->advData,
        (uint16_t *)&lpParam.rawData.advDataLen);
    if (lpParam.rawData.advData == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "assemble adv data failed, advHandle=%{public}d", bcParam->advHandle);
        return SOFTBUS_ERR;
    }
    if (bcParam->advData.rspData.payloadLen > 0 && bcParam->advData.rspData.payload != NULL) {
        lpParam.rawData.rspData = (unsigned char *)AssembleRspData(&bcParam->advData.rspData,
            (uint16_t *)&lpParam.rawData.rspDataLen);
        if (lpParam.rawData.rspData == NULL) {
            SoftBusFree(lpParam.rawData.advData);
            DISC_LOGE(DISC_BLE_ADAPTER, "assemble rsp data failed, advHandle=%{public}d", bcParam->advHandle);
            return SOFTBUS_ERR;
        }
    }
    lpParam.filter = (BleScanNativeFilter *)SoftBusCalloc(sizeof(BleScanNativeFilter) * scanParam->filterSize);
    if (lpParam.filter == NULL) {
        SoftBusFree(lpParam.rawData.advData);
        SoftBusFree(lpParam.rawData.rspData);
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc native filter failed, advHandle=%{public}d", bcParam->advHandle);
        return SOFTBUS_MALLOC_ERR;
    }
    SoftbusFilterToBt(lpParam.filter, scanParam->filter, scanParam->filterSize);
    lpParam.filterSize = (unsigned int)scanParam->filterSize;
    SoftbusAdvParamToBt(&bcParam->advParam, &lpParam.advParam);
    BtUuid btUuid = {};
    btUuid.uuid = LP_BT_UUID;
    btUuid.uuidLen = (unsigned char)strlen(LP_BT_UUID);
    lpParam.uuid = btUuid;
    lpParam.activeDeviceInfo = NULL;
    lpParam.activeDeviceSize = 0;
    lpParam.deliveryMode = LP_DELIVERY_MODE_REPLY;
    lpParam.advHandle = bcParam->advHandle;
    lpParam.duration = LP_ADV_DURATION_MS;
    int ret = SetLpDeviceParam(&lpParam);
    FreeBtFilter(lpParam.filter, scanParam->filterSize);
    SoftBusFree(lpParam.rawData.advData);
    SoftBusFree(lpParam.rawData.rspData);
    DISC_LOGI(DISC_BLE_ADAPTER, "advHandle=%{public}d, ret=%{public}d", bcParam->advHandle, ret);
    return (ret == OHOS_BT_STATUS_SUCCESS) ? true : false;
}

static int32_t GetBroadcastHandle(int32_t advId, int32_t *bcHandle)
{
    if (SoftBusMutexLock(&g_advLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock adv failed, advId=%{public}d", advId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "adv is not in used=%{public}d", advId);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int32_t btAdvId = g_advChannel[advId].advId;
    SoftBusMutexUnlock(&g_advLock);
    int ret = GetAdvHandle(btAdvId, bcHandle);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        DISC_LOGW(DISC_BLE_ADAPTER, "failed, advId=%{public}d, bt-advId=%{public}d, ret=%{public}d",
            advId, btAdvId, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t EnableSyncDataToLp(void)
{
    int ret = EnableSyncDataToLpDevice();
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        DISC_LOGW(DISC_BLE_ADAPTER, "failed, enable sync data to lp, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DisableSyncDataToLp(void)
{
    int ret = DisableSyncDataToLpDevice();
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        DISC_LOGW(DISC_BLE_ADAPTER, "failed, disable sync data to lp, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetScanReportChannelToLp(int32_t scannerId, bool enable)
{
    if (SoftBusMutexLock(&g_scannerLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "lock failed, scannerId=%{public}d", scannerId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(scannerId)) {
        DISC_LOGE(DISC_BLE_ADAPTER, "scanner is not in used=%{public}d", scannerId);
        SoftBusMutexUnlock(&g_scannerLock);
        return SOFTBUS_ERR;
    }
    int32_t btScannerId = g_scanChannel[scannerId].scannerId;
    SoftBusMutexUnlock(&g_scannerLock);
    int ret = SetScanReportChannelToLpDevice(btScannerId, enable);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        DISC_LOGW(DISC_BLE_ADAPTER, "failed, scannerId=%{public}d, bt-scannerId=%{public}d, ret=%{public}d",
            scannerId, btScannerId, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle)
{
    int ret = SetLpDeviceAdvParam(duration, maxExtAdvEvents, window, interval, bcHandle);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        DISC_LOGW(DISC_BLE_ADAPTER, "failed, advHandle=%{public}d, ret=%{public}d", bcHandle, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SoftbusBleAdapterInit(void)
{
    DISC_LOGI(DISC_BLE_ADAPTER, "SoftbusBleAdapterInit");
    static SoftbusBroadcastMediumInterface interface = {
        .Init = Init,
        .DeInit = DeInit,
        .RegisterBroadcaster = RegisterAdvCallback,
        .UnRegisterBroadcaster = UnRegisterAdvCallback,
        .RegisterScanListener = RegisterScanCallback,
        .UnRegisterScanListener = UnRegisterScanCallback,
        .StartBroadcasting = StartAdv,
        .StopBroadcasting = StopAdv,
        .SetBroadcastingData = SetAdvData,
        .UpdateBroadcasting = UpdateAdvData,
        .StartScan = StartScan,
        .StopScan = StopScan,
        .IsLpDeviceAvailable = IsLpAvailable,
        .SetAdvFilterParam = SetLpParam,
        .GetBroadcastHandle = GetBroadcastHandle,
        .EnableSyncDataToLpDevice = EnableSyncDataToLp,
        .DisableSyncDataToLpDevice = DisableSyncDataToLp,
        .SetScanReportChannelToLpDevice = SetScanReportChannelToLp,
        .SetLpDeviceParam = SetLpAdvParam,
    };
    if (RegisterBroadcastMediumFunction(BROADCAST_MEDIUM_TYPE_BLE, &interface) != 0) {
        DISC_LOGE(DISC_BLE_ADAPTER, "Register gatt interface failed.");
    }
}