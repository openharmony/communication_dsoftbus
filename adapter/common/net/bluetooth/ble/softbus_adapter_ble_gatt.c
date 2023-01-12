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
#include "softbus_adapter_ble_gatt.h"

#include "adapter_bt_utils.h"
#include "ohos_bt_def.h"
#include "ohos_bt_gap.h"
#include "ohos_bt_gatt.h"
#include "securec.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define SOFTBUS_SCAN_CLIENT_ID 0
#define ADV_MAX_NUM 7
#define SCAN_MAX_NUM 5

typedef struct {
    int advId;
    bool isUsed;
    bool isAdvertising;
    SoftBusCond cond;
    SoftBusBleAdvData advData;
    SoftBusAdvCallback *advCallback;
} AdvChannel;

typedef struct {
    bool isUsed;
    bool isNeedReset;
    bool isScanning;
    SoftBusBleScanParams param;
    SoftBusBleScanFilter *filter;
    uint8_t filterSize;
    SoftBusScanListener *listener;
} ScanListener;

static AdvChannel g_advChannel[ADV_MAX_NUM];
static ScanListener g_scanListener[SCAN_MAX_NUM];
static SoftBusMutex g_advLock = {0};
static SoftBusMutex g_scanerLock = {0};
static volatile bool g_isRegCb = false;

static void OnBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    if (state != SOFTBUS_BT_STATE_TURN_OFF) {
        return;
    }

    CLOGI("receive bt turn off event, start reset bt adapter state...");
    if (SoftBusMutexLock(&g_advLock) != 0) {
        CLOGE("ATTENTION, try to get adv lock failed, something unexpected happened");
        return;
    }
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->isUsed && advChannel->advId != -1) {
            // ignore status code explicitedly, just to notify bt cleanup resources associated with this advertisement
            (void)BleStopAdv(advChannel->advId);
            advChannel->advId = -1;
            advChannel->isAdvertising = false;
            SoftBusCondBroadcast(&advChannel->cond);
            advChannel->advCallback->AdvDisableCallback(index, SOFTBUS_BT_STATUS_SUCCESS);
        }
    }
    (void)SoftBusMutexUnlock(&g_advLock);

    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        CLOGE("ATTENTION, try to get scan lock failed, something unexpected happened");
        return;
    }
    bool needStopScan = false;
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        ScanListener *scanListener = &g_scanListener[index];
        if (scanListener->isUsed && scanListener->isScanning) {
            scanListener->isScanning = false;
            scanListener->listener->OnScanStop(index, SOFTBUS_BT_STATUS_SUCCESS);
            needStopScan = true;
        }
    }
    if (needStopScan) {
        // ignore status code explicitedly, just to notify bt cleanup resources associated with this scan
        (void)BleStopScan();
    }
    (void)SoftBusMutexUnlock(&g_scanerLock);
}
int BleGattLockInit(void)
{
    if (SoftBusMutexInit(&g_advLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "g_advLock init failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_scanerLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "g_scanerLock init failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static unsigned char ConvertScanFilterPolicy(unsigned char policy)
{
    switch (policy) {
        case OHOS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL:
            return SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL;
        case OHOS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST:
            return SOFTBUS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST;
        case OHOS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL_AND_RPA:
            return SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL_AND_RPA;
        case OHOS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA:
            return SOFTBUS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA;
        default:
            return SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL;
    }
}

static unsigned char ConvertScanEventType(unsigned char eventType)
{
    switch (eventType) {
        case OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE:
            return SOFTBUS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE;
        case OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED:
            return SOFTBUS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED;
        case OHOS_BLE_EVT_CONNECTABLE:
            return SOFTBUS_BLE_EVT_CONNECTABLE;
        case OHOS_BLE_EVT_CONNECTABLE_DIRECTED:
            return SOFTBUS_BLE_EVT_CONNECTABLE_DIRECTED;
        case OHOS_BLE_EVT_SCANNABLE:
            return SOFTBUS_BLE_EVT_SCANNABLE;
        case OHOS_BLE_EVT_SCANNABLE_DIRECTED:
            return SOFTBUS_BLE_EVT_SCANNABLE_DIRECTED;
        case OHOS_BLE_EVT_LEGACY_NON_CONNECTABLE:
            return SOFTBUS_BLE_EVT_LEGACY_NON_CONNECTABLE;
        case OHOS_BLE_EVT_LEGACY_SCANNABLE:
            return SOFTBUS_BLE_EVT_LEGACY_SCANNABLE;
        case OHOS_BLE_EVT_LEGACY_CONNECTABLE:
            return SOFTBUS_BLE_EVT_LEGACY_CONNECTABLE;
        case OHOS_BLE_EVT_LEGACY_CONNECTABLE_DIRECTED:
            return SOFTBUS_BLE_EVT_LEGACY_CONNECTABLE_DIRECTED;
        case OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN:
            return SOFTBUS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN;
        case OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV:
            return SOFTBUS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV;
        default:
            return SOFTBUS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE;
    }
}

static unsigned char ConvertScanPhyType(unsigned char phyType)
{
    switch (phyType) {
        case OHOS_BLE_SCAN_PHY_NO_PACKET:
            return SOFTBUS_BLE_SCAN_PHY_NO_PACKET;
        case OHOS_BLE_SCAN_PHY_1M:
            return SOFTBUS_BLE_SCAN_PHY_1M;
        case OHOS_BLE_SCAN_PHY_2M:
            return SOFTBUS_BLE_SCAN_PHY_2M;
        case OHOS_BLE_SCAN_PHY_CODED:
            return SOFTBUS_BLE_SCAN_PHY_CODED;
        default:
            return SOFTBUS_BLE_SCAN_PHY_NO_PACKET;
    }
}

static unsigned char ConvertScanDataStatus(unsigned char dataStatus)
{
    switch (dataStatus) {
        case OHOS_BLE_DATA_COMPLETE:
            return SOFTBUS_BLE_DATA_COMPLETE;
        case OHOS_BLE_DATA_INCOMPLETE_MORE_TO_COME:
            return SOFTBUS_BLE_DATA_INCOMPLETE_MORE_TO_COME;
        case OHOS_BLE_DATA_INCOMPLETE_TRUNCATED:
            return SOFTBUS_BLE_DATA_INCOMPLETE_TRUNCATED;
        default:
            return SOFTBUS_BLE_DATA_INCOMPLETE_TRUNCATED;
    }
}

static unsigned char ConvertScanAddrType(unsigned char addrType)
{
    switch (addrType) {
        case OHOS_BLE_PUBLIC_DEVICE_ADDRESS:
            return SOFTBUS_BLE_PUBLIC_DEVICE_ADDRESS;
        case OHOS_BLE_RANDOM_DEVICE_ADDRESS:
            return SOFTBUS_BLE_RANDOM_DEVICE_ADDRESS;
        case OHOS_BLE_PUBLIC_IDENTITY_ADDRESS:
            return SOFTBUS_BLE_PUBLIC_IDENTITY_ADDRESS;
        case OHOS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS:
            return SOFTBUS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS;
        case OHOS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS:
            return SOFTBUS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS;
        case OHOS_BLE_NO_ADDRESS:
            return SOFTBUS_BLE_NO_ADDRESS;
        default:
            return SOFTBUS_BLE_NO_ADDRESS;
    }
}

static unsigned char ConvertScanType(unsigned char scanType)
{
    switch (scanType) {
        case OHOS_BLE_SCAN_TYPE_PASSIVE:
            return SOFTBUS_BLE_SCAN_TYPE_PASSIVE;
        case OHOS_BLE_SCAN_TYPE_ACTIVE:
            return SOFTBUS_BLE_SCAN_TYPE_ACTIVE;
        default:
            return SOFTBUS_BLE_SCAN_TYPE_PASSIVE;
    }
}

static int ConvertScanMode(unsigned short scanInterval, unsigned short scanWindow)
{
    if (scanInterval == SOFTBUS_BLE_SCAN_INTERVAL_P2 && scanWindow == SOFTBUS_BLE_SCAN_WINDOW_P2) {
        return OHOS_BLE_SCAN_MODE_OP_P2_60_3000;
    }
    if (scanInterval == SOFTBUS_BLE_SCAN_INTERVAL_P10 && scanWindow == SOFTBUS_BLE_SCAN_WINDOW_P10) {
        return OHOS_BLE_SCAN_MODE_OP_P10_60_600;
    }
    if (scanInterval == SOFTBUS_BLE_SCAN_INTERVAL_P25 && scanWindow == SOFTBUS_BLE_SCAN_WINDOW_P25) {
        return OHOS_BLE_SCAN_MODE_OP_P25_60_240;
    }
    if (scanInterval == SOFTBUS_BLE_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BLE_SCAN_WINDOW_P100) {
        return OHOS_BLE_SCAN_MODE_OP_P100_1000_1000;
    }
    return OHOS_BLE_SCAN_MODE_LOW_POWER;
}

void ConvertScanParam(const SoftBusBleScanParams *src, BleScanParams *dst)
{
    if (src == NULL || dst == NULL) {
        return;
    }
    dst->scanInterval = src->scanInterval;
    dst->scanWindow = src->scanWindow;
    dst->scanType = ConvertScanType(src->scanType);
    dst->scanPhy = ConvertScanPhyType(src->scanPhy);
    dst->scanFilterPolicy = ConvertScanFilterPolicy(src->scanFilterPolicy);
}

static void SetAndGetSuitableScanConfig(int listenerId, const SoftBusBleScanParams *params, BleScanConfigs *configs)
{
    static int lastScanMode = OHOS_BLE_SCAN_MODE_LOW_POWER;

    if (params == NULL || configs == NULL) {
        return;
    }
    (void)memset_s(configs, sizeof(BleScanConfigs), 0x0, sizeof(BleScanConfigs));
    g_scanListener[listenerId].param = *params;
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (!g_scanListener[index].isUsed || (!g_scanListener[index].isScanning && index != listenerId)) {
            continue;
        }
        int scanMode = ConvertScanMode(g_scanListener[index].param.scanInterval,
            g_scanListener[index].param.scanWindow);
        if (scanMode > configs->scanMode) {
            configs->scanMode = scanMode;
        }
    }
    if (lastScanMode != configs->scanMode) {
        g_scanListener[listenerId].isNeedReset = true;
        lastScanMode = configs->scanMode;
    }
}

static void DumpBleScanFilter(BleScanNativeFilter *nativeFilter, uint8_t filterSize)
{
#define HEX_STR_MULTIPLE_NUM 2

    if (nativeFilter == NULL || filterSize == 0) {
        return;
    }
    while (filterSize-- > 0) {
        if ((nativeFilter + filterSize) == NULL) {
            continue;
        }
        int32_t len = (nativeFilter + filterSize)->serviceDataLength;
        int32_t hexLen = (nativeFilter + filterSize)->serviceDataLength * HEX_STR_MULTIPLE_NUM + 1;
        char *serviceData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
        if (serviceData == NULL) {
            continue;
        }
        char *serviceDataMask = (char *)SoftBusCalloc(sizeof(char) * hexLen);
        if (serviceDataMask == NULL) {
            SoftBusFree(serviceData);
            serviceData = NULL;
            continue;
        }
        (void)ConvertBytesToHexString(serviceData, hexLen, (nativeFilter + filterSize)->serviceData, len);
        (void)ConvertBytesToHexString(serviceDataMask, hexLen, (nativeFilter + filterSize)->serviceDataMask, len);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BLE Scan Filter id:%d [serviceData:%s, serviceDataMask:%s]",
            filterSize, serviceData, serviceDataMask);
        SoftBusFree(serviceData);
        SoftBusFree(serviceDataMask);
    }
}

static void GetAllNativeScanFilter(int thisListenerId, BleScanNativeFilter **nativeFilter, uint8_t *filterSize)
{
    uint8_t nativeSize = 0;

    if (nativeFilter == NULL || filterSize == NULL) {
        return;
    }
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (!g_scanListener[index].isUsed || (!g_scanListener[index].isScanning && index != thisListenerId)) {
            g_scanListener[index].isNeedReset = false;
            continue;
        }
        g_scanListener[index].isNeedReset = true;
        nativeSize += g_scanListener[index].filterSize;
    }
    *filterSize = nativeSize;
    *nativeFilter = (BleScanNativeFilter *)SoftBusCalloc(sizeof(BleScanNativeFilter) * nativeSize);
    if (*nativeFilter == NULL) {
        *filterSize = 0;
        return;
    }
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (!g_scanListener[index].isNeedReset) {
            continue;
        }
        uint8_t size = g_scanListener[index].filterSize;
        const SoftBusBleScanFilter *filter = g_scanListener[index].filter;
        while (size-- > 0) {
            nativeSize--;
            (*nativeFilter + nativeSize)->address = (filter + size)->address;
            (*nativeFilter + nativeSize)->deviceName = (filter + size)->deviceName;
            (*nativeFilter + nativeSize)->manufactureData = (filter + size)->manufactureData;
            (*nativeFilter + nativeSize)->manufactureDataLength = (filter + size)->manufactureDataLength;
            (*nativeFilter + nativeSize)->manufactureDataMask = (filter + size)->manufactureDataMask;
            (*nativeFilter + nativeSize)->manufactureId = (filter + size)->manufactureId;
            (*nativeFilter + nativeSize)->serviceData = (filter + size)->serviceData;
            (*nativeFilter + nativeSize)->serviceDataLength = (filter + size)->serviceDataLength;
            (*nativeFilter + nativeSize)->serviceDataMask = (filter + size)->serviceDataMask;
            (*nativeFilter + nativeSize)->serviceUuid = (filter + size)->serviceUuid;
            (*nativeFilter + nativeSize)->serviceUuidLength = (filter + size)->serviceUuidLength;
            (*nativeFilter + nativeSize)->serviceUuidMask = (filter + size)->serviceUuidMask;
        }
    }
}

static void ConvertScanResult(const BtScanResultData *src, SoftBusBleScanResult *dst)
{
    if (src == NULL || dst == NULL) {
        return;
    }
    dst->eventType = ConvertScanEventType(src->eventType);
    dst->dataStatus = ConvertScanDataStatus(src->dataStatus);
    dst->addrType = ConvertScanAddrType(src->addrType);
    if (memcpy_s(dst->addr.addr, BT_ADDR_LEN, src->addr.addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConvertScanResult memcpy addr fail");
        return;
    }
    dst->primaryPhy = ConvertScanPhyType(src->primaryPhy);
    dst->secondaryPhy = ConvertScanPhyType(src->secondaryPhy);
    dst->advSid = src->advSid;
    dst->txPower = src->txPower;
    dst->rssi = src->rssi;
    dst->periodicAdvInterval = src->periodicAdvInterval;
    dst->directAddrType = ConvertScanAddrType(src->directAddrType);
    if (memcpy_s(dst->directAddr.addr, BT_ADDR_LEN, src->directAddr.addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConvertScanResult memcpy directAddr fail");
        return;
    }
    dst->advLen = src->advLen;
    dst->advData = src->advData;
}

static unsigned char ConvertAdvType(unsigned char advType)
{
    switch (advType) {
        case SOFTBUS_BLE_ADV_IND:
            return OHOS_BLE_ADV_IND;
        case SOFTBUS_BLE_ADV_DIRECT_IND_HIGH:
            return OHOS_BLE_ADV_DIRECT_IND_HIGH;
        case SOFTBUS_BLE_ADV_SCAN_IND:
            return OHOS_BLE_ADV_SCAN_IND;
        case SOFTBUS_BLE_ADV_NONCONN_IND:
            return OHOS_BLE_ADV_NONCONN_IND;
        case SOFTBUS_BLE_ADV_DIRECT_IND_LOW:
            return OHOS_BLE_ADV_DIRECT_IND_LOW;
        default:
            return OHOS_BLE_ADV_IND;
    }
}

static unsigned char ConvertAdvFilter(unsigned char advFilter)
{
    switch (advFilter) {
        case SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
        case SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY;
        case SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST;
        case SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST;
        default:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
    }
}

static void ConvertAdvData(const SoftBusBleAdvData *src, StartAdvRawData *dst)
{
    dst->advDataLen = src->advLength;
    dst->advData = (unsigned char *)src->advData;
    dst->rspDataLen = src->scanRspLength;
    dst->rspData = (unsigned char *)src->scanRspData;
}

static void ConvertAdvParam(const SoftBusBleAdvParams *src, BleAdvParams *dst)
{
    dst->minInterval = src->minInterval;
    dst->maxInterval = src->maxInterval;
    dst->advType = ConvertAdvType(src->advType);
    dst->ownAddrType = 0x00;
    dst->peerAddrType = 0x00;
    if (memcpy_s(dst->peerAddr.addr, BT_ADDR_LEN, src->peerAddr.addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConvertScanResult memcpy directAddr fail");
        return;
    }
    dst->channelMap = src->channelMap;
    dst->advFilterPolicy = ConvertAdvFilter(src->advFilterPolicy);
    dst->txPower = src->txPower;
    dst->duration = src->duration;
}

static void WrapperAdvEnableCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvEnableCallback == NULL) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperAdvEnableCallback, inner-advId: %d, bt-advId: %d, "
            "status: %d", index, advId, st);
        if (st == SOFTBUS_BT_STATUS_SUCCESS) {
            advChannel->isAdvertising = true;
            SoftBusCondSignal(&advChannel->cond);
        }
        advChannel->advCallback->AdvEnableCallback(index, st);
        break;
    }
}

static void WrapperAdvDisableCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvDisableCallback == NULL) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperAdvDisableCallback, inner-advId: %d, bt-advId: %d, "
            "status: %d", index, advId, st);
        if (st == SOFTBUS_BT_STATUS_SUCCESS) {
            advChannel->advId = -1;
            advChannel->isAdvertising = false;
            SoftBusCondSignal(&advChannel->cond);
        }
        advChannel->advCallback->AdvDisableCallback(index, st);
        break;
    }
}

static void WrapperAdvDataCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvDataCallback == NULL) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperAdvDataCallback, inner-advId: %d, bt-advId: %d, "
            "status: %d", index, advId, st);
        advChannel->advCallback->AdvDataCallback(index, st);
        break;
    }
}

static void WrapperAdvUpdateCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvUpdateCallback == NULL) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperAdvUpdateCallback, inner-advId: %d, bt-advId: %d, "
            "status: %d", index, advId, st);
        advChannel->advCallback->AdvUpdateCallback(index, st);
        break;
    }
}

static void WrapperSecurityRespondCallback(const BdAddr *bdAddr)
{
    (void)bdAddr;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperSecurityRespondCallback");
}

static void WrapperScanResultCallback(BtScanResultData *scanResultdata)
{
    if (scanResultdata == NULL) {
        return;
    }
    int listenerId;
    SoftBusBleScanResult sr;
    ConvertScanResult(scanResultdata, &sr);
    for (listenerId = 0; listenerId < SCAN_MAX_NUM; listenerId++) {
        SoftBusMutexLock(&g_scanerLock);
        ScanListener *scanListener = &g_scanListener[listenerId];
        if (!scanListener->isUsed || scanListener->listener == NULL || !scanListener->isScanning ||
            scanListener->listener->OnScanResult == NULL) {
            SoftBusMutexUnlock(&g_scanerLock);
            continue;
        }
        SoftBusMutexUnlock(&g_scanerLock);
        scanListener->listener->OnScanResult(listenerId, &sr);
    }
}

static void WrapperScanParameterSetCompletedCallback(int clientId, int status)
{
    (void)clientId;
    (void)status;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WrapperScanParameterSetCompletedCallback");
}

static BtGattCallbacks g_softbusGattCb = {
    .advEnableCb = WrapperAdvEnableCallback,
    .advDisableCb = WrapperAdvDisableCallback,
    .advDataCb = WrapperAdvDataCallback,
    .advUpdateCb = WrapperAdvUpdateCallback,
    .securityRespondCb = WrapperSecurityRespondCallback,
    .scanResultCb = WrapperScanResultCallback,
    .scanParamSetCb = WrapperScanParameterSetCompletedCallback
};

static SoftBusBtStateListener g_btStateLister = {
    .OnBtStateChanged = OnBtStateChanged,
    .OnBtAclStateChanged = NULL,
};

static int RegisterBleGattCallback(void)
{
    if (g_isRegCb) {
        return SOFTBUS_OK;
    }
    if (BleGattRegisterCallbacks(&g_softbusGattCb) != 0) {
        return SOFTBUS_ERR;
    }
    if (SoftBusAddBtStateListener(&g_btStateLister) < 0) {
        return SOFTBUS_ERR;
    }
    g_isRegCb = true;
    return SOFTBUS_OK;
}

static bool CheckAdvChannelInUsed(int advId)
{
    if (advId < 0 || advId >= ADV_MAX_NUM) {
        return false;
    }
    if (!g_advChannel[advId].isUsed) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "advId %d is ready released", advId);
        return false;
    }
    return true;
}

static bool CheckScanChannelInUsed(int listenerId)
{
    if (listenerId < 0 || listenerId >= SCAN_MAX_NUM) {
        return false;
    }
    if (!g_scanListener[listenerId].isUsed) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "listenerId %d is ready released", listenerId);
        return false;
    }
    return true;
}

static int SetAdvData(int advId, const SoftBusBleAdvData *data)
{
    g_advChannel[advId].advData.advLength = data->advLength;
    g_advChannel[advId].advData.scanRspLength = data->scanRspLength;
    if (g_advChannel[advId].advData.advData != NULL) {
        SoftBusFree(g_advChannel[advId].advData.advData);
        g_advChannel[advId].advData.advData = NULL;
    }
    if (g_advChannel[advId].advData.scanRspData != NULL) {
        SoftBusFree(g_advChannel[advId].advData.scanRspData);
        g_advChannel[advId].advData.scanRspData = NULL;
    }
    if (data->advLength != 0) {
        g_advChannel[advId].advData.advData = SoftBusCalloc(data->advLength);
        if (g_advChannel[advId].advData.advData == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetAdvData calloc advData failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(g_advChannel[advId].advData.advData, data->advLength,
            data->advData, data->advLength) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetAdvData memcpy advData failed");
            SoftBusFree(g_advChannel[advId].advData.advData);
            g_advChannel[advId].advData.advData = NULL;
            return SOFTBUS_MEM_ERR;
        }
    }
    if (data->scanRspLength != 0) {
        g_advChannel[advId].advData.scanRspData = SoftBusCalloc(data->scanRspLength);
        if (g_advChannel[advId].advData.scanRspData == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetAdvData calloc scanRspData failed");
            SoftBusFree(g_advChannel[advId].advData.advData);
            g_advChannel[advId].advData.advData = NULL;
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(g_advChannel[advId].advData.scanRspData, data->scanRspLength,
            data->scanRspData, data->scanRspLength) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SetAdvData memcpy scanRspData failed");
            SoftBusFree(g_advChannel[advId].advData.advData);
            SoftBusFree(g_advChannel[advId].advData.scanRspData);
            g_advChannel[advId].advData.advData = NULL;
            g_advChannel[advId].advData.scanRspData = NULL;
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static void ClearAdvData(int advId)
{
    g_advChannel[advId].advData.advLength = 0;
    g_advChannel[advId].advData.scanRspLength = 0;
    SoftBusFree(g_advChannel[advId].advData.advData);
    SoftBusFree(g_advChannel[advId].advData.scanRspData);
    g_advChannel[advId].advData.advData = NULL;
    g_advChannel[advId].advData.scanRspData = NULL;
}

int SoftBusGetAdvChannel(const SoftBusAdvCallback *callback)
{
    if (callback == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterBleGattCallback() != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int freeAdvId;
    for (freeAdvId = 0; freeAdvId < ADV_MAX_NUM; freeAdvId++) {
        if (!g_advChannel[freeAdvId].isUsed) {
            break;
        }
    }
    if (freeAdvId == ADV_MAX_NUM) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "no available adv channel");
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    g_advChannel[freeAdvId].advId = -1;
    g_advChannel[freeAdvId].isUsed = true;
    g_advChannel[freeAdvId].isAdvertising = false;
    SoftBusCondInit(&g_advChannel[freeAdvId].cond);
    g_advChannel[freeAdvId].advCallback = (SoftBusAdvCallback *)callback;
    SoftBusMutexUnlock(&g_advLock);
    return freeAdvId;
}

int SoftBusReleaseAdvChannel(int advId)
{
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    ClearAdvData(advId);
    g_advChannel[advId].advId = -1;
    g_advChannel[advId].isUsed = false;
    g_advChannel[advId].isAdvertising = false;
    SoftBusCondDestroy(&g_advChannel[advId].cond);
    g_advChannel[advId].advCallback = NULL;
    SoftBusMutexUnlock(&g_advLock);
    return SOFTBUS_OK;
}

int SoftBusSetAdvData(int advId, const SoftBusBleAdvData *data)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int ret = SetAdvData(advId, data);
    if (ret == SOFTBUS_OK) {
        g_advChannel[advId].advCallback->AdvDataCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    } else {
        g_advChannel[advId].advCallback->AdvDataCallback(advId, SOFTBUS_BT_STATUS_FAIL);
    }
    SoftBusMutexUnlock(&g_advLock);
    return ret;
}

int SoftBusStartAdv(int advId, const SoftBusBleAdvParams *param)
{
    if (param == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    if (g_advChannel[advId].isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "SoftBusStartAdv, wait condition inner-advId: %d", advId);
        SoftBusCondWait(&g_advChannel[advId].cond, &g_advLock, NULL);
    }
    int innerAdvId;
    BleAdvParams dstParam;
    StartAdvRawData advData;
    ConvertAdvParam(param, &dstParam);
    ConvertAdvData(&g_advChannel[advId].advData, &advData);
    int ret = BleStartAdvEx(&innerAdvId, advData, dstParam);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleStartAdvEx, inner-advId: %d, bt-advId: %d, "
        "ret: %d", advId, innerAdvId, ret);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        g_advChannel[advId].advCallback->AdvEnableCallback(advId, SOFTBUS_BT_STATUS_FAIL);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    g_advChannel[advId].advCallback->AdvEnableCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    g_advChannel[advId].advId = innerAdvId;
    SoftBusMutexUnlock(&g_advLock);
    return SOFTBUS_OK;
}

int SoftBusStopAdv(int advId)
{
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    if (!g_advChannel[advId].isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "SoftBusStopAdv, wait condition inner-advId: %d, "
            "bt-advId: %d", advId, g_advChannel[advId].advId);
        SoftBusCondWait(&g_advChannel[advId].cond, &g_advLock, NULL);
    }
    int ret = BleStopAdv(g_advChannel[advId].advId);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftBusStopAdv, inner-advId: %d, "
        "bt-advId: %d, ret: %d", advId, g_advChannel[advId].advId, ret);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        g_advChannel[advId].advCallback->AdvDisableCallback(advId, SOFTBUS_BT_STATUS_FAIL);
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_OK;
    }
    ClearAdvData(advId);
    g_advChannel[advId].advCallback->AdvDisableCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    SoftBusMutexUnlock(&g_advLock);
    return SOFTBUS_OK;
}

int SoftBusUpdateAdv(int advId, const SoftBusBleAdvData *data, const SoftBusBleAdvParams *param)
{
    if (param == NULL || data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        return SOFTBUS_ERR;
    }
    int ret = SoftBusStopAdv(advId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = SetAdvData(advId, data);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SoftBusStartAdv(advId, param);
}

int SoftBusAddScanListener(const SoftBusScanListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterBleGattCallback() != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (!g_scanListener[index].isUsed) {
            (void)memset_s(g_scanListener + index, sizeof(ScanListener), 0x0, sizeof(ScanListener));
            g_scanListener[index].isUsed = true;
            g_scanListener[index].isNeedReset = true;
            g_scanListener[index].isScanning = false;
            g_scanListener[index].listener = (SoftBusScanListener *)listener;
            SoftBusMutexUnlock(&g_scanerLock);
            return index;
        }
    }
    SoftBusMutexUnlock(&g_scanerLock);
    return SOFTBUS_ERR;
}

static void FreeScanFilter(int listenerId)
{
    uint8_t filterSize = g_scanListener[listenerId].filterSize;
    SoftBusBleScanFilter *filter = g_scanListener[listenerId].filter;
    while (filterSize-- > 0) {
        SoftBusFree((filter + filterSize)->address);
        SoftBusFree((filter + filterSize)->deviceName);
        SoftBusFree((filter + filterSize)->serviceUuid);
        SoftBusFree((filter + filterSize)->serviceUuidMask);
        SoftBusFree((filter + filterSize)->serviceData);
        SoftBusFree((filter + filterSize)->serviceDataMask);
        SoftBusFree((filter + filterSize)->manufactureData);
        SoftBusFree((filter + filterSize)->manufactureDataMask);
    }
    SoftBusFree(filter);
    g_scanListener[listenerId].filterSize = 0;
    g_scanListener[listenerId].filter = NULL;
}

int SoftBusRemoveScanListener(int listenerId)
{
    if (listenerId < 0 || listenerId >= SCAN_MAX_NUM) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    g_scanListener[listenerId].isUsed = false;
    g_scanListener[listenerId].isNeedReset = true;
    g_scanListener[listenerId].isScanning = false;
    g_scanListener[listenerId].listener = NULL;
    FreeScanFilter(listenerId);
    SoftBusMutexUnlock(&g_scanerLock);
    return SOFTBUS_OK;
}

static bool CheckNeedReStartScan(void)
{
    for (int listenerId = 0; listenerId < SCAN_MAX_NUM; listenerId++) {
        if (g_scanListener[listenerId].isNeedReset) {
            return true;
        }
        if (g_scanListener[listenerId].isScanning) {
            return false;
        }
    }
    return true;
}

static bool CheckNeedStopScan(int listenerId)
{
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (index == listenerId && !g_scanListener[index].isScanning) {
            return false;
        }
        if (index != listenerId && g_scanListener[index].isScanning) {
            return false;
        }
    }
    return true;
}

int SoftBusSetScanFilter(int listenerId, SoftBusBleScanFilter *filter, uint8_t filterSize)
{
    if (filter == NULL || filterSize == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(listenerId)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ScanListener id:%d is not in use", listenerId);
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    FreeScanFilter(listenerId);
    g_scanListener[listenerId].filter = filter;
    g_scanListener[listenerId].filterSize = filterSize;
    g_scanListener[listenerId].isNeedReset = true;
    SoftBusMutexUnlock(&g_scanerLock);
    return SOFTBUS_OK;
}

int SoftBusStartScan(int listenerId, const SoftBusBleScanParams *param)
{
    if (param == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(listenerId)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ScanListener id:%d is not in use", listenerId);
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    BleScanConfigs scanConfig;
    SetAndGetSuitableScanConfig(listenerId, param, &scanConfig);
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    if (CheckNeedReStartScan()) {
        uint8_t filterSize = 0;
        BleScanNativeFilter *nativeFilter = NULL;
        GetAllNativeScanFilter(listenerId, &nativeFilter, &filterSize);
        DumpBleScanFilter(nativeFilter, filterSize);
        status = BleOhosStatusToSoftBus(BleStartScanEx(&scanConfig, nativeFilter, filterSize));
        SoftBusFree(nativeFilter);
    }
    if (status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    g_scanListener[listenerId].isScanning = true;
    if (g_scanListener[listenerId].listener != NULL &&
        g_scanListener[listenerId].listener->OnScanStart != NULL) {
        g_scanListener[listenerId].listener->OnScanStart(listenerId, SOFTBUS_BT_STATUS_SUCCESS);
    }
    SoftBusMutexUnlock(&g_scanerLock);
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusStopScan(int listenerId)
{
    if (SoftBusMutexLock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckScanChannelInUsed(listenerId)) {
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    if (!g_scanListener[listenerId].isScanning) {
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_OK;
    }
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    if (CheckNeedStopScan(listenerId)) {
        status = BleOhosStatusToSoftBus(BleStopScan());
    }
    if (status != SOFTBUS_BT_STATUS_SUCCESS) {
        SoftBusMutexUnlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    g_scanListener[listenerId].isScanning = false;
    if (g_scanListener[listenerId].listener != NULL &&
        g_scanListener[listenerId].listener->OnScanStop != NULL) {
        g_scanListener[listenerId].listener->OnScanStop(listenerId, status);
    }
    SoftBusMutexUnlock(&g_scanerLock);
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusReplaceAdvertisingAdv(int advId, const SoftBusBleAdvData *data)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        SoftBusMutexUnlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    if (!g_advChannel[advId].isAdvertising) {
        SoftBusMutexUnlock(&g_advLock);
        CLOGE("adv %d is not advertising", advId);
        return SOFTBUS_ERR;
    }
    int btAdvId = g_advChannel[advId].advId;
    int ret = SetAdvData(advId, data);
    SoftBusMutexUnlock(&g_advLock);
    if (ret != SOFTBUS_OK) {
        CLOGE("SetAdvData failed, advId: %d, btadvId: %d", advId, btAdvId);
        return SOFTBUS_ERR;
    }
    StartAdvRawData advData = {0};
    ConvertAdvData(data, &advData);
    ret = BleOhosStatusToSoftBus(BleSetAdvData(btAdvId, advData));
    return ret;
}
