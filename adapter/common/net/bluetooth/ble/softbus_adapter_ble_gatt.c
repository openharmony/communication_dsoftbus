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

#include <pthread.h>
#include "ohos_bt_def.h"
#include "ohos_bt_gap.h"
#include "ohos_bt_gatt.h"
#include "securec.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define SOFTBUS_SCAN_CLIENT_ID 0
#define ADV_MAX_NUM 4
#define SCAN_MAX_NUM 2

typedef struct {
    int advId;
    bool isUsed;
    bool isAdvertising;
    pthread_cond_t cond;
    SoftBusBleAdvData advData;
    SoftBusAdvCallback *advCallback;
} AdvChannel;

typedef struct {
    bool isUsed;
    bool isScanning;
    SoftBusBleScanParams param;
    SoftBusScanListener *listener;
} ScanListener;

static AdvChannel g_advChannel[ADV_MAX_NUM];
static ScanListener g_scanListener[SCAN_MAX_NUM];
static pthread_mutex_t g_advLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_scanerLock = PTHREAD_MUTEX_INITIALIZER;
static bool g_isRegCb = false;

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

static void ConvertScanParam(const SoftBusBleScanParams *src, BleScanParams *dst)
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

static void ConvertScanResult(const BtScanResultData *src, SoftBusBleScanResult *dst)
{
    if (src == NULL || dst == NULL) {
        return;
    }
    dst->eventType = ConvertScanEventType(src->eventType);
    dst->dataStatus = ConvertScanDataStatus(src->dataStatus);
    dst->addrType = ConvertScanAddrType(src->addrType);
    (void)memcpy_s(dst->addr.addr, BT_ADDR_LEN, src->addr.addr, BT_ADDR_LEN);
    dst->primaryPhy = ConvertScanPhyType(src->primaryPhy);
    dst->secondaryPhy = ConvertScanPhyType(src->secondaryPhy);
    dst->advSid = src->advSid;
    dst->txPower = src->txPower;
    dst->rssi = src->rssi;
    dst->periodicAdvInterval = src->periodicAdvInterval;
    dst->directAddrType = ConvertScanAddrType(src->directAddrType);
    (void)memcpy_s(dst->directAddr.addr, BT_ADDR_LEN, src->directAddr.addr, BT_ADDR_LEN);
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
    (void)memcpy_s(dst->peerAddr.addr, BT_ADDR_LEN, src->peerAddr.addr, BT_ADDR_LEN);
    dst->channelMap = src->channelMap;
    dst->advFilterPolicy = ConvertAdvFilter(src->advFilterPolicy);
    dst->txPower = src->txPower;
    dst->duration = src->duration;
}

static void WrapperAdvEnableCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        pthread_mutex_lock(&g_advLock);
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvEnableCallback == NULL) {
            pthread_mutex_unlock(&g_advLock);
            continue;
        }
        if (st == SOFTBUS_BT_STATUS_SUCCESS) {
            advChannel->isAdvertising = true;
            pthread_cond_signal(&advChannel->cond);
        }
        advChannel->advCallback->AdvEnableCallback(index, st);
        pthread_mutex_unlock(&g_advLock);
        break;
    }
}

static void WrapperAdvDisableCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        pthread_mutex_lock(&g_advLock);
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvDisableCallback == NULL) {
            pthread_mutex_unlock(&g_advLock);
            continue;
        }
        if (st == SOFTBUS_BT_STATUS_SUCCESS) {
            advChannel->isAdvertising = false;
            pthread_cond_signal(&advChannel->cond);
        }
        advChannel->advCallback->AdvDisableCallback(index, st);
        pthread_mutex_unlock(&g_advLock);
        break;
    }
}

static void WrapperAdvDataCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        pthread_mutex_lock(&g_advLock);
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvDataCallback == NULL) {
            pthread_mutex_unlock(&g_advLock);
            continue;
        }
        advChannel->advCallback->AdvDataCallback(index, st);
        pthread_mutex_unlock(&g_advLock);
        break;
    }
}

static void WrapperAdvUpdateCallback(int advId, int status)
{
    int st = BleOhosStatusToSoftBus((BtStatus)status);
    for (uint32_t index = 0; index < ADV_MAX_NUM; index++) {
        pthread_mutex_lock(&g_advLock);
        AdvChannel *advChannel = &g_advChannel[index];
        if (advChannel->advId != advId ||
            advChannel->isUsed == false ||
            advChannel->advCallback == NULL ||
            advChannel->advCallback->AdvUpdateCallback == NULL) {
            pthread_mutex_unlock(&g_advLock);
            continue;
        }
        advChannel->advCallback->AdvUpdateCallback(index, st);
        pthread_mutex_unlock(&g_advLock);
        break;
    }
}

static void WrapperSecurityRespondCallback(const BdAddr *bdAddr)
{
    (void)bdAddr;
    LOG_INFO("WrapperSecurityRespondCallback");
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
        pthread_mutex_lock(&g_scanerLock);
        ScanListener *scanListener = &g_scanListener[listenerId];
        if (!scanListener->isUsed || scanListener->listener == NULL || !scanListener->isScanning ||
            scanListener->listener->OnScanResult == NULL) {
            pthread_mutex_unlock(&g_scanerLock);
            continue;
        }
        pthread_mutex_unlock(&g_scanerLock);
        scanListener->listener->OnScanResult(listenerId, &sr);
    }
}

static void WrapperScanParameterSetCompletedCallback(int clientId, int status)
{
    (void)clientId;
    (void)status;
    LOG_INFO("WrapperScanParameterSetCompletedCallback");
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

static int RegisterBleGattCallback(void)
{
    if (g_isRegCb) {
        return SOFTBUS_OK;
    }
    if (BleGattRegisterCallbacks(&g_softbusGattCb) != 0) {
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
        LOG_ERR("advId %d is ready released", advId);
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
            LOG_ERR("SetAdvData calloc advData failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(g_advChannel[advId].advData.advData, data->advLength, 
            data->advData, data->advLength) != EOK) {
            LOG_ERR("SetAdvData memcpy advData failed");
            SoftBusFree(g_advChannel[advId].advData.advData);
            g_advChannel[advId].advData.advData = NULL;
            return SOFTBUS_MEM_ERR;
        }
    }
    if (data->scanRspLength != 0) {
        g_advChannel[advId].advData.scanRspData = SoftBusCalloc(data->scanRspLength);
        if (g_advChannel[advId].advData.scanRspData == NULL) {
            LOG_ERR("SetAdvData calloc scanRspData failed");
            SoftBusFree(g_advChannel[advId].advData.advData);
            g_advChannel[advId].advData.advData = NULL;
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s(g_advChannel[advId].advData.scanRspData, data->scanRspLength, 
            data->scanRspData, data->scanRspLength) != EOK) {
            LOG_ERR("SetAdvData memcpy scanRspData failed");
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
    if (pthread_mutex_lock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterBleGattCallback() != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int freeAdvId;
    for (freeAdvId = 0; freeAdvId < ADV_MAX_NUM; freeAdvId++) {
        if (!g_advChannel[freeAdvId].isUsed) {
            break;
        }
    }
    if (freeAdvId == ADV_MAX_NUM) {
        LOG_ERR("no available adv channel");
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    g_advChannel[freeAdvId].advId = -1;
    g_advChannel[freeAdvId].isUsed = true;
    g_advChannel[freeAdvId].isAdvertising = false;
    pthread_cond_init(&g_advChannel[freeAdvId].cond, NULL);
    g_advChannel[freeAdvId].advCallback = (SoftBusAdvCallback *)callback;
    pthread_mutex_unlock(&g_advLock);
    return freeAdvId;
}

int SoftBusReleaseAdvChannel(int advId)
{
    if (pthread_mutex_lock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    ClearAdvData(advId);
    g_advChannel[advId].advId = -1;
    g_advChannel[advId].isUsed = false;
    g_advChannel[advId].isAdvertising = false;
    pthread_cond_destroy(&g_advChannel[advId].cond);
    g_advChannel[advId].advCallback = NULL;
    pthread_mutex_unlock(&g_advLock);
    return SOFTBUS_OK;
}

int SoftBusSetAdvData(int advId, const SoftBusBleAdvData *data)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    int ret = SetAdvData(advId, data);
    if (ret == SOFTBUS_OK) {
        g_advChannel[advId].advCallback->AdvDataCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    } else {
        g_advChannel[advId].advCallback->AdvDataCallback(advId, SOFTBUS_BT_STATUS_FAIL);
    }
    pthread_mutex_unlock(&g_advLock);
    return ret;
}

int SoftBusStartAdv(int advId, const SoftBusBleAdvParams *param)
{
    if (param == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    if (g_advChannel[advId].isAdvertising) {
        pthread_cond_wait(&g_advChannel[advId].cond, &g_advLock);
    }
    int innerAdvId;
    BleAdvParams dstParam;
    StartAdvRawData advData;
    ConvertAdvParam(param, &dstParam);
    ConvertAdvData(&g_advChannel[advId].advData, &advData);
    int ret = BleStartAdvEx(&innerAdvId, advData, dstParam);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        g_advChannel[advId].advCallback->AdvEnableCallback(advId, SOFTBUS_BT_STATUS_FAIL);
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    g_advChannel[advId].advCallback->AdvEnableCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    g_advChannel[advId].advId = innerAdvId;
    pthread_mutex_unlock(&g_advLock);
    return SOFTBUS_OK;
}

int SoftBusStopAdv(int advId)
{
    if (pthread_mutex_lock(&g_advLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!CheckAdvChannelInUsed(advId)) {
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_ERR;
    }
    if (!g_advChannel[advId].isAdvertising) {
        pthread_cond_wait(&g_advChannel[advId].cond, &g_advLock);
    }
    int ret = BleStopAdv(g_advChannel[advId].advId);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        g_advChannel[advId].advCallback->AdvDisableCallback(advId, SOFTBUS_BT_STATUS_FAIL);
        pthread_mutex_unlock(&g_advLock);
        return SOFTBUS_OK;
    }
    ClearAdvData(advId);
    g_advChannel[advId].advCallback->AdvDisableCallback(advId, SOFTBUS_BT_STATUS_SUCCESS);
    pthread_mutex_unlock(&g_advLock);
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
    if (pthread_mutex_lock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterBleGattCallback() != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    for (int index = 0; index < SCAN_MAX_NUM; index++) {
        if (!g_scanListener[index].isUsed) {
            g_scanListener[index].isUsed = true;
            g_scanListener[index].isScanning = false;
            (void)memset_s(&g_scanListener[index].param, sizeof(SoftBusBleScanParams),
                           0x0, sizeof(SoftBusBleScanParams));
            g_scanListener[index].listener = (SoftBusScanListener *)listener;
            pthread_mutex_unlock(&g_scanerLock);
            return index;
        }
    }
    pthread_mutex_unlock(&g_scanerLock);
    return SOFTBUS_ERR;
}

int SoftBusRemoveScanListener(int listenerId)
{
    if (listenerId < 0 || listenerId >= SCAN_MAX_NUM) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    g_scanListener[listenerId].isUsed = false;
    g_scanListener[listenerId].isScanning = false;
    g_scanListener[listenerId].listener = NULL;
    pthread_mutex_unlock(&g_scanerLock);
    return SOFTBUS_OK;
}

static bool CheckNeedStartScan(void)
{
    for (int listenerId = 0; listenerId < SCAN_MAX_NUM; listenerId++) {
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

int SoftBusStartScan(int listenerId, const SoftBusBleScanParams *param)
{
    if (param == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!g_scanListener[listenerId].isUsed) {
        LOG_ERR("ScanListener id:%d is not in use", listenerId);
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    if (CheckNeedStartScan()) {
        status = BleOhosStatusToSoftBus(BleStartScan());
    }
    if (status != SOFTBUS_BT_STATUS_SUCCESS) {
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    g_scanListener[listenerId].isScanning = true;
    if (g_scanListener[listenerId].listener != NULL &&
        g_scanListener[listenerId].listener->OnScanStart != NULL) {
        g_scanListener[listenerId].listener->OnScanStart(listenerId, SOFTBUS_BT_STATUS_SUCCESS);        
    }
    pthread_mutex_unlock(&g_scanerLock);
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusStopScan(int listenerId)
{
    if (pthread_mutex_lock(&g_scanerLock) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!g_scanListener[listenerId].isUsed) {
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    if (!g_scanListener[listenerId].isScanning) {
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_OK;
    }
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    if (CheckNeedStopScan(listenerId)) {
        status = BleOhosStatusToSoftBus(BleStopScan());
    }
    if (status != SOFTBUS_BT_STATUS_SUCCESS) {
        pthread_mutex_unlock(&g_scanerLock);
        return SOFTBUS_ERR;
    }
    g_scanListener[listenerId].isScanning = false;
    if (g_scanListener[listenerId].listener != NULL &&
        g_scanListener[listenerId].listener->OnScanStop != NULL) {
        g_scanListener[listenerId].listener->OnScanStop(listenerId, status);    
    }
    pthread_mutex_unlock(&g_scanerLock);
    if (status == SOFTBUS_BT_STATUS_SUCCESS) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}