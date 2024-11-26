/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbusbroadcast_fuzzer.h"
#include "softbus_broadcast_manager.h"

#include <cstddef>
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define MIN_DATA_LEN 50

#define BC_INTERNAL 48
#define BC_ADV_TX_POWER_DEFAULT (-6)
#define SERVICE_UUID 0xFDEE
#define BC_ADV_FLAG 0x2
#define MANUFACTURE_COMPANY_ID 0x027D
#define ADV_DATA_MAX_LEN 24
#define RESP_DATA_MAX_LEN 26
#define BROADCAST_MAX_LEN (ADV_DATA_MAX_LEN + RESP_DATA_MAX_LEN)

namespace OHOS {

const uint8_t *BASE_FUZZ_DATA = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (BASE_FUZZ_DATA == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, BASE_FUZZ_DATA + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

static int32_t BuildBroadcastParam(const uint8_t* data, size_t size, BroadcastParam *param)
{
    g_baseFuzzPos = 0;
    param->minInterval = GetData<int32_t>() % BC_INTERNAL;
    param->maxInterval = GetData<int32_t>() % BC_INTERNAL;
    param->advType = GetData<uint8_t>() % SOFTBUS_BC_ADV_DIRECT_IND_LOW;
    param->ownAddrType = GetData<uint8_t>() % SOFTBUS_BC_RANDOM_STATIC_IDENTITY_ADDRESS;
    param->peerAddrType = GetData<uint8_t>() % SOFTBUS_BC_RANDOM_STATIC_IDENTITY_ADDRESS;
    param->channelMap = GetData<int32_t>();
    param->txPower = BC_ADV_TX_POWER_DEFAULT;
    param->advFilterPolicy = GetData<uint8_t>();
    param->isSupportRpa = GetData<bool>();
    param->duration = GetData<int32_t>();

    if (memcpy_s(param->ownIrk, BC_IRK_LEN, data, BC_IRK_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(param->ownUdidHash, BC_UDID_HASH_LEN, data, BC_UDID_HASH_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void DestroyBleConfigAdvData(BroadcastPacket *packet)
{
    SoftBusFree(packet->bcData.payload);
    SoftBusFree(packet->rspData.payload);
    packet->bcData.payload = nullptr;
    packet->rspData.payload = nullptr;
}

static int32_t BuildBroadcastPacket(const uint8_t* data, size_t size, BroadcastPacket *packet)
{
    packet->isSupportFlag = true;
    packet->flag = BC_ADV_FLAG;
    packet->bcData.type = BC_DATA_TYPE_SERVICE;
    packet->bcData.id = SERVICE_UUID;
    packet->rspData.type = BC_DATA_TYPE_MANUFACTURER;
    packet->rspData.id = MANUFACTURE_COMPANY_ID;

    packet->bcData.payload = (uint8_t *)SoftBusCalloc(ADV_DATA_MAX_LEN);
    if (packet->bcData.payload == nullptr) {
        return SOFTBUS_MALLOC_ERR;
    }
    packet->bcData.payloadLen = (size > ADV_DATA_MAX_LEN) ? ADV_DATA_MAX_LEN : size;
    if (memcpy_s(packet->bcData.payload, ADV_DATA_MAX_LEN, data, packet->bcData.payloadLen) != EOK) {
        SoftBusFree(packet->bcData.payload);
        packet->rspData.payload = nullptr;
        return SOFTBUS_MEM_ERR;
    }

    packet->rspData.payloadLen = (BROADCAST_MAX_LEN - packet->bcData.payloadLen > RESP_DATA_MAX_LEN) ?
        RESP_DATA_MAX_LEN : (BROADCAST_MAX_LEN - packet->bcData.payloadLen);
    if (packet->rspData.payloadLen == 0) {
        packet->rspData.payload = nullptr;
        return SOFTBUS_OK;
    }
    packet->rspData.payload = (uint8_t *)SoftBusCalloc(RESP_DATA_MAX_LEN);
    if (packet->rspData.payload == nullptr) {
        SoftBusFree(packet->bcData.payload);
        packet->bcData.payload = nullptr;
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&packet->rspData.payload[0], RESP_DATA_MAX_LEN, data, packet->rspData.payloadLen) != EOK) {
        DestroyBleConfigAdvData(packet);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static BcScanParams BuildScanParam()
{
    g_baseFuzzPos = 0;
    BcScanParams scanParam;
    scanParam.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
    scanParam.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    scanParam.scanType = GetData<bool>();
    scanParam.scanPhy = GetData<uint8_t>() % SOFTBUS_BC_SCAN_PHY_CODED;
    scanParam.scanFilterPolicy = GetData<uint8_t>() % SOFTBUS_BC_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA;
    return scanParam;
}

static int32_t BuildLpBroadcastParam(const uint8_t* data, size_t size, LpBroadcastParam *lpBcParam)
{
    g_baseFuzzPos = 0;
    lpBcParam->bcHandle = GetData<int32_t>();
    int32_t ret = BuildBroadcastParam(data, size, &lpBcParam->bcParam);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = BuildBroadcastPacket(data, size, &lpBcParam->packet);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    return SOFTBUS_OK;
}

static LpScanParam BuildLpScanParam()
{
    LpScanParam lpScanParam;
    lpScanParam.scanParam = BuildScanParam();

    return lpScanParam;
}

static void BleAdvEnableCallback(int32_t channel, int32_t status)
{
    (void)channel;
    (void)status;
}

static void BleAdvDisableCallback(int32_t channel, int32_t status)
{
    (void)channel;
    (void)status;
}

static void BleAdvDataCallback(int32_t channel, int32_t status)
{
    (void)channel;
    (void)status;
}

static void BleAdvUpdateCallback(int32_t channel, int32_t status)
{
    (void)channel;
    (void)status;
}

static BroadcastCallback g_advCallback = {
    .OnStartBroadcastingCallback = BleAdvEnableCallback,
    .OnStopBroadcastingCallback = BleAdvDisableCallback,
    .OnUpdateBroadcastingCallback = BleAdvUpdateCallback,
    .OnSetBroadcastingCallback = BleAdvDataCallback,
};

static void BleOnScanStart(int32_t listenerId, int32_t status)
{
    (void)listenerId;
    (void)status;
}

static void BleOnScanStop(int32_t listenerId, int32_t status)
{
    (void)listenerId;
    (void)status;
}

static void BleScanResultCallback(int32_t listenerId, const BroadcastReportInfo *reportInfo)
{
    (void)listenerId;
    (void)reportInfo;
}

static ScanCallback g_scanListener = {
    .OnStartScanCallback = BleOnScanStart,
    .OnStopScanCallback = BleOnScanStop,
    .OnReportScanDataCallback = BleScanResultCallback,
};

void StartBroadcastingFuzzTest(int32_t bcId, const uint8_t* data, size_t size)
{
    BroadcastParam param;
    BuildBroadcastParam(data, size, &param);
    BroadcastPacket packet;
    BuildBroadcastPacket(data, size, &packet);

    StartBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void UpdateBroadcastingFuzzTest(int32_t bcId, const uint8_t* data, size_t size)
{
    BroadcastParam param;
    BuildBroadcastParam(data, size, &param);
    BroadcastPacket packet;
    BuildBroadcastPacket(data, size, &packet);

    UpdateBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void SetBroadcastingDataFuzzTest(int32_t bcId, const uint8_t* data, size_t size)
{
    BroadcastPacket packet;
    BuildBroadcastPacket(data, size, &packet);

    SetBroadcastingData(bcId, &packet);
    DestroyBleConfigAdvData(&packet);
}

void StopBroadcastingFuzzTest(int32_t bcId)
{
    StopBroadcasting(bcId);
}

void StartScanFuzzTest(int32_t listenerId)
{
    BcScanParams scanParam = BuildScanParam();

    StartScan(listenerId, &scanParam);
}

void StopScanFuzzTest(int32_t listenerId)
{
    StopScan(listenerId);
}

void BroadcastSetAdvDeviceParamFuzzTest(int32_t listenerId, const uint8_t* data, size_t size)
{
    g_baseFuzzPos = 0;
    uint8_t type = GetData<uint8_t>();
    LpScanParam lpScanParam = BuildLpScanParam();
    lpScanParam.listenerId = listenerId;
    LpBroadcastParam lpBcParam;
    BuildLpBroadcastParam(data, size, &lpBcParam);

    BroadcastSetAdvDeviceParam(static_cast<LpServerType>(type), &lpBcParam, &lpScanParam);
    DestroyBleConfigAdvData(&lpBcParam.packet);
}

void BroadcastGetBroadcastHandleFuzzTest(int32_t bcId)
{
    g_baseFuzzPos = 0;
    int32_t bcHandle = GetData<int32_t>();

    BroadcastGetBroadcastHandle(bcId, &bcHandle);
}

void BroadcastSetScanReportChannelToLpDeviceFuzzTest(int32_t listenerId)
{
    g_baseFuzzPos = 0;
    bool enable = GetData<bool>();

    BroadcastSetScanReportChannelToLpDevice(listenerId, enable);
}

void BroadcastSetLpAdvParamFuzzTest()
{
    g_baseFuzzPos = 0;
    int32_t duration = GetData<int32_t>();
    int32_t maxExtAdvEvents = GetData<int32_t>();
    int32_t window = GetData<int32_t>();
    int32_t interval = GetData<int32_t>();
    int32_t lpAdvBCHandle = GetData<int32_t>();

    BroadcastSetLpAdvParam(duration, maxExtAdvEvents, window, interval, lpAdvBCHandle);
}

} // OHOS namespace

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_DATA_LEN) {
        return 0;
    }
    OHOS::BASE_FUZZ_DATA = data;
    OHOS::g_baseFuzzSize = size;

    int32_t listenerId = -1;
    int32_t bcId = -1;

    InitBroadcastMgr();
    RegisterBroadcaster(SRV_TYPE_DIS, &bcId, &OHOS::g_advCallback);
    RegisterScanListener(SRV_TYPE_DIS, &listenerId, &OHOS::g_scanListener);

    OHOS::StartBroadcastingFuzzTest(bcId, data, size);
    OHOS::UpdateBroadcastingFuzzTest(bcId, data, size);
    OHOS::SetBroadcastingDataFuzzTest(bcId, data, size);
    OHOS::StopBroadcastingFuzzTest(bcId);
    OHOS::StartScanFuzzTest(listenerId);
    OHOS::StopScanFuzzTest(listenerId);
    OHOS::BroadcastSetAdvDeviceParamFuzzTest(listenerId, data, size);
    OHOS::BroadcastGetBroadcastHandleFuzzTest(bcId);
    OHOS::BroadcastSetScanReportChannelToLpDeviceFuzzTest(listenerId);
    OHOS::BroadcastSetLpAdvParamFuzzTest();

    UnRegisterScanListener(listenerId);
    UnRegisterBroadcaster(bcId);
    DeInitBroadcastMgr();
    return 0;
}
