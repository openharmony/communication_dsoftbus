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
#include "softbus_ble_utils.h"
#include "softbus_ble_gatt_public.h"

#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <type_traits>
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
#define FILTER_SIZE 1

using namespace std;
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

template <class T> T* GetDataArray()
{
    const size_t outSize = sizeof(T);
    const size_t outLength = g_baseFuzzSize / outSize;

    size_t allocSize = outLength * outSize;
    if constexpr (std::is_same_v<T, char>) {
        allocSize += outSize;
    }

    T* array = static_cast<T*>(malloc(allocSize));
    if (BASE_FUZZ_DATA == nullptr || array == nullptr) {
        return nullptr;
    }

    errno_t ret = memcpy_s(array, allocSize, BASE_FUZZ_DATA, outLength * outSize);
    if (ret != EOK) {
        free(array);
        return nullptr;
    }

    if constexpr (std::is_same_v<T, char>) {
        array[outLength] = '\0';
    }

    return array;
}

template <class T> void GetDataArray(T *dst, size_t dstLength)
{
    size_t dstLen = dstLength * sizeof(T);
    size_t copyLen = (g_baseFuzzSize < dstLen) ? g_baseFuzzSize : dstLen;
    errno_t ret = memcpy_s(dst, dstLen, BASE_FUZZ_DATA, copyLen);
    if (ret != EOK) {
        return;
    }
    if (copyLen < dstLen) {
        ret = memset_s(static_cast<uint8_t*>(dst) + copyLen, dstLen, 0, dstLen - copyLen);
        if (ret != EOK) {
            return;
        }
    }
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

static BcScanFilter BuildScanFilter()
{
    g_baseFuzzPos = 0;
    BcScanFilter scanFilter;
    scanFilter.advIndReport = GetData<bool>();
    scanFilter.serviceUuid = GetData<uint16_t>();
    scanFilter.serviceDataLength = GetData<uint32_t>();
    scanFilter.manufactureId = GetData<uint16_t>();
    scanFilter.manufactureDataLength = GetData<uint32_t>();
    scanFilter.filterIndex = GetData<uint8_t>();
    scanFilter.address = GetDataArray<int8_t>();
    scanFilter.deviceName = GetDataArray<int8_t>();
    scanFilter.serviceData = GetDataArray<uint8_t>();
    scanFilter.serviceDataMask = GetDataArray<uint8_t>();
    scanFilter.manufactureData = GetDataArray<uint8_t>();
    scanFilter.manufactureDataMask = GetDataArray<uint8_t>();
    return scanFilter;
}

static BleScanNativeFilter BuildBleScanNativeFilter()
{
    g_baseFuzzPos = 0;
    BleScanNativeFilter nativeFilter;
    nativeFilter.serviceUuidLength = GetData<unsigned int>();
    nativeFilter.serviceDataLength = GetData<unsigned int>();
    nativeFilter.manufactureDataLength = GetData<unsigned int>();
    nativeFilter.manufactureId = GetData<unsigned short>();
    nativeFilter.advIndReport = GetData<bool>();
    nativeFilter.filterIndex = GetData<uint8_t>();
    nativeFilter.address = GetDataArray<char>();
    nativeFilter.deviceName = GetDataArray<char>();
    nativeFilter.serviceUuid = GetDataArray<unsigned char>();
    nativeFilter.serviceUuidMask = GetDataArray<unsigned char>();
    nativeFilter.serviceData = GetDataArray<unsigned char>();
    nativeFilter.serviceDataMask = GetDataArray<unsigned char>();
    nativeFilter.manufactureData = GetDataArray<unsigned char>();
    nativeFilter.manufactureDataMask = GetDataArray<unsigned char>();
    return nativeFilter;
}

static SoftbusBroadcastPayload BuildSoftbusBroadcastPayload()
{
    g_baseFuzzPos = 0;
    SoftbusBroadcastPayload payload;
    size_t enumRange = BROADCAST_DATA_TYPE_BUTT - BROADCAST_DATA_TYPE_SERVICE + 1;
    uint8_t adjustedValue = GetData<uint8_t>() % enumRange;
    payload.type = (SoftbusBcDataType)adjustedValue;
    payload.id = GetData<uint16_t>();
    payload.payloadLen = g_baseFuzzSize;
    payload.payload = GetDataArray<uint8_t>();
    return payload;
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

void StartBroadcastingFuzzTest(int32_t bcId, FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
    BroadcastParam param;
    BuildBroadcastParam(data, stringData.size(), &param);
    string stringData1 = provider.ConsumeBytesAsString(size);
    const uint8_t *data1 = reinterpret_cast<const uint8_t *>(stringData1.data());
    BroadcastPacket packet;
    BuildBroadcastPacket(data1, stringData1.size(), &packet);

    StartBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void UpdateBroadcastingFuzzTest(int32_t bcId, FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
    BroadcastParam param;
    BuildBroadcastParam(data, stringData.size(), &param);
    string stringData1 = provider.ConsumeBytesAsString(size);
    const uint8_t *data1 = reinterpret_cast<const uint8_t *>(stringData1.data());
    BroadcastPacket packet;
    BuildBroadcastPacket(data1, stringData1.size(), &packet);

    UpdateBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void SetBroadcastingDataFuzzTest(int32_t bcId, FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
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

void BroadcastSetAdvDeviceParamFuzzTest(int32_t listenerId, FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
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

void SetBroadcastingParamFuzzTest(int32_t bcId, FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
    BroadcastParam param;
    BuildBroadcastParam(data, size, &param);

    SetBroadcastingParam(bcId, &param);
}

void SetScanFilterFuzzTest(int32_t listenerId)
{
    g_baseFuzzPos = 0;
    uint8_t filterNum = GetData<uint8_t>();
    BcScanFilter scanFilter = BuildScanFilter();

    SetScanFilter(listenerId, &scanFilter, filterNum);
}

void GetScanFilterFuzzTest(int32_t listenerId)
{
    g_baseFuzzPos = 0;
    uint8_t filterNum = GetData<uint8_t>();
    BcScanFilter *scanFilterRef = nullptr;

    GetScanFilter(listenerId, &scanFilterRef, &filterNum);
}

void QueryBroadcastStatusFuzzTest(int32_t bcId)
{
    int32_t *status = GetDataArray<int32_t>();

    QueryBroadcastStatus(bcId, status);
}

void BtStatusToSoftBusFuzzTest()
{
    size_t enumRange = OHOS_BT_STATUS_DUPLICATED_ADDR - OHOS_BT_STATUS_SUCCESS + 1;
    uint8_t adjustedValue = GetData<uint8_t>() % enumRange;

    BtStatusToSoftBus((BtStatus)adjustedValue);
}

void SoftbusAdvParamToBtFuzzTest()
{
    g_baseFuzzPos = 0;
    SoftbusBroadcastParam param;
    param.advType = GetData<uint8_t>();
    param.advFilterPolicy = GetData<uint8_t>();
    param.ownAddrType = GetData<uint8_t>();
    param.peerAddrType = GetData<uint8_t>();
    param.txPower = GetData<int8_t>();
    param.isSupportRpa = GetData<bool>();
    param.peerAddr = GetData<SoftbusMacAddr>();
    param.localAddr = GetData<SoftbusMacAddr>();
    param.minInterval = GetData<int32_t>();
    param.maxInterval = GetData<int32_t>();
    param.channelMap = GetData<int32_t>();
    param.duration = GetData<int32_t>();
    GetDataArray<uint8_t>(param.ownIrk, SOFTBUS_IRK_LEN);
    GetDataArray<uint8_t>(param.ownUdidHash, SOFTBUS_UDID_HASH_LEN);

    BleAdvParams advParams;
    param.minInterval = GetData<int>();
    param.maxInterval = GetData<int>();
    param.advType = GetData<BleAdvType>();
    param.ownAddrType = GetData<unsigned char>();
    param.peerAddrType = GetData<unsigned char>();
    param.channelMap = GetData<int>();
    param.advFilterPolicy = GetData<BleAdvFilter>();
    param.txPower = GetData<int>();
    param.duration = GetData<int>();
    GetDataArray<unsigned char>(param.peerAddr.addr, OHOS_BD_ADDR_LEN);

    SoftbusAdvParamToBt(&param, &advParams);
}

void BtScanResultToSoftbusFuzzTest()
{
    BtScanResultData src;
    src.eventType = GetData<unsigned char>();
    src.dataStatus = GetData<unsigned char>();
    src.addrType = GetData<unsigned char>();
    src.addr = GetData<BdAddr>();
    src.primaryPhy = GetData<unsigned char>();
    src.secondaryPhy = GetData<unsigned char>();
    src.advSid = GetData<unsigned char>();
    src.txPower = GetData<char>();
    src.rssi = GetData<char>();
    src.periodicAdvInterval = GetData<unsigned short>();
    src.directAddrType = GetData<unsigned char>();
    src.directAddr = GetData<BdAddr>();
    src.advLen = GetData<unsigned char>();
    src.advData = GetDataArray<unsigned char>();
    SoftBusBcScanResult dst;
    dst.eventType = GetData<uint8_t>();
    dst.dataStatus = GetData<uint8_t>();
    dst.primaryPhy = GetData<uint8_t>();
    dst.secondaryPhy = GetData<uint8_t>();
    dst.advSid = GetData<uint8_t>();
    dst.txPower = GetData<int8_t>();
    dst.rssi = GetData<int8_t>();
    dst.addrType = GetData<uint8_t>();
    dst.addr = GetData<SoftbusMacAddr>();
    dst.data.isSupportFlag = GetData<bool>();
    dst.data.flag = GetData<uint8_t>();
    GetDataArray<uint8_t>(dst.localName, SOFTBUS_LOCAL_NAME_LEN_MAX);
    dst.deviceName = GetDataArray<int8_t>();
    dst.data.bcData = BuildSoftbusBroadcastPayload();
    dst.data.rspData = BuildSoftbusBroadcastPayload();

    BtScanResultToSoftbus(&src, &dst);
}

void SoftbusSetManufactureFilterFuzzTest()
{
    BleScanNativeFilter nativeFilter = BuildBleScanNativeFilter();

    SoftbusSetManufactureFilter(&nativeFilter, FILTER_SIZE);
}

void FreeBtFilterFuzzTest()
{
    BleScanNativeFilter nativeFilter = BuildBleScanNativeFilter();

    FreeBtFilter(&nativeFilter, FILTER_SIZE);
}

void GetBtScanModeFuzzTest()
{
    uint16_t scanInterval = GetData<uint16_t>();
    uint16_t scanWindow = GetData<uint16_t>();

    GetBtScanMode(scanInterval, scanWindow);
}

void AssembleAdvDataFuzzTest()
{
    uint16_t dataLen = GetData<uint16_t>();
    SoftbusBroadcastData data;
    data.flag = GetData<uint8_t>();
    data.bcData = BuildSoftbusBroadcastPayload();
    data.rspData = BuildSoftbusBroadcastPayload();
    uint8_t *advData = AssembleAdvData(&data, &dataLen);
    if (advData != NULL) {
        SoftBusFree(advData);
    }
}

void AssembleRspDataFuzzTest()
{
    SoftbusBroadcastPayload payload = BuildSoftbusBroadcastPayload();
    uint16_t dataLen = GetData<uint16_t>();
    uint8_t *rspData = AssembleRspData(&payload, &dataLen);
    if (rspData != NULL) {
        SoftBusFree(rspData);
    }
}

void ParseScanResultFuzzTest()
{
    SoftBusBcScanResult dst;
    (void)memset_s(&dst, sizeof(SoftBusBcScanResult), 0, sizeof(SoftBusBcScanResult));
    dst.eventType = GetData<uint8_t>();
    dst.dataStatus = GetData<uint8_t>();
    dst.primaryPhy = GetData<uint8_t>();
    dst.secondaryPhy = GetData<uint8_t>();
    dst.advSid = GetData<uint8_t>();
    dst.txPower = GetData<int8_t>();
    dst.rssi = GetData<int8_t>();
    dst.addrType = GetData<uint8_t>();
    dst.addr = GetData<SoftbusMacAddr>();
    dst.data.isSupportFlag = GetData<bool>();
    dst.data.flag = GetData<uint8_t>();
    GetDataArray<uint8_t>(dst.localName, SOFTBUS_LOCAL_NAME_LEN_MAX);
    dst.deviceName = GetDataArray<int8_t>();
    dst.data.bcData = BuildSoftbusBroadcastPayload();
    dst.data.rspData = BuildSoftbusBroadcastPayload();
    uint8_t *data = GetDataArray<uint8_t>();

    ParseScanResult(data, g_baseFuzzSize, &dst);
    if (dst.data.bcData.payload != NULL) {
        SoftBusFree(dst.data.bcData.payload);
    }
}

void DumpSoftbusAdapterDataFuzzTest()
{
    char *description = GetDataArray<char>();
    uint8_t *data = GetDataArray<uint8_t>();
    DumpSoftbusAdapterData(description, data, g_baseFuzzSize);
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

    RegisterBroadcaster(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &bcId, &OHOS::g_advCallback);
    RegisterScanListener(BROADCAST_PROTOCOL_BLE, SRV_TYPE_DIS, &listenerId, &OHOS::g_scanListener);

    FuzzedDataProvider provider(data, size);
    OHOS::StartBroadcastingFuzzTest(bcId, provider);
    OHOS::UpdateBroadcastingFuzzTest(bcId, provider);
    OHOS::SetBroadcastingDataFuzzTest(bcId, provider);
    OHOS::StopBroadcastingFuzzTest(bcId);
    OHOS::StartScanFuzzTest(listenerId);
    OHOS::StopScanFuzzTest(listenerId);
    OHOS::BroadcastSetAdvDeviceParamFuzzTest(listenerId, provider);
    OHOS::BroadcastGetBroadcastHandleFuzzTest(bcId);
    OHOS::BroadcastSetScanReportChannelToLpDeviceFuzzTest(listenerId);
    OHOS::BroadcastSetLpAdvParamFuzzTest();
    OHOS::SetBroadcastingParamFuzzTest(bcId, provider);
    OHOS::GetScanFilterFuzzTest(listenerId);
    OHOS::QueryBroadcastStatusFuzzTest(bcId);
    OHOS::BtStatusToSoftBusFuzzTest();
    OHOS::SoftbusAdvParamToBtFuzzTest();
    OHOS::BtScanResultToSoftbusFuzzTest();
    OHOS::GetBtScanModeFuzzTest();
    OHOS::AssembleAdvDataFuzzTest();
    OHOS::AssembleRspDataFuzzTest();
    OHOS::ParseScanResultFuzzTest();
    OHOS::DumpSoftbusAdapterDataFuzzTest();

    UnRegisterScanListener(listenerId);
    UnRegisterBroadcaster(bcId);
    DeInitBroadcastMgr();
    return 0;
}
