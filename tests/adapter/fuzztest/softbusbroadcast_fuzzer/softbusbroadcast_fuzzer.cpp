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
#include <cstdio>
#include <securec.h>
#include <sstream>
#include <string>

#include "disc_ble.h"
#include "disc_ble_utils.h"
#include "lnn_local_net_ledger.h"
#include "message_handler.h"
#include "message_parcel.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_adapter_type.h"
#include "softbus_broadcast_adapter_interface.h"
#include "softbus_ble_gatt.h"
#include "softbus_errcode.h"

#define MIN_DATA_LEN 30

#define BC_NUM_MAX 16
#define BC_INTERNAL 48
#define BC_ADV_TX_POWER_DEFAULT (-6)
#define BC_CHANNLE_MAP 0x0
#define SERVICE_UUID 0xFDEE
#define BC_ADV_FLAG 0x2
#define MANUFACTURE_COMPANY_ID 0x027D

namespace OHOS {

size_t size;

static int32_t BuildBroadcastParam(MessageParcel &parcel, BroadcastParam *param)
{
    param->minInterval = BC_INTERNAL;
    param->maxInterval = BC_INTERNAL;
    param->advType = SOFTBUS_BC_ADV_IND;
    param->ownAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    param->peerAddrType = SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
    param->channelMap = BC_CHANNLE_MAP;
    param->txPower = BC_ADV_TX_POWER_DEFAULT;

    if (!parcel.ReadUint8(param->advFilterPolicy) || !parcel.ReadBool(param->isSupportRpa) ||
        !parcel.ReadInt32(param->duration)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(param->ownIrk, BC_IRK_LEN, parcel.ReadBuffer(BC_IRK_LEN), BC_IRK_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(param->ownUdidHash, BC_UDID_HASH_LEN, parcel.ReadBuffer(BC_UDID_HASH_LEN),
        BC_UDID_HASH_LEN) != EOK) {
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

static int32_t BuildBroadcastPacket(MessageParcel &parcel, BroadcastPacket *packet)
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
    if (memcpy_s(packet->bcData.payload, ADV_DATA_MAX_LEN, parcel.ReadBuffer(packet->bcData.payloadLen),
        packet->bcData.payloadLen) != EOK) {
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
    if (memcpy_s(&packet->rspData.payload[0], RESP_DATA_MAX_LEN, parcel.ReadBuffer(packet->rspData.payloadLen),
        packet->rspData.payloadLen) != EOK) {
        DestroyBleConfigAdvData(packet);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static BcScanParams BuildScanParam()
{
    BcScanParams scanParam;
    scanParam.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
    scanParam.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    scanParam.scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE;
    scanParam.scanPhy = SOFTBUS_BC_SCAN_PHY_1M;
    scanParam.scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL;
    return scanParam;
}

static int32_t BuildLpBroadcastParam(MessageParcel &parcel, LpBroadcastParam *lpBcParam)
{
    int32_t ret = BuildBroadcastParam(parcel, &lpBcParam->bcParam);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = BuildBroadcastPacket(parcel, &lpBcParam->packet);
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

static void BleAdvEnableCallback(int channel, int status)
{
    (void)channel;
    (void)status;
}

static void BleAdvDisableCallback(int channel, int status)
{
    (void)channel;
    (void)status;
}

static void BleAdvDataCallback(int channel, int status)
{
    (void)channel;
    (void)status;
}

static void BleAdvUpdateCallback(int channel, int status)
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

static void BleOnScanStart(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
}

static void BleOnScanStop(int listenerId, int status)
{
    (void)listenerId;
    (void)status;
}

static void BleScanResultCallback(int listenerId, const BroadcastReportInfo *reportInfo)
{
    (void)listenerId;
    (void)reportInfo;
}

static ScanCallback g_scanListener = {
    .OnStartScanCallback = BleOnScanStart,
    .OnStopScanCallback = BleOnScanStop,
    .OnReportScanDataCallback = BleScanResultCallback,
};

void StartBroadcastingFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t bcId;
    if (!parcel.ReadInt32(bcId)) {
        return;
    }
    BroadcastParam param;
    if (BuildBroadcastParam(parcel, &param) != SOFTBUS_OK) {
        return;
    }
    BroadcastPacket packet;
    if (BuildBroadcastPacket(parcel, &packet) != SOFTBUS_OK) {
        return;
    }

    StartBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void UpdateBroadcastingFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t bcId;
    if (!parcel.ReadInt32(bcId)) {
        return;
    }
    BroadcastParam param;
    if (BuildBroadcastParam(parcel, &param) != SOFTBUS_OK) {
        return;
    }
    BroadcastPacket packet;
    if (BuildBroadcastPacket(parcel, &packet) != SOFTBUS_OK) {
        return;
    }

    UpdateBroadcasting(bcId, &param, &packet);
    DestroyBleConfigAdvData(&packet);
}

void SetBroadcastingDataFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t bcId;
    if (!parcel.ReadInt32(bcId)) {
        return;
    }
    BroadcastPacket packet;
    if (BuildBroadcastPacket(parcel, &packet) != SOFTBUS_OK) {
        return;
    }

    SetBroadcastingData(bcId, &packet);
    DestroyBleConfigAdvData(&packet);
}

void StopBroadcastingFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t bcId;
    if (!parcel.ReadInt32(bcId)) {
        return;
    }
    StopBroadcasting(bcId);
}

void StartScanFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t listenerId;
    if (!parcel.ReadInt32(listenerId)) {
        return;
    }
    BcScanParams scanParam = BuildScanParam();

    StartScan(listenerId, &scanParam);
}

void StopScanFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t listenerId;
    if (!parcel.ReadInt32(listenerId)) {
        return;
    }
    StopScan(listenerId);
}

void BroadcastSetAdvDeviceParamFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    uint8_t type;
    if (!parcel.ReadUint8(type)) {
        return;
    }
    LpScanParam lpScanParam = BuildLpScanParam();
    LpBroadcastParam lpBcParam;
    if (!parcel.ReadInt32(lpScanParam.listenerId) || !parcel.ReadInt32(lpBcParam.bcHandle)) {
        return;
    }
    if (BuildLpBroadcastParam(parcel, &lpBcParam) != SOFTBUS_OK) {
        return;
    }

    BroadcastSetAdvDeviceParam(static_cast<SensorHubServerType>(type), &lpBcParam, &lpScanParam);
    DestroyBleConfigAdvData(&lpBcParam.packet);
}

void BroadcastGetBroadcastHandleFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t bcHandle;
    int32_t bcId;
    if (!parcel.ReadInt32(bcHandle) || !parcel.ReadInt32(bcId)) {
        return;
    }

    BroadcastGetBroadcastHandle(bcId, &bcHandle);
}

void BroadcastSetScanReportChannelToLpDeviceFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    bool enable;
    int32_t listenerId;
    if (!parcel.ReadBool(enable) || !parcel.ReadInt32(listenerId)) {
        return;
    }

    BroadcastSetScanReportChannelToLpDevice(listenerId, enable);
}

void BroadcastSetLpAdvParamFuzzTest(MessageParcel &parcel)
{
    parcel.RewindRead(0);
    int32_t duration;
    int32_t maxExtAdvEvents;
    int32_t window;
    int32_t interval;
    int32_t lpAdvBCHandle;
    if (!parcel.ReadInt32(duration) || !parcel.ReadInt32(maxExtAdvEvents) || !parcel.ReadInt32(window) ||
        !parcel.ReadInt32(interval) || !parcel.ReadInt32(lpAdvBCHandle)) {
        return;
    }

    BroadcastSetLpAdvParam(duration, maxExtAdvEvents, window, interval, lpAdvBCHandle);
}

} // OHOS namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < MIN_DATA_LEN) {
        return 0;
    }
    OHOS::size = size;
    OHOS::MessageParcel parcel;
    parcel.WriteBuffer(data, size);

    int32_t listenerId = -1;
    int32_t bcId = -1;

    InitBroadcastMgr();
    RegisterBroadcaster(SRV_TYPE_DIS, &bcId, &OHOS::g_advCallback);
    RegisterScanListener(SRV_TYPE_DIS, &listenerId, &OHOS::g_scanListener);

    OHOS::StartBroadcastingFuzzTest(parcel);
    OHOS::UpdateBroadcastingFuzzTest(parcel);
    OHOS::SetBroadcastingDataFuzzTest(parcel);
    OHOS::StopBroadcastingFuzzTest(parcel);
    OHOS::StartScanFuzzTest(parcel);
    OHOS::StopScanFuzzTest(parcel);
    OHOS::BroadcastSetAdvDeviceParamFuzzTest(parcel);
    OHOS::BroadcastGetBroadcastHandleFuzzTest(parcel);
    OHOS::BroadcastSetScanReportChannelToLpDeviceFuzzTest(parcel);
    OHOS::BroadcastSetLpAdvParamFuzzTest(parcel);

    UnRegisterScanListener(listenerId);
    UnRegisterBroadcaster(bcId);
    DeInitBroadcastMgr();
    return 0;
}
