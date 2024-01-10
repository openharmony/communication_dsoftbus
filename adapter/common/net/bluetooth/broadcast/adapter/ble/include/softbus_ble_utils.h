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

/**
 * @file softbus_ble_utils.h
 * @brief ble utils
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BLE_UTILS_H
#define SOFTBUS_BLE_UTILS_H

#include "softbus_broadcast_adapter_interface.h"
#include "c_header/ohos_bt_gatt.h"
#include "c_header/ohos_bt_def.h"

#ifdef __cplusplus
extern "C"{
#endif

int32_t BtStatusToSoftBus(BtStatus btStatus);

void SoftbusAdvParamToBt(const SoftbusBroadcastParam *src, BleAdvParams *dst);

void BtScanResultToSoftbus(const BtScanResultData *src, SoftBusBcScanResult *dst);

void SoftbusFilterToBt(BleScanNativeFilter *nativeFilter, const SoftBusBcScanFilter *filter, uint8_t filterSize);

void FreeBtFilter(BleScanNativeFilter *nativeFilter, int32_t filterSize);

void DumpBleScanFilter(BleScanNativeFilter *nativeFilter, int32_t filterSize);

int GetBtScanMode(uint16_t scanInterval, uint16_t scanWindow);

uint8_t *AssembleAdvData(const SoftbusBroadcastData *data, uint16_t *dataLen);

uint8_t *AssembleRspData(const SoftbusBroadcastPayload *data, uint16_t *dataLen);

int32_t ParseScanResult(const uint8_t *advData, uint8_t advLen, SoftBusBcScanResult *dst);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BLE_UTILS_H */