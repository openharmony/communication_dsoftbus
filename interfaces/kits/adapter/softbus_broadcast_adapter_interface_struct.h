/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 * @file softbus_broadcast_adapter_interface.h
 * @brief Different broadcast protocol stacks adapt layer interfaces
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_ADAPTER_INTERFACE_STRUCT_H
#define SOFTBUS_BROADCAST_ADAPTER_INTERFACE_STRUCT_H

#include "softbus_broadcast_adapter_type_struct.h"
#include "softbus_broadcast_type_struct.h"

#ifdef __cplusplus
extern "C"{
#endif

#define MEDIUM_MAX_NUM 2

/**
 * @brief Defines the broadcast callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnStopBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnUpdateBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnSetBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnSetBroadcastingParamCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnEnableBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
    void (*OnDisableBroadcastingCallback)(BroadcastProtocol protocol, int32_t advId, int32_t status);
} SoftbusBroadcastCallback;

/**
 * @brief Defines the broadcast scan callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(BroadcastProtocol protocol, int32_t scannerId, int32_t status);
    void (*OnStopScanCallback)(BroadcastProtocol protocol, int32_t scannerId, int32_t status);
    void (*OnReportScanDataCallback)(BroadcastProtocol protocol, int32_t scannerId,
        const SoftBusBcScanResult *reportData);
    void (*OnScanStateChanged)(BroadcastProtocol protocol, int32_t resultCode, bool isStartScan);
    void (*OnLpDeviceInfoCallback)(BroadcastProtocol protocol, const SoftbusBroadcastUuid *uuid,
        int32_t type, uint8_t *data, uint32_t dataSize);
} SoftbusScanCallback;

/**
 * @brief Defines Different broadcast protocol stacks adapt layer interfaces
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    int32_t (*Init)(void);
    int32_t (*DeInit)(void);
    int32_t (*RegisterBroadcaster)(int32_t *advId, const SoftbusBroadcastCallback *cb);
    int32_t (*UnRegisterBroadcaster)(int32_t advId);
    int32_t (*RegisterScanListener)(int32_t *scannerId, const SoftbusScanCallback *cb);
    int32_t (*UnRegisterScanListener)(int32_t scannerId);
    int32_t (*StartBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, SoftbusBroadcastData *data);
    int32_t (*SetScanParams)(int32_t scannerId, const SoftBusBcScanParams *param, const SoftBusBcScanFilter *scanFilter,
        int32_t filterSize, SoftbusSetFilterCmd cmdId);
    int32_t (*StopBroadcasting)(int32_t advId);
    int32_t (*EnableAdvertising)(uint8_t advHandle);
    int32_t (*DisableAdvertising)(uint8_t advHandle);
    int32_t (*SetBroadcastingData)(int32_t advId, const SoftbusBroadcastData *data);
    int32_t (*SetBroadcastingParam)(int32_t advId, const SoftbusBroadcastParam *param);
    int32_t (*EnableBroadcasting)(int32_t advId);
    int32_t (*DisableBroadcasting)(int32_t advId);
    int32_t (*UpdateBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, SoftbusBroadcastData *data);
    int32_t (*StartScan)(int32_t scannerId, const SoftBusBcScanParams *param, const SoftBusBcScanFilter *scanFilter,
        int32_t filterSize);
    int32_t (*StopScan)(int32_t scannerId);
    bool (*IsLpDeviceAvailable)(void);
    bool (*SetAdvFilterParam)(LpServerType type, const SoftBusLpBroadcastParam *bcParam,
        const SoftBusLpScanParam *scanParam);
    int32_t (*GetBroadcastHandle)(int32_t advId, int32_t *bcHandle);
    int32_t (*EnableSyncDataToLpDevice)(void);
    int32_t (*DisableSyncDataToLpDevice)(void);
    int32_t (*SetScanReportChannelToLpDevice)(int32_t scannerId, bool enable);
    int32_t (*SetLpDeviceParam)(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
        int32_t interval, int32_t bcHandle);
} SoftbusBroadcastMediumInterface;

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_ADAPTER_INTERFACE_STRUCT_H */
