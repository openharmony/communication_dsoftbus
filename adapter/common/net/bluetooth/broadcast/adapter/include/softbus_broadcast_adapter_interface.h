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
 * @file softbus_broadcast_adapter_interface.h
 * @brief Different broadcast protocol stacks adapt layer interfaces
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H
#define SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H

#include "softbus_broadcast_adapter_type.h"
#include "softbus_broadcast_type.h"

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
    void (*OnStartBroadcastingCallback)(int32_t advId, int32_t status);
    void (*OnStopBroadcastingCallback)(int32_t advId, int32_t status);
    void (*OnUpdateBroadcastingCallback)(int32_t advId, int32_t status);
    void (*OnSetBroadcastingCallback)(int32_t advId, int32_t status);
} SoftbusBroadcastCallback;

/**
 * @brief Defines the broadcast scan callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(int32_t scannerId, int32_t status);
    void (*OnStopScanCallback)(int32_t scannerId, int32_t status);
    void (*OnReportScanDataCallback)(int32_t scannerId, const SoftBusBcScanResult *reportData);
    void (*OnScanStateChanged)(int32_t resultCode, bool isStartScan);
    void (*OnLpDeviceInfoCallback)(const SoftbusBroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize);
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
    int32_t (*StartBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data);
    int32_t (*StopBroadcasting)(int32_t advId);
    int32_t (*SetBroadcastingData)(int32_t advId, const SoftbusBroadcastData *data);
    int32_t (*UpdateBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data);
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

/**
 * @brief Defines interface functions for registering different media
 *
 * @since 4.1
 * @version 1.0
 */
int32_t RegisterBroadcastMediumFunction(SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface);

/**
 * @brief Defines interface functions for unregistering different media
 *
 * @since 4.1
 * @version 1.0
 */
int32_t UnRegisterBroadcastMediumFunction(SoftbusMediumType type);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H */
