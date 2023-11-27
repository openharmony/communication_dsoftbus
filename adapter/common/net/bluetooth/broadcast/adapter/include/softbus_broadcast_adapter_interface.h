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
 * @since 1.0
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H
#define SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H

#include "softbus_broadcast_adapter_type.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines the broadcast callback function.
 *
 * @since 1.0
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
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(int32_t scanId, int32_t status);
    void (*OnStopScanCallback)(int32_t scanId, int32_t status);
    void (*OnReportScanDataCallback)(int32_t scanId, const SoftBusBleScanResult *reportData);
} SoftbusScanCallback;

/**
 * @brief Defines Different broadcast protocol stacks adapt layer interfaces
 *
 * @since 1.0
 * @version 1.0
 */
struct SoftbusBroadcastMediumInterface {
    int32_t (*InitBroadcast)(void);
    int32_t (*DeInitBroadcast)(void);
    int32_t (*RegisterBroadcaster)(int32_t *advId, const SoftbusBroadcastCallback *cb);
    int32_t (*UnRegisterBroadcaster)(int32_t advId);
    int32_t (*RegisterScanListener)(int32_t *scanerId, const SoftbusScanCallback *cb);
    int32_t (*UnRegisterScanListener)(int32_t scanerId);
    int32_t (*StartBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *bcData,
        const SoftbusBroadcastData *rspData);
    int32_t (*UpdateBroadcasting)(int32_t advId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *bcData,
        const SoftbusBroadcastData *rspData);
    int32_t (*StopBroadcasting)(int32_t advId);
    int32_t (*StartScan)(int32_t scanerId, const SoftBusBcScanParams *param);
    int32_t (*StopScan)(int32_t scanerId);
    int32_t (*SetScanFilter)(int32_t scanerId, const SoftBusBcScanFilter *scanFilter, uint8_t filterSize);
    int32_t (*GetScanFilter)(int32_t scanerId, const SoftBusBcScanFilter *scanFilter, uint8_t *filterSize);
    int32_t (*QueryBroadcastStatus)(int32_t advId, int32_t *status);
};

/**
 * @brief Defines interface functions for registering different media
 *
 * @since 1.0
 * @version 1.0
 */

int32_t RegisterBroadcastMediumFunction(enum SoftbusMediumType type,
    const struct SoftbusBroadcastMediumInterface *interface);
/**
 * @brief Defines interface functions for unregistering different media
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnRegisterBroadcastMediumFunction(enum SoftbusMediumType type);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_ADAPTER_INTERFACE_H */