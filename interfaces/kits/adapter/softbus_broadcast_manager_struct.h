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
 * @file softbus_broadcast_manager.h
 * @brief
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_MANAGER_STRUCT_H
#define SOFTBUS_BROADCAST_MANAGER_STRUCT_H

#include <stdint.h>
#include "softbus_broadcast_type_struct.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines the broadcast callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnStopBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnUpdateBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnSetBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnSetBroadcastingParamCallback)(int32_t bcId, int32_t status);
    void (*OnEnableBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnDisableBroadcastingCallback)(int32_t bcId, int32_t status);
} BroadcastCallback;

/**
 * @brief Defines the broadcast scan callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(int32_t listenerId, int32_t status);
    void (*OnStopScanCallback)(int32_t listenerId, int32_t status);
    void (*OnReportScanDataCallback)(int32_t listenerId, const BroadcastReportInfo *reportInfo);
    void (*OnScanStateChanged)(int32_t resultCode, bool isStartScan);
    void (*OnLpDeviceInfoCallback)(const BroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize);
} ScanCallback;

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_MANAGER_STRUCT_H */
