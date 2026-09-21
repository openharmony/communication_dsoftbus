/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_PERCEPTION_H
#define LNN_PERCEPTION_H

#include <stdint.h>

#include "softbus_broadcast_type_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PERCEPTION_MAX_DEVICE_NUM      30

/** @brief Defines the supported perception service types. */
typedef enum {
    PERCEPTION_TYPE_COLLABORATIVE_WAKE = 0,
    PERCEPTION_TYPE_BUTT,
} PerceptionType;

/** @brief Defines the custom payload used to start or update perception advertising. */
typedef struct {
    uint8_t customData[PERCEPTION_CUSTOM_DATA_MAX_LEN];
    uint32_t customDataLen;
} PerceptionAdvParam;

/** @brief Defines the perception scan keepalive cycle. */
typedef enum {
    PERCEPTION_CYCLE_LOW = 0,    /**< Low cycle, keepalive 30s. */
    PERCEPTION_CYCLE_MEDIUM,     /**< Medium cycle, keepalive 75s. */
    PERCEPTION_CYCLE_HIGH,       /**< High cycle, keepalive 150s. */
    PERCEPTION_CYCLE_BUTT,
} PerceptionCycle;

/** @brief Starts perception advertising or updates its custom payload for the current owner. */
int32_t StartPerceptionAdv(const char *pkgName, PerceptionType type, const PerceptionAdvParam *param);

/** @brief Switches an active perception advertiser to high frequency for ten seconds and updates its custom payload. */
int32_t SetPerceptionAdvHighFreq(const char *pkgName, PerceptionType type, const PerceptionAdvParam *param);

/** @brief Stops perception advertising for the current owner. */
int32_t StopPerceptionAdv(const char *pkgName, PerceptionType type);

/** @brief Starts perception scanning for the current owner with specified keepalive cycle. */
int32_t StartPerceptionScan(const char *pkgName, PerceptionType type, PerceptionCycle cycle);

/** @brief Stops perception scanning and clears its device list. */
int32_t StopPerceptionScan(const char *pkgName, PerceptionType type);

/** @brief Returns a snapshot of devices discovered by perception scanning. The list is dynamically
 *  allocated by softbus and must be released by FreePerceptionDeviceList. */
int32_t GetPerceptionDeviceList(
    const char *pkgName, PerceptionType type, PerceptionDeviceInfo **list, uint32_t *count);

/** @brief Releases the device list returned by GetPerceptionDeviceList. */
void FreePerceptionDeviceList(PerceptionDeviceInfo *list);

#ifdef __cplusplus
}
#endif
#endif // LNN_PERCEPTION_H
