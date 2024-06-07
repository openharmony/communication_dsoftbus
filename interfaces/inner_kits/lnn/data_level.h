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

/**
 * @addtogroup SoftBus
 * @{
 *
 * @brief Provides data level of distributed database transport by DSoftBus ble heratbeat.
 *
 * This module implements unified distributed communication management of nearby devices and provides link-independent
 * device discovery and transmission interfaces to support service publishing and data transmission.
 * @since 1.0
 * @version 1.0
 */
/** @} */

#ifndef DATA_LEVEL_H
#define DATA_LEVEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Defines a callback that is invoked when receive the data level from remote device.
 * For details, see {@link RegDataLevelChangeCb}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    uint16_t dynamicLevel; /**< dynamic data level, 16bit */
    uint16_t staticLevel; /**< static data level, 16bit */
    uint32_t switchLevel; /**< switch data level, alterable length, 16bit, 24bit or 32bit */
    uint16_t switchLength; /**< switch data length, max 24 switchs */
} DataLevel;

typedef struct {
    /**
     * @brief Called when the Data level of a device received.
     *
     * @param networkId Indicates the network id of the device.
     * @param dataLevel Indicates the received data level.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onDataLevelChanged)(const char *networkId, const DataLevel dataLevel);
} IDataLevelCb;

/**
 * @brief Registers a callback for data level received.
 *
 * @param pkgName Indicates the package name of the caller.
 * @param callback Indicates the function callback to be registered. For details, see {@link IDataLevelCb}.
 * @return Returns <b>0</b> if the registeration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegDataLevelChangeCb(const char *pkgName, IDataLevelCb *callback);

/**
 * @brief Unregisters a callback for data level received.
 *
 * @param pkgName Indicates the package name of the caller.
 * @return Returns <b>0</b> if the registeration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnregDataLevelChangeCb(const char *pkgName);

/**
 * @brief Set the DistributedDataBase Data Level. This interface CAN ONLY invoked by DistributedDataBase.
 *
 * @param dataLevel Indicates the data level.
 * @return Returns <b>0</b> if the registeration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t SetDataLevel(const DataLevel *dataLevel);

#ifdef __cplusplus
}
#endif
#endif