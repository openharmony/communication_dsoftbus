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

#ifndef BLE_RANGE_H
#define BLE_RANGE_H

#include <stdint.h>
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BLE_ADV_HB,
    SLE_CONN_HADM,
} RangeMedium;

typedef struct {
    RangeMedium medium;
    float distance;
    char networkId[NETWORK_ID_BUF_LEN];
    uint32_t length;
    uint8_t *addition;
} RangeResult;

typedef struct {
    RangeMedium medium;
    int32_t state;
    int32_t reason;
    char networkId[NETWORK_ID_BUF_LEN];
} RangeState;

typedef struct {
    /**
     * @brief Called when the devices receive ble range result.
     *
     * @param info Indicates the ble range result.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onRangeResult)(const RangeResult *result);
    void (*onRangeStateChange)(const RangeState state);
} IRangeCallback;

/**
 * @brief Registers a callback for ble range result.
 *
 * @param pkgName Indicates the package name of the caller.
 * @param callback Indicates the function callback to be registered. For details, see {@link IRangeCallback}.
 * @return Returns <b>0</b> if the registeration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegisterRangeCallbackForMsdp(const char *pkgName, IRangeCallback *callback);

/**
 * @brief Unregisters a callback for ble range result.
 *
 * @param pkgName Indicates the package name of the caller.
 * @return Returns <b>0</b> if the registeration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnregisterRangeCallbackForMsdp(const char *pkgName);

/**
 * @brief Defines heartbeat mode parameter, see{@link HbMode}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    int32_t duration; /** Heartbeat for range duration, unit is seconds */
    bool connFlag;    /** Heartbeat could connect or not */
    bool replyFlag;   /** Heartbeat need reply or not, set this parameter to true if need reply */
} HbMode;

typedef struct {
    RangeMedium medium;
    union {
        struct  HbConfig {
            HbMode mode;                            // BLE_ADV_HB
        } heartbeat;
        struct SleConfig {
            char networkId[NETWORK_ID_BUF_LEN];     // SLE_CONN_HADM
        } sle;
    } configInfo;
} RangeConfig;

/**
 * @brief Modify heartbeat parameters and trigger a temporary heartbeat.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * @param callerId The id of the caller, whitch cannot be <b>NULL</b>, and maxium length is {@link CALLER_ID_MAX_LEN}.
 *
 * @return Returns <b>0</b> if the call is success; returns any other value if it fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t TriggerRangeForMsdp(const char *pkgName, const RangeConfig *config);

int32_t StopRangeForMsdp(const char *pkgName, const RangeConfig *config);

#ifdef __cplusplus
}
#endif
#endif