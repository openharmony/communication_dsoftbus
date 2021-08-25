/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
 * @addtogroup Softbus
 * @{
 *
 * @brief Provides high-speed, secure communication between devices.
 *
 * This module implements unified distributed communication capability management between nearby devices, and provides
 * link-independent device discovery and transmission interfaces to support service publishing and data transmission.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file softbus_bus_center.h
 *
 * @brief Declares functions and constants for the bus center of the Intelligent Soft Bus.
 *
 * The functions are used to perform
 * the following operations: \n
 * <ul>
 * <li>Adding a device to and removing a device from a LNN</li>
 * <li>Listening for device online, offline, and information change events</li>
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef SOFTBUS_BUS_CENTER_H
#define SOFTBUS_BUS_CENTER_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates the length of a device name buffer, including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define DEVICE_NAME_BUF_LEN 128

/**
 * @brief Indicates the mask bit for a device online event.
 * If you want to receive such events, set the mask bit in {@link INodeStateCb.events}.
 *
 * @since 1.0
 * @version 1.0
 */
#define EVENT_NODE_STATE_ONLINE 0x1

/**
 * @brief Indicates the mask bit for a device offline event.
 * If you want to receive such events, set the mask bit in {@link INodeStateCb.events}.
 *
 * @since 1.0
 * @version 1.0
 */
#define EVENT_NODE_STATE_OFFLINE 0x02

/**
 * @brief Indicates the mask bit for a peer device information change event.
 * If you want to receive such events, set the mask bit in {@link INodeStateCb.events}.
 *
 * @since 1.0
 * @version 1.0
 */
#define EVENT_NODE_STATE_INFO_CHANGED 0x04

/**
 * @brief Indicates mask bits for {@link INodeStateCb.events}.
 *
 * @since 1.0
 * @version 1.0
 */
#define EVENT_NODE_STATE_MASK 0x07

/**
 * @brief Enumerates keys for an online device.
 * The key can be obtained via {@link GetNodeKeyInfo}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    NODE_KEY_UDID = 0,  /**< UDID in string format*/
    NODE_KEY_UUID,      /**< UUID in string format */
} NodeDeivceInfoKey;

/**
 * @brief Enumerates accuracy for time synchronize among device.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    LOW_ACCURACY = 10,
    NORMAL_ACCURACY,
    HIGH_ACCURACY,
    SUPER_HIGH_ACCURACY,
    UNAVAIL_ACCURACY = 0xFFFF,
} TimeSyncAccuracy;

/**
 * @brief Enumerates time synchronize period among device.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    SHORT_PERIOD = 0,
    NORMAL_PERIOD,
    LONG_PERIOD,
} TimeSyncPeriod;

/**
 * @brief Enumerates time synchronize flag.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    NODE_SPECIFIC = 0,
    ALL_LNN,
    WRITE_RTC,
} TimeSyncFlag;

/**
 * @brief Defines the basic information about a device.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];    /**< Device ID */
    char deviceName[DEVICE_NAME_BUF_LEN];  /**< Device name */
    uint8_t deviceTypeId;                  /**< Device type ID */
} NodeBasicInfo;

/**
 * @brief Enumerates device information change types. For details, see {@link INodeStateCb.onNodeBasicInfoChanged}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    TYPE_NETWORK_ID = 0,  /**< Network ID change */
    TYPE_DEVICE_NAME,     /**< Device name change */
} NodeBasicInfoType;

/**
 * @brief time synchronize result.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    int32_t millisecond;
    int32_t microsecond;
    TimeSyncAccuracy accuracy;
} TimeSyncResult;

/**
 * @brief time synchronize result info.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    TimeSyncResult result;
    TimeSyncFlag flag;
    union {
        char targetNetworkId[NETWORK_ID_BUF_LEN];
        char masterNetworkId[NETWORK_ID_BUF_LEN];
    } target;
} TimeSyncResultInfo;

/**
 * @brief Defines a callback that is invoked when the device state or information changes.
 * For details, see {@link RegNodeDeviceStateCb}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    /**
     * Mask of an event that is listened for.
     * The event can be received only if the corresponding mask bit is set and the callback is specified.
     */
    uint32_t events;
    /**
     * @brief Called when a specified device gets online.
     *
     * @param info Indicates the pointer to the basic information about the device.
     * For details, see {@link NodeBasicInfo}.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onNodeOnline)(NodeBasicInfo *info);
    /**
     * @brief Called when a specified device gets offline.
     *
     * @param info Indicates the pointer to the basic information about the device.
     * For details, see {@link NodeBasicInfo}.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onNodeOffline)(NodeBasicInfo *info);
    /**
     * @brief Called when the basic information of a device changes.
     *
     * @param type Indicates the device type. For details, see {@link NodeBasicInfoType}.
     * @param info Indicates the pointer to the new basic information of the device.
     * For details, see {@link NodeBasicInfo}.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onNodeBasicInfoChanged)(NodeBasicInfoType type, NodeBasicInfo *info);
} INodeStateCb;

/**
 * @brief Defines a callback that is invoked when the time synchronize has result.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    /**
     * @brief Called when the time synchronize has result.
     *
     * @param info Contains the time synchronize result info, see {@link TimeSyncResultInfo}.
     * @param retCode Indicates the result code. Value <b>0</b> indicates that the time synchronize is successful and
     * result is valid, and any other value indicates the opposite.
     *
     * @since 1.0
     * @version 1.0
     */
    void (*onTimeSyncResult)(const TimeSyncResultInfo *info, int32_t retCode);
} ITimeSyncCb;

/**
 * @brief Called when a device is added to a LNN via {@link JoinLNN}.
 *
 * @param addr Indicates the pointer to the address of the peer device.
 * @param networkId Indicates the pointer to the network ID of the device if it is successfully added to the LNN.
 * This parameter makes no sense if the device fails to be added to the LNN.
 * @param retCode Indicates the result code. Value <b>0</b> indicates that the device is successfully added to the LNN,
 * and any other value indicates the opposite.
 *
 * @since 1.0
 * @version 1.0
 */
typedef void (*OnJoinLNNResult)(ConnectionAddr *addr, const char *networkId, int32_t retCode);

/**
 * @brief Called when a device is removed from a LNN via {@link LeaveLNN}.
 *
 * @param networkId Indicates the pointer to the network ID of the device.
 * @param retCode Indicates the result code. Value <b>0</b> indicates that the device is successfully
 * removed from the LNN, and any other value indicates the opposite.
 *
 * @since 1.0
 * @version 1.0
 */
typedef void (*OnLeaveLNNResult)(const char *networkId, int32_t retCode);

/**
 * @brief Adds the current device to the LNN where a specified device resides.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param target Indicates the pointer to the address of the specified device. For details, see {@link ConnectionAddr}.
 * @param cb Indicates the callback for the result. If you set this parameter to NULL, you will not receive the result.
 *
 * @return Returns <b>0</b> if the request to add the device is accepted, and the result can be obtained from the
 * callback; returns any other value if the device fails to be added to the network, in which case you will not receive
 * the result.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb);

/**
 * @brief Removes the current device from the LNN.
 *
 * @param networkId Indicates the pointer to the network ID that is returned
 * after the device is added to the LNN via {@link JoinLNN}.
 * @param cb Indicates the callback for the result. If you set this parameter to <b>NULL</b>,
 * you will not receive the result.
 *
 * @return Returns <b>0</b> if the request to remove the device is accepted, and the result can be obtained from the
 * callback; returns any other value if the device fails to be removed from the network, in which case you will not
 * receive the result.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t LeaveLNN(const char *networkId, OnLeaveLNNResult cb);

/**
 * @brief Registers a callback for device state changes.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param callback Indicates the pointer to the callback to register. For details, see {@link INodeStateCb}.
 *
 * @return Returns <b>0</b> if the registration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback);

/**
 * @brief Unregisters a callback for device state changes.
 *
 * @param callback Indicates the pointer to the callback to unregister. For details, see {@link INodeStateCb}.
 *
 * @return Returns <b>0</b> if the unregistration is successful; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t UnregNodeDeviceStateCb(INodeStateCb *callback);

/**
 * @brief Obtains basic information about all the online devices.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param info Indicates the double pointer to the memory that stores the obtained basic information.
 * @param infoNum Indicates the pointer to the number of devices.
 *
 * @return Returns <b>0</b> if the basic information is obtained, in which case <b>info</b> and <b>infoNum</b> are
 * valid; returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum);

/**
 * @brief Releases the memory returned by {@link GetAllNodeDeviceInfo}.
 *
 * @param info Indicates the pointer to the memory returned by {@link GetAllNodeDeviceInfo}.
 *
 * @since 1.0
 * @version 1.0
 */
void FreeNodeInfo(NodeBasicInfo *info);

/**
 * @brief Obtains basic information about the current device.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param info Indicates the double pointer to the memory that stores the obtained basic information.
 *
 * @return Returns <b>0</b> if the basic information is obtained, in which case <b>info</b> is valid;
 * returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info);

/**
 * @brief Obtains a specified {@link NodeDeivceInfoKey} of an online device.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param networkId Indicates the pointer to the network ID of the device.
 * @param key Indicates the key to be obtained.
 * @param info Indicates the pointer to the buffer that stores the obtained key.
 * @param infoLen Indicates the buffer length.
 *
 * @return Returns <b>0</b> if the {@link NodeDeivceInfoKey} is obtained, in which case <b>info</b> is valid;
 * returns any other value otherwise.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId,
    NodeDeivceInfoKey key, uint8_t *info, int32_t infoLen);

/**
 * @brief Start the time synchronize with specific target node.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param targetNetworkId Indicates the pointer to the address of the specified device.
 * @param accuracy Time synchronize accuracy.
 * @param period Time synchronize period
 * @param cb Indicates the callback for the result.
 *
 * @return Returns <b>0</b> if the request is accepted, and the result can be obtained from the
 * callback; returns any other value if the request fails, in which case you will not receive
 * the result.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StartTimeSync(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb);

/**
 * @brief Stop the time synchronize with specific target node.
 *
 * @param pkgName Indicates the pointer to the caller ID, for example, the package name.
 * For the same caller, the value of this parameter must be the same for all functions.
 * @param targetNetworkId Indicates the pointer to the address of the specified device.
 *
 * @return Returns <b>0</b> if the request is removed; returns any other value if the request fails.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t StopTimeSync(const char *pkgName, const char *targetNetworkId);

#ifdef __cplusplus
}
#endif

#endif
/** @} */