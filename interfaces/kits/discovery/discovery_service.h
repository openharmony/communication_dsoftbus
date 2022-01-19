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

#ifndef DISCOVERY_SERVICE_H
#define DISCOVERY_SERVICE_H

#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief Indicates the maximum length of the device address in <b>IDiscoveryCallback</b>.
 *
 */
#define CONNECT_ADDR_LEN 46

/**
 * @brief Enumerates error codes for service publishing failures.
 *
 * The error codes are returned to the caller through <b>IPublishCallback</b>.
 *
 */
typedef enum {
    /* Unsupported medium */
    PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM = 1,
    /* internal error */
    PUBLISH_FAIL_REASON_INTERNAL = 2,
    /* Unknown reason */
    PUBLISH_FAIL_REASON_UNKNOWN = 0xFF
} PublishFailReason;

/**
 * @brief Defines the callbacks for successful and failed service publishing.
 *
 */
typedef struct {
    /** Callback for successful publishing */
    void (*OnPublishSuccess)(int publishId);
    /** Callback for failed publishing */
    void (*OnPublishFail)(int publishId, PublishFailReason reason);
} IPublishCallback;

/**
 * @brief Enumerates error codes for service subscription failures.
 *
 * The error codes are returned to the caller through <b>IDiscoveryCallback</b>.
 *
 */
typedef enum {
    /* Unsupported medium */
    DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM = 1,
    /* internal error */
    DISCOVERY_FAIL_REASON_INTERNAL = 2,
    /* Unknown error */
    DISCOVERY_FAIL_REASON_UNKNOWN = 0xFF
} DiscoveryFailReason;

/**
 * @brief Defines a callback for service subscription.
 *
 * Three types of callbacks are available.
 *
 */
typedef struct {
    /** Callback that is invoked when a device is found */
    void (*OnDeviceFound)(const DeviceInfo *device);
    /** Callback for a subscription failure */
    void (*OnDiscoverFailed)(int subscribeId, DiscoveryFailReason failReason);
    /** Callback for a subscription success */
    void (*OnDiscoverySuccess)(int subscribeId);
} IDiscoveryCallback;

/**
 * @brief Publishes a specified service.
 *
 * Peer devices in the same LAN as the device that publishes this service can discover this service as needed.
 * The service is identified by <b>publicId</b> and <b>pkgName</b>.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param info Indicates the pointer to the service publishing information. For details, see {@link PublishInfo}.
 * @param cb Indicates the pointer to the service publishing callback {@link IPublishCallback}.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_LOCK_ERR</b> if the mutex fails to be locked.
 * @return Returns <b>SOFTBUS_OK</b> if the service is successfully published.
 */
int PublishService(const char *pkgName, const PublishInfo *info, const IPublishCallback *cb);

/**
 * @brief Unpublishes a specified service.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param publishId Indicates the service ID.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>pkgName</b> is invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_OK</b> if the service is successfully unpublished.
 */
int UnPublishService(const char *pkgName, int publishId);

/**
 * @brief Subscribes to a specified service.
 *
 * Information about the device that publishes the service will be reported to the device that subscribes to
 * the service.
 * The service is identified by <b>subscribeId</b> and <b>pkgName</b>.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param info Indicates the pointer to the service subscription information. For details, see {@link SubscribeInfo}.
 * @param cb Indicates the service subscription callback {@link IDiscoveryCallback}.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_LOCK_ERR</b> if the mutex fails to be locked.
 * @return Returns <b>SOFTBUS_OK</b> if the service subscription is successful.
 */
int StartDiscovery(const char *pkgName, const SubscribeInfo *info, const IDiscoveryCallback *cb);

/**
 * @brief Unsubscribes from a specified service.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param subscribeId Indicates the service ID.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>pkgName</b> is invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_OK</b> if the service unsubscription is successful.
 */
int StopDiscovery(const char *pkgName, int subscribeId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISCOVERY_SERVICE_H */
