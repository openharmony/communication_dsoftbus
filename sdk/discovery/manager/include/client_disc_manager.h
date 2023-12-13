/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CLIENT_DISC_MANAGER_H
#define SOFTBUS_CLIENT_DISC_MANAGER_H

#include "discovery_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Client initialization. Configure the storage information environment,
 * this interface is only called once when the softbus service is created.
 * @see {@link DiscClientDeinit}
 * @return <b>SOFTBUS_MALLOC_ERR</b> Failed to allocate space for global variable of discovery information.
 * @return <b>SOFTBUS_ERR</b> Failed to initialize the server agent on the discovery side.
 * @return <b>SOFTBUS_OK</b> The discoverer client was initialized successfully.
 */
int32_t DiscClientInit(void);

/**
 * @brief The client deinitializes, releasing the stored information.
 * This interface is only called once when the softbus service is destroyed.
 * @see {@link DiscClientInit}
 */
void DiscClientDeinit(void);

/**
 * @brief Internal publishing service. Publish its own capability information to other devices,
 * and other devices can capture this information to establish connections.
 * @see {@link UnPublishServiceInner}
 * @param[in] packageName Indicates the pointer to the package name,
 * and the name of the relevant package carrying its own capabilities.
 * @param[in] info Indicates the pointer to the published information,
 * which is used to publish the information body of its own information. For details, see {@link PublishInfo}.
 * @param[in] cb Indicates the pointer to the callback of the publishing function,
 * which is used to notify itself whether the publishing of its
 * own information is successful after the publishing function is triggered. For details, see {@link IPublishCallback}.
 * @return <b>SOFTBUS_ERR</b> Failed to publish internal information function.
 * @return <b>SOFTBUS_OK</b> The function of internal publishing self information was published successfully.
 */
int32_t PublishServiceInner(const char *packageName, const PublishInfo *info, const IPublishCallback *cb);

/**
 * @brief Internal unpublish service. Stop publishing its own information,
 * and external devices cannot capture this device's capability information.
 * @see {@link PublishServiceInner}
 * @param[in] packageName Indicates the pointer to the package name,
 * and the name of the relevant package carrying its own capabilities.
 * @param[in] publishId ID of the internal release information to be cancelled this time.
 * @return <b>SOFTBUS_ERR</b> Internal unpublishing function failed. Other devices can still find the device.
 * @return <b>SOFTBUS_OK</b> The internal unpublishing function is successful,
 * and the party cannot publish its own information.
 */
int32_t UnpublishServiceInner(const char *packageName, int32_t publishId);

/**
 * @brief Internal discovery service. Other devices can be discovered.
 * @see {@link StopDiscoveryInner}
 * @param[in] packageName Indicates the pointer to the package name,
 * and the name of the relevant package carrying its own capabilities.
 * @param[in] info Indicates a pointer to published information used
 * to discover the body of information for a specific capability. For more information, see {@link SubscribeInfo}.
 * @param[in] cb Indicates the pointer to the discovery callback, It is used to inform yourself,
 * Whether the discovery capability is successfully started after the discovery function is triggered.
 * For more information, see {@link IDiscoveryCallback}.
 * @return <b>SOFTBUS_ERR</b> The internal start Discovery Function failed to start. No other devices can be found.
 * @return <b>SOFTBUS_OK</b> The internal start discovery function is started successfully.
 * You can discover specific capability devices.
 */
int32_t StartDiscoveryInner(const char *packageName, const SubscribeInfo *info, const IDiscoveryCallback *cb);

/**
 * @brief Stop discovery service internally. Stop discovering other devices,
 * after which other devices cannot be discovered.
 * @see {@link StartDiscoveryInner}
 * @param[in] packageName Indicates the pointer to the package name,
 * and the name of the relevant package carrying its own capabilities.
 * @param[in] subscribeId ID to stop discovery this time.
 * @return <b>SOFTBUS_ERR</b> The internal stop discovery function cannot be started. Other devices can still be found.
 * @return <b>SOFTBUS_OK</b> Internal stop discovery function started successfully.
 * You cannot discover devices with specific functions.
 */
int32_t StopDiscoveryInner(const char *packageName, int32_t subscribeId);

/**
 * @brief The server discovers the local device and calls this callback.
 * @see {@link DiscClientOnDiscoverySuccess} or {@link DiscClientOnDiscoverFailed}.
 * @param[in] device Indicates a pointer to device information to record the devices on
 * which the discovery client was discovered. For more information, see {@link DeviceInfo}.
 */
void DiscClientOnDeviceFound(const DeviceInfo *device);

/**
 * @brief When the server subscribes to the local device successfully,
 * this callback is called to notify the local device.
 * @see {@link DiscClientOnDeviceFound} or {@link DiscClientOnDiscoverFailed}.
 * @param[in] subscribeId The id of the subscription information used to record
 * the successful discovery of the discovered peer.
 */
void DiscClientOnDiscoverySuccess(int32_t subscribeId);

/**
 * @brief When the server fails to subscribe to the local device, this callback is called to notify the local device.
 * @see {@link DiscClientOnDiscoverySuccess} or {@link DiscClientOnDeviceFound}.
 * @param[in] subscribeId The id of the subscription information used to record the discovered peer discovery failure.
 * @param[in] failReason reason of failure. For more information, see {@link DiscoveryFailReason}.
 */
void DiscClientOnDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason);

/**
 * @brief The local end publishes the service successfully, and the callback is called to notify the local end.
 * @see {@link DiscClientOnPublishFail}.
 * @param[in] publishId The information id used for the client to publish successfully.
 */
void DiscClientOnPublishSuccess(int32_t publishId);

/**
 * @brief The local end fails to publish the service, and this callback is called to notify the local end.
 * @see {@link DiscClientOnPublishSuccess}.
 * @param[in] publishId The information id used for the client to publish failed.
 * @param[in] reason reason of failure. For more information, see {@link PublishFailReason}.
 */
void DiscClientOnPublishFail(int32_t publishId, PublishFailReason reason);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CLIENT_DISC_MANAGER_H