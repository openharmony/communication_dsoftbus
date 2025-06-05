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

#ifndef SOFTBUS_SERVICE_DISCOVERY_H
#define SOFTBUS_SERVICE_DISCOVERY_H

#include "softbus_service_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register the service to softbus.
 *
 * Registration services will not trigger broadcasts or scans.
 * Service information is cached to softbus.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param serviceInfo Indicates the pointer to the service info.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>serviceInfo</b> is invalid.
 * @return Returns <b>SOFTBUS_SERVICE_ALREADY_EXISTS</b> if the service is already registered.
 * @return Returns <b>SOFTBUS_OK</b> if the service register is successful.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusRegisterService(const char *pkgName, const ServiceInfo *serviceInfo);

/**
 * @brief UnRegister the service to the softbus.
 *
 * Service information is removed from the cache.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param serviceId Indicates the service ID.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>serviceId</b> is invalid.
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister is successful. If the service is not registered,
 * <b>SOFTBUS_OK</b> is also returned.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusUnregisterService(const char *pkgName, int64_t serviceId);

/**
 * @brief Publish a service.
 *
 * Services can only be published after they have been registered.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param serviceId Indicates the service ID.
 * @param publishParam Indicates the pointer to the publishing parameters.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>serviceId</b> is invalid.
 * @return Returns <b>SOFTBUS_SERVICE_NOT_FOUND</b> if the service is not registered.
 * @return Returns <b>SOFTBUS_OK</b> if the service publishing is successful.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusPublishService(const char *pkgName, int64_t serviceId, const ServiceDiscoveryParam *publishParam);

/**
 * @brief UnPublish a service.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param serviceId Indicates the service ID.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>serviceId</b> is invalid.
 * @return Returns <b>SOFTBUS_OK</b> if the service publishing is successful. If the service is not published,
 * <b>SOFTBUS_OK</b> is also returned.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusUnpublishService(const char *pkgName, int64_t serviceId);

/**
 * @brief Update the service information and publish it.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param serviceInfo Indicates the pointer to the service info.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>serviceInfo</b> is invalid.
 * @return Returns <b>SOFTBUS_OK</b> if the service is successfully updated.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusUpdateService(const char *pkgName, const ServiceInfo *serviceInfo);

/**
 * @brief Defines the callbacks for service discovery.
 *
 * @since 6.0
 * @version 1.0
 */
typedef struct {
    /**
     * @brief Callback that is invoked when a service is found.
     *
     * @param service Indicates the pointer to the service info. For details, see {@link ServiceInfo}.
     *
     * @since 6.0
     * @version 1.0
     */
    void (*OnServiceFound)(const ServiceInfo *service);

    /**
     * @brief Callback that is invoked when a service is lost.
     *
     * @param serviceId Indicates the service ID.
     *
     * @since 6.0
     * @version 1.0
     */
    void (*OnServiceLost)(int64_t serviceId);
} IServiceDiscoveryCb;

/**
 * @brief Search for services by service type.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param info Indicates the pointer to the service discovery information. For details, see {@link DiscoveryInfo}.
 * @param discoveryParam Indicates the pointer to the discovery parameters.
 * @param cb Indicates the service discovery callback {@link IServiceDiscoveryCb}.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_OK</b> if the service discovery is successful.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusStartServiceDiscovery(const char *pkgName, const DiscoveryInfo *info,
    const ServiceDiscoveryParam *discoveryParam, const IServiceDiscoveryCb *cb);

/**
 * @brief Stop searching for services.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param localServiceId Indicates the local service ID.
 * @param serviceType Indicates the pointer to the service type.
 *
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_OK</b> if the service discovery is stopped successfully.
 *
 * @since 6.0
 * @version 1.0
 */
int32_t SoftbusStopServiceDiscovery(const char *pkgName, int64_t localServiceId, const char *serviceType);

#ifdef __cplusplus
}
#endif

#endif
