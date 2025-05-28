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

#ifndef SD_MANAGER_H
#define SD_MANAGER_H

#include "softbus_service_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup softbus_sd_manager
 * Inner Module.
 *
 */

/**
 * @ingroup softbus_sd_manager
 * Inner Callback.
 *
 */
typedef struct {
    /**
     * @brief Callback that is invoked when a service is found.
     *
     * @param service Indicates the pointer to the service info. For details, see {@link ServiceInfo}.
     * @param media Indicates the medium through which the service was discovered.
     *
     * @since 6.0
     * @version 1.0
     */
    void (*OnServiceFound)(const ServiceInfo *service, const ServiceMediumType media);

    /**
     * @brief Callback that is invoked when a service is lost.
     *
     * @param service serviceId Indicates the pointer to the service ID.
     * @param media Indicates the medium through which the service was lost.
     *
     * @since 6.0
     * @version 1.0
     */
    void (*OnServiceLost)(const char *serviceId, const ServiceMediumType media);
} ServiceInnerCallback;

typedef struct {
    ServiceInfo *serviceInfo;
    ServiceDiscoverMode mode;   // The publishing and discovery mode.
    EnableFreq freq;            // The publishing frequency.
} ServicePublishInfo;

typedef struct {
    DiscoveryInfo *discoveryInfo;
    ServiceDiscoverMode mode;   // The publishing and discovery mode.
    EnableFreq freq;            // The publishing frequency.
} ServiceDiscoveryInfo;

typedef struct {
    int32_t (*Publish)(const ServicePublishInfo *publishInfo);
    int32_t (*UnPublish)(const char *serviceId);
    int32_t (*Update)(const ServicePublishInfo *publishInfo);
    int32_t (*StartDiscovery)(const ServiceDiscoveryInfo *discoveryInfo);
    int32_t (*StopDiscovery)(const char *localServiceId, const char *serviceType);
} ServiceDiscoveryFuncInterface;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SD_MANAGER_H */
