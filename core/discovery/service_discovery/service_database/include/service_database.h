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

#ifndef SERVICE_DATABASE_H
#define SERVICE_DATABASE_H

#include "softbus_service_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISC_SERVICE_MAX_NUM 1024

/**
 * @ingroup softbus_service_database
 * Inner Module.
 *
 */

/**
 * @ingroup softbus_service_database
 * @brief Initialization of service database. Set the necessary environment for the database.
 * This interface is only called once when the softbus service is created.
 * @see {@link ServiceDatabaseDeinit}
 * @return <b>SOFTBUS_DISCOVER_SD_INIT_FAIL</b> Create Softbus list failed.
 * @return <b>SOFTBUS_OK</b> Database is Successfully inited.
 */
int32_t ServiceDatabaseInit(void);

/**
 * @ingroup softbus_service_database
 * @brief Service database deinitialization. Clear the corresponding configuration of the database.
 * This interface is only called once when the softbus service is destroyed.
 * @see {@link ServiceDatabaseInit}
 */
void ServiceDatabaseDeinit(void);

/**
 * @ingroup softbus_service_database
 * @brief Get all registered service infos.
 * @param[out] infos Indicates a pointer to the service infos.
 * @param[out] cnt Indicates the count of service info.
 *
 * @return <b>SOFTBUS_OK</b> if getting all registered service infos successfully.
 */
int32_t GetAllServiceInfos(ServiceInfo *infos, uint32_t *cnt);

/**
 * @ingroup softbus_service_database
 * @brief Get a specific service info by service ID (65 bytes).
 * @param[in] serviceId Indicates a pointer to the service ID.
 * @param[out] info Indicates a pointer to the service info.
 *
 * @return <b>SOFTBUS_OK</b> if getting the service infos successfully.
 */
int32_t GetServiceInfo(int64_t serviceId, ServiceInfo *info);

/**
 * @ingroup softbus_service_database
 * @brief Add a service info to the database.
 * @param[in] info Indicates a pointer to the service info.
 *
 * @return <b>SOFTBUS_OK</b> if adding the service info successfully.
 */
int32_t AddServiceInfo(const ServiceInfo *info);

/**
 * @ingroup softbus_service_database
 * @brief Update the service info in the database. If the service ID is not existed, add it to the database.
 * @param[in] info Indicates a pointer to the service info.
 *
 * @return <b>SOFTBUS_OK</b> if updating the service info successfully.
 */
int32_t UpdateServiceInfo(const ServiceInfo *info);

/**
 * @ingroup softbus_service_database
 * @brief Remove the service info by the service ID from the database.
 * @param[in] serviceId Indicates a pointer to the service ID (65 bytes).
 *
 * @return <b>SOFTBUS_OK</b> if removing the service info successfully.
 * or the service ID is not existed in the database.
 */
int32_t RemoveServiceInfo(int64_t serviceId);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SERVICE_DATABASE_H */
