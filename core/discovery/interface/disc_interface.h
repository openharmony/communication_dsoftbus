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

#ifndef DISC_MANAGER_INTERFACE_H
#define DISC_MANAGER_INTERFACE_H

#include "softbus_common.h"
#include "stdint.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @ingroup softbus_disc_manager
 * Inner Module.
 *
 */
typedef enum {
    MODULE_MIN = 1,
    MODULE_LNN = MODULE_MIN,
    MODULE_CONN = 2,
    MODULE_MAX = MODULE_CONN
} DiscModule;

typedef enum {
    LINK_STATUS_UP = 0,
    LINK_STATUS_DOWN,
} LinkStatus;

typedef enum {
    TYPE_LOCAL_DEVICE_NAME,
    TYPE_ACCOUNT,
} InfoTypeChanged;

/**
 * @ingroup softbus_disc_manager
 * Inner Callback.
 *
 */
typedef struct {
    void (*OnDeviceFound)(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions);
} DiscInnerCallback;

/**
 * @ingroup softbus_disc_manager
 * @brief Initialization of discovery management. Set the necessary environment for the discovery side.
 * This interface is only called once when the softbus service is created.
 * @see {@link DiscMgrDeinit}
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INIT_FAIL</b> Create Softbus list failed.
 * @return <b>SOFTBUS_OK</b> Manager is Successfully inited
 */
int32_t DiscMgrInit(void);

/**
 * @ingroup softbus_disc_manager
 * @brief Discovery managed deinitialization. Clear the corresponding configuration of the discovery terminal.
 * This interface is only called once when the softbus service is destroyed.
 * @see {@link DiscMgrInit}
 */
void DiscMgrDeinit(void);

/**
 * @ingroup softbus_disc_manager
 * @brief Found management module information destroy callback function.
 * Destroy the configuration related to the discovery release and clear it.
 * @param[in] pkgName Indicates the pointer to package name, which can contain a maximum of 64 bytes.
 */
void DiscMgrDeathCallback(const char *pkgName);

/**
 * @ingroup softbus_disc_manager
 * @brief Set the discovery callback and set the discovery client environment.
 * @param[in] moduleId Mouble Id. For details, see {@link DiscModule}.
 * @param[in] callback Indicates a pointer to the discovery internal callback.
 * For details, see {@link DiscInnerCallback}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> if the Intelligent Soft Bus server fails to be initialized.
 * @return <b>SOFTBUS_MEM_ERR</b> if Memcpy failed.
 * @return <b>SOFTBUS_LOCK_ERR</b> if Mutex lock failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM</b> if duplicate info.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE</b> if item node create failed.
 * @return <b>SOFTBUS_OK</b> if the set discovery callback is successful.
 */
int32_t DiscSetDiscoverCallback(DiscModule moduleId, const DiscInnerCallback *callback);

/**
 * @ingroup softbus_disc_manager
 * @brief Publish capabilities and create the necessary environment for their own capabilities information.
 * @see {@link DiscUnpublish}.
 * @param[in] moduleId Mouble Id. For details, see {@link DiscModule}.
 * @param[in] info Indicates the pointer to the service publishing information.
 * For details, see {@link PublishInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> if the Intelligent Soft Bus server fails to be initialized.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE</b> if the creation of the information node fails.
 * @return <b>SOFTBUS_MEM_ERR</b> if Memcpy failed.
 * @return <b>SOFTBUS_LOCK_ERR</b> if Mutex lock failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM</b> if duplicate info.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE</b> if item node create failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> if InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> if the active release is successful.
 */
int32_t DiscPublish(DiscModule moduleId, const PublishInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Start the scan and set the corresponding environment according to the scan information.
 * @param[in] moduleId Mouble Id. For details, see {@link DiscModule}.
 * @param[in] info Indicates the pointer to the service publishing information.
 * For details, see {@link PublishInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> if the Intelligent Soft Bus server fails to be initialized.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE</b> if the creation of the information node fails.
 * @return <b>SOFTBUS_MEM_ERR</b> if Memcpy failed.
 * @return <b>SOFTBUS_LOCK_ERR</b> if Mutex lock failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM</b> if duplicate info.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE</b> if item node create failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> if InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> if the passive publish is successful.
 */
int32_t DiscStartScan(DiscModule moduleId, const PublishInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Cancel the ability to publish, and clear the configuration environment where it publishes information.
 * @see {@link DiscPublish}.
 * @param[in] moduleId module ID. For details, see {@link DiscModule}.
 * @param[in] publishId the publish ID which will be stopped.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> if the Intelligent Soft Bus server fails to be initialized.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE</b> if info node delete failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> if InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> if the stop publish is successful.
 */
int32_t DiscUnpublish(DiscModule moduleId, int32_t publishId);

/**
 * @ingroup softbus_disc_manager
 * @brief Start the broadcast and create the necessary environment for its own broadcast information.
 * @see {@link DiscStopAdvertise}.
 * @param[in] moduleId module ID. For details, see {@link DiscModule}.
 * @param[in] info Indicates the pointer to the service subscribe information.
 * For details, see {@link SubscribeInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> Invalid moduleId or info parameter.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> Discovery manager is not initialised.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE</b> InfoNode create failed.
 * @return <b>SOFTBUS_MEM_ERR</b> Memcpy failed.
 * @return <b>SOFTBUS_LOCK_ERR</b> Mutex lock failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM</b> Duplicate info.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE</b> ItemNode create failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> Active discover successfully.
 */
int32_t DiscStartAdvertise(DiscModule moduleId, const SubscribeInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Subscription capability, configure the environment required for its own subscription information.
 * @param[in] moduleId module ID. For details, see {@link DiscModule}.
 * @param[in] info Indicates the pointer to the service subscribe information.
 * For details, see {@link SubscribeInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> Invalid moduleId or info parameter.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> Discovery manager is not initialised.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE</b> InfoNode create failed.
 * @return <b>SOFTBUS_MEM_ERR</b> Memcpy failed.
 * @return <b>SOFTBUS_LOCK_ERR</b> Mutex lock failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM</b> Duplicate info.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE</b> ItemNode create failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> Passive discover successfully.
 */
int32_t DiscSubscribe(DiscModule moduleId, const SubscribeInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Stop the broadcast and clear the environment configured by the start broadcast.
 * @see {@link DiscStartAdvertise}.
 * @param[in] moduleId module ID. For details, see {@link DiscModule}.
 * @param[in] subscribeId the subscribe ID which will be stop broadcast.
 * @return <b>SOFTBUS_INVALID_PARAM</b> Invalid moduleId or info parameter.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_NOT_INIT</b> Discovery manager is not initialised.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE</b> InfoNode delete failed.
 * @return <b>SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL</b> InnerFunction failed.
 * @return <b>SOFTBUS_OK</b> Stop discover successfully.
 */
int32_t DiscStopAdvertise(DiscModule moduleId, int32_t subscribeId);

/**
 * @brief Modify the connection state.
 * @param[in] status Used to indicate a certain connection state discovered. For details, see {@link LinkStatus}.
 * @param[in] medium A medium for sending information that can be used in a connection route.
 * For details, see {@link ExchangeMedium}.
 */
void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium);

/**
 * @ingroup softbus_disc_manager
 * @brief Update broadcast packets when the local device information changes.
 * @param[in] type Information that changes
 */
void DiscDeviceInfoChanged(InfoTypeChanged type);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISC_MANAGER_INTERFACE_H */