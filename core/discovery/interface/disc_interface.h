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

#include "discovery_service.h"
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

/**
 * @ingroup softbus_disc_manager
 * Inner publish info.
 *
 */
typedef struct {
    int publishId;
    ExchanageMedium medium;
    ExchangeFreq freq;
    const char *capability;
    unsigned char *capabilityData;
    unsigned int dataLen;
} PublishInnerInfo;

/**
 * @ingroup softbus_disc_manager
 * Inner subscribe info.
 *
 */
typedef struct {
    int subscribeId;
    ExchanageMedium medium;
    ExchangeFreq freq;
    bool isSameAccount;
    bool isWakeRemote;
    const char *capability;
    unsigned char *capabilityData;
    unsigned int dataLen;
} SubscribeInnerInfo;

typedef enum {
    LINK_STATUS_UP = 0,
    LINK_STATUS_DOWN,
} LinkStatus;

/**
 * @ingroup softbus_disc_manager
 * Inner Callback.
 *
 */
typedef struct {
    void (*OnDeviceFound)(const DeviceInfo *device);
} DiscInnerCallback;

/**
 * @ingroup softbus_disc_manager
 * @brief softbus discovery manager init
 *
 * @retval #SOFTBUS_ERR        Create Softbus list failed.
 * @retval #SOFTBUS_OK         Manager is Successfully inited
 *
 */
int32_t DiscMgrInit(void);

/**
 * @ingroup softbus_disc_manager
 * @brief softbus discovery manager deinit
 *
 */
void DiscMgrDeinit(void);

/**
 * @ingroup softbus_disc_manager
 * @brief softbus discovery manager death callback
 *
 */
void DiscMgrDeathCallback(const char *pkgName);

/**
 * @ingroup softbus_disc_manager
 * @brief Subscribe inner callback update.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  initParam   [IN]  Type  #DiscInnerCallback * update the callback of the module.
 *
 * @retval #SOFTBUS_INVALID_PARAM                   Invalid moduleId or cb.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT       Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE Module to string failed.
 * @retval #SOFTBUS_LOCK_ERR                        Mutex lock failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_PARAM  Module not found.
 * @retval #SOFTBUS_OK                              Subscribe inner callback update successfully.
 *
 */
int32_t DiscSetDiscoverCallback(DiscModule moduleId, const DiscInnerCallback *cb);

/**
 * @ingroup softbus_disc_manager
 * @brief Active publish.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  info        [IN]  Type  #PublishInnerInfo * publish information.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE    InfoNode create failed.
 * @retval #SOFTBUS_MEM_ERR                             Memcpy failed.
 * @retval #SOFTBUS_LOCK_ERR                            Mutex lock failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM    Duplicate info.
 * @retval #SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE    ItemNode create failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Active publish successfully.
 *
 */
int32_t DiscPublish(DiscModule moduleId, const PublishInnerInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Passive publish.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  info        [IN]  Type  #PublishInnerInfo * publish information.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE    InfoNode create failed.
 * @retval #SOFTBUS_MEM_ERR                             Memcpy failed.
 * @retval #SOFTBUS_LOCK_ERR                            Mutex lock failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM    Duplicate info.
 * @retval #SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE    ItemNode create failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Passive publish successfully.
 *
 */
int32_t DiscStartScan(DiscModule moduleId, const PublishInnerInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Stop publish.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  publishId   [IN]  Type  #int32_t the publish ID which will be stopped.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE    InfoNode delete failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Stop publish successfully.
 *
 */
int32_t DiscUnpublish(DiscModule moduleId, int32_t publishId);

/**
 * @ingroup softbus_disc_manager
 * @brief Active discover.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  info        [IN]  Type  #SubscribeInnerInfo * discover information.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE    InfoNode create failed.
 * @retval #SOFTBUS_MEM_ERR                             Memcpy failed.
 * @retval #SOFTBUS_LOCK_ERR                            Mutex lock failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM    Duplicate info.
 * @retval #SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE    ItemNode create failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Active discover successfully.
 *
 */
int32_t DiscStartAdvertise(DiscModule moduleId, const SubscribeInnerInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Passive discover.
 *
 * @param  moduleId    [IN]  Type  #DiscModule module ID.
 * @param  info        [IN]  Type  #SubscribeInnerInfo * discover information.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE    InfoNode create failed.
 * @retval #SOFTBUS_MEM_ERR                             Memcpy failed.
 * @retval #SOFTBUS_LOCK_ERR                            Mutex lock failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM    Duplicate info.
 * @retval #SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE    ItemNode create failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Passive discover successfully.
 *
 */
int32_t DiscSubscribe(DiscModule moduleId, const SubscribeInnerInfo *info);

/**
 * @ingroup softbus_disc_manager
 * @brief Stop discover.
 *
 * @param  moduleId      [IN]  Type  #DiscModule module ID.
 * @param  subscribeId   [IN]  Type  #int32_t the discover ID which will be stopped.
 *
 * @retval #SOFTBUS_INVALID_PARAM                       Invalid moduleId or info parameter.
 * @retval #SOFTBUS_DISCOVER_MANAGER_NOT_INIT           Discovery manager is not initialised.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE     Module to string failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE    InfoNode delete failed.
 * @retval #SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL InnerFunction failed.
 * @retval #SOFTBUS_OK                                  Stop discover successfully.
 *
 */
int32_t DiscStopAdvertise(DiscModule moduleId, int32_t subscribeId);

void DiscLinkStatusChanged(LinkStatus status, ExchanageMedium medium);

void SetCallLnnStatus(bool flag);
bool GetCallLnnStatus(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISC_MANAGER_INTERFACE_H */