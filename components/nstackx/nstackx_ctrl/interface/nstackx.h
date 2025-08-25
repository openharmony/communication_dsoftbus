/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_H
#define NSTACKX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nstackx_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register local device information */
DFINDER_EXPORT int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo);

/* Register local device name */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceName(const char *devName);

/* Register local device information with deviceHash */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash);

/* New interface to register local device with multiple interfaces */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceV2(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo);

DFINDER_EXPORT int NSTACKX_DFinderSetEventFunc(void *softobj, DFinderEventFunc func);

DFINDER_EXPORT int NSTACKX_DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump);

/*
 * NSTACKX Initialization
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter);

/*
 * NSTACKX Initialization V2
 * support notify device info one by one
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_InitV2(const NSTACKX_Parameter *parameter, bool isNotifyPerDevice);

/* NSTACKX Destruction */
DFINDER_EXPORT void NSTACKX_Deinit(void);

/*
 * NSTACKX thread Initialization
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_ThreadInit(void);

/* NSTACKX thread Destruction */
DFINDER_EXPORT void NSTACKX_ThreadDeinit(void);

/*
 * Start device discovery
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_StartDeviceFind(void);

/*
 * Start device discovery by mode
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_StartDeviceFindAn(uint8_t mode);

/*
 * Stop device discovery
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_StopDeviceFind(void);

/*
 * subscribe module
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_SubscribeModule(void);

/*
 * unsubscribe module
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_UnsubscribeModule(void);

/*
 * Register the device hash of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceHash(uint64_t deviceHash);

/*
 * Register the serviceData of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterServiceDataV2(const struct NSTACKX_ServiceData *param, uint32_t cnt);

/*
 * Register the capability of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);

/*
 * Set the capability to filter remote devices.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);

/*
 * Set the agingTime of the device list.
 * The unit of agingTime is seconds, and the range is 1 to 10 seconds.
 */
DFINDER_EXPORT int32_t NSTACKX_SetDeviceListAgingTime(uint32_t agingTime);

/*
 * Set the size of the device list.
 * The range is 20 to 400.
 */
DFINDER_EXPORT int32_t NSTACKX_SetMaxDeviceNum(uint32_t maxDeviceNum);

/*
 * dfinder set screen status
 * param: isScreenOn, screen status
 * return: always return 0 on success
 */
DFINDER_EXPORT int32_t NSTACKX_ScreenStatusChange(bool isScreenOn);

/*
 * Register the serviceData of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterServiceData(const char *serviceData);

/**
 * @brief register business data to local device, the data will be used as bData filed in json format in coap payload
 *
 * @param [in] (const char *) businessData: specific data which need to be put into the coap payload
 *
 * @return (int32_t)
 *      0                operation success
 *      negative value   a number indicating the rough cause of this failure
 *
 * @note 1. the length of businessData should be less than NSTACKX_MAX_BUSINESS_DATA_LEN
 *       2. the registered business data will only be used in unicast which is confusing
 *       3. this interface will be DEPRECATED soon, in some special case, you can replace it with:
 *          NSTACKX_StartDeviceDiscovery && NSTACKX_SendDiscoveryRsp
 *
 * @exception
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterBusinessData(const char *businessData);

/*
 * Register the extendServiceData of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterExtendServiceData(const char *extendServiceData);

/*
 * Send Msg to remote peer
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_SendMsg(const char *moduleName, const char *deviceId, const uint8_t *data,
                                       uint32_t len);

/*
 * Send Msg to remote peer
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_SendMsgDirect(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t sendType);

/*
 * Get device list from cache
 * param: deviceList - Device list return from NSTACKX, user should prepare sufficient buffer to store
 *                     device list.
 * param: deviceCountPtr - In/Out parameter. It indicates buffer size (number of elements) in deviceList
 *                         When returns, it indicates numbers of valid device in deviceList.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr);

/*
 * NSTACKX Initialization, only used for restart.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_InitRestart(const NSTACKX_Parameter *parameter);

/*
 * NSTACKX Initialization, only used for restart.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT void NSTACKX_StartDeviceFindRestart(void);

/**
 * @brief start device find with configurable parameters
 *
 * @param [in] (const NSTACKX_DiscoverySettings *) discoverySettings: configurable discovery properties
 *
 * @return (int32_t)
 *      0                operation success
 *      negative value   a number indicating the rough cause of this failure
 *
 * @note 1. if the discovery is already running, calling this interface will stop the previous one and start a new one
 *       2. if both advertiseCount and advertiseDuration in discoverySettings are zero, the discovery interval will
 *          fallback to 5 sec 12 times(100 ms, 200, 200, 300...)
 *       3. if advertiseCount is not zero, the broadcast interval equals advertiseDuration / advertiseCount
 *
 * @exception
 */
DFINDER_EXPORT int32_t NSTACKX_StartDeviceDiscovery(const NSTACKX_DiscoverySettings *discoverySettings);

/*
 * Start device discovery with configured broadcast interval and other settings
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_StartDeviceDiscoveryWithConfig(const DFinderDiscConfig *discConfig);

/**
 * @brief reply unicast to remote device specified by remoteIp, using local nic specified by localNetworkName
 *
 * @param [in] (const NSTACKX_ResponseSettings *) responseSettings: configurable unicast reply properties
 *
 * @return (int32_t)
 *      0                operation success
 *      negative value   a number indicating the rough cause of this failure
 *
 * @note only one unicast reply will be sent each time this interface is called
 *
 * @exception
 */
DFINDER_EXPORT int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings);

/**
 * @brief start sending broadcast notifications
 *
 * @param [in] config: configurable properties to send notification, see struct NSTACKX_NotificationConfig
 *
 * @return (int32_t)
 *      0                operation success
 *      negative value   a number indicating the rough cause of this failure
 *
 * @note 1. if the sending is already running, calling this interface will stop the previous one and start a new one,
 *          caller can update its notification msg through this way
 *       2. caller should ensure the consistency of associated data
 * @exception
 */
DFINDER_EXPORT int32_t NSTACKX_SendNotification(const NSTACKX_NotificationConfig *config);

/**
 * @brief stop sending broadcast notifications
 *
 * @param [in] businessType: service identify, notification of which business we should stop
 *
 * @return (int32_t)
 *      0                operation success
 *      negative value   a number indicating the rough cause of this failure
 *
 * @note 1. calling this interface will stop the sending timer
 *       2. if not business sensitive, should use NSTACKX_BUSINESS_TYPE_NULL, see struct NSTACKX_BusinessType
 *
 * @exception
 */
DFINDER_EXPORT int32_t NSTACKX_StopSendNotification(uint8_t businessType);

#ifdef ENABLE_USER_LOG

/*
 * Set the DFinder log implementation
 */
DFINDER_EXPORT int32_t NSTACKX_DFinderRegisterLog(DFinderLogCallback userLogCallback);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NSTACKX_H */
