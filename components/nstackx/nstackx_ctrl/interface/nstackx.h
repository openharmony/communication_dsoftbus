/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

#define NSTACKX_MAX_DEVICE_NAME_LEN 64
#define NSTACKX_MAX_MODULE_NAME_LEN 64
#define NSTACKX_MAX_DEVICE_ID_LEN 96
#define NSTACKX_MAX_SENDMSG_DATA_LEN 512
#define NSTACKX_MAX_MAC_STRING_LEN 18
#define NSTACKX_MAX_IP_STRING_LEN 16
#define NSTACKX_MAX_CAPABILITY_NUM 2
#define NSTACKX_MAX_DEVICE_NUM 20
#define NSTACKX_MAX_INTERFACE_NAME_LEN 16
#define NSTACKX_MAX_HICOM_VERSION 16
#define NSTACKX_MAX_SERVICE_DATA_LEN 64

#define NSTACKX_MAX_RESERVED_INFO_LEN 219 // expand from 131 to 219 (+88) bytes to hold service data
#define DEVICE_HASH_LEN 21
#define DEFAULT_MODE 0
#define DISCOVER_MODE 1
#define PUBLISH_MODE_UPLINE 2
#define PUBLISH_MODE_OFFLINE 3
#define PUBLISH_MODE_PROACTIVE 10
#define PUBLISH_DEVICE_NUM 1
#define INNER_DISCOVERY 1
#define PUBLISH_NUM 1

/* Remote device information */
typedef struct NSTACKX_DeviceInfo {
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    uint8_t deviceType;
    uint8_t mode;
    uint8_t update : 1;
    uint8_t reserved : 7;
    char version[NSTACKX_MAX_HICOM_VERSION];
    char reservedInfo[NSTACKX_MAX_RESERVED_INFO_LEN];
} NSTACKX_DeviceInfo;

/* Local device information */
typedef struct {
    char name[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char btMacAddr[NSTACKX_MAX_MAC_STRING_LEN];
    char wifiMacAddr[NSTACKX_MAX_MAC_STRING_LEN];
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    uint8_t is5GHzBandSupported;
    uint8_t deviceType;
    char version[NSTACKX_MAX_HICOM_VERSION];
} NSTACKX_LocalDeviceInfo;

/* Register local device information */
int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo);

/* Register local device information with deviceHash */
int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash);

/* Device list change callback type */
typedef void (*NSTACKX_OnDeviceListChanged)(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount);

/* Data receive callback type */
typedef void (*NSTACKX_OnMsgReceived)(const char *moduleName, const char *deviceId,
                                      const uint8_t *data, uint32_t len);

/* DFinder message type list. */
typedef enum {
    DFINDER_ON_TOO_BUSY = 1,
    DFINDER_ON_INNER_ERROR,
} DFinderMsgType;

/* Data receive callback type */
typedef void (*NSTACKX_OnDFinderMsgReceived)(DFinderMsgType msgType);

/* NSTACKX parameter, which contains callback list */
typedef struct {
    NSTACKX_OnDeviceListChanged onDeviceListChanged;
    NSTACKX_OnDeviceListChanged onDeviceFound;
    NSTACKX_OnMsgReceived onMsgReceived;
    NSTACKX_OnDFinderMsgReceived onDFinderMsgReceived;
} NSTACKX_Parameter;

/*
 * NSTACKX Initialization
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter);

/* NSTACKX Destruction */
void NSTACKX_Deinit(void);

/*
 * Start device discovery
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_StartDeviceFind(void);

/*
 * Start device discovery by mode
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_StartDeviceFindAn(uint8_t mode);

/*
 * Stop device discovery
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_StopDeviceFind(void);

/*
 * subscribe module
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_SubscribeModule(void);

/*
 * unsubscribe module
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_UnsubscribeModule(void);

/*
 * Register the capability of local device.
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);

/*
 * Set the capability to filter remote devices.
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);

/*
 * Register the serviceData of local device.
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_RegisterServiceData(const char* serviceData);

/*
 * Send Msg to remote peer
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_SendMsg(const char *moduleName, const char *deviceId, const uint8_t *data,
                        uint32_t len);

/*
 * Send Msg to remote peer
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_SendMsgDirect(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t sendType);

/*
 * Get device list from cache
 * param: deviceList - Device list return from NSTACKX, user should prepare sufficient buffer to store
 *                     device list.
 * param: deviceCountPtr - In/Out parameter. It indicates buffer size (number of elements) in deviceList
 *                         When returns, it indicates numbers of valid device in deviceList.
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr);

/*
 * NSTACKX Initialization, only used for restart.
 * return 0 on success, negative value on failure
 */
int32_t NSTACKX_InitRestart(const NSTACKX_Parameter *parameter);

/*
 * NSTACKX Initialization, only used for restart.
 * return 0 on success, negative value on failure
 */
void NSTACKX_StartDeviceFindRestart(void);

#ifdef __cplusplus
}
#endif

#endif /* NSTACKX_H */
