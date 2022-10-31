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
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_MAX_DEVICE_NAME_LEN 64
#define NSTACKX_MAX_MODULE_NAME_LEN 64
#define NSTACKX_MAX_DEVICE_ID_LEN 96
#define NSTACKX_MAX_SENDMSG_DATA_LEN 512
#define NSTACKX_MAX_MAC_STRING_LEN 18
#define NSTACKX_MAX_IP_STRING_LEN 16
#define NSTACKX_MAX_CAPABILITY_NUM 2
#define NSTACKX_MAX_INTERFACE_NAME_LEN 16
#define NSTACKX_MAX_HICOM_VERSION 16
#define NSTACKX_MAX_SERVICE_DATA_LEN 64
#define NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN 128
#ifndef NSTACKX_EXTEND_BUSINESSDATA
#define NSTACKX_MAX_BUSINESS_DATA_LEN 1
#else
#define NSTACKX_MAX_BUSINESS_DATA_LEN 300
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
#define NSTACKX_MIN_DEVICE_NUM 1
#define NSTACKX_DEFAULT_DEVICE_NUM 20
#define NSTACKX_MAX_DEVICE_NUM 400
#else
#define NSTACKX_MAX_DEVICE_NUM 1
#endif

// expand from 131 to 219 (+88) bytes to hold service data
// expand from 219 to 400 (+128 +53) bytes to hold extend service data
// expand from 400 to (420 + NSTACKX_MAX_BUSINESS_DATA_LEN) bytes to hold business data and type
#define NSTACKX_MAX_RESERVED_INFO_LEN (420 + NSTACKX_MAX_BUSINESS_DATA_LEN)

#define DEVICE_HASH_LEN 21
enum {
    DEFAULT_MODE = 0,
    DISCOVER_MODE = 1,
    PUBLISH_MODE_UPLINE = 2,
    PUBLISH_MODE_OFFLINE = 3,
    PUBLISH_MODE_PROACTIVE = 10
}; // discovery mode
#define PUBLISH_DEVICE_NUM 1
#define INNER_DISCOVERY 1
#define PUBLISH_NUM 1
#define COUNT_INIT 0

enum {
    NSTACKX_DISCOVERY_TYPE_PASSIVE = 1,
    NSTACKX_DISCOVERY_TYPE_ACTIVE = 2
};

#ifndef DFINDER_EXPORT
#ifdef _WIN32
#define DFINDER_EXPORT __declspec(dllexport)
#else
#define DFINDER_EXPORT
#endif
#endif

/* Remote device information */
typedef struct NSTACKX_DeviceInfo {
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    uint8_t deviceType;
    uint8_t mode;
#ifdef DFINDER_SAVE_DEVICE_LIST
    uint8_t update : 1;
    uint8_t reserved : 7;
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
#endif
    uint8_t discoveryType;
    uint8_t businessType;
    char version[NSTACKX_MAX_HICOM_VERSION];
    char reservedInfo[NSTACKX_MAX_RESERVED_INFO_LEN];
} NSTACKX_DeviceInfo;

#ifdef DFINDER_SUPPORT_MULTI_NIF
#define NSTACKX_MAX_LISTENED_NIF_NUM 2
#else
#define NSTACKX_MAX_LISTENED_NIF_NUM 1
#endif
typedef struct {
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN];
} NSTACKX_InterfaceInfo;


/* Local device information */
typedef struct {
    char name[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char btMacAddr[NSTACKX_MAX_MAC_STRING_LEN];
    char wifiMacAddr[NSTACKX_MAX_MAC_STRING_LEN];

    /* Configuration for network interface */
    NSTACKX_InterfaceInfo localIfInfo[NSTACKX_MAX_LISTENED_NIF_NUM];
    uint8_t ifNums;

    /* Obsoleted. Use localIfInfo instead. */
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    /* Obsoleted. Use localIfInfo instead. */
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    uint8_t is5GHzBandSupported;
    uint8_t deviceType;
    char version[NSTACKX_MAX_HICOM_VERSION];
    uint8_t businessType;
} NSTACKX_LocalDeviceInfo;

typedef enum {
    NSTACKX_BUSINESS_TYPE_NULL = 0,
    NSTACKX_BUSINESS_TYPE_HICOM = 1,
    NSTACKX_BUSINESS_TYPE_SOFTBUS = 2,
    NSTACKX_BUSINESS_TYPE_NEARBY = 3
} NSTACKX_BusinessType;

#define NSTACKX_MIN_ADVERTISE_COUNT 1
#define NSTACKX_MAX_ADVERTISE_COUNT 100
/* The unit of duration is ms. */
#define NSTACKX_MIN_ADVERTISE_DURATION 5000
#define NSTACKX_MAX_ADVERTISE_DURATION 50000

typedef struct {
    uint8_t businessType;
    uint8_t discoveryMode;
    uint32_t advertiseCount;
    uint32_t advertiseDuration;
    char *businessData;
    uint32_t length;
} NSTACKX_DiscoverySettings;

/* Register local device information */
DFINDER_EXPORT int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo);

/* Register local device name */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceName(const char *devName);

/* Register local device information with deviceHash */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash);

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
    uint32_t maxDeviceNum; // the size of the device list configured by the caller
} NSTACKX_Parameter;

/* DFinder log level */
enum {
    DFINDER_LOG_LEVEL_OFF     = 0,
    DFINDER_LOG_LEVEL_FATAL   = 1,
    DFINDER_LOG_LEVEL_ERROR   = 2,
    DFINDER_LOG_LEVEL_WARNING = 3,
    DFINDER_LOG_LEVEL_INFO    = 4,
    DFINDER_LOG_LEVEL_DEBUG   = 5,
    DFINDER_LOG_LEVEL_END,
};

typedef enum {
    DFINDER_EVENT_TYPE_FAULT,
    DFINDER_EVENT_TYPE_STATISTIC,
    DFINDER_EVENT_TYPE_SECURITY,
    DFINDER_EVENT_TYPE_BEHAVIOR,
} DFinderEventType;

typedef enum {
    DFINDER_EVENT_LEVEL_CRITICAL,
    DFINDER_EVENT_LEVEL_MINOR,
} DFinderEventLevel;

typedef enum {
    DFINDER_PARAM_TYPE_BOOL,
    DFINDER_PARAM_TYPE_UINT8,
    DFINDER_PARAM_TYPE_UINT16,
    DFINDER_PARAM_TYPE_INT32,
    DFINDER_PARAM_TYPE_UINT32,
    DFINDER_PARAM_TYPE_UINT64,
    DFINDER_PARAM_TYPE_FLOAT,
    DFINDER_PARAM_TYPE_DOUBLE,
    DFINDER_PARAM_TYPE_STRING,
} DFinderEventParamType;

#define DFINDER_EVENT_NAME_LEN 33
#define DFINDER_EVENT_TAG_LEN 16

typedef struct {
    DFinderEventParamType type;
    char name[DFINDER_EVENT_NAME_LEN];
    union {
        bool b;
        uint8_t u8v;
        uint16_t u16v;
        int32_t i32v;
        uint32_t u32v;
        uint64_t u64v;
        float f;
        double d;
        char str[DFINDER_EVENT_NAME_LEN];
    } value;
} DFinderEventParam;

typedef struct {
    char eventName[DFINDER_EVENT_NAME_LEN];
    DFinderEventType type;
    DFinderEventLevel level;
    uint32_t paramNum;
    DFinderEventParam *params;
} DFinderEvent;

typedef void (*DFinderEventFunc)(void *softObj, const DFinderEvent *info);

DFINDER_EXPORT int NSTACKX_DFinderSetEventFunc(void *softobj, DFinderEventFunc func);

typedef void (*DFinderDumpFunc)(void *softObj, const char *data, uint32_t len);
DFINDER_EXPORT int NSTACKX_DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump);

/*
 * NSTACKX Initialization
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter);

/* NSTACKX Destruction */
DFINDER_EXPORT void NSTACKX_Deinit(void);

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
 * Register the serviceData of local device.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_RegisterServiceData(const char *serviceData);

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

/*
 * Start device discovery with settings. If advertiseCount and advertiseDuration both 0, discovery with default
 * advertise settings.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_StartDeviceDiscovery(const NSTACKX_DiscoverySettings *discoverySettings);

typedef struct {
    uint8_t businessType;
    char localNetworkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char remoteIp[NSTACKX_MAX_IP_STRING_LEN];
    char *businessData;
    uint32_t length;
} NSTACKX_ResponseSettings;

/*
 * Send discovery response to remote in unicast.
 * return 0 on success, negative value on failure
 */
DFINDER_EXPORT int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings);

#ifdef ENABLE_USER_LOG
typedef void (*DFinderLogCallback)(const char *moduleName, uint32_t logLevel, const char *format, ...);

/*
 * Set the DFinder log implementation
 */
DFINDER_EXPORT int32_t NSTACKX_DFinderRegisterLog(DFinderLogCallback userLogCallback);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NSTACKX_H */
