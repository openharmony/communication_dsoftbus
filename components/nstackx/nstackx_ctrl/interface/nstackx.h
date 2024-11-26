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
#define NSTACKX_MAX_SERVICE_DATA_LEN 64
#define NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN 128
#ifndef NSTACKX_EXTEND_BUSINESSDATA
#define NSTACKX_MAX_BUSINESS_DATA_LEN 1
#else
#define NSTACKX_MAX_BUSINESS_DATA_LEN 300
#endif
#define NSTACKX_MAX_NOTIFICATION_DATA_LEN 800

#ifdef DFINDER_SAVE_DEVICE_LIST
#define NSTACKX_MIN_DEVICE_NUM 1
#define NSTACKX_DEFAULT_DEVICE_NUM 20
#define NSTACKX_MAX_DEVICE_NUM 400
#define NSTACKX_DEFAULT_AGING_TIME 1
#define NSTACKX_MIN_AGING_TIME 1
#define NSTACKX_MAX_AGING_TIME 10
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
    uint32_t deviceType;
    uint8_t mode;
    uint8_t update : 1;
    uint8_t reserved : 7;
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    uint8_t discoveryType;
    uint8_t businessType;
    char reservedInfo[NSTACKX_MAX_RESERVED_INFO_LEN];
} NSTACKX_DeviceInfo;

#define NSTACKX_MAX_LISTENED_NIF_NUM 2

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
    uint8_t businessType;
    uint32_t deviceType;
} NSTACKX_LocalDeviceInfo;

typedef enum {
    NSTACKX_BUSINESS_TYPE_NULL = 0,     /* if not set business type, type null will be used as default choice */
    NSTACKX_BUSINESS_TYPE_HICOM = 1,    /* designed for hicom, but not used currently */
    NSTACKX_BUSINESS_TYPE_SOFTBUS = 2,  /* designed for softbus-mineharmony to implement some customized features */
    NSTACKX_BUSINESS_TYPE_NEARBY = 3,   /* designed to handle the interaction between two nearby service */
    NSTACKX_BUSINESS_TYPE_AUTONET = 4,  /* designed for softbus-autonet to implement some customized features */
    NSTACKX_BUSINESS_TYPE_STRATEGY = 5, /* designed for softbus-strategy to report disc result in different rounds */
    NSTACKX_BUSINESS_TYPE_MAX           /* for parameter legality verification */
} NSTACKX_BusinessType;

#define NSTACKX_MIN_ADVERTISE_COUNT 1
#define NSTACKX_MAX_ADVERTISE_COUNT 100
/* The unit is ms. */
#define NSTACKX_MIN_ADVERTISE_DURATION 5000
#define NSTACKX_MAX_ADVERTISE_DURATION 50000
#define NSTACKX_MIN_ADVERTISE_INTERVAL 10
#define NSTACKX_MAX_ADVERTISE_INTERVAL 10000

typedef struct {
    uint8_t businessType;       /* service identify */
    uint8_t discoveryMode;      /* discovery mode, e.g. PUBLISH_MODE_PROACTIVE */
    uint32_t advertiseCount;    /* the number of broadcasts to be sent */
    uint32_t advertiseDuration; /* duration of discovery this time */
    uint32_t length;            /* the length of business data, include '\0' */
    char *businessData;         /* business data in broadcast: {"bData":"xxx"} */
} NSTACKX_DiscoverySettings;

typedef struct {
    uint8_t businessType;
    uint8_t discoveryMode;
    uint32_t intervalArrLen;
    uint32_t *bcastInterval;
    uint32_t businessDataLen;
    char *businessData;
} DFinderDiscConfig;

typedef struct {
    const char *name;
    const char *deviceId;
    const NSTACKX_InterfaceInfo *localIfInfo;
    uint32_t ifNums;
    uint32_t deviceType;
    uint64_t deviceHash;
    bool hasDeviceHash;
    uint8_t businessType;
} NSTACKX_LocalDeviceInfoV2;

/* Register local device information */
DFINDER_EXPORT int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo);

/* Register local device name */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceName(const char *devName);

/* Register local device information with deviceHash */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash);

/* New interface to register local device with multiple interfaces */
DFINDER_EXPORT int32_t NSTACKX_RegisterDeviceV2(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo);

/* Device list change callback type */
typedef void (*NSTACKX_OnDeviceListChanged)(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount);

typedef void (*NSTACKX_OnMsgReceived)(const char *moduleName, const char *deviceId,
    const uint8_t *data, uint32_t len, const char *srcIp); /* Data receive callback type */

/* DFinder message type list. */
typedef enum {
    DFINDER_ON_TOO_BUSY = 1,
    DFINDER_ON_INNER_ERROR,
    DFINDER_ON_TOO_MANY_DEVICE,
} DFinderMsgType;

/* store the notification config, used with interface: NSTACKX_SendNotification */
typedef struct {
    char *msg;                /* notification data in json format */
    size_t msgLen;            /* strlen of notification data */
    uint16_t *intervalsMs;    /* pointer to intervals to send notification, first element should be 0 */
    uint8_t intervalLen;      /* configured number of intervals */
    uint8_t businessType;     /* service identify, see enum NSTACKX_BusinessType */
} NSTACKX_NotificationConfig;

/* Data receive callback type */
typedef void (*NSTACKX_OnDFinderMsgReceived)(DFinderMsgType msgType);

/**
 * @brief define function pointer type, used to report the notification data received
 *
 * @param [out] element: notification data to report, see struct NSTACKX_NotificationConfig
 */
typedef void (*NSTACKX_OnNotificationReceived)(const NSTACKX_NotificationConfig *notification);

/* NSTACKX parameter, which contains callback list */
typedef struct {
    NSTACKX_OnDeviceListChanged onDeviceListChanged;
    NSTACKX_OnDeviceListChanged onDeviceFound;
    NSTACKX_OnMsgReceived onMsgReceived;
    NSTACKX_OnDFinderMsgReceived onDFinderMsgReceived;
    NSTACKX_OnNotificationReceived onNotificationReceived;
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

#define DFINDER_EVENT_NAME_LEN 32
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
    char tag[DFINDER_EVENT_TAG_LEN];
    char desc[DFINDER_EVENT_NAME_LEN];
    DFinderEventParam *params;
    uint32_t paramNum;
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

typedef struct {
    char localNetworkName[NSTACKX_MAX_INTERFACE_NAME_LEN];  /* nic name of local device */
    char remoteIp[NSTACKX_MAX_IP_STRING_LEN];               /* ip of remote device */
    char *businessData;                                     /* business data in unicast: {"bData":"xxx"} */
    uint32_t length;                                        /* the length of business data, include '\0' */
    uint8_t businessType;                                   /* service identify */
} NSTACKX_ResponseSettings;

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
