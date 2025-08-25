/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_STRUCT_H
#define NSTACKX_STRUCT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_MAX_DEVICE_NAME_LEN               64
#define NSTACKX_MAX_MODULE_NAME_LEN               64
#define NSTACKX_MAX_DEVICE_ID_LEN                 96
#define NSTACKX_MAX_SENDMSG_DATA_LEN              512
#define NSTACKX_MAX_MAC_STRING_LEN                18
#define NSTACKX_MAX_IP_STRING_LEN                 46
#define NSTACKX_MAX_CAPABILITY_NUM                2
#define NSTACKX_MAX_INTERFACE_NAME_LEN            16
#define NSTACKX_MAX_SERVICE_DATA_LEN              64
#define NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN       128
#ifndef NSTACKX_EXTEND_BUSINESSDATA
#define NSTACKX_MAX_BUSINESS_DATA_LEN             1
#else
#define NSTACKX_MAX_BUSINESS_DATA_LEN             300
#endif
#define NSTACKX_MAX_NOTIFICATION_DATA_LEN         800

#ifdef DFINDER_SAVE_DEVICE_LIST
#define NSTACKX_MIN_DEVICE_NUM                    1
#define NSTACKX_DEFAULT_DEVICE_NUM                20
#define NSTACKX_MAX_DEVICE_NUM                    400
#define NSTACKX_DEFAULT_AGING_TIME                1
#define NSTACKX_MIN_AGING_TIME                    1
#define NSTACKX_MAX_AGING_TIME                    10
#else
#define NSTACKX_MAX_DEVICE_NUM                    1
#endif

// expand from 131 to 219 (+88) bytes to hold service data
// expand from 219 to 400 (+128 +53) bytes to hold extend service data
// expand from 400 to (420 + NSTACKX_MAX_BUSINESS_DATA_LEN) bytes to hold business data and type
#define NSTACKX_MAX_RESERVED_INFO_LEN             (420 + NSTACKX_MAX_BUSINESS_DATA_LEN)

#define DEVICE_HASH_LEN                           21

#define NSTACKX_MAX_LISTENED_NIF_NUM              2

#define NSTACKX_MIN_ADVERTISE_COUNT               1
#define NSTACKX_MAX_ADVERTISE_COUNT               100

/* The unit is ms. */
#define NSTACKX_MIN_ADVERTISE_DURATION            5000
#define NSTACKX_MAX_ADVERTISE_DURATION            50000
#define NSTACKX_MIN_ADVERTISE_INTERVAL            10
#define NSTACKX_MAX_ADVERTISE_INTERVAL            10000

#define PUBLISH_DEVICE_NUM                        1
#define INNER_DISCOVERY                           1
#define PUBLISH_NUM                               1
#define COUNT_INIT                                0

#define DFINDER_EVENT_NAME_LEN                    32
#define DFINDER_EVENT_TAG_LEN                     16

#ifndef DFINDER_EXPORT
#ifdef _WIN32
#define DFINDER_EXPORT                    __declspec(dllexport)
#else
#define DFINDER_EXPORT
#endif
#endif

enum {
    DEFAULT_MODE = 0,
    DISCOVER_MODE = 1,
    PUBLISH_MODE_UPLINE = 2,
    PUBLISH_MODE_OFFLINE = 3,
    PUBLISH_MODE_PROACTIVE = 10
}; // discovery mode

enum {
    NSTACKX_DISCOVERY_TYPE_PASSIVE = 1,
    NSTACKX_DISCOVERY_TYPE_ACTIVE = 2
};

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


typedef struct {
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
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

typedef void (*DFinderDumpFunc)(void *softObj, const char *data, uint32_t len);

struct NSTACKX_ServiceData {
    char ip[NSTACKX_MAX_IP_STRING_LEN];
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
};

typedef struct {
    char localNetworkName[NSTACKX_MAX_INTERFACE_NAME_LEN];  /* nic name of local device */
    char remoteIp[NSTACKX_MAX_IP_STRING_LEN];               /* ip of remote device */
    char *businessData;                                     /* business data in unicast: {"bData":"xxx"} */
    uint32_t length;                                        /* the length of business data, include '\0' */
    uint8_t businessType;                                   /* service identify */
} NSTACKX_ResponseSettings;

#ifdef ENABLE_USER_LOG
typedef void (*DFinderLogCallback)(const char *moduleName, uint32_t logLevel, const char *format, ...);
#endif

#define LINKLESS_MAC_LEN                        6
#define LINKLESS_NETWORK_ID_BUF_LEN             65 /* include '\0' */
#define LINKLESS_INVALID_ACTION_LISTEN_CHANNEL  0

typedef enum {
    LINKLESS_APP_SHARE,
    LINKLESS_APP_TOUCH,
    LINKLESS_APP_CAST,
    LINKLESS_APP_SERVICE_DISC,
    LINKLESS_APP_VIRTUAL = 256,
    LINKLESS_APP_MAX,
} LinklessAppId;

typedef enum {
    LINKLESS_LINK_TYPE_AUTO,
    LINKLESS_LINK_TYPE_DIRECT,
    LINKLESS_LINK_TYPE_VIRTUAL,
    LINKLESS_LINK_TYPE_MAX,
} LinklessLinkType;

typedef enum {
    LINKLESS_MODE_PUSH,
    LINKLESS_MODE_PULL,
    LINKLESS_MODE_MAX,
} LinklessMode;

typedef enum {
    LINKLESS_PRIORITY_NORMAL,
    LINKLESS_PRIORITY_HIGH,
    LINKLESS_PRIORITY_MAX,
} LinklessPriority;

typedef enum {
    LINKLESS_LOG_LEVEL_OFF,
    LINKLESS_LOG_LEVEL_FATAL,
    LINKLESS_LOG_LEVEL_ERROR,
    LINKLESS_LOG_LEVEL_WARNING,
    LINKLESS_LOG_LEVEL_INFO,
    LINKLESS_LOG_LEVEL_DEBUG,
    LINKLESS_LOG_LEVEL_END,
} LinklessLogLevel;

typedef enum {
    LINKLESS_MSG_TYPE_REQ,
    LINKLESS_MSG_TYPE_RESP,
    LINKLESS_MSG_TYPE_MAX,
} LinklessMsgType;

typedef enum {
    LINKLESS_WIFI_STATUS_DEFAULT,
    LINKLESS_WIFI_STATUS_BUSY,
    LINKLESS_WIFI_STATUS_MAX,
} LinklessWifiStatus;

typedef enum {
    LINKLESS_VIRTUAL_CONNECTED,
    LINKLESS_VIRTUAL_DISCONNECTED,
    LINKLESS_VIRTUAL_CONN_MAX,
} LinklessVirtualConnStatus;

typedef struct {
    uint16_t appId;
    uint8_t linkType;
    uint8_t priority;
    uint8_t mode;
    bool proxy;
    bool enableListen;
    uint8_t channel;
    uint8_t mac[LINKLESS_MAC_LEN];
    bool encrypt;
    bool needAck;
    uint8_t *data;
    uint16_t dataLen;
    char peerNetworkId[LINKLESS_NETWORK_ID_BUF_LEN];
} LinklessParam;

typedef struct {
    int32_t txChannel;
    uint8_t mac[LINKLESS_MAC_LEN];
    char peerNetworkId[LINKLESS_NETWORK_ID_BUF_LEN];
    uint8_t *payload;
    uint16_t payloadLen;
} LinklessActionSendParam;

typedef int32_t (*LinklessDirectlySendCb)(const LinklessActionSendParam *param);
typedef int32_t (*LinklessStartActionListenCb)(uint8_t *mac, int32_t len, int32_t *channel);
typedef int32_t (*LinklessStopActionListenCb)(void);
typedef void (*LinklessSendCompleteCb)(int32_t transactionId, uint32_t status);
typedef void (*LinklessRecvCb)(const LinklessParam *info);
typedef int32_t (*LinklessVirtualSendCb)(const LinklessActionSendParam *param);

typedef struct {
    LinklessStartActionListenCb startListenCb;
    LinklessStopActionListenCb stopListenCb;
    LinklessDirectlySendCb directlySendCb;
    LinklessVirtualSendCb virtualSendCb;
} LinklessInitParam;

typedef struct {
    uint16_t appId;
    LinklessSendCompleteCb onSendComplete;
    LinklessRecvCb onRecv;
} LinklessRegisterCbParam;

typedef struct {
    uint16_t appId;
    uint8_t channel;
    uint8_t mac[LINKLESS_MAC_LEN];
} LinklessRecvParam;

typedef struct {
    uint8_t txChannel;
    uint8_t rxChannel;
    uint8_t peerMac[LINKLESS_MAC_LEN];
    uint8_t *payload;
    int32_t payloadLen;
    char peerNetworkId[LINKLESS_NETWORK_ID_BUF_LEN];
} LinklessActionRecvParam;

typedef struct {
    uint8_t channel;
    uint8_t mac[LINKLESS_MAC_LEN];
} LinklessActionStateChangeParam;

typedef struct {
    char *networkId;
    char *mac;
    char *ip;
} LinklessVirtualConn;

enum LinklessErrorCode {
    LINKLESS_ERRNO_SUCCESS = 0,
    LINKLESS_ERRNO_FAIL = -101,
    LINKLESS_ERRNO_INVALID_PARAM = -102,
    LINKLESS_ERRNO_MODULE_NOT_INIT = -103,
    LINKLESS_ERRNO_MODULE_ALREADY_INITED = -104,
    LINKLESS_ERRNO_FEATURE_NOT_IMPLEMENTED = -105,
    LINKLESS_ERRNO_USER_CALLBACK_NOT_FOUND = -106,
    LINKLESS_ERRNO_USER_CALLBACK_NOT_REGISTERED = -107,
    LINKLESS_ERRNO_NO_TRANSACTION_ONGOING = -108,
    LINKLESS_ERRNO_LISTEN_CHANNEL_CONFLICT = -109,
    LINKLESS_ERRNO_UNPACK_ACTION_DATA_FAIL = -110,
    LINKLESS_ERRNO_CREATE_TIMER_FAIL = -111,
    LINKLESS_ERRNO_START_ACTION_LISTEN_FAIL = -112,
    LINKLESS_ERRNO_STOP_ACTION_LISTEN_FAIL = -113,
};

#ifdef __cplusplus
}
#endif

#endif /* NSTACKX_H */
