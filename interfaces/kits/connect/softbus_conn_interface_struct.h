/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONN_INTERFACE_STRUCT_H
#define SOFTBUS_CONN_INTERFACE_STRUCT_H

#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef enum {
    MODULE_TRUST_ENGINE = 1,
    MODULE_HICHAIN = 2,
    MODULE_AUTH_SDK = 3,
    MODULE_AUTH_CONNECTION = 5,
    MODULE_AUTH_CANCEL = 6,
    MODULE_MESSAGE_SERVICE = 8,
    MODULE_AUTH_CHANNEL = 8,
    MODULE_AUTH_MSG = 9,
    MODULE_BLUETOOTH_MANAGER = 9,
    MODULE_CONNECTION = 11,
    MODULE_DIRECT_CHANNEL = 12,
    MODULE_PROXY_CHANNEL = 13,
    MODULE_DEVICE_AUTH = 14,
    MODULE_P2P_LINK = 15,
    MODULE_P2P_LISTEN = 16,
    MODULE_UDP_INFO = 17,
    MODULE_P2P_NETWORKING_SYNC = 18,
    MODULE_TIME_SYNC = 19,
    MODULE_PKG_VERIFY = 20,
    MODULE_META_AUTH = 21,
    MODULE_P2P_NEGO = 22,
    MODULE_AUTH_SYNC_INFO = 23,
    MODULE_PTK_VERIFY = 24,
    MODULE_SESSION_AUTH = 25,
    MODULE_SESSION_KEY_AUTH = 26,
    MODULE_SLE_AUTH_CMD = 27,
    MODULE_APPLY_KEY_CONNECTION = 28,
    MODULE_LANE_SELECT = 29,
    MODULE_VIRTUAL_LINK = 30,
    MODULE_BLE_NET = 100,
    MODULE_BLE_CONN = 101,
    MODULE_BLE_GENERAL = 102,
    MODULE_PAGING_CONN = 103,
    MODULE_NIP_BR_CHANNEL = 201,
    MODULE_OLD_NEARBY = 300,
} ConnModule;

typedef enum {
    CONNECT_TCP = 1,
    CONNECT_BR,
    CONNECT_BLE,
    CONNECT_P2P,
    CONNECT_P2P_REUSE,
    CONNECT_BLE_DIRECT,
    CONNECT_HML,
    CONNECT_TRIGGER_HML,
    CONNECT_SLE,
    CONNECT_SLE_DIRECT,
    CONNECT_BLE_GENERAL,
    CONNECT_TRIGGER_HML_V2C,
    CONNECT_PROXY_CHANNEL,
    CONNECT_PAGING,
    CONNECT_TYPE_MAX
} ConnectType;

#define CONN_INVALID_LISTENER_MODULE_ID    0xffff
#define CONN_DYNAMIC_LISTENER_MODULE_COUNT 32
#define DEVID_BUFF_LEN                     65
#define NETIF_NAME_LEN                     16

#define BT_LINK_TYPE_BR  1
#define BT_LINK_TYPE_BLE 2
#define HML_NUM 8
#define AUTH_ENHANCED_P2P_NUM 8

typedef enum {
    PROXY = 0,
    AUTH,
    AUTH_P2P,
    AUTH_ENHANCED_P2P_START,
    AUTH_ENHANCED_P2P_END = AUTH_ENHANCED_P2P_START + AUTH_ENHANCED_P2P_NUM - 1,
    DIRECT_CHANNEL_SERVER_P2P,
    DIRECT_CHANNEL_CLIENT,
    DIRECT_CHANNEL_SERVER_WIFI,
    DIRECT_CHANNEL_SERVER_USB,
    DIRECT_CHANNEL_SERVER_HML_START,
    DIRECT_CHANNEL_SERVER_HML_END = DIRECT_CHANNEL_SERVER_HML_START + HML_NUM * 2 - 1,
    DIRECT_LOWLATENCY,
    LANE,
    NETLINK,
    AUTH_RAW_P2P_SERVER,
    AUTH_RAW_P2P_CLIENT,
    AUTH_USB,
    AUTH_SESSION_KEY,
    TIME_SYNC,

    LISTENER_MODULE_DYNAMIC_START,
    LISTENER_MODULE_DYNAMIC_END = LISTENER_MODULE_DYNAMIC_START + CONN_DYNAMIC_LISTENER_MODULE_COUNT,
    UNUSE_BUTT,
} ListenerModule;

struct BrInfo {
    char brMac[BT_MAC_LEN];
};
struct BleInfo {
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    BleProtocolType protocol;
    uint32_t psm;
    uint16_t challengeCode;
};

struct SleInfo {
    char address[BT_MAC_LEN];
    uint16_t challengeCode;
    SleProtocolType protocol;
    char networkId[NETWORK_ID_BUF_LEN];

    uint8_t deviceIdHash[SHA_256_HASH_LEN];
    uint8_t deviceIdHashLen;
};

struct ConnSocketInfo {
    char addr[IP_LEN];
    ProtocolType protocol;
    int32_t port;
    int32_t fd;
    int32_t moduleId; /* For details, see {@link ListenerModule}. */
};

typedef struct {
    int32_t isAvailable;
    int32_t isServer;
    ConnectType type;
    union {
        struct BrInfo brInfo;
        struct BleInfo bleInfo;
        struct SleInfo sleInfo;
        struct ConnSocketInfo socketInfo;
    };
} ConnectionInfo;

typedef struct {
    void (*OnConnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnReusedConnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDisconnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDataReceived)(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len);
} ConnectCallback;

typedef enum {
    CONN_DEFAULT = 0,
    CONN_LOW,
    CONN_MIDDLE,
    CONN_HIGH
} SendPriority;

typedef enum {
    CONN_SIDE_ANY = 0,
    CONN_SIDE_CLIENT,
    CONN_SIDE_SERVER
} ConnSideType;

typedef struct {
    int32_t module; // ConnModule
    int64_t seq;
    int32_t flag; // SendPriority
    int32_t pid;
    uint32_t len;
    char *buf;
} ConnPostData;

typedef struct {
    void (*OnConnectSuccessed)(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info);
    void (*OnConnectFailed)(uint32_t requestId, int32_t reason);
} ConnectResult;

struct BrOption {
    char brMac[BT_MAC_LEN];
    uint32_t connectionId;
    ConnSideType sideType;
    uint32_t waitTimeoutDelay;
};

struct BleOption {
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    bool fastestConnectEnable;
    uint16_t challengeCode;
    uint32_t psm;
    BleProtocolType protocol;
    uint32_t connectTimeoutMs;
};

struct BleDirectOption {
    char networkId[NETWORK_ID_BUF_LEN];
    BleProtocolType protoType;
};

struct SleDirectOption {
    char networkId[NETWORK_ID_BUF_LEN];
    SleProtocolType protoType;
};

struct SocketOption {
    char ifName[NETIF_NAME_LEN];
    char addr[IP_LEN]; /* ipv6 addr format: ip%ifname */
    int32_t port;
    int32_t moduleId; /* For details, see {@link ListenerModule}. */
    ProtocolType protocol;
    int32_t keepAlive;
    char localMac[MAC_MAX_LEN];
    char remoteMac[MAC_MAX_LEN];
};

struct SleOption {
    char networkId[NETWORK_ID_BUF_LEN];
    char address[BT_MAC_LEN];
    uint16_t challengeCode;
    bool isFrameType4;
    bool isLiteHead;
    SleProtocolType protocol;
};

struct PagingOption {
    char accountId[ACCOUNT_ID_SIZE_MAX];
};

typedef struct {
    ConnectType type;
    union {
        struct BrOption brOption;
        struct BleOption bleOption;
        struct SocketOption socketOption;
        struct BleDirectOption bleDirectOption;
        struct SleOption sleOption;
        struct SleDirectOption sleDirectOption;
        struct PagingOption pagingOption;
    };
} ConnectOption;

typedef enum {
    CONN_BLE_PRIORITY_BALANCED = 0x0,
    CONN_BLE_PRIORITY_HIGH,
    CONN_BLE_PRIORITY_LOW_POWER,
} ConnectBlePriority;

typedef enum {
    CONN_SLE_POWER_LEVEL_DEFAULT = 0x0,
    CONN_SLE_POWER_LEVEL_7,
    CONN_SLE_POWER_LEVEL_8,
} ConnectSlePowerLevel;

typedef struct {
    ConnectType type;
    union {
        struct {
            ConnectBlePriority priority;
        } bleOption;
        struct {
            ConnectSlePowerLevel slePowerLevel;
        } sleOption;
        struct {
            bool enableIdleCheck;
        } brOption;
    };
} UpdateOption;

struct ListenerSocketOption {
    char addr[IP_LEN];
    int32_t port;
    ListenerModule moduleId; /* For details, see {@link ListenerModule}. */
    ProtocolType protocol;
    char ifName[NETIF_NAME_LEN];
    char localMac[MAC_MAX_LEN];
    char remoteMac[MAC_MAX_LEN];
};

typedef struct {
    ConnectType type;
    union {
        struct ListenerSocketOption socketOption;
    };
} LocalListenerInfo;

typedef struct {
    bool active;
    ConnectType type;
    int32_t windowInMillis;
    int32_t quotaInBytes;
} LimitConfiguration;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif