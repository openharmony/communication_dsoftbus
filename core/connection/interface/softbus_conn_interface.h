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

#ifndef SOFTBUS_CONN_INTERFACE_H
#define SOFTBUS_CONN_INTERFACE_H
#include <stdint.h>
#include "softbus_common.h"
#include "softbus_def.h"

#define DEV_ID_HASH_LEN 32

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
    MODULE_MESSAGE_SERVICE = 8,
    MODULE_AUTH_CHANNEL = 8,
    MODULE_AUTH_MSG = 9,
    MODULE_BLUETOOTH_MANAGER = 9,
    MODULE_CONNECTION = 11,
    MODULE_DIRECT_CHANNEL = 12,
    MODULE_PROXY_CHANNEL = 13,
    MODULE_DEVICE_AUTH = 14,
    MODULE_P2P_LINK = 15,
    MODULE_UDP_INFO = 17,
    MODULE_TIME_SYNC = 18,
    MODULE_PKG_VERIFY = 20,
    MODULE_BLE_NET = 100,
    MODULE_BLE_CONN = 101
} ConnModule;

typedef enum {
    CONNECT_TCP = 1,
    CONNECT_BR,
    CONNECT_BLE,
    CONNECT_TYPE_MAX
} ConnectType;

typedef struct {
    int32_t isAvailable;
    int32_t isServer;
    ConnectType type;
    union {
        struct BrInfo {
            char brMac[BT_MAC_LEN];
        } brInfo;
        struct BleInfo {
            char bleMac[BT_MAC_LEN];
            char deviceIdHash[DEV_ID_HASH_LEN];
        } bleInfo;
        struct IpInfo {
            char ip[IP_LEN];
            int32_t port;
            int32_t fd;
        } ipInfo;
    } info;
} ConnectionInfo;

typedef struct {
    void (*OnConnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDisconnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDataReceived)(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len);
} ConnectCallback;

typedef enum {
    CONN_DEFAULT = 0,
    CONN_LOW,
    CONN_MIDDLE,
    CONN_HIGH
} SendPriority;

typedef struct {
    int32_t module; // ConnModule
    int64_t seq;
    int32_t flag; // SendPriority
    int32_t pid;
    int32_t len;
    char *buf;
} ConnPostData;

typedef struct {
    void (*OnConnectSuccessed)(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info);
    void (*OnConnectFailed)(uint32_t requestId, int32_t reason);
} ConnectResult;

typedef struct {
    ConnectType type;
    union {
        struct BrOption {
            char brMac[BT_MAC_LEN];
        } brOption;
        struct BleOption {
            char bleMac[BT_MAC_LEN];
            char deviceIdHash[DEV_ID_HASH_LEN];
        } bleOption;
        struct IpOption {
            char ip[IP_LEN];
            int32_t port;
        } ipOption;
    } info;
} ConnectOption;

typedef struct {
    ConnectType type;
    union {
        struct IpListenerInfo {
            char ip[IP_LEN];
            int32_t port;
        } ipListenerInfo;
    } info;
} LocalListenerInfo;

uint32_t ConnGetHeadSize(void);

int32_t ConnServerInit(void);

void ConnServerDeinit(void);

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback);

void ConnUnSetConnectCallback(ConnModule moduleId);

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data);

int32_t ConnTypeIsSupport(ConnectType type);

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info);

uint32_t ConnGetNewRequestId(ConnModule moduleId);

int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

int32_t ConnDisconnectDevice(uint32_t connectionId);

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);

int32_t ConnStopLocalListening(const LocalListenerInfo *info);

int32_t ConnStartLocalListening(const LocalListenerInfo *info);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
