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

#ifndef LNN_NODE_INFO_H
#define LNN_NODE_INFO_H

#include <stdbool.h>
#include <stdint.h>

#include "lnn_connect_info.h"
#include "lnn_device_info.h"
#include "lnn_net_capability.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ROLE_UNKNOWN = 0,
    ROLE_CONTROLLER,
    ROLE_LEAF,
} ConnectRole;

typedef enum {
    STATUS_OFFLINE = 0,
    STATUS_ONLINE,
} ConnectStatus;

typedef enum {
    DISCOVERY_TYPE_UNKNOWN = 0,
    DISCOVERY_TYPE_WIFI,
    DISCOVERY_TYPE_BLE,
    DISCOVERY_TYPE_BR,
    DISCOVERY_TYPE_P2P,
    DISCOVERY_TYPE_COUNT,
} DiscoveryType;

typedef struct {
    char softBusVersion[VERSION_MAX_LEN];
    char versionType[VERSION_MAX_LEN]; // compatible nearby
    char uuid[UUID_BUF_LEN]; // compatible nearby
    char networkId[NETWORK_ID_BUF_LEN];
    char publicId[ID_MAX_LEN];
    char parentId[ID_MAX_LEN];
    uint32_t weight;
    ConnectRole role;
    ConnectStatus status;
    uint32_t netCapacity;
    uint32_t discoveryType;
    int64_t authSeqNum;
    DeviceBasicInfo deviceInfo;
    ConnectInfo connectInfo;
} NodeInfo;

const char *LnnGetDeviceUdid(const NodeInfo *info);
int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid);
bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type);
bool LnnIsNodeOnline(const NodeInfo *info);
void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status);
const char *LnnGetBtMac(const NodeInfo *info);
void LnnSetBtMac(NodeInfo *info, const char *mac);
const char *LnnGetWiFiIp(const NodeInfo *info);
void LnnSetWiFiIp(NodeInfo *info, const char *ip);
const char *LnnGetNetIfName(const NodeInfo *info);
void LnnSetNetIfName(NodeInfo *info, const char *netIfName);
int32_t LnnGetAuthPort(const NodeInfo *info);
int32_t LnnSetAuthPort(NodeInfo *info, int32_t port);
int32_t LnnGetSessionPort(const NodeInfo *info);
int32_t LnnSetSessionPort(NodeInfo *info, int32_t port);
int32_t LnnGetProxyPort(const NodeInfo *info);
int32_t LnnSetProxyPort(NodeInfo *info, int32_t port);

#ifdef __cplusplus
}
#endif

#endif // LNN_NODE_INFO_H
