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
#define WIFI_SSID_LEN 32
#define WIFI_MAC_LEN 6
#define OFFLINE_CODE_LEN 32
#define OFFLINE_CODE_BYTE_SIZE 4

#define LNN_RELATION_MASK 0x03

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
    char ssid[WIFI_SSID_LEN + 1];
    unsigned char targetBssid[WIFI_MAC_LEN];
} BssTransInfo;

typedef struct {
    int32_t p2pRole;
    char p2pMac[MAC_LEN]; // the mac of local p2p interface
    char goMac[MAC_LEN]; // the mac of p2p Go device, while local device as Gc role.
} P2pInfo;

typedef struct {
    bool isMetaNode;
    uint32_t metaDiscType;
} MetaInfo;

typedef struct {
    char softBusVersion[VERSION_MAX_LEN];
    char versionType[VERSION_MAX_LEN]; // compatible nearby
    char uuid[UUID_BUF_LEN]; // compatible nearby
    char networkId[NETWORK_ID_BUF_LEN];
    char publicId[ID_MAX_LEN];
    char parentId[ID_MAX_LEN];
    char masterUdid[UDID_BUF_LEN];
    char nodeAddress[SHORT_ADDRESS_MAX_LEN];
    uint8_t relation[CONNECTION_ADDR_MAX];
    int32_t masterWeight;
    ConnectRole role;
    ConnectStatus status;
    uint32_t netCapacity;
    uint32_t discoveryType;
    uint64_t heartbeatTimeStamp;
    DeviceBasicInfo deviceInfo;
    ConnectInfo connectInfo;
    int64_t authSeqNum;
    int32_t authChannelId[CONNECTION_ADDR_MAX];
    BssTransInfo bssTransInfo;
    bool isBleP2p; // true: this device support connect p2p via ble connection
    P2pInfo p2pInfo;
    uint64_t supportedProtocols;
    char accountHash[SHA_256_HASH_LEN];
    unsigned char offlineCode[OFFLINE_CODE_BYTE_SIZE];
    int64_t authSeq[DISCOVERY_TYPE_COUNT];
    MetaInfo metaInfo;
    uint32_t AuthTypeValue;
    uint16_t dataChangeFlag;
} NodeInfo;

const char *LnnGetDeviceUdid(const NodeInfo *info);
int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid);
bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type);
int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type);
bool LnnIsNodeOnline(const NodeInfo *info);
void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status);
const char *LnnGetBtMac(const NodeInfo *info);
void LnnSetBtMac(NodeInfo *info, const char *mac);
const char *LnnGetWiFiIp(const NodeInfo *info);
void LnnSetWiFiIp(NodeInfo *info, const char *ip);
const char *LnnGetNetIfName(const NodeInfo *info);
void LnnSetNetIfName(NodeInfo *info, const char *netIfName);
const char *LnnGetMasterUdid(const NodeInfo *info);
int32_t LnnSetMasterUdid(NodeInfo *info, const char *udid);
int32_t LnnGetAuthPort(const NodeInfo *info);
int32_t LnnSetAuthPort(NodeInfo *info, int32_t port);
int32_t LnnGetSessionPort(const NodeInfo *info);
int32_t LnnSetSessionPort(NodeInfo *info, int32_t port);
int32_t LnnGetProxyPort(const NodeInfo *info);
int32_t LnnSetProxyPort(NodeInfo *info, int32_t port);
int32_t LnnSetP2pRole(NodeInfo *info, int32_t role);
int32_t LnnGetP2pRole(const NodeInfo *info);
int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac);
uint16_t LnnGetDataChangeFlag(const NodeInfo *info);
int32_t LnnSetDataChangeFlag(NodeInfo *info, uint16_t dataChangeFlag);
const char *LnnGetP2pMac(const NodeInfo *info);
int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac);
const char *LnnGetP2pGoMac(const NodeInfo *info);
uint64_t LnnGetSupportedProtocols(const NodeInfo *info);
int32_t LnnSetSupportedProtocols(NodeInfo *info, uint64_t protocols);

#ifdef __cplusplus
}
#endif

#endif // LNN_NODE_INFO_H
