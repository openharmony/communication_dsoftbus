/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif
#define WIFI_SSID_LEN 32
#define WIFI_MAC_LEN 6
#define OFFLINE_CODE_LEN 32
#define OFFLINE_CODE_BYTE_SIZE 4
#define EXTDATA_LEN 8
#define PTK_DEFAULT_LEN 32
#define STATIC_CAP_LEN 100
#define USERID_CHECKSUM_LEN 4
#define USERID_LEN 4
#define STATIC_CAP_STR_LEN 201
#define PTK_ENCODE_LEN 45

#define LNN_RELATION_MASK 0x03
#define WIFI_CFG_INFO_MAX_LEN 512
#define CHANNEL_LIST_STR_LEN  256

#define SESSION_KEY_STR_LEN 65
#define PTK_STR_LEN 65

#define BROADCAST_IV_LEN 16
#define BROADCAST_IV_STR_LEN 33

#define LFINDER_UDID_HASH_LEN 32
#define LFINDER_IRK_LEN 16
#define LFINDER_IRK_STR_LEN 33
#define LFINDER_MAC_ADDR_LEN 6
#define LFINDER_MAC_ADDR_STR_LEN 13

typedef enum {
    AUTH_AS_CLIENT_SIDE = 0,
    AUTH_AS_SERVER_SIDE,
    AUTH_SIDE_MAX,
} AuthSide;

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
    DISCOVERY_TYPE_LSA,
    DISCOVERY_TYPE_COUNT,
} DiscoveryType;

typedef struct {
    char ssid[WIFI_SSID_LEN + 1];
    unsigned char targetBssid[WIFI_MAC_LEN];
} BssTransInfo;

typedef struct {
    int32_t p2pRole;
    char wifiCfg[WIFI_CFG_INFO_MAX_LEN];
    char chanList5g[CHANNEL_LIST_STR_LEN];
    int32_t staFrequency;
    char p2pMac[MAC_LEN]; // the mac of local p2p interface
    char goMac[MAC_LEN]; // the mac of p2p Go device, while local device as Gc role.
    char p2pIp[IP_LEN];
} P2pInfo;

typedef struct {
    bool isMetaNode;
    uint32_t metaDiscType;
} MetaInfo;

typedef struct {
    bool isCharging;
    int32_t batteryLevel;
} BatteryInfo;

typedef enum {
    BIT_SUPPORT_EXCHANGE_NETWORKID = 0,
    BIT_SUPPORT_NORMALIZED_LINK = 1,
    BIT_SUPPORT_NEGOTIATION_AUTH = 2,
    BIT_SUPPORT_BR_DUP_BLE = 3,
    BIT_SUPPORT_ADV_OFFLINE = 4,
    BIT_SUPPORT_ENHANCEDP2P_DUP_BLE = 5,
    BIT_SUPPORT_SESSION_DUP_BLE = 6,
} AuthCapability;

typedef struct {
    int32_t keylen;
    unsigned char key[SESSION_KEY_LENGTH];
    unsigned char iv[BROADCAST_IV_LEN];
} BroadcastCipherInfo;

typedef struct {
    uint8_t peerIrk[LFINDER_IRK_LEN];
    unsigned char publicAddress[LFINDER_MAC_ADDR_LEN];
    unsigned char peerUdidHash[LFINDER_UDID_HASH_LEN];
} RpaInfo;

typedef struct {
    char softBusVersion[VERSION_MAX_LEN];
    char versionType[VERSION_MAX_LEN]; // compatible nearby
    char pkgVersion[VERSION_MAX_LEN];
    char uuid[UUID_BUF_LEN]; // compatible nearby
    char lastNetworkId[NETWORK_ID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];
    char publicId[ID_MAX_LEN];
    char parentId[ID_MAX_LEN];
    char masterUdid[UDID_BUF_LEN];
    char nodeAddress[SHORT_ADDRESS_MAX_LEN];
    char extData[EXTDATA_LEN];
    char wifiDirectAddr[MAC_LEN];
    char accountHash[SHA_256_HASH_LEN];
    unsigned char offlineCode[OFFLINE_CODE_BYTE_SIZE];
    char remotePtk[PTK_DEFAULT_LEN];
    char remoteMetaPtk[PTK_DEFAULT_LEN];
    bool isScreenOn;
    bool initPreventFlag;
    bool isAuthExchangeUdid;
    bool isSupportIpv6;
    bool isBleP2p; // true: this device support connect p2p via ble connection
    bool isSupportSv;
    uint8_t staticCapability[STATIC_CAP_LEN];
    uint8_t relation[CONNECTION_ADDR_MAX];
    uint8_t userIdCheckSum[USERID_CHECKSUM_LEN];
    uint16_t dataChangeFlag;
    uint16_t dataDynamicLevel;
    uint16_t dataStaticLevel;
    uint32_t dataSwitchLevel;
    uint16_t dataSwitchLength;
    BssTransInfo bssTransInfo;
    RpaInfo rpaInfo;
    int32_t masterWeight;
    ConnectRole role;
    ConnectStatus status;
    uint32_t netCapacity;
    uint32_t authCapacity;
    uint32_t heartbeatCapacity;
    uint32_t discoveryType;
    int32_t wifiBuffSize;
    int32_t brBuffSize;
    int32_t stateVersion;
    int32_t localStateVersion;
    uint32_t groupType;
    int32_t bleMacRefreshSwitch;
    int32_t bleConnCloseDelayTime;
    int32_t staticCapLen;
    int32_t userId;
    uint32_t stateVersionReason;
    int32_t deviceSecurityLevel;
    int32_t authChannelId[CONNECTION_ADDR_MAX][AUTH_SIDE_MAX];
    uint32_t AuthTypeValue;
    DeviceBasicInfo deviceInfo;
    P2pInfo p2pInfo;
    MetaInfo metaInfo;
    BatteryInfo batteryInfo;
    BroadcastCipherInfo cipherInfo;
    int64_t wifiVersion;
    int64_t bleVersion;
    uint64_t feature;
    uint64_t connSubFeature;
    int64_t bleStartTimestamp;
    uint64_t supportedProtocols;
    int64_t accountId;
    int64_t authSeq[DISCOVERY_TYPE_COUNT];
    int64_t networkIdTimestamp;
    int64_t authSeqNum;
    uint64_t heartbeatTimestamp;
    uint64_t bleDirectTimestamp;
    uint64_t onlinetTimestamp;
    uint64_t updateTimestamp;
    int64_t lastAuthSeq;
    ConnectInfo connectInfo;
} NodeInfo;

const char *LnnGetDeviceUdid(const NodeInfo *info);
int32_t LnnSetDeviceUdid(NodeInfo *info, const char *udid);
const char *LnnGetDeviceUuid(const NodeInfo *info);
bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
int32_t LnnSetDiscoveryType(NodeInfo *info, DiscoveryType type);
int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type);
bool LnnIsNodeOnline(const NodeInfo *info);
void LnnSetNodeConnStatus(NodeInfo *info, ConnectStatus status);
const char *LnnGetBtMac(const NodeInfo *info);
void LnnSetBtMac(NodeInfo *info, const char *mac);
const char *LnnGetBleMac(const NodeInfo *info);
void LnnSetBleMac(NodeInfo *info, const char *mac);
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
int32_t LnnSetWifiCfg(NodeInfo *info, const char *wifiCfg);
const char *LnnGetWifiCfg(const NodeInfo *info);
int32_t LnnSetChanList5g(NodeInfo *info, const char *chanList5g);
const char *LnnGetChanList5g(const NodeInfo *info);
int32_t LnnSetStaFrequency(NodeInfo *info, int32_t staFrequency);
int32_t LnnGetStaFrequency(const NodeInfo *info);
int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac);
uint16_t LnnGetDataChangeFlag(const NodeInfo *info);
int32_t LnnSetDataChangeFlag(NodeInfo *info, uint16_t dataChangeFlag);
uint16_t LnnGetDataDynamicLevel(const NodeInfo *info);
int32_t LnnSetDataDynamicLevel(NodeInfo *info, uint16_t dataDynamicLevel);
uint16_t LnnGetDataStaticLevel(const NodeInfo *info);
int32_t LnnSetDataStaticLevel(NodeInfo *info, uint16_t dataStaticLvel);
uint32_t LnnGetDataSwitchLevel(const NodeInfo *info);
int32_t LnnSetDataSwitchLevel(NodeInfo *info, uint32_t dataSwitchLevel);
uint16_t LnnGetDataSwitchLength(const NodeInfo *info);
int32_t LnnSetDataSwitchLength(NodeInfo *info, uint16_t dataSwitchLevel);
const char *LnnGetP2pMac(const NodeInfo *info);
int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac);
const char *LnnGetP2pGoMac(const NodeInfo *info);
uint64_t LnnGetSupportedProtocols(const NodeInfo *info);
int32_t LnnSetSupportedProtocols(NodeInfo *info, uint64_t protocols);
int32_t LnnSetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len);
int32_t LnnGetStaticCapability(NodeInfo *info, uint8_t *cap, uint32_t len);
int32_t LnnSetUserIdCheckSum(NodeInfo *info, uint8_t *data, uint32_t len);
int32_t LnnGetUserIdCheckSum(NodeInfo *info, uint8_t *data, uint32_t len);
int32_t LnnSetPtk(NodeInfo *info, const char *remotePtk);
void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log);
int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr);
const char *LnnGetWifiDirectAddr(const NodeInfo *info);
void LnnDumpNodeInfo(const NodeInfo *deviceInfo, const char *log);
int32_t LnnSetScreenStatus(NodeInfo *info, bool isScreenOn);
#ifdef __cplusplus
}
#endif

#endif // LNN_NODE_INFO_H
