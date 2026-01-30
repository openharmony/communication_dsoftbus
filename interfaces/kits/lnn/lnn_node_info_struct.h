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

#ifndef LNN_NODE_INFO_STRUCT_H
#define LNN_NODE_INFO_STRUCT_H

#include <stdbool.h>
#include <stdint.h>

#include "bus_center_info_key_struct.h"
#include "lnn_connect_info_struct.h"
#include "lnn_device_info_struct.h"
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

#define SPARK_CHECK_LENGTH 16
#define SPARK_CHECK_STR_LEN 33

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
    DISCOVERY_TYPE_SLE,
    DISCOVERY_TYPE_SESSION_KEY,
    DISCOVERY_TYPE_USB,
    DISCOVERY_TYPE_COUNT,
} DiscoveryType;

typedef enum {
    ACL_WRITE_DEFAULT = 0,
    ACL_CAN_WRITE,
    ACL_NOT_WRITE,
} AclWriteState;

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
    BIT_SUPPORT_USERKEY_NEGO = 7,
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
    char accountUid[ACCOUNT_UID_STR_LEN];
    unsigned char offlineCode[OFFLINE_CODE_BYTE_SIZE];
    char remotePtk[PTK_DEFAULT_LEN];
    char remoteMetaPtk[PTK_DEFAULT_LEN];
    char serviceFindCap[SERVICE_FIND_CAP_LEN];
    bool isNeedReSyncDeviceName;
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
    uint32_t staticNetCap;
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
    uint64_t sleHbTiemstamp;
    uint64_t onlineTimestamp;
    uint64_t offlineTimestamp;
    uint64_t updateTimestamp;
    int64_t lastAuthSeq;
    uint64_t huksKeyTime;
    ConnectInfo connectInfo;
    int32_t sleRangeCapacity;
    AclWriteState aclState;
    unsigned char sparkCheck[SPARK_CHECK_LENGTH];
    int32_t localUserId;
} NodeInfo;

#ifdef __cplusplus
}
#endif

#endif // LNN_NODE_INFO_STRUCT_H