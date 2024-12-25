/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_TYPES_H
#define WIFI_DIRECT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "wifi_direct_defines.h"
#include "softbus_common.h"
#include "wifi_direct_error_code.h"

#ifndef NULL
#define NULL 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum WifiDirectConnectType {
    WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P = 0,
    WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML = 1,

    WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML = 2,
    WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML = 3,
    WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML = 4,
};

enum WifiDirectRole {
    WIFI_DIRECT_ROLE_AUTO = 1,
    WIFI_DIRECT_ROLE_GO = 2,
    WIFI_DIRECT_ROLE_GC = 3,
    WIFI_DIRECT_ROLE_BRIDGE_GC = 4,
    WIFI_DIRECT_ROLE_NONE = 5,
    WIFI_DIRECT_ROLE_HML = 6,
    WIFI_DIRECT_ROLE_INVALID = 7,
};

enum WifiDirectApiRole {
    WIFI_DIRECT_API_ROLE_NONE = 0,
    WIFI_DIRECT_API_ROLE_STA = 1,
    WIFI_DIRECT_API_ROLE_AP = 2,
    WIFI_DIRECT_API_ROLE_GO = 4,
    WIFI_DIRECT_API_ROLE_GC = 8,
    WIFI_DIRECT_API_ROLE_HML = 16,
};

enum P2pGroupConfigIndex {
    P2P_GROUP_CONFIG_INDEX_SSID = 0,
    P2P_GROUP_CONFIG_INDEX_BSSID = 1,
    P2P_GROUP_CONFIG_INDEX_SHARE_KEY = 2,
    P2P_GROUP_CONFIG_INDEX_FREQ = 3,
    P2P_GROUP_CONFIG_INDEX_MODE = 4,
    P2P_GROUP_CONFIG_INDEX_MAX,
};

enum WifiDirectLinkType {
    WIFI_DIRECT_LINK_TYPE_INVALID = -1,
    WIFI_DIRECT_LINK_TYPE_P2P,
    WIFI_DIRECT_LINK_TYPE_HML,
};

enum WifiDirectBandWidth {
    BAND_WIDTH_RANDOM = 0x0,
    BAND_WIDTH_20M,
    BAND_WIDTH_40M,
    BAND_WIDTH_80M,
    BAND_WIDTH_80P80M,
    BAND_WIDTH_160M,
    BAND_WIDTH_BUTT = 0xFF,
};

typedef enum {
    CONN_HML_CAP_UNKNOWN = -1,
    CONN_HML_SUPPORT = 0,
    CONN_HML_NOT_SUPPORT = 1,
} HmlCapabilityCode;

struct WifiDirectLink {
    int32_t linkId;
    char localIp[IP_STR_MAX_LEN];
    char remoteIp[IP_STR_MAX_LEN];
    int32_t remotePort;
    enum WifiDirectLinkType linkType;
    enum WifiDirectBandWidth bandWidth;
    bool isReuse;
    int channelId;
};

struct WifiDirectSinkLink {
    char remoteUuid[UUID_BUF_LEN];
    int channelId;
    enum WifiDirectBandWidth bandWidth;
    enum WifiDirectLinkType linkType;

    char localIp[IP_STR_MAX_LEN];
    char remoteIp[IP_STR_MAX_LEN];

    char remoteMac[MAC_ADDR_STR_LEN];
};

enum WifiDirectNegoChannelType {
    NEGO_CHANNEL_NULL = 0,
    NEGO_CHANNEL_AUTH = 1,
    NEGO_CHANNEL_COC = 2,
    NEGO_CHANNEL_ACTION = 3,
    NEGO_CHANNEL_SHARE = 4,
};

struct WifiDirectNegotiateChannel {
    enum WifiDirectNegoChannelType type;
    union {
        AuthHandle authHandle;
        int32_t channelId;
        uint32_t actionAddr;
    } handle;
};

enum IpAddrType {
    IPV4,
    IPV6
};

enum StatisticLinkType {
    STATISTIC_P2P = 0,
    STATISTIC_HML = 1,
    STATISTIC_TRIGGER_HML = 2,
    STATISTIC_LINK_TYPE_NUM = 3,
};

enum StatisticBootLinkType {
    STATISTIC_NONE = 0,
    STATISTIC_WLAN = 1,
    STATISTIC_BLE = 2,
    STATISTIC_BR = 3,
    STATISTIC_COC = 4,
    STATISTIC_ACTION = 5,
    STATISTIC_RENEGOTIATE = 6,
    STATISTIC_BOOT_LINK_TYPE_NUM = 7,
};

struct WifiDirectDfxInfo {
    enum StatisticLinkType linkType;
    enum StatisticBootLinkType bootLinkType;
    int renegotiate;
    int reuse;
    int costTime;
    uint16_t challengeCode;
    int frequency;
    int staChannel;
    int hmlChannel;
    int p2pChannel;
    int apChannel;
};

struct WifiDirectConnectInfo {
    uint32_t requestId;
    int32_t pid;
    enum WifiDirectConnectType connectType;
    struct WifiDirectNegotiateChannel negoChannel;
    bool reuseOnly;
    uint32_t expectApiRole;
    bool isStrict;
    char remoteNetworkId[NETWORK_ID_BUF_LEN];
    char remoteMac[MAC_ADDR_STR_LEN];
    bool isNetworkDelegate;
    int32_t bandWidth;
    enum IpAddrType ipAddrType;

    struct WifiDirectDfxInfo dfxInfo;
};

struct WifiDirectDisconnectInfo {
    uint32_t requestId;
    int32_t pid;
    int32_t linkId;
    struct WifiDirectNegotiateChannel negoChannel;
};

struct WifiDirectForceDisconnectInfo {
    uint32_t requestId;
    int32_t pid;
    char remoteUuid[UUID_BUF_LEN];
    enum WifiDirectLinkType linkType;
    struct WifiDirectNegotiateChannel negoChannel;
};

struct WifiDirectConnectCallback {
    void (*onConnectSuccess)(uint32_t requestId, const struct WifiDirectLink *link);
    void (*onConnectFailure)(uint32_t requestId, int32_t reason);
};

struct WifiDirectDisconnectCallback {
    void (*onDisconnectSuccess)(uint32_t requestId);
    void (*onDisconnectFailure)(uint32_t requestId, int32_t reason);
};

#ifdef __cplusplus
}
#endif
#endif
