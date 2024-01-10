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

enum WifiDirectP2pContentType {
    P2P_CONTENT_TYPE_INVALID = -1,
    P2P_CONTENT_TYPE_GO_INFO = 1,
    P2P_CONTENT_TYPE_GC_INFO = 2,
    P2P_CONTENT_TYPE_RESULT = 3,
};

enum WifiDirectNegotiateCmdType {
    CMD_INVALID = -1,
    /* v1 cmd */
    CMD_DISCONNECT_V1_REQ = 5,
    CMD_CONN_V1_REQ = 8,
    CMD_CONN_V1_RESP = 9,
    CMD_REUSE_REQ = 12,
    CMD_CTRL_CHL_HANDSHAKE = 13,
    CMD_GC_WIFI_CONFIG_CHANGED = 17,
    CMD_REUSE_RESP = 19,

    /* v2 cmd */
    CMD_CONN_V2_REQ_1 = 21,
    CMD_CONN_V2_REQ_2 = 22,
    CMD_CONN_V2_REQ_3 = 23,
    CMD_CONN_V2_RESP_1 = 24,
    CMD_CONN_V2_RESP_2 = 25,
    CMD_CONN_V2_RESP_3 = 26,
    CMD_DISCONNECT_V2_REQ = 27,
    CMD_DISCONNECT_V2_RESP = 28,
    CMD_CLIENT_JOIN_FAIL_NOTIFY = 29,

    CMD_PC_GET_INTERFACE_INFO_REQ = 30,
    CMD_PC_GET_INTERFACE_INFO_RESP = 31,

    CMD_RENEGOTIATE_REQ = 50,
    CMD_RENEGOTIATE_RESP = 51,
};

enum WifiDirectEntityType {
    ENTITY_TYPE_P2P = 0,
    ENTITY_TYPE_HML = 1,
    ENTITY_TYPE_MAX,
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
    WIFI_DIRECT_LINK_TYPE_MAX,
};

struct WifiDirectLink {
    int32_t linkId;
    char localIp[IP_ADDR_STR_LEN];
    char remoteIp[IP_ADDR_STR_LEN];
    enum WifiDirectLinkType linkType;
};

struct WifiDirectNegotiateChannel;
struct WifiDirectConnectInfo {
    int32_t requestId;
    int32_t pid;
    enum WifiDirectConnectType connectType;
    struct WifiDirectNegotiateChannel *negoChannel;
    uint32_t expectApiRole;
    bool isStrict;
    char remoteNetworkId[NETWORK_ID_BUF_LEN];
    char remoteMac[MAC_ADDR_STR_LEN];
    bool isNetworkDelegate;
    int32_t linkId;
    uint32_t bandWidth;
};

struct WifiDirectConnectCallback {
    void (*onConnectSuccess)(int32_t requestId, const struct WifiDirectLink *link);
    void (*onConnectFailure)(int32_t requestId, enum WifiDirectErrorCode reason);
    void (*onDisconnectSuccess)(int32_t requestId);
    void (*onDisconnectFailure)(int32_t requestId, enum WifiDirectErrorCode reason);
};

#ifdef __cplusplus
}
#endif
#endif