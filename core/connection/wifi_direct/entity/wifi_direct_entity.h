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
#ifndef WIFI_DIRECT_ENTITY_H
#define WIFI_DIRECT_ENTITY_H

#include <stdbool.h>
#include "wifi_direct_types.h"
#include "data/link_info.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectConnectParams {
    int32_t frequency;
    bool isNeedDhcp;
    bool isWideBandSupported;
    bool isProxyEnable;

    char remoteMac[MAC_ADDR_STR_LEN];
    char remoteUuid[UUID_BUF_LEN];
    char groupConfig[GROUP_CONFIG_STR_LEN];
    char gcIp[IP_ADDR_STR_LEN];
    char interface[IF_NAME_LEN];
    struct LinkInfo *linkInfo;

    char *extension;
};

enum EntityState {
    ENTITY_STATE_AVAILABLE = 0,
    ENTITY_STATE_WORKING = 1,
    ENTITY_STATE_UNAVAILABLE_WIFI_OFF = 2,
    ENTITY_STATE_UNAVAILABLE_RPT_ENABLED = 3,
};

enum EntityOperationEvent {
    ENTITY_EVENT_P2P_START = 0,
    ENTITY_EVENT_P2P_CONNECT_COMPLETE,
    ENTITY_EVENT_P2P_CREATE_COMPLETE,
    ENTITY_EVENT_P2P_REMOVE_COMPLETE,
    ENTITY_EVENT_P2P_END,

    ENTITY_EVENT_HML_START,
    ENTITY_EVENT_HML_CONNECT_COMPLETE,
    ENTITY_EVENT_HML_CREATE_COMPLETE,
    ENTITY_EVENT_HML_DISCONNECT_COMPLETE,
    ENTITY_EVENT_HML_REMOVE_COMPLETE,
    ENTITY_EVENT_HML_NOTIFY_COMPLETE,
    ENTITY_EVENT_HML_JOIN_COMPLETE,
    ENTITY_EVENT_HML_SWITCH_NOTIFY_COMPLETE,
    ENTITY_EVENT_HML_END,
};

struct EntityListener {
    void (*onOperationComplete)(int32_t event, void *data);
    void (*onEntityChanged)(enum EntityState state);
};

#define WIFI_DIRECT_ENTITY_BASE                                                       \
    int32_t (*createServer)(struct WifiDirectConnectParams *params);                  \
    int32_t (*connect)(struct WifiDirectConnectParams *params);                       \
    int32_t (*connectNotify)(struct WifiDirectConnectParams *params);                 \
    int32_t (*reuseLink)(struct WifiDirectConnectParams *params);                     \
    int32_t (*disconnect)(struct WifiDirectConnectParams *params);                    \
    int32_t (*destroyServer)(struct WifiDirectConnectParams *params);                 \
    int32_t (*switchNotify)(struct WifiDirectConnectParams *params);                  \
    void (*notifyNewClientJoining)(struct WifiDirectConnectParams *params);           \
    void (*notifyNewClientJoinFail)(struct WifiDirectConnectParams *params);          \
    void (*cancelNewClientJoining)(struct WifiDirectConnectParams *params);           \
    void (*registerListener)(struct EntityListener *listener);                        \
                                                                                      \
    bool isInited;                                                                    \
    struct EntityListener *listener;

struct WifiDirectEntity {
    WIFI_DIRECT_ENTITY_BASE;
};

#ifdef __cplusplus
}
#endif
#endif