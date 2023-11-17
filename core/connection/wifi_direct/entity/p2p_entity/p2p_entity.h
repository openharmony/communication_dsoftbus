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
#ifndef WIFI_P2P_ENTITY_H
#define WIFI_P2P_ENTITY_H

#include "entity/wifi_direct_entity.h"
#include "entity/p2p_entity/p2p_entity_state.h"
#include "wifi_direct_p2p_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TIMEOUT_CREATE_GROUP_MS 5000 // 5s
#define TIMEOUT_CONNECT_GROUP_MS 5000 // 5s
#define TIMEOUT_CONNECT_GROUP_DHCP 15000 // 15s
#define TIMEOUT_WAIT_CLIENT_JOIN_MS 10000 // 10s
#define TIMEOUT_WAIT_REMOVE_GROUP_MS 15000 // 15s

struct P2pEntityConnectingClient {
    ListNode node;
    int32_t timerId;
    int32_t requestId;
    char remoteMac[MAC_ADDR_STR_LEN];
};

enum P2pEntityTimeoutEvent {
    P2P_ENTITY_TIMEOUT_CREATE_SERVER = 1,
    P2P_ENTITY_TIMEOUT_CONNECT_SERVER = 2,
    P2P_ENTITY_TIMEOUT_REMOVE_GROUP = 3,
};

struct P2pEntity {
    WIFI_DIRECT_ENTITY_BASE;

    /* private member */
    void (*changeState)(enum P2pEntityStateType state);
    void (*startTimer)(int64_t timeMs, enum P2pEntityTimeoutEvent event);
    void (*stopTimer)(void);
    void (*notifyOperationComplete)(int32_t result);
    void (*enable)(bool enable, enum EntityState state);
    void (*handleConnectionChange)(struct WifiDirectP2pGroupInfo *groupInfo);
    void (*handleConnectStateChange)(enum WifiDirectP2pConnectState state);
    void (*configIp)(const char *interface);
    void (*removeJoiningClient)(const char *remoteMac);
    void (*clearJoiningClient)(void);

    struct P2pEntityState *states[P2P_ENTITY_STATE_MAX];
    struct P2pEntityState *currentState;
    enum P2pEntityStateType currentStateType;
    int32_t currentTimerId;
    int32_t joiningClientCount;
    ListNode joiningClientList;
    bool isNeedDhcp;
    bool isConnectionChangeReceived;
    bool isConnectStateChangeReceived;
    char gcIp[IP_ADDR_STR_LEN];
    char interface[IF_NAME_LEN];
};

struct P2pEntity* GetP2pEntity(void);

#ifdef __cplusplus
}
#endif
#endif