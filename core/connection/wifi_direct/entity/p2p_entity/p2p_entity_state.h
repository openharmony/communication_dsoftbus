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
#ifndef P2P_STATE_BASE_H
#define P2P_STATE_BASE_H

#include "wifi_direct_p2p_adapter.h"
#include "broadcast_receiver.h"

#ifdef __cplusplus
extern "C" {
#endif

enum P2pEntityStateType {
    P2P_ENTITY_STATE_AVAILABLE = 0,
    P2P_ENTITY_STATE_UNAVAILABLE = 1,
    P2P_ENTITY_STATE_GROUP_CREATING = 2,
    P2P_ENTITY_STATE_GROUP_CONNECTING = 3,
    P2P_ENTITY_STATE_GROUP_REMOVING = 4,
    P2P_ENTITY_STATE_MAX,
};

struct WifiDirectConnectParams;
enum P2pEntityTimeoutEvent;

#define P2P_ENTITY_STATE_BASE \
    void (*enter)(struct P2pEntityState *self);                                                                  \
    void (*exit)(struct P2pEntityState *self);                                                                   \
                                                                                                                 \
    int32_t (*createServer)(struct P2pEntityState *self, struct WifiDirectConnectParams *params);                \
    int32_t (*connect)(struct P2pEntityState *self, struct WifiDirectConnectParams *params);                     \
    int32_t (*removeLink)(struct P2pEntityState *self, struct WifiDirectConnectParams *params);                  \
    int32_t (*destroyServer)(struct P2pEntityState *self, struct WifiDirectConnectParams *params);               \
                                                                                                                 \
    void (*handleTimeout)(struct P2pEntityState *self, enum P2pEntityTimeoutEvent event);                        \
    void (*handleConnectionChange)(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo);       \
    void (*handleConnectStateChange)(struct P2pEntityState *self, enum WifiDirectP2pConnectState state);         \
                                                                                                                 \
    bool isInited;                                                                                               \
    const char *name;

struct P2pEntityState {
    P2P_ENTITY_STATE_BASE;
};

void P2pEntityStateConstructor(struct P2pEntityState *self);

#ifdef __cplusplus
}
#endif
#endif