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
#include "conn_log.h"
#include "entity/p2p_entity/p2p_group_creating_state.h"
#include "entity/p2p_entity/p2p_entity.h"

/* public interface */
static void Enter(struct P2pEntityState *self)
{
    (void)self;
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    GetP2pEntity()->stopTimer();
    GetP2pEntity()->startTimer(TIMEOUT_CREATE_GROUP_MS, P2P_ENTITY_TIMEOUT_CREATE_SERVER);
}

static void Exit(struct P2pEntityState *self)
{
    (void)self;
    CONN_LOGI(CONN_WIFI_DIRECT, "exit");
}

static void HandleTimeout(struct P2pEntityState *self, enum P2pEntityTimeoutEvent event)
{
    (void)self;
    struct P2pEntity *entity = GetP2pEntity();
    if (event != P2P_ENTITY_TIMEOUT_CREATE_SERVER) {
        CONN_LOGW(CONN_WIFI_DIRECT, "mismatch timeout event");
        return;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "create group timeout");
    entity->isConnectionChangeReceived = false;
    entity->isConnectStateChangeReceived = false;
    GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(entity->interface);
    GetP2pEntity()->notifyOperationComplete(ERROR_P2P_CREATE_GROUP_FAILED);
    GetP2pEntity()->changeState(P2P_ENTITY_STATE_AVAILABLE);
}

static void HandleConnectionChange(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo)
{
    (void)self;
    struct P2pEntity *entity = GetP2pEntity();

    if (groupInfo == NULL) {
        CONN_LOGW(CONN_WIFI_DIRECT, "create group error");
        entity->clearJoiningClient();
        entity->isConnectionChangeReceived = false;
        entity->isConnectStateChangeReceived = false;
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ERROR_P2P_CREATE_GROUP_FAILED);
        return;
    }

    entity->isConnectionChangeReceived = true;
    CONN_LOGI(CONN_WIFI_DIRECT, "isConnectionChangeReceived=%{public}d, isConnectStateChangeReceived=%{public}d",
          entity->isConnectionChangeReceived, entity->isConnectStateChangeReceived);

    if (entity->isConnectionChangeReceived && entity->isConnectStateChangeReceived) {
        CONN_LOGI(CONN_WIFI_DIRECT, "create group complete");
        entity->isConnectionChangeReceived = false;
        entity->isConnectStateChangeReceived = false;
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ENTITY_EVENT_P2P_CREATE_COMPLETE);
        return;
    }
}

static void HandleConnectStateChange(struct P2pEntityState *self, enum WifiDirectP2pConnectState state)
{
    (void)self;
    struct P2pEntity *entity = GetP2pEntity();

    if (state == WIFI_DIRECT_P2P_CONNECTING) {
        CONN_LOGI(CONN_WIFI_DIRECT, "p2p connecting");
    } else if (state == WIFI_DIRECT_P2P_CONNECTED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "p2p connected");
        entity->isConnectStateChangeReceived = true;
        CONN_LOGI(CONN_WIFI_DIRECT, "isConnectionChangeReceived=%{public}d, isConnectStateChangeReceived=%{public}d",
              entity->isConnectionChangeReceived, entity->isConnectStateChangeReceived);

        if (entity->isConnectionChangeReceived && entity->isConnectStateChangeReceived) {
            CONN_LOGI(CONN_WIFI_DIRECT, "create group complete");
            entity->isConnectionChangeReceived = false;
            entity->isConnectStateChangeReceived = false;
            entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
            entity->notifyOperationComplete(ENTITY_EVENT_P2P_CREATE_COMPLETE);
        }
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "create group error");
        entity->isConnectionChangeReceived = false;
        entity->isConnectStateChangeReceived = false;
        GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(entity->interface);
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ERROR_P2P_CREATE_GROUP_FAILED);
    }
}

/* constructor */
void P2pGroupCreatingStateConstructor(struct P2pGroupCreatingState *self)
{
    P2pEntityStateConstructor((struct P2pEntityState *)self);

    self->enter = Enter;
    self->exit = Exit;
    self->handleTimeout = HandleTimeout;
    self->handleConnectionChange = HandleConnectionChange;
    self->handleConnectStateChange = HandleConnectStateChange;
    self->isInited = true;
}

static struct P2pGroupCreatingState g_state = {
    .isInited = false,
    .name = "P2pEntityGroupCreatingState",
};

/* class static method */
struct P2pGroupCreatingState *GetP2pGroupCreatingState(void)
{
    struct P2pGroupCreatingState *self = (struct P2pGroupCreatingState *)&g_state;
    if (!self->isInited) {
        P2pGroupCreatingStateConstructor(self);
    }

    return self;
}