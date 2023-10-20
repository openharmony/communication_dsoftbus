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

#include "entity/p2p_entity/p2p_entity_state.h"
#include "softbus_adapter_mem.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "entity/p2p_entity/p2p_entity.h"

#define LOG_LABEL "[WifiDirect] P2pEntityState: "

static void Enter(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "%s default implement", self->name);
}

static void Exit(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "%s default implement", self->name);
}

static int32_t CreateServer(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "%s ERROR_ENTITY_BUSY", self->name);
    return ERROR_ENTITY_BUSY;
}

static int32_t Connect(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "%s ERROR_ENTITY_BUSY", self->name);
    return ERROR_ENTITY_BUSY;
}

static int32_t RemoveLink(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "%s ERROR_ENTITY_BUSY", self->name);
    return ERROR_ENTITY_BUSY;
}

static int32_t DestroyServer(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "%s ERROR_ENTITY_BUSY", self->name);
    return ERROR_ENTITY_BUSY;
}

static void HandleTimeout(struct P2pEntityState *self, enum P2pEntityTimeoutEvent event)
{
    CLOGE(LOG_LABEL "%s default implement, event=%d", self->name, event);
    struct P2pEntity *entity = GetP2pEntity();
    entity->notifyOperationComplete(SOFTBUS_TIMOUT);
    entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
}

static void HandleConnectionChange(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo)
{
    CLOGI(LOG_LABEL "%s default implement", self->name);
}

static void HandleConnectStateChange(struct P2pEntityState *self, enum WifiDirectP2pConnectState state)
{
    CLOGI(LOG_LABEL "%s default implement", self->name);
}

/* base constructor */
void P2pEntityStateConstructor(struct P2pEntityState *self)
{
    self->enter = Enter;
    self->exit = Exit;
    self->createServer = CreateServer;
    self->connect = Connect;
    self->removeLink = RemoveLink;
    self->destroyServer = DestroyServer;
    self->handleTimeout = HandleTimeout;
    self->handleConnectionChange = HandleConnectionChange;
    self->handleConnectStateChange = HandleConnectStateChange;
}