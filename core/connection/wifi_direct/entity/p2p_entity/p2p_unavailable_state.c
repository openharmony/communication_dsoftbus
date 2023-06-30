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

#include "entity/p2p_entity/p2p_unavailable_state.h"
#include "softbus_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "entity/p2p_entity/p2p_entity.h"

#define LOG_LABEL  "[WifiDirect] P2pUnavailableState: "

/* public interface */
static void Enter(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "enter");
    GetP2pEntity()->stopTimer();
}

static void Exit(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "enter");
}

static int32_t CreateServer(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "entity unavailable");
    return SOFTBUS_ERR;
}

static int32_t Connect(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "entity unavailable");
    return SOFTBUS_ERR;
}

static int32_t RemoveLink(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "entity unavailable");
    return SOFTBUS_ERR;
}

static int32_t DestroyServer(struct P2pEntityState *self, struct WifiDirectConnectParams *params)
{
    CLOGE(LOG_LABEL "entity unavailable");
    return SOFTBUS_ERR;
}

static void HandleTimeout(struct P2pEntityState *self, enum P2pEntityTimeoutEvent event)
{
    CLOGE(LOG_LABEL "entity unavailable");
}

static void HandleConnectionChange(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo)
{
    CLOGE(LOG_LABEL "entity unavailable");
}

static void HandleConnectStateChange(struct P2pEntityState *self, enum WifiDirectP2pConnectState state)
{
    CLOGE(LOG_LABEL "entity unavailable");
}

/* constructor */
static struct P2pUnavailableState g_state = {
    .enter = Enter,
    .exit = Exit,
    .createServer = CreateServer,
    .connect = Connect,
    .removeLink = RemoveLink,
    .destroyServer = DestroyServer,
    .handleTimeout = HandleTimeout,
    .handleConnectionChange = HandleConnectionChange,
    .handleConnectStateChange = HandleConnectStateChange,
    .isInited = false,
    .name = "P2pEntityUnavailableState",
};

static void UnavailableStateConstructor(struct P2pUnavailableState *self)
{
    self->isInited = true;
}

struct P2pUnavailableState* GetP2pUnavailableState(void)
{
    struct P2pUnavailableState *self = (struct P2pUnavailableState *)&g_state;
    if (!self->isInited) {
        UnavailableStateConstructor(self);
    }

    return self;
}