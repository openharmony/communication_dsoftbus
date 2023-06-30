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

#include "entity/p2p_entity/p2p_group_removing_state.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

#define LOG_LABEL "[WifiDirect] P2pGroupRemovingState: "

/* public interface */
static void Enter(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "enter");
    GetP2pEntity()->stopTimer();
    GetP2pEntity()->startTimer(TIMEOUT_WAIT_REMOVE_GROUP_MS, P2P_ENTITY_TIMEOUT_REMOVE_GROUP);
}

static void Exit(struct P2pEntityState *self)
{
    CLOGI(LOG_LABEL "enter");
}

static void HandleTimeout(struct P2pEntityState *self, enum P2pEntityTimeoutEvent event)
{
    if (event != P2P_ENTITY_TIMEOUT_REMOVE_GROUP) {
        CLOGE(LOG_LABEL "mismatch timeout event");
        return;
    }

    CLOGE(LOG_LABEL "remove group timeout");
    GetP2pEntity()->notifyOperationComplete(ERROR_REMOVE_LINK_FAILED);
    GetP2pEntity()->changeState(P2P_ENTITY_STATE_AVAILABLE);
}

static void HandleConnectionChange(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo)
{
    if (!groupInfo) {
        CLOGI(LOG_LABEL "remove group complete");
        struct P2pEntity *entity = GetP2pEntity();
        entity->stopNewClientTimer();
        entity->clearJoiningClient();
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(OK);
    }
}

/* constructor */
static void P2pGroupRemovingStateConstructor(struct P2pGroupRemovingState *self)
{
    P2pEntityStateConstructor((struct P2pEntityState *)self);

    self->enter = Enter;
    self->exit = Exit;
    self->handleTimeout = HandleTimeout;
    self->handleConnectionChange = HandleConnectionChange;
    self->isInited = true;
}

/* class static method */
static struct P2pGroupRemovingState g_state = {
    .isInited = false,
    .name = "P2pEntityGroupRemovingState",
};

struct P2pGroupRemovingState* GetP2pGroupRemovingState(void)
{
    struct P2pGroupRemovingState *self = (struct P2pGroupRemovingState *)&g_state;
    if (!self->isInited) {
        P2pGroupRemovingStateConstructor(self);
    }

    return self;
}