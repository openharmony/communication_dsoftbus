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

#include "entity/p2p_entity/p2p_group_connecting_state.h"
#include <string.h>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

/* public interface */
static void Enter(struct P2pEntityState *self)
{
    (void)self;
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    GetP2pEntity()->stopTimer();
    int64_t timeout = TIMEOUT_CONNECT_GROUP_MS;
    if (GetP2pEntity()->isNeedDhcp) {
        timeout = TIMEOUT_CONNECT_GROUP_DHCP;
    }
    GetP2pEntity()->startTimer(timeout, P2P_ENTITY_TIMEOUT_CONNECT_SERVER);
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
    if (event != P2P_ENTITY_TIMEOUT_CONNECT_SERVER) {
        CONN_LOGW(CONN_WIFI_DIRECT, "mismatch timeout events");
        return;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "connect group timeout");
    GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(entity->interface);
    entity->notifyOperationComplete(ERROR_P2P_CONNECT_GROUP_FAILED);
    entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
}

static void HandleConnectionChange(struct P2pEntityState *self, struct WifiDirectP2pGroupInfo *groupInfo)
{
    (void)self;
    struct P2pEntity *entity = GetP2pEntity();

    if (groupInfo == NULL) {
        CONN_LOGI(CONN_WIFI_DIRECT, "connect group failed");
        entity->clearJoiningClient();
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ERROR_P2P_CONNECT_GROUP_FAILED);
    }

    if (entity->isNeedDhcp) {
        CONN_LOGI(CONN_WIFI_DIRECT, "connect group complete in DHCP mode");
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ENTITY_EVENT_P2P_CONNECT_COMPLETE);
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
        if (entity->isNeedDhcp) {
            CONN_LOGI(CONN_WIFI_DIRECT, "wait connection change event in DHCP mode");
            return;
        }

        struct WifiDirectP2pGroupInfo *groupInfo = NULL;
        int32_t ret = GetWifiDirectP2pAdapter()->getGroupInfo(&groupInfo);
        CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get groupInfo failed");

        entity->configIp(groupInfo->interface);
        SoftBusFree(groupInfo);

        CONN_LOGI(CONN_WIFI_DIRECT, "connect group complete");
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ENTITY_EVENT_P2P_CONNECT_COMPLETE);
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "p2p connect failed");
        GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(entity->interface);
        entity->changeState(P2P_ENTITY_STATE_AVAILABLE);
        entity->notifyOperationComplete(ERROR_P2P_CONNECT_GROUP_FAILED);
    }
}

/* constructor */
void P2pGroupConnectingStateConstructor(struct P2pGroupConnectingState *self)
{
    P2pEntityStateConstructor((struct P2pEntityState *)self);

    self->enter = Enter;
    self->exit = Exit;
    self->handleTimeout = HandleTimeout;
    self->handleConnectionChange = HandleConnectionChange;
    self->handleConnectStateChange = HandleConnectStateChange;
    self->isInited = true;
}

static struct P2pGroupConnectingState g_state = {
    .isInited = false,
    .name = "P2pEntityGroupConnectingState",
};

struct P2pGroupConnectingState* GetP2pGroupConnectingState(void)
{
    struct P2pGroupConnectingState *self = (struct P2pGroupConnectingState *)&g_state;
    if (!self->isInited) {
        P2pGroupConnectingStateConstructor(self);
    }

    return self;
}