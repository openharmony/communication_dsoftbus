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

#include "p2p_entity_broadcast_handler.h"
#include "conn_log.h"
#include "broadcast_receiver.h"
#include "wifi_direct_p2p_adapter.h"
#include "entity/p2p_entity/p2p_entity.h"

static void HandleP2pStateChanged(enum P2pState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "state=%{public}d", state);
    enum EntityState entityState;
    if (state == P2P_STATE_STARTED) {
        entityState = ENTITY_STATE_AVAILABLE;
    } else {
        entityState = ENTITY_STATE_UNAVAILABLE_WIFI_OFF;
    }
    GetP2pEntity()->enable(state == P2P_STATE_STARTED, entityState);
}

static void HandleP2pConnectionChanged(const struct P2pBroadcastParam *param)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (param->p2pLinkInfo.connectState == P2P_DISCONNECTED || param->groupInfo == NULL) {
        GetP2pEntity()->handleConnectionChange(NULL);
    } else {
        GetP2pEntity()->handleConnectionChange(param->groupInfo);
        GetP2pEntity()->handleConnectStateChange(WIFI_DIRECT_P2P_CONNECTED);
    }
}

static void Listener(enum BroadcastReceiverAction action, const struct BroadcastParam *param)
{
    if (action == WIFI_P2P_STATE_CHANGED_ACTION) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_P2P_STATE_CHANGED_ACTION");
        HandleP2pStateChanged(param->p2pParam.p2pState);
    } else if (action == WIFI_P2P_CONNECTION_CHANGED_ACTION) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_P2P_CONNECTION_CHANGED_ACTION");
        HandleP2pConnectionChanged(&param->p2pParam);
    }
}

void P2pEntityBroadcastHandlerInit(void)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    enum BroadcastReceiverAction actions[] = {
        WIFI_P2P_STATE_CHANGED_ACTION,
        WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };

    broadcastReceiver->registerBroadcastListener(actions, ARRAY_SIZE(actions), "P2pEntity",
                                                 LISTENER_PRIORITY_LOW, Listener);
}