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
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "broadcast_receiver.h"
#include "wifi_direct_p2p_adapter.h"
#include "entity/p2p_entity/p2p_entity.h"

#define LOG_LABEL "[WifiDirect] P2pEntityBroadcastHandler: "

static void HandleP2pStateChanged(enum P2pState state)
{
    CLOGI(LOG_LABEL "state=%d", state);
    enum EntityState entityState;
    if (state == P2P_STATE_STARTED) {
        entityState = ENTITY_STATE_AVAILABLE;
    } else {
        entityState = ENTITY_STATE_UNAVAILABLE_WIFI_OFF;
    }
    GetP2pEntity()->enable(state == P2P_STATE_STARTED, entityState);
}

static void HandleP2pConnectionChanged(const struct P2pConnChangedInfo *changedInfo)
{
    CLOGI(LOG_LABEL "enter");
    if (changedInfo->p2pLinkInfo.connectState == P2P_DISCONNECTED || changedInfo->groupInfo == NULL) {
        GetP2pEntity()->handleConnectionChange(NULL);
    } else {
        GetP2pEntity()->handleConnectionChange(changedInfo->groupInfo);
        GetP2pEntity()->handleConnectStateChange(WIFI_DIRECT_P2P_CONNECTED);
    }
}

static void Listener(enum BroadcastReceiverAction action, const struct BroadcastParam *param)
{
    if (action == WIFI_P2P_STATE_CHANGED_ACTION) {
        CLOGI(LOG_LABEL "WIFI_P2P_STATE_CHANGED_ACTION");
        HandleP2pStateChanged(param->p2pState);
    } else if (action == WIFI_P2P_CONNECTION_CHANGED_ACTION) {
        CLOGI(LOG_LABEL "WIFI_P2P_CONNECTION_CHANGED_ACTION");
        HandleP2pConnectionChanged(&param->changedInfo);
    }
}

void P2pEntityBroadcastHandlerInit(void)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    enum BroadcastReceiverAction actions[] = {
        WIFI_P2P_STATE_CHANGED_ACTION,
        WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };

    broadcastReceiver->registerBroadcastListener(actions, ARRAY_SIZE(actions), "P2pEntity", Listener);
}