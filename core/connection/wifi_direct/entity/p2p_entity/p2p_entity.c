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

#include "entity/p2p_entity/p2p_entity.h"
#include <string.h>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "broadcast_handler.h"
#include "broadcast_receiver.h"
#include "wifi_direct_p2p_adapter.h"
#include "data/resource_manager.h"
#include "utils/wifi_direct_timer_list.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_anonymous.h"
#include "entity/p2p_entity/p2p_available_state.h"
#include "entity/p2p_entity/p2p_unavailable_state.h"
#include "entity/p2p_entity/p2p_group_creating_state.h"
#include "entity/p2p_entity/p2p_group_connecting_state.h"
#include "entity/p2p_entity/p2p_group_removing_state.h"

#define LOG_LABEL "[WifiDirect] P2pEntity: "

/* private method forward declare */
static void OnEntityTimeout(void *data);
static void OnClientJoinTimeout(void *data);

/* public interface */
static int32_t CreateServer(struct WifiDirectConnectParams *params)
{
    CLOGI(LOG_LABEL "requestId=%d freq=%d isNeedDhcp=%d isWideBandSupported=%d ifName=%s peerMac=%s",
          params->requestId, params->freq, params->isNeedDhcp, params->isWideBandSupported, params->interface,
          WifiDirectAnonymizeMac(params->remoteMac));

    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOG(self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR,
                                  "unavailable state");

    self->currentRequestId = params->requestId;
    return self->currentState->createServer(self->currentState, params);
}

static int32_t Connect(struct WifiDirectConnectParams *params)
{
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOG(self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR,
                                  "unavailable state");

    self->currentRequestId = params->requestId;
    self->isNeedDhcp = params->isNeedDhcp;
    int32_t ret = strcpy_s(self->interface, sizeof(self->interface), params->interface);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy interface failed");
    ret = strcpy_s(self->gcIp, sizeof(self->gcIp), params->gcIp);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, LOG_LABEL "copy ip failed");
    CLOGI(LOG_LABEL "gcIp=%s", WifiDirectAnonymizeIp(self->gcIp));
    return self->currentState->connect(self->currentState, params);
}

static int32_t ReuseLink(struct WifiDirectConnectParams *params)
{
    CLOGD(LOG_LABEL "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOG(self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR,
                                  "unavailable state");
    int32_t ret = GetWifiDirectP2pAdapter()->shareLinkReuse();
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ERROR_P2P_SHARE_LINK_REUSE_FAILED,
                                  LOG_LABEL "ERROR_P2P_SHARE_LINK_REUSE_FAILED");
    return ret;
}

static int32_t P2pDisconnect(struct WifiDirectConnectParams *params)
{
    CLOGD(LOG_LABEL "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOG(self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR,
                                  "unavailable state");

    self->currentRequestId = params->requestId;
    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(params->interface);
    CONN_CHECK_AND_RETURN_RET_LOG(info, SOFTBUS_ERR, LOG_LABEL "interface info is null");
    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, -1);
    CLOGI(LOG_LABEL "reuseCount=%d", reuseCount);

    if (reuseCount <= 1) {
        return self->currentState->removeLink(self->currentState, params);
    }

    CLOGI(LOG_LABEL "shareLinkRemoveGroupSync");
    return GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(params->interface);
}

static int32_t DestroyServer(struct WifiDirectConnectParams *params)
{
    CLOGD(LOG_LABEL "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOG(self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR,
                                  "unavailable state");
    self->currentRequestId = params->requestId;
    return self->currentState->destroyServer(self->currentState, params);
}

static void NotifyNewClientJoining(struct WifiDirectConnectParams *params)
{
    CLOGI(LOG_LABEL "requestId=%d remoteMac=%s", params->requestId, WifiDirectAnonymizeMac(params->remoteMac));
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = SoftBusCalloc(sizeof(*client));
    CONN_CHECK_AND_RETURN_LOG(client, LOG_LABEL "malloc connecting client failed");
    ListInit(&client->node);
    client->requestId = params->requestId;
    strcpy_s(client->remoteMac, sizeof(client->remoteMac), params->remoteMac);
    ListTailInsert(&self->joiningClientList, &client->node);
    self->joiningClientCount++;
    CLOGI(LOG_LABEL "joiningClientCount=%d", self->joiningClientCount);

    self->startNewClientTimer(TIMEOUT_WAIT_CLIENT_JOIN_MS, client);
}

static void CancelNewClientJoining(struct WifiDirectConnectParams *params)
{
    struct P2pEntity *self = GetP2pEntity();
    self->stopNewClientTimer();
    self->removeJoiningClient(params->remoteMac);
}

static void RegisterListener(struct EntityListener *listener)
{
    GetP2pEntity()->listener = listener;
}

static int32_t P2pConnectNotify(struct WifiDirectConnectParams *params)
{
    CLOGD(LOG_LABEL "not supported");
    return SOFTBUS_ERR;
}

static void ChangeState(enum P2pEntityStateType state)
{
    struct P2pEntity *self = GetP2pEntity();
    if (state == self->currentStateType) {
        CLOGD(LOG_LABEL "no change");
        return;
    }

    struct P2pEntityState *old = self->currentState;
    struct P2pEntityState *new = self->states[state];

    old->exit(old);
    new->enter(new);

    CLOGI(LOG_LABEL "%s -> %s", old->name, new->name);
    self->currentState = new;
    self->currentStateType = state;
}

static void StartTimer(int64_t timeMs, enum P2pEntityTimeoutEvent event)
{
    struct P2pEntity *self = GetP2pEntity();
    if (self->currentTimerId != TIMER_ID_INVALID) {
        CLOGE(LOG_LABEL "timer conflict");
        return;
    }

    self->currentTimerId =
        GetWifiDirectTimerList()->startTimer(OnEntityTimeout, timeMs, TIMER_FLAG_ONE_SHOOT, (void *)event);
}

static void StopTimer(void)
{
    struct P2pEntity *self = GetP2pEntity();
    if (self->currentTimerId != TIMER_ID_INVALID) {
        (void)GetWifiDirectTimerList()->stopTimer(self->currentTimerId);
        self->currentTimerId = TIMER_ID_INVALID;
    }
}

static void StartNewClientTimer(int64_t timeMs, struct P2pEntityConnectingClient *client)
{
    struct P2pEntity *self = GetP2pEntity();
    if (self->joiningClientTimerId != TIMER_ID_INVALID) {
        CLOGE(LOG_LABEL "timer conflict");
        return;
    }

    self->joiningClientTimerId =
        GetWifiDirectTimerList()->startTimer(OnClientJoinTimeout, timeMs, TIMER_FLAG_ONE_SHOOT, client);
}

static void StopNewClientTimer(void)
{
    struct P2pEntity *self = GetP2pEntity();
    if (self->joiningClientTimerId != TIMER_ID_INVALID) {
        (void)GetWifiDirectTimerList()->stopTimer(self->joiningClientTimerId);
        self->joiningClientTimerId = TIMER_ID_INVALID;
    }
}

static void OperationCompleteWorkHandler(void *data)
{
    int32_t *result = data;
    struct P2pEntity *self = GetP2pEntity();
    if (self->listener && self->listener->onOperationComplete) {
        self->listener->onOperationComplete(self->currentRequestId, *result);
    }
    SoftBusFree(data);
}

static void NotifyOperationComplete(int32_t result)
{
    CLOGD(LOG_LABEL "result=%d", result);
    int32_t *resultPtr = SoftBusMalloc(sizeof(result));
    CONN_CHECK_AND_RETURN_LOG(resultPtr, LOG_LABEL "malloc result buffer failed");
    *resultPtr = result;

    if (CallMethodAsync(OperationCompleteWorkHandler, resultPtr, 0) != SOFTBUS_OK) {
        SoftBusFree(resultPtr);
    }
}

static void Enable(bool enable, enum EntityState state)
{
    CLOGI(LOG_LABEL "enable=%d state=%d", enable, state);
    struct P2pEntity *self = GetP2pEntity();
    self->changeState(enable ? P2P_ENTITY_STATE_AVAILABLE : P2P_ENTITY_STATE_UNAVAILABLE);

    if (self->listener && self->listener->onEntityChanged) {
        self->listener->onEntityChanged(state);
    }
}

static void HandleConnectionChange(struct WifiDirectP2pGroupInfo *groupInfo)
{
    struct P2pEntity *self = GetP2pEntity();
    CLOGI(LOG_LABEL "currentState=%s", self->currentState->name);
    self->currentState->handleConnectionChange(self->currentState, groupInfo);
}

static void HandleConnectStateChange(enum WifiDirectP2pConnectState state)
{
    struct P2pEntity *self = GetP2pEntity();
    CLOGI(LOG_LABEL "currentState=%s state=%d", self->currentState->name, state);
    self->currentState->handleConnectStateChange(self->currentState, state);
}

static void ConfigIp(const char *interface)
{
    if (GetWifiDirectP2pAdapter()->configGcIp(interface, GetP2pEntity()->gcIp) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "failed");
    }
}

static void ClearJoiningClient(void)
{
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = NULL;
    struct P2pEntityConnectingClient *clientNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(client, clientNext, &self->joiningClientList, struct P2pEntityConnectingClient, node) {
        CLOGD(LOG_LABEL "requestId=%d remoteMac=%s", client->requestId, WifiDirectAnonymizeMac(client->remoteMac));
        ListDelete(&client->node);
        SoftBusFree(client);
        self->joiningClientCount--;
    }
    CLOGD(LOG_LABEL "joiningClientCount=%d", self->joiningClientCount);
}

static void RemoveJoiningClient(const char *remoteMac)
{
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = NULL;
    struct P2pEntityConnectingClient *clientNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(client, clientNext, &self->joiningClientList, struct P2pEntityConnectingClient, node) {
        if (strcmp(client->remoteMac, remoteMac) == 0) {
            CLOGD(LOG_LABEL "requestId=%d remoteMac=%s", client->requestId, WifiDirectAnonymizeMac(client->remoteMac));
            ListDelete(&client->node);
            SoftBusFree(client);
            self->joiningClientCount--;
            break;
        }
    }
    CLOGD(LOG_LABEL "joiningClientCount=%d", self->joiningClientCount);
}

/* private method implement */
static void OnEntityTimeout(void *data)
{
    struct P2pEntity *self = GetP2pEntity();
    self->currentTimerId = TIMER_ID_INVALID;
    enum P2pEntityTimeoutEvent event = (intptr_t)data;
    CLOGD(LOG_LABEL "event=%d", event);
    self->currentState->handleTimeout(self->currentState, event);
}

static void OnClientJoinTimeout(void *data)
{
    GetP2pEntity()->joiningClientTimerId = TIMER_ID_INVALID;
    struct P2pEntityConnectingClient *client = data;
    CLOGD(LOG_LABEL "requestId=%d remoteMac=%s", client->requestId, WifiDirectAnonymizeMac(client->remoteMac));
    ListDelete(&client->node);
    SoftBusFree(client);

    struct WifiDirectConnectParams params;
    strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);

    int32_t ret = P2pDisconnect(&params);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "disconnect failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (info) {
        info->decreaseRefCount(info);
    }
}

/* constructor related method */
static void P2pEntityConstructor(struct P2pEntity *self)
{
    /* base */
    self->createServer = CreateServer;
    self->connect = Connect;
    self->reuseLink = ReuseLink;
    self->disconnect = P2pDisconnect;
    self->destroyServer = DestroyServer;
    self->notifyNewClientJoining = NotifyNewClientJoining;
    self->cancelNewClientJoining = CancelNewClientJoining;
    self->connectNotify = P2pConnectNotify;

    /* self */
    self->registerListener = RegisterListener;
    self->changeState = ChangeState;
    self->startTimer = StartTimer;
    self->stopTimer = StopTimer;
    self->startNewClientTimer = StartNewClientTimer;
    self->stopNewClientTimer = StopNewClientTimer;
    self->notifyOperationComplete = NotifyOperationComplete;
    self->enable = Enable;
    self->handleConnectionChange = HandleConnectionChange;
    self->handleConnectStateChange = HandleConnectStateChange;
    self->configIp = ConfigIp;
    self->clearJoiningClient = ClearJoiningClient;
    self->removeJoiningClient = RemoveJoiningClient;

    struct WifiDirectP2pAdapter *adapter = GetWifiDirectP2pAdapter();
    if (adapter->isWifiP2pEnabled()) {
        self->currentState = (struct P2pEntityState *)GetP2pAvailableState();
        self->currentStateType = P2P_ENTITY_STATE_AVAILABLE;
    } else {
        self->currentState = (struct P2pEntityState *)GetP2pUnavailableState();
        self->currentStateType = P2P_ENTITY_STATE_UNAVAILABLE;
    }

    self->states[P2P_ENTITY_STATE_AVAILABLE] = (struct P2pEntityState *)GetP2pAvailableState();
    self->states[P2P_ENTITY_STATE_UNAVAILABLE] = (struct P2pEntityState *)GetP2pUnavailableState();
    self->states[P2P_ENTITY_STATE_GROUP_CREATING] = (struct P2pEntityState *)GetP2pGroupCreatingState();
    self->states[P2P_ENTITY_STATE_GROUP_CONNECTING] = (struct P2pEntityState *)GetP2pGroupConnectingState();
    self->states[P2P_ENTITY_STATE_GROUP_REMOVING] = (struct P2pEntityState *)GetP2pGroupRemovingState();

    CLOGI(LOG_LABEL "currentStateType=%d", self->currentStateType);
    self->currentState = self->states[self->currentStateType];

    ListInit(&self->joiningClientList);
    self->isInited = true;
}

/* static class method */
static struct P2pEntity g_entity = {
    .isInited = false,
    .currentRequestId = REQUEST_ID_INVALID,
    .currentTimerId = TIMER_ID_INVALID,
    .joiningClientTimerId = TIMER_ID_INVALID,
    .listener = NULL,
    .isConnectionChangeReceived = false,
    .isConnectStateChangeReceived = false,
};

struct P2pEntity* GetP2pEntity(void)
{
    if (!g_entity.isInited) {
        P2pEntityConstructor(&g_entity);
    }
    return &g_entity;
}