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
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
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

/* private method forward declare */
static void OnEntityTimeout(void *data);
static void OnClientJoinTimeout(void *data);

/* public interface */
static int32_t CreateServer(struct WifiDirectConnectParams *params)
{
    CONN_LOGI(CONN_WIFI_DIRECT,
        "freq=%{public}d, isNeedDhcp=%{public}d, isWideBandSupported=%{public}d, ifName=%{public}s, peerMac=%{public}s",
        params->frequency, params->isNeedDhcp, params->isWideBandSupported, params->interface,
        WifiDirectAnonymizeMac(params->remoteMac));

    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR, CONN_WIFI_DIRECT, "unavailable state");

    return self->currentState->createServer(self->currentState, params);
}

static int32_t Connect(struct WifiDirectConnectParams *params)
{
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR, CONN_WIFI_DIRECT, "unavailable state");

    self->isNeedDhcp = params->isNeedDhcp;
    int32_t ret = strcpy_s(self->interface, sizeof(self->interface), params->interface);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy interface failed");
    ret = strcpy_s(self->gcIp, sizeof(self->gcIp), params->gcIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy ip failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "gcIp=%{public}s", WifiDirectAnonymizeIp(self->gcIp));
    return self->currentState->connect(self->currentState, params);
}

static int32_t ReuseLink(struct WifiDirectConnectParams *params)
{
    (void)params;
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR, CONN_WIFI_DIRECT, "unavailable state");
    int32_t ret = GetWifiDirectP2pAdapter()->shareLinkReuse();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ERROR_P2P_SHARE_LINK_REUSE_FAILED, CONN_WIFI_DIRECT, "ERROR_P2P_SHARE_LINK_REUSE_FAILED");
    return ret;
}

static int32_t Disconnect(struct WifiDirectConnectParams *params)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR, CONN_WIFI_DIRECT, "unavailable state");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(params->interface);
    CONN_CHECK_AND_RETURN_RET_LOGW(info, SOFTBUS_ERR, CONN_WIFI_DIRECT, "interface info is null");
    int32_t reuseCount = info->getInt(info, II_KEY_REUSE_COUNT, -1);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", reuseCount);

    if (reuseCount <= 1) {
        return self->currentState->removeLink(self->currentState, params);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "shareLinkRemoveGroupSync");
    return GetWifiDirectP2pAdapter()->shareLinkRemoveGroupSync(params->interface);
}

static int32_t DestroyServer(struct WifiDirectConnectParams *params)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "enter");
    struct P2pEntity *self = GetP2pEntity();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        self->currentStateType != P2P_ENTITY_STATE_UNAVAILABLE, SOFTBUS_ERR, CONN_WIFI_DIRECT, "unavailable state");
    return self->currentState->destroyServer(self->currentState, params);
}

static void NotifyNewClientJoining(struct WifiDirectConnectParams *params)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(params->remoteMac));
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = SoftBusCalloc(sizeof(*client));
    CONN_CHECK_AND_RETURN_LOGE(client, CONN_WIFI_DIRECT, "malloc connecting client failed");
    ListInit(&client->node);
    int32_t ret = strcpy_s(client->remoteMac, sizeof(client->remoteMac), params->remoteMac);
    if (ret != EOK) {
        CONN_LOGW(CONN_WIFI_DIRECT, "copy remote mac failed");
    }
    ListTailInsert(&self->joiningClientList, &client->node);
    self->joiningClientCount++;
    CONN_LOGI(CONN_WIFI_DIRECT, "joiningClientCount=%{public}d", self->joiningClientCount);

    client->timerId = GetWifiDirectTimerList()->startTimer(
        OnClientJoinTimeout, TIMEOUT_WAIT_CLIENT_JOIN_MS, TIMER_FLAG_ONE_SHOOT, client);
}

static void CancelNewClientJoining(struct WifiDirectConnectParams *params)
{
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = NULL;
    struct P2pEntityConnectingClient *clientNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(client, clientNext, &self->joiningClientList, struct P2pEntityConnectingClient, node) {
        if (strcmp(client->remoteMac, params->remoteMac) == 0) {
            CONN_LOGD(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s", client->requestId,
                WifiDirectAnonymizeMac(client->remoteMac));
            GetWifiDirectTimerList()->stopTimer(client->timerId);
            ListDelete(&client->node);
            SoftBusFree(client);
            self->joiningClientCount--;
            break;
        }
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "joiningClientCount=%{public}d", self->joiningClientCount);
}

static void RegisterListener(struct EntityListener *listener)
{
    GetP2pEntity()->listener = listener;
}

static int32_t P2pConnectNotify(struct WifiDirectConnectParams *params)
{
    (void)params;
    CONN_LOGD(CONN_WIFI_DIRECT, "not supported");
    return SOFTBUS_ERR;
}

static void ChangeState(enum P2pEntityStateType state)
{
    struct P2pEntity *self = GetP2pEntity();
    if (state == self->currentStateType) {
        CONN_LOGD(CONN_WIFI_DIRECT, "no change");
        return;
    }

    struct P2pEntityState *old = self->currentState;
    struct P2pEntityState *new = self->states[state];

    old->exit(old);
    new->enter(new);

    CONN_LOGI(CONN_WIFI_DIRECT, "name:%{public}s->%{public}s", old->name, new->name);
    self->currentState = new;
    self->currentStateType = state;
}

static void StartTimer(int64_t timeMs, enum P2pEntityTimeoutEvent event)
{
    struct P2pEntity *self = GetP2pEntity();
    if (self->currentTimerId != TIMER_ID_INVALID) {
        CONN_LOGE(CONN_WIFI_DIRECT, "timer conflict");
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

static void OperationCompleteWorkHandler(void *data)
{
    int32_t *result = data;
    struct P2pEntity *self = GetP2pEntity();
    if (self->listener && self->listener->onOperationComplete) {
        self->listener->onOperationComplete(*result, NULL);
    }
    SoftBusFree(data);
}

static void NotifyOperationComplete(int32_t result)
{
    CONN_LOGD(CONN_WIFI_DIRECT, "result=%{public}d", result);
    int32_t *resultPtr = SoftBusMalloc(sizeof(result));
    CONN_CHECK_AND_RETURN_LOGE(resultPtr, CONN_WIFI_DIRECT, "malloc result buffer failed");
    *resultPtr = result;

    if (CallMethodAsync(OperationCompleteWorkHandler, resultPtr, 0) != SOFTBUS_OK) {
        SoftBusFree(resultPtr);
    }
}

static void Enable(bool enable, enum EntityState state)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enable=%{public}d, state=%{public}d", enable, state);
    struct P2pEntity *self = GetP2pEntity();
    self->changeState(enable ? P2P_ENTITY_STATE_AVAILABLE : P2P_ENTITY_STATE_UNAVAILABLE);

    if (self->listener && self->listener->onEntityChanged) {
        self->listener->onEntityChanged(state);
    }
}

static void HandleConnectionChange(struct WifiDirectP2pGroupInfo *groupInfo)
{
    struct P2pEntity *self = GetP2pEntity();
    CONN_LOGI(CONN_WIFI_DIRECT, "currentState=%{public}s", self->currentState->name);
    self->currentState->handleConnectionChange(self->currentState, groupInfo);
}

static void HandleConnectStateChange(enum WifiDirectP2pConnectState state)
{
    struct P2pEntity *self = GetP2pEntity();
    CONN_LOGI(CONN_WIFI_DIRECT, "currentState=%{public}s, state=%{public}d", self->currentState->name, state);
    self->currentState->handleConnectStateChange(self->currentState, state);
}

static void ConfigIp(const char *interface)
{
    if (GetWifiDirectP2pAdapter()->configGcIp(interface, GetP2pEntity()->gcIp) != SOFTBUS_OK) {
        CONN_LOGW(CONN_WIFI_DIRECT, "config gc ip failed");
    }
}

static void RemoveJoiningClient(const char *remoteMac)
{
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = NULL;
    struct P2pEntityConnectingClient *clientNext = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(client, clientNext, &self->joiningClientList, struct P2pEntityConnectingClient, node) {
        if (strcmp(remoteMac, client->remoteMac) == 0) {
            CONN_LOGI(CONN_WIFI_DIRECT, "request=%{public}d, remoteMac=%{public}s", client->requestId,
                WifiDirectAnonymizeMac(client->remoteMac));
            GetWifiDirectTimerList()->stopTimer(client->timerId);
            ListDelete(&client->node);
            SoftBusFree(client);
            self->joiningClientCount--;
        }
    }
    CONN_LOGD(CONN_WIFI_DIRECT, "joiningClientCount=%{public}d", self->joiningClientCount);
}

static void ClearJoiningClient(void)
{
    struct P2pEntity *self = GetP2pEntity();
    struct P2pEntityConnectingClient *client = NULL;
    struct P2pEntityConnectingClient *clientNext = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(client, clientNext, &self->joiningClientList, struct P2pEntityConnectingClient, node) {
        CONN_LOGD(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s", client->requestId,
            WifiDirectAnonymizeMac(client->remoteMac));
        GetWifiDirectTimerList()->stopTimer(client->timerId);
        ListDelete(&client->node);
        SoftBusFree(client);
        self->joiningClientCount--;
    }
    CONN_LOGD(CONN_WIFI_DIRECT, "joiningClientCount=%{public}d", self->joiningClientCount);
}

/* private method implement */
static void OnEntityTimeout(void *data)
{
    struct P2pEntity *self = GetP2pEntity();
    self->currentTimerId = TIMER_ID_INVALID;
    enum P2pEntityTimeoutEvent event = (intptr_t)data;
    CONN_LOGD(CONN_WIFI_DIRECT, "event=%{public}d", event);
    self->currentState->handleTimeout(self->currentState, event);
}

static void OnClientJoinTimeout(void *data)
{
    struct P2pEntityConnectingClient *client = data;
    CONN_LOGD(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s, joiningClientCount=%{public}d",
        client->requestId, WifiDirectAnonymizeMac(client->remoteMac), GetP2pEntity()->joiningClientCount);
    ListDelete(&client->node);
    SoftBusFree(client);
    GetP2pEntity()->joiningClientCount--;
    client = NULL;

    struct WifiDirectConnectParams params;
    int32_t ret = strcpy_s(params.interface, sizeof(params.interface), IF_NAME_P2P);
    CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_WIFI_DIRECT, "copy interface failed");

    ret = Disconnect(&params);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "disconnect failed");

    struct InterfaceInfo *info = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (info != NULL) {
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
    self->disconnect = Disconnect;
    self->destroyServer = DestroyServer;
    self->notifyNewClientJoining = NotifyNewClientJoining;
    self->cancelNewClientJoining = CancelNewClientJoining;
    self->connectNotify = P2pConnectNotify;

    /* self */
    self->registerListener = RegisterListener;
    self->changeState = ChangeState;
    self->startTimer = StartTimer;
    self->stopTimer = StopTimer;
    self->notifyOperationComplete = NotifyOperationComplete;
    self->enable = Enable;
    self->handleConnectionChange = HandleConnectionChange;
    self->handleConnectStateChange = HandleConnectStateChange;
    self->configIp = ConfigIp;

    self->removeJoiningClient = RemoveJoiningClient;
    self->clearJoiningClient = ClearJoiningClient;

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

    CONN_LOGI(CONN_WIFI_DIRECT, "currentStateType=%{public}d", self->currentStateType);
    self->currentState = self->states[self->currentStateType];

    ListInit(&self->joiningClientList);
    self->isInited = true;
}

/* static class method */
static struct P2pEntity g_entity = {
    .isInited = false,
    .currentTimerId = TIMER_ID_INVALID,
    .listener = NULL,
    .isConnectionChangeReceived = false,
    .isConnectStateChangeReceived = false,
};

struct P2pEntity *GetP2pEntity(void)
{
    if (!g_entity.isInited) {
        P2pEntityConstructor(&g_entity);
    }
    return &g_entity;
}