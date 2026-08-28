/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "far_field_proxy_manager.h"
#include "far_field_proxy_adapter.h"
#include "../proxy_manager.h"
#include "br/br_proxy_manager.h"
#include "softbus_rc_object.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_conn_async_helper.h"
#include "message_handler.h"
#include "softbus_conn_common.h"

#define FAR_FIELD_CONNECT_TIMEOUT_MS 9000
#define SOFTBUS_CONN_ERR_BASE_OFFSET 700

#ifndef SOFTBUS_CONN_TIMEOUT
#define SOFTBUS_CONN_TIMEOUT (SOFTBUS_CONNECTION_ERR_CLOSED + SOFTBUS_CONN_ERR_BASE_OFFSET)
#endif
#ifndef SOFTBUS_CONN_DISCONNECT
#define SOFTBUS_CONN_DISCONNECT (SOFTBUS_CONNECTION_ERR_CLOSED + SOFTBUS_CONN_ERR_BASE_OFFSET + 1)
#endif
#ifndef SOFTBUS_CONN_NOT_CONNECTED
#define SOFTBUS_CONN_NOT_CONNECTED (SOFTBUS_CONNECTION_ERR_CLOSED + SOFTBUS_CONN_ERR_BASE_OFFSET + 2)
#endif

typedef enum {
    STATE_EVENT_INVALID = -1,
    STATE_EVENT_DIRECTLY_CONNECT,
    STATE_EVENT_REMOTE_CONNECT,
    STATE_EVENT_P2P_CONNECTED,
    STATE_EVENT_P2P_DISCONNECTED,
    STATE_EVENT_REMOTE_DISCONNECT,
    STATE_EVENT_TIMEOUT,
    STATE_EVENT_REFRESH,
} StateEvent;

typedef struct {
    char brMac[BT_MAC_LEN];
    char uuid[UUID_STRING_LEN];
    StateEvent event;
    int32_t reason;
    uint32_t requestId;
} StateMachineEvent;

typedef struct {
    SOFT_BUS_RC_OBJECT_BASE;
    P2PDeviceInfo device;
    char srcMac[BT_MAC_MAX_LEN];
    FarFieldProxyState state;
    struct ProxyChannel channel;
    uint32_t channelId;
    int32_t timeoutCallId;
} FarFieldDeviceConnection;

typedef struct {
    FarFieldProxyListener listener;
    SoftBusRcCollection connectionList;
    ConnAsync async;
} FarFieldProxyManagerContext;

static FarFieldProxyManagerContext g_farFieldManager = {
    .listener = {0},
};

static OpenProxyChannelCallback g_refreshCallback = {0};

typedef struct {
    char brMac[BT_MAC_LEN];
    char uuid[UUID_STRING_LEN];
    char srcMac[BT_MAC_MAX_LEN];
    uint32_t requestId;
} OpenFarFieldContext;

static void FarFieldConnectTimeoutTask(int32_t callId, void *arg);
static void StateMachineEventHandler(int32_t callId, void *arg);
static int32_t FarFieldProxySend(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
static void FarFieldProxyClose(struct ProxyChannel *channel, bool isClearReconnectEvent);
static void FarFieldProxyRefresh(struct ProxyChannel *channel, uint32_t newRequestId,
    const OpenProxyChannelCallback *callback);
static int32_t ConstructProxyChannel(FarFieldDeviceConnection *conn, uint32_t requestId);
static void CleanupConnectionResources(FarFieldDeviceConnection *conn);
static void CancelConnectionTimeout(FarFieldDeviceConnection *conn);
static int32_t SetupConnectionTimeout(FarFieldDeviceConnection *conn);
static FarFieldProxyState GetConnectionState(FarFieldDeviceConnection *conn);
static void SetConnectionState(FarFieldDeviceConnection *conn, FarFieldProxyState state);
static int32_t StateMachineProcess(FarFieldDeviceConnection *conn, StateEvent event, int32_t reason);
static bool FarFieldBrMacMatcher(const SoftBusRcObject *object, const void *arg);

typedef struct {
    FarFieldProxyState currentState;
    StateEvent event;
    FarFieldProxyState nextState;
    const char *name;
} StateTransition;

typedef struct {
    int32_t (*onEnter)(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason);
    int32_t (*onExit)(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason);
    const char *name;
} StateHandler;

static int32_t ConnectingOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason);
static int32_t ConnectingOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason);

static int32_t ConnectedOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason);
static int32_t ConnectedOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason);

static int32_t RefreshingOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason);
static int32_t RefreshingOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason);

static int32_t DisconnectedOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason);
static int32_t DisconnectedOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason);

static void NotifyDisconnected(FarFieldDeviceConnection *conn, int32_t reason)
{
    CONN_LOGI(CONN_PROXY, "far field proxy channel disconnected, reqId=%{public}u, channelId=%{public}u",
        conn->channel.requestId, conn->channelId);
    if (
        g_farFieldManager.listener.onFarFieldProxyDisconnected != NULL) {
        g_farFieldManager.listener.onFarFieldProxyDisconnected(&conn->channel, reason);
    }
}

static void NotifyFarFieldConnected(FarFieldDeviceConnection *conn)
{
    CONN_LOGI(CONN_PROXY, "proxy channel opened successfully, reqId=%{public}u, channelId=%{public}u",
        conn->channel.requestId, conn->channelId);
    if (g_farFieldManager.listener.onFarFieldConnected != NULL) {
        g_farFieldManager.listener.onFarFieldConnected(conn->channel.requestId, &conn->channel);
    }
}

static void NotifyOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    CONN_LOGI(CONN_PROXY, "far field proxy channel open failed, reqId=%{public}u, err=%{public}d",
        requestId, reason);
    if (g_farFieldManager.listener.onFarFieldOpenFail != NULL) {
        g_farFieldManager.listener.onFarFieldOpenFail(requestId, reason, brMac);
    }
}

static const StateHandler *GetStateHandler(FarFieldProxyState state)
{
    static const StateHandler handlers[] = {
        [P2P_AVAILABLE_STATE] = {
            .onEnter = NULL,
            .onExit = NULL,
            .name = "available"
        },
        [P2P_CONNECTING] = {
            .onEnter = ConnectingOnEnter,
            .onExit = ConnectingOnExit,
            .name = "Connecting"
        },
        [P2P_RECONNECTING] = {
            .onEnter = ConnectingOnEnter,
            .onExit = ConnectingOnExit,
            .name = "Reconnecting"
        },
        [P2P_CONNECTED] = {
            .onEnter = ConnectedOnEnter,
            .onExit = ConnectedOnExit,
            .name = "Connected"
        },
        [P2P_REFRESHING] = {
            .onEnter = RefreshingOnEnter,
            .onExit = RefreshingOnExit,
            .name = "Refreshing"
        },
        [P2P_DISCONNECTED] = {
            .onEnter = DisconnectedOnEnter,
            .onExit = DisconnectedOnExit,
            .name = "Disconnected"
        },
    };

    if (state >= 0 && state < (FarFieldProxyState)(sizeof(handlers)/sizeof(handlers[0]))) {
        return &handlers[state];
    }
    return NULL;
}

static const StateTransition *FindTransition(FarFieldProxyState currentState, StateEvent event)
{
    static const StateTransition transitions[] = {
        {P2P_AVAILABLE_STATE,      STATE_EVENT_DIRECTLY_CONNECT, P2P_CONNECTING, "available->Connecting"},
        {P2P_CONNECTING,          STATE_EVENT_P2P_CONNECTED,    P2P_CONNECTED,        "Connecting->Connected"},
        {P2P_CONNECTING,          STATE_EVENT_P2P_DISCONNECTED, P2P_DISCONNECTED,      "Connecting->Disconnected"},
        {P2P_CONNECTING,          STATE_EVENT_TIMEOUT,         P2P_DISCONNECTED,      "Connecting->Disconnected"},
        {P2P_CONNECTED,           STATE_EVENT_P2P_DISCONNECTED, P2P_DISCONNECTED, "Connected->Disconnected"},
        {P2P_CONNECTED,           STATE_EVENT_REFRESH,          P2P_REFRESHING,       "Connected->Refreshing"},
        {P2P_REFRESHING,          STATE_EVENT_P2P_CONNECTED,   P2P_CONNECTED,        "Refreshing->Connected"},
        {P2P_REFRESHING,          STATE_EVENT_TIMEOUT,           P2P_DISCONNECTED, "Refreshing->RefreshingTimeout"},
        {P2P_DISCONNECTED,        STATE_EVENT_P2P_CONNECTED,     P2P_CONNECTED,     "Disconnected->Connected"},
        {P2P_DISCONNECTED,        STATE_EVENT_DIRECTLY_CONNECT, P2P_CONNECTING, "Disconnected->Connecting"},
    };

    for (size_t i = 0; i < sizeof(transitions)/sizeof(transitions[0]); i++) {
        if (transitions[i].currentState == currentState && transitions[i].event == event) {
            return &transitions[i];
        }
    }
    return NULL;
}

static int32_t ExecuteStateTransition(FarFieldDeviceConnection *conn, FarFieldProxyState fromState,
    FarFieldProxyState toState, StateEvent event, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);

    CONN_LOGI(CONN_PROXY, "State transition: %{public}s (%{public}d) -> %{public}s (%{public}d), event=%{public}d,"
        "addr=%{public}s", GetStateHandler(fromState)->name, fromState,
        GetStateHandler(toState)->name, toState, event, anonymizeAddr);

    const StateHandler *currentHandler = GetStateHandler(fromState);
    if (currentHandler != NULL && currentHandler->onExit != NULL) {
        int32_t ret = currentHandler->onExit(conn, toState, reason);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_PROXY, "State exit handler failed, ret=%{public}d", ret);
            return ret;
        }
    }

    SetConnectionState(conn, toState);

    const StateHandler *newHandler = GetStateHandler(toState);
    if (newHandler != NULL && newHandler->onEnter != NULL) {
        int32_t ret = newHandler->onEnter(conn, fromState, reason);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_PROXY, "State enter handler failed, ret=%{public}d", ret);
            return ret;
        }
    }

    return SOFTBUS_OK;
}

static void StateMachineEventHandler(int32_t callId, void *arg)
{
    (void)callId;
    StateMachineEvent *event = (StateMachineEvent *)arg;
    CONN_CHECK_AND_RETURN_LOGE(event != NULL, CONN_PROXY, "event is NULL");

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, event->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "StateMachine event: type=%{public}d, reason=%{public}d, addr=%{public}s",
              event->event, event->reason, anonymizeAddr);
    StateEvent eventType = event->event;
    int32_t eventReason = event->reason;
    uint32_t eventRequestId = event->requestId;

    P2PDeviceInfo device = {0};
    if (memcpy_s(device.brMac, sizeof(device.brMac), event->brMac, sizeof(event->brMac)) != EOK ||
        memcpy_s(device.uuid, sizeof(device.uuid), event->uuid, sizeof(event->uuid)) != EOK) {
        CONN_LOGE(CONN_PROXY, "Failed to copy device info");
        SoftBusFree(event);
        return;
    }

    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, &device);

    SoftBusFree(event);

    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY, "Connection not found");

    if (eventType == STATE_EVENT_REFRESH) {
        // refresh the lastest requestid to br proxy channel
        GetBrProxyChannelManager()->updateDevInfoReqIdUnsafe(device.brMac, eventRequestId);
        conn->channel.requestId = eventRequestId;
    }

    char anonymizeAddr2[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr2, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Processing state machine: conn=%{public}s, event=%{public}d, reason=%{public}d",
              anonymizeAddr2, eventType, eventReason);

    StateMachineProcess(conn, eventType, eventReason);

    conn->Dereference((SoftBusRcObject **)&conn);
}

static int32_t SubmitStateMachineEvent(const P2PDeviceInfo *device, StateEvent event, int32_t reason,
    uint32_t requestId)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(device != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "device is NULL");

    StateMachineEvent *eventData = (StateMachineEvent *)SoftBusCalloc(sizeof(StateMachineEvent));
    CONN_CHECK_AND_RETURN_RET_LOGE(eventData != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "Failed to allocate event data");
    if (memcpy_s(eventData->brMac, sizeof(eventData->brMac), device->brMac, sizeof(device->brMac)) != EOK ||
        memcpy_s(eventData->uuid, sizeof(eventData->uuid), device->uuid, sizeof(device->uuid)) != EOK) {
        CONN_LOGE(CONN_PROXY, "Failed to copy device info to event data");
        SoftBusFree(eventData);
        return SOFTBUS_MEM_ERR;
    }
    eventData->event = event;
    eventData->reason = reason;
    eventData->requestId = requestId;

    int32_t ret = ConnAsyncCall(&g_farFieldManager.async, StateMachineEventHandler, eventData, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "Failed to submit state machine event, ret=%{public}d", ret);
        SoftBusFree(eventData);
        return ret;
    }

    CONN_LOGI(CONN_PROXY, "State machine event submitted: event=%{public}d, reason=%{public}d", event, reason);
    return SOFTBUS_OK;
}

static int32_t StateMachineProcess(FarFieldDeviceConnection *conn, StateEvent event, int32_t reason)
{
    FarFieldProxyState currentState = GetConnectionState(conn);
    const StateHandler *handler = GetStateHandler(currentState);

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);

    const StateTransition *trans = FindTransition(currentState, event);
    if (trans == NULL) {
        CONN_LOGW(CONN_PROXY, "No valid transition: state=%{public}s (%{public}d), event=%{public}d, addr=%{public}s",
                  handler ? handler->name : "Unknown", currentState, event, anonymizeAddr);
        return SOFTBUS_ERR;
    }

    return ExecuteStateTransition(conn, currentState, trans->nextState, event, reason);
}

static int32_t ConnectingOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Entering Connecting state (from=%{public}s), addr=%{public}s",
              GetStateHandler(prevState)->name, anonymizeAddr);

    int32_t ret = FarFieldAdapterOpenP2P(&conn->device);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to open P2P, ret=%{public}d", ret);
        SetConnectionState(conn, P2P_DISCONNECTED);
    }

    if (ret == SOFTBUS_OK) {
        ret = SetupConnectionTimeout(conn);
        if (ret != SOFTBUS_OK) {
            CONN_LOGW(CONN_PROXY, "Failed to setup connection timeout, ret=%{public}d", ret);
        }
    }
    return ret;
}

static int32_t ConnectingOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Exiting Connecting state, nextState=%{public}s, addr=%{public}s",
              GetStateHandler(nextState)->name, anonymizeAddr);

    CancelConnectionTimeout(conn);
    return SOFTBUS_OK;
}

static int32_t ConnectedOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Entering Connected state (from=%{public}s), addr=%{public}s",
              GetStateHandler(prevState)->name, anonymizeAddr);

    if (prevState == P2P_REFRESHING && g_refreshCallback.onOpenSuccess != NULL) {
        g_refreshCallback.onOpenSuccess(conn->channel.requestId, &conn->channel);
    } else {
        NotifyFarFieldConnected(conn);
    }
    return SOFTBUS_OK;
}


static int32_t ConnectedOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Exiting Connected state, nextState=%{public}s, addr=%{public}s",
              GetStateHandler(nextState)->name, anonymizeAddr);

    if (nextState == P2P_DISCONNECTED) {
        NotifyDisconnected(conn, SOFTBUS_CONN_DISCONNECT);
        SetConnectionState(conn, P2P_DISCONNECTED);
    }
    if (nextState == P2P_REFRESHING) {
        NotifyDisconnected(conn, SOFTBUS_CONN_DISCONNECT);
    }

    return SOFTBUS_OK;
}

static int32_t RefreshingOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Entering Refreshing state, addr=%{public}s", anonymizeAddr);

    int32_t ret = FarFieldAdapterRefresh(&conn->device);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to refresh, ret=%{public}d", ret);
        SetConnectionState(conn, P2P_CONNECTED);
        return ret;
    }

    SetupConnectionTimeout(conn);
    return SOFTBUS_OK;
}

static int32_t RefreshingOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Exiting Refreshing state, nextState=%{public}s, addr=%{public}s",
              GetStateHandler(nextState)->name, anonymizeAddr);
    CancelConnectionTimeout(conn);
    return SOFTBUS_OK;
}

static int32_t DisconnectedOnEnter(FarFieldDeviceConnection *conn, FarFieldProxyState prevState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "from state=%{public}s, addr=%{public}s, reason=%{public}d",
              GetStateHandler(prevState)->name, anonymizeAddr, reason);
    if (prevState == P2P_CONNECTING || prevState == P2P_REFRESHING) {
        NotifyOpenFail(conn->channel.requestId, reason, conn->device.brMac);
    }
    return SOFTBUS_OK;
}

static int32_t DisconnectedOnExit(FarFieldDeviceConnection *conn, FarFieldProxyState nextState, int32_t reason)
{
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "exit Disconnected state (to=%{public}s), addr=%{public}s, reqId=%{public}u",
              GetStateHandler(nextState)->name, anonymizeAddr, conn->channel.requestId);
    return SOFTBUS_OK;
}

static void FreeDeviceConnection(FarFieldDeviceConnection *conn)
{
    SoftBusRcObjectDestruct((SoftBusRcObject *)conn);
    SoftBusFree(conn);
}

static void FarFieldDeviceConnectionFreeHook(SoftBusRcObject *object)
{
    FreeDeviceConnection((FarFieldDeviceConnection *)object);
}

static bool FarFieldBrMacMatcher(const SoftBusRcObject *object, const void *arg)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(arg != NULL && object != NULL, false, CONN_PROXY, "param is NULL");
    const char *brMac = (const char *)arg;
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)object;
    return StrCmpIgnoreCase(conn->device.brMac, brMac) == 0 ||
        StrCmpIgnoreCase(conn->srcMac, brMac) == 0;
}

static bool FarFieldConnectionMatcherById(const SoftBusRcObject *object, const void *arg)
{
    uint32_t channelId = *(const uint32_t *)arg;
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)object;
    return conn->channelId == channelId;
}

static void SetConnectionState(FarFieldDeviceConnection *conn, FarFieldProxyState state)
{
    int32_t ret = conn->Lock((SoftBusRcObject *)conn);
    if (ret != SOFTBUS_OK) {
        return;
    }
    conn->state = state;
    conn->Unlock((SoftBusRcObject *)conn);
    return;
}

static FarFieldProxyState GetConnectionState(FarFieldDeviceConnection *conn)
{
    FarFieldProxyState state = FAR_FIELD_STATE_INVALID;
    int32_t ret = conn->Lock((SoftBusRcObject *)conn);
    if (ret != SOFTBUS_OK) {
        return state;
    }
    state = conn->state;
    conn->Unlock((SoftBusRcObject *)conn);
    return state;
}

static void CancelConnectionTimeout(FarFieldDeviceConnection *conn)
{
    if (conn == NULL || conn->timeoutCallId < 0) {
        return;
    }
    ConnAsyncCancel(&g_farFieldManager.async, conn->timeoutCallId, NULL);
    conn->timeoutCallId = 0;
}

static FarFieldDeviceConnection *CreateAndSaveConnection(OpenFarFieldContext *ctx)
{
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, ctx->brMac);
    if (conn != NULL) {
        conn->channel.requestId = ctx->requestId;
        return conn;
    }
    conn = (FarFieldDeviceConnection *)SoftBusCalloc(sizeof(FarFieldDeviceConnection));
    CONN_CHECK_AND_RETURN_RET_LOGE(conn != NULL, NULL, CONN_PROXY, "Failed to allocate device connection");

    int32_t ret = SoftBusRcObjectConstruct("far_field_connection", (SoftBusRcObject *)conn,
        FarFieldDeviceConnectionFreeHook);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to construct RC object, ret=%{public}d", ret);
        SoftBusFree(conn);
        return NULL;
    }

    if (strcpy_s(conn->device.brMac, sizeof(conn->device.brMac), ctx->brMac) != EOK ||
        strcpy_s(conn->device.uuid, sizeof(conn->device.uuid), ctx->uuid) != EOK ||
        strcpy_s(conn->srcMac, sizeof(conn->srcMac), ctx->srcMac) != EOK) {
        FreeDeviceConnection(conn);
        return NULL;
    }
    conn->channelId = GetProxyChannelManager()->generateChannelId();
    conn->timeoutCallId = 0;
    conn->state = P2P_AVAILABLE_STATE;
    ret = ConstructProxyChannel(conn, ctx->requestId);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "construct proxy channel, err=%{public}d", ret);
        FreeDeviceConnection(conn);
        return NULL;
    }
    ret = SoftBusRcSave(&g_farFieldManager.connectionList, (SoftBusRcObject *)conn);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to save connection to list, ret=%{public}d", ret);
        FreeDeviceConnection(conn);
        return NULL;
    }

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Device connection created for %{public}s", anonymizeAddr);
    ret = FarFieldAdapterInit();
    if (ret != SOFTBUS_OK && ret != FAR_FIELD_ADAPTER_ALREADY_INITIALIZED) {
        CONN_LOGE(CONN_PROXY, "Failed to init adapter, ret=%{public}d", ret);
        FreeDeviceConnection(conn);
        return NULL;
    }
    return conn;
}

static int32_t ConstructProxyChannel(FarFieldDeviceConnection *conn, uint32_t requestId)
{
    conn->channel.channelId = conn->channelId;
    conn->channel.requestId = requestId;

    if (strcpy_s(conn->channel.brMac, BT_MAC_MAX_LEN, conn->srcMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "Failed to copy brMac");
        return SOFTBUS_MEM_ERR;
    }

    if (strcpy_s(conn->channel.uuid, UUID_STRING_LEN, conn->device.uuid) != EOK) {
        CONN_LOGE(CONN_PROXY, "Failed to copy uuid");
        return SOFTBUS_MEM_ERR;
    }
    conn->channel.send = FarFieldProxySend;
    conn->channel.close = FarFieldProxyClose;
    conn->channel.refresh = FarFieldProxyRefresh;
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "ProxyChannel initialized for %{public}s, channelId=%{public}u",
        anonymizeAddr, conn->channelId);
    return SOFTBUS_OK;
}

static void CleanupConnectionResources(FarFieldDeviceConnection *conn)
{
    FarFieldAdapterDeinit();
    SoftBusRcRemove(&g_farFieldManager.connectionList, (SoftBusRcObject *)conn);
}

static int32_t FarFieldProxySend(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(channel != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "channel is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "data is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(dataLen > 0, SOFTBUS_INVALID_PARAM, CONN_PROXY, "dataLen is 0");
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldConnectionMatcherById, &channel->channelId);
    CONN_CHECK_AND_RETURN_RET_LOGE(conn != NULL, SOFTBUS_NOT_FIND, CONN_PROXY,
        "Connection not found, channelId=%{public}u", channel->channelId);
    FarFieldProxyState state = GetConnectionState(conn);
    if (state != P2P_CONNECTED) {
        CONN_LOGW(CONN_PROXY, "Connection not connected, state=%{public}d", conn->state);
        conn->Dereference((SoftBusRcObject **)&conn);
        return SOFTBUS_CONN_NOT_CONNECTED;
    }
    int32_t ret = FarFieldAdapterSendMsg(&conn->device, data, dataLen);
    conn->Dereference((SoftBusRcObject **)&conn);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY,
        "Failed to send message, ret=%{public}d", ret);

    CONN_LOGI(CONN_PROXY, "Far field data sent successfully, len=%{public}u", dataLen);
    return SOFTBUS_OK;
}

static void FarFieldProxyRefresh(struct ProxyChannel *channel, uint32_t newRequestId,
    const OpenProxyChannelCallback *callback)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is NULL");
    CONN_CHECK_AND_RETURN_LOGE(callback != NULL, CONN_PROXY, "callback is NULL");
    g_refreshCallback = *callback;
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldConnectionMatcherById, &channel->channelId);
    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY,
        "Connection not found, channelId=%{public}u", channel->channelId);
    CONN_LOGI(CONN_PROXY, "channelId=%{public}u, newRequestId=%{public}u", channel->channelId, newRequestId);
    SubmitStateMachineEvent(&conn->device, STATE_EVENT_REFRESH, 0, newRequestId);
    conn->Dereference((SoftBusRcObject **)&conn);
}

static void FarFieldProxyClose(struct ProxyChannel *channel, bool isClearReconnectEvent)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is NULL");

    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldConnectionMatcherById, &channel->channelId);
    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY,
        "Connection not found, channelId=%{public}u", channel->channelId);
    SetConnectionState(conn, P2P_DISCONNECTED);

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Closing far field channel for %{public}s", anonymizeAddr);

    int32_t ret = FarFieldAdapterCloseP2P(&conn->device);
    if (ret != SOFTBUS_OK) {
        CONN_LOGW(CONN_PROXY, "Failed to close P2P, ret=%{public}d", ret);
    }
    if (isClearReconnectEvent) {
        GetBrProxyChannelManager()->clearDevInfoUnsafe(&conn->channel);
    }

    CleanupConnectionResources(conn);
    conn->Dereference((SoftBusRcObject **)&conn);
}

static StateEvent ConvertP2PStateToEvent(P2PState state)
{
    switch (state) {
        case P2P_STATE_CONNECT:
            return STATE_EVENT_P2P_CONNECTED;
        case P2P_STATE_DISCONNECT:
            return STATE_EVENT_P2P_DISCONNECTED;
        default:
            CONN_LOGW(CONN_PROXY, "Unhandled P2P state: %{public}d", state);
            return STATE_EVENT_INVALID;
    }
}

static StateEvent ConvertRemoteEventToEvent(RemoteEvent event)
{
    switch (event) {
        case REQ_CONNECT_P2P:
            return STATE_EVENT_REMOTE_CONNECT;
        case REQ_DISCONNECT_P2P:
            return STATE_EVENT_REMOTE_DISCONNECT;
        default:
            CONN_LOGW(CONN_PROXY, "Unhandled remote event: %{public}d", event);
            return STATE_EVENT_INVALID;
    }
}

static void OnP2PStateChanged(const P2PDeviceInfo *device, P2PState state, int32_t reason)
{
    CONN_CHECK_AND_RETURN_LOGE(device != NULL, CONN_PROXY, "device is NULL");

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, device->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "P2P state changed: addr=%{public}s, state=%{public}d, reason=%{public}d",
              anonymizeAddr, state, reason);
    StateEvent event = ConvertP2PStateToEvent(state);
    CONN_CHECK_AND_RETURN_LOGE(event != STATE_EVENT_INVALID, CONN_PROXY, "ignore state");

    SubmitStateMachineEvent(device, event, reason, 0);
}

static void OnRemoteEvent(const P2PDeviceInfo *device, RemoteEvent event)
{
    CONN_CHECK_AND_RETURN_LOGE(device != NULL, CONN_PROXY, "device is NULL");

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, device->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Remote event for %{public}s: %{public}d", anonymizeAddr, event);

    StateEvent stateEvent = ConvertRemoteEventToEvent(event);
    CONN_CHECK_AND_RETURN_LOGE(stateEvent != STATE_EVENT_INVALID, CONN_PROXY, "ignore state");

    SubmitStateMachineEvent(device, stateEvent, 0, 0);
}

static void OnRecvP2PMsg(const P2PDeviceInfo *device, const uint8_t *msgBody, uint32_t len)
{
    CONN_CHECK_AND_RETURN_LOGE(device != NULL, CONN_PROXY, "device is NULL");
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, device->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Received P2P message from %{public}s, len=%{public}u", anonymizeAddr, len);
    CONN_CHECK_AND_RETURN_LOGE(msgBody != NULL && len > 0, CONN_PROXY, "Invalid params");

    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, device);

    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY, "Connection not found, addr=%{public}s", anonymizeAddr);
    FarFieldProxyState curState = GetConnectionState(conn);
    if (curState != P2P_CONNECTED) {
        CONN_LOGW(CONN_PROXY, "unexpected state=%{public}d", curState);
    }

    if (g_farFieldManager.listener.onFarFieldProxyDataReceived != NULL) {
        g_farFieldManager.listener.onFarFieldProxyDataReceived(&conn->channel,
            (const uint8_t *)msgBody, len);
    }
    conn->Dereference((SoftBusRcObject **)&conn);
}

static FarFieldCallbackSt g_farFieldCallback = {
    .p2pStateCallback = OnP2PStateChanged,
    .remoteEventCallback = OnRemoteEvent,
    .recvP2PMsgCallback = OnRecvP2PMsg,
};

static int32_t SetupConnectionTimeout(FarFieldDeviceConnection *conn)
{
    char *timeoutArg = (char *)SoftBusCalloc(BT_MAC_LEN);
    if (timeoutArg == NULL) {
        CONN_LOGE(CONN_PROXY, "Failed to allocate timeout arg");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = strcpy_s(timeoutArg, BT_MAC_LEN, conn->device.brMac);
    if (ret != EOK) {
        CONN_LOGE(CONN_PROXY, "Failed to copy brMac to timeout arg, ret=%{public}d", ret);
        SoftBusFree(timeoutArg);
        return SOFTBUS_STRCPY_ERR;
    }

    ret = ConnAsyncCall(&g_farFieldManager.async, FarFieldConnectTimeoutTask, timeoutArg,
                        FAR_FIELD_CONNECT_TIMEOUT_MS);
    if (ret < 0) {
        CONN_LOGW(CONN_PROXY, "Failed to schedule timeout, ret=%{public}d", ret);
        SoftBusFree(timeoutArg);
        return ret;
    }
    conn->timeoutCallId = ret;
    return SOFTBUS_OK;
}

static bool AttemptReuseConnection(OpenFarFieldContext *ctx)
{
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, ctx->brMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(conn != NULL, false, CONN_PROXY, "not exist same conn");
    FarFieldProxyState state = GetConnectionState(conn);
    if (state == P2P_CONNECTED) {
        conn->channel.requestId = ctx->requestId;
        NotifyFarFieldConnected(conn);
        return true;
    }
    if (state == P2P_CONNECTING) {
        CONN_LOGE(CONN_PROXY, "state=%{public}d, wait reqId=%{public}u", state, conn->channel.requestId);
        conn->channel.requestId = ctx->requestId;
        return true;
    }

    if (state == P2P_REFRESHING) {
        conn->channel.requestId = ctx->requestId;
        CONN_LOGE(CONN_PROXY, "state=%{public}d transfer connecting, reqId=%{public}u", state, conn->channel.requestId);
        SetConnectionState(conn, P2P_CONNECTING);
        return true;
    }
    return false;
}

static void OpenFarFieldChannelTask(int32_t callId, void *arg)
{
    (void)callId;
    OpenFarFieldContext *ctx = (OpenFarFieldContext *)arg;
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "ctx is null");
    GetBrProxyChannelManager()->updateDevInfoReqIdUnsafe(ctx->brMac, ctx->requestId);

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, ctx->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Opening far field channel for %{public}s, reqId=%{public}u",
        anonymizeAddr, ctx->requestId);
    if (AttemptReuseConnection(ctx)) {
        SoftBusFree(ctx);
        return;
    }
    FarFieldDeviceConnection *conn = CreateAndSaveConnection(ctx);
    if (conn == NULL) {
        CONN_LOGE(CONN_PROXY, "Failed to create connection");
        NotifyOpenFail(ctx->requestId, SOFTBUS_MALLOC_ERR, ctx->brMac);
        SoftBusFree(ctx);
        return;
    }
    SoftBusFree(ctx);
    int32_t ret = StateMachineProcess(conn, STATE_EVENT_DIRECTLY_CONNECT, 0);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "start open farField channel err=%{public}d", ret);
        NotifyOpenFail(conn->channel.requestId, ret, conn->device.brMac);
        conn->Dereference((SoftBusRcObject **)&conn);
        return;
    }
    conn->Dereference((SoftBusRcObject **)&conn);
}

static void FarFieldConnectTimeoutTask(int32_t callId, void *arg)
{
    (void)callId;
    char *brMac = (char *)arg;
    CONN_CHECK_AND_RETURN_LOGE(brMac != NULL, CONN_PROXY, "ctx is null");
    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, brMac, BT_MAC_LEN);
    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, brMac);
    SoftBusFree(brMac);
    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY, "Connection not found for timeout");
    CONN_LOGW(CONN_PROXY, "connect timeout for %{public}s, channelId=%{public}u", anonymizeAddr, conn->channelId);

    StateMachineProcess(conn, STATE_EVENT_TIMEOUT, SOFTBUS_CONN_TIMEOUT);
    conn->Dereference((SoftBusRcObject **)&conn);
}

void ClearFarFieldProxy(const char *addr)
{
    CONN_CHECK_AND_RETURN_LOGE(addr != NULL, CONN_PROXY, "addr is NULL");

    FarFieldDeviceConnection *conn = (FarFieldDeviceConnection *)SoftBusRcGetCommon(
        &g_farFieldManager.connectionList, FarFieldBrMacMatcher, addr);
    CONN_CHECK_AND_RETURN_LOGE(conn != NULL, CONN_PROXY,
        "Connection not found, addr=%{public}s", addr);

    char anonymizeAddr[BT_MAC_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, conn->device.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "Closing far field channel for %{public}s", anonymizeAddr);
    if (GetConnectionState(conn) == P2P_CONNECTED) {
        int32_t ret = FarFieldAdapterCloseP2P(&conn->device);
        if (ret != SOFTBUS_OK) {
            CONN_LOGW(CONN_PROXY, "Failed to close P2P, ret=%{public}d", ret);
        }
    }

    CleanupConnectionResources(conn);
    conn->Dereference((SoftBusRcObject **)&conn);
}

int32_t RegisterFarFieldProxyListener(FarFieldProxyListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "Listener is NULL");

    g_farFieldManager.listener = *listener;

    CONN_LOGI(CONN_PROXY, "Far field proxy listener registered");
    return SOFTBUS_OK;
}

int32_t OpenFarFieldProxyChannel(FarFieldProxyParam *param)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(param != NULL,
        SOFTBUS_INVALID_PARAM, CONN_PROXY, "Invalid params param is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(param->device.brMac[0] != '\0' && param->device.uuid[0] != '\0',
        SOFTBUS_INVALID_PARAM, CONN_PROXY, "brMac or uuid is null");
    char anonymizeAddr[BT_MAC_LEN] = {0};
    char anonymizeUuid[UUID_STRING_LEN] = {0};
    ConvertAnonymizeMacAddress(anonymizeAddr, BT_MAC_LEN, param->device.brMac, BT_MAC_LEN);
    ConvertAnonymizeSensitiveString(anonymizeUuid, UUID_STRING_LEN, param->device.uuid);

    CONN_LOGI(CONN_PROXY, "Opening far field channel, reqId=%{public}d, brMac=%{public}s, uuid=%{public}s",
        param->requestId, anonymizeAddr, anonymizeUuid);

    OpenFarFieldContext *ctx = (OpenFarFieldContext *)SoftBusCalloc(sizeof(OpenFarFieldContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "Failed to allocate context");

    if (strcpy_s(ctx->brMac, sizeof(ctx->brMac), param->device.brMac) != EOK ||
        strcpy_s(ctx->uuid, sizeof(ctx->uuid), param->device.uuid) != EOK ||
        strcpy_s(ctx->srcMac, sizeof(ctx->srcMac), param->srcMac) != EOK) {
        SoftBusFree(ctx);
        return SOFTBUS_MEM_ERR;
    }
    ctx->requestId = param->requestId;
    int32_t ret = ConnAsyncCall(&g_farFieldManager.async, OpenFarFieldChannelTask, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "Failed to call async, ret=%{public}d", ret);
        SoftBusFree(ctx);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t FarFieldProxyManagerInit(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_CONN);
    CONN_CHECK_AND_RETURN_RET_LOGE(looper != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY,
        "Failed to get looper");

    int32_t ret = ConnAsyncConstruct("far_field_async", &g_farFieldManager.async, looper);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to construct async, ret=%{public}d", ret);
        return ret;
    }

    ret = SoftBusRcCollectionConstruct("far_field_conn", &g_farFieldManager.connectionList, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to construct RC collection, ret=%{public}d", ret);
        ConnAsyncDestruct(&g_farFieldManager.async);
        return ret;
    }
    ret = FarFieldAdapterManagerInit(&g_farFieldCallback);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "Failed to init adapter manager, ret=%{public}d", ret);
        ConnAsyncDestruct(&g_farFieldManager.async);
        SoftBusRcCollectionDestruct(&g_farFieldManager.connectionList);
        return ret;
    }

    CONN_LOGI(CONN_PROXY, "Far field proxy manager initialized");
    return ret;
}

void FarFieldProxyManagerDeinit(void)
{
    FarFieldAdapterManagerDeinit();
    SoftBusRcCollectionDestruct(&g_farFieldManager.connectionList);
    ConnAsyncDestruct(&g_farFieldManager.async);

    CONN_LOGI(CONN_PROXY, "Far field proxy manager deinitialized");
}