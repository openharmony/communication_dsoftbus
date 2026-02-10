/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "proxy_manager.h"

#include "securec.h"

#include "conn_log.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"

#include "proxy_config.h"
#include "proxy_connection.h"
#include "proxy_observer.h"

#define INNER_RECONNECT_TIMEOUT_MS 8000
#define INNER_RECONNECT_RETRY_WAIT_MS 1000
#define RECONNECT_AFTER_DISCONNECT_WAIT_MS 500
#define RECONNECT_AFTER_BT_OPEN_WAIT_MS 500
#define OPEN_PROXY_CHANNEL_WAIT_MS 200
#define ACL_WAIT_HFP_DELAY_MS (10 * 1000)

#define REQUEST_ID_MATCH_ALL 0

typedef struct {
    bool isSuccess;
    uint32_t channelId;
    int32_t status;
} ProxyChannelNotifyContext;

typedef struct {
    char brMac[BT_MAC_LEN];
    int32_t state;
} ProxyChannelAclStateContext;

enum BrProxyLooperMsgType {
    MSG_OPEN_PROXY_CHANNEL = 100,
    MSG_OPEN_PROXY_CHANNEL_TIMEOUT,
    MSG_OPEN_PROXY_CHANNEL_RETRY,
    MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT,
    MSG_CLOSE_PROXY_CHANNEL,
    MSG_CLOSE_PROXY_DISCONNECT,
    MSG_ACL_STATE_CHANGE,
    MSG_PROXY_BT_TURN_OFF,
    MSG_PROXY_BT_TURN_ON,
    MSG_PROXY_UNPAIRED,
};

static void ProxyChannelMsgHandler(SoftBusMessage *msg);
static int ProxyChannelLooperEventFunc(const SoftBusMessage *msg, void *args);

static SoftBusHandlerWrapper g_proxyChannelAsyncHandler = {
    .handler = {
        .name = (char *)"ProxyChannelAsyncHandler",
        .HandleMessage = ProxyChannelMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = ProxyChannelLooperEventFunc,
};

static void DestoryProxyConnectInfo(ProxyConnectInfo **connectInfo);
static void DestoryProxyConnection(struct ProxyConnection *proxyConnection);
static struct ProxyConnection *GetProxyChannelByChannelId(uint32_t channelId);
static void NotifyOpenProxyChannelResult(struct ProxyConnection *channel, bool isSuccess, int32_t status);
static void ProxyChannelConnectResultHandler(ProxyChannelNotifyContext *ctx);
static void AddReconnectDeviceInfoUnsafe(ProxyConnectInfo *connectInfo);
static void RemoveReconnectDeviceInfoByAddrUnsafe(const char *addr);
static ProxyConnectInfo *GetReconnectDeviceInfoByAddrUnsafe(const char *addr);
static void AttemptReconnectDevice(char *brAddr);
static void RemoveProxyChannelByChannelId(uint32_t channelId);
static ProxyConnectInfo *CopyProxyConnectInfo(ProxyConnectInfo *srcInfo);

static ProxyConnectListener g_listener = { 0 };
static SoftBusMutex g_reqIdLock;
static uint32_t g_reqId = 1;

static uint32_t GenerateRequestId(void)
{
    int32_t ret = SoftBusMutexLock(&g_reqIdLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel fail, error=%{public}d", ret);
    if (g_reqId == REQUEST_ID_MATCH_ALL) {
        g_reqId++;
    }
    uint32_t reqId = g_reqId++;
    SoftBusMutexUnlock(&g_reqIdLock);
    return reqId;
}

static ProxyChannelState GetProxyChannelState(struct ProxyConnection *proxyConnection)
{
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    ProxyChannelState state = proxyConnection->state;
    SoftBusMutexUnlock(&proxyConnection->lock);
    return state;
}

static ProxyChannelState SetProxyChannelState(struct ProxyConnection *proxyConnection, ProxyChannelState state)
{
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    proxyConnection->state = state;
    SoftBusMutexUnlock(&proxyConnection->lock);
    return state;
}

static void ProxyChannelDereference(struct ProxyConnection *proxyConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY, "proxyConnection is null");
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    proxyConnection->refCount -= 1;
    bool destruct = (proxyConnection->refCount <= 0);
    SoftBusMutexUnlock(&proxyConnection->lock);
    if (destruct) {
        CONN_LOGW(CONN_PROXY, "destory proxy channel=%{public}u", proxyConnection->channelId);
        DestoryProxyConnection(proxyConnection);
    }
}

static void ProxyChannelReference(struct ProxyConnection *proxyConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY, "proxyConnection is null");
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    proxyConnection->refCount += 1;
    SoftBusMutexUnlock(&proxyConnection->lock);
}

int32_t ProxyChannelSend(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(channel != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "channel is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "data is null");
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channel->channelId);
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, SOFTBUS_NOT_FIND, CONN_PROXY,
        "get proxyConnection fail, channelId=%{public}u", channel->channelId);
    int32_t ret = GetProxyBrConnectionManager()->send(proxyConnection, data, dataLen);
    proxyConnection->dereference(proxyConnection);
    return ret;
}

static void ResetReconnectEvent(uint32_t requestId, const char *brMac)
{
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_RETRY, 0, 0, (void *)brMac);
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL, requestId, 0, NULL);

    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel != NULL && connectingChannel->requestId == requestId &&
        StrCmpIgnoreCase(brMac, connectingChannel->brMac) == 0) {
        CONN_LOGW(CONN_PROXY, "reset connectingChannel, reqId=%{public}u", requestId);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
    }
}

static void ProxyChannelCloseHandler(uint32_t requestId, char *brAddr)
{
    CONN_LOGI(CONN_PROXY, "start handle close channel event");
    ResetReconnectEvent(requestId, brAddr);
    RemoveReconnectDeviceInfoByAddrUnsafe(brAddr);
}

static void AttemptPostChannelCloseEvent(struct ProxyChannel *channel, bool isClearReconnectEvent)
{
    CONN_CHECK_AND_RETURN_LOGI(isClearReconnectEvent, CONN_PROXY, "no need clear reconnect event");
    char *copyAddr = (char *)SoftBusCalloc(BT_MAC_MAX_LEN);
    if (copyAddr == NULL || strcpy_s(copyAddr, BT_MAC_MAX_LEN, channel->brMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr fail");
        SoftBusFree(copyAddr);
        return;
    }
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_CLOSE_PROXY_CHANNEL,
        channel->requestId, 0, copyAddr, 0);
    if (ret < 0) {
        // fall-through
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        SoftBusFree(copyAddr);
    }
}

static void ProxyChannelClose(struct ProxyChannel *channel, bool isClearReconnectEvent)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is null");
    AttemptPostChannelCloseEvent(channel, isClearReconnectEvent);

    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channel->channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection fail, channelId=%{public}u", channel->channelId);
    SetProxyChannelState(proxyConnection, PROXY_CHANNEL_DISCONNECTING);
    int32_t ret = GetProxyBrConnectionManager()->disconnect(proxyConnection);
    CONN_LOGW(CONN_PROXY, "channel=%{public}u, reqId=%{public}u, error=%{public}d, isClear=%{public}d",
        channel->channelId, channel->requestId, ret, isClearReconnectEvent);
    proxyConnection->dereference(proxyConnection);
#define WAIT_CLOSE_END_TIME_MS 1000
    // add 10 ms after close, because of the remote device will refresh service after disconnected
    SoftBusSleepMs(WAIT_CLOSE_END_TIME_MS);
}

static struct ProxyConnection *CreateProxyConnection(ProxyConnectInfo *connectInfo)
{
    struct ProxyConnection *proxyConnection = (struct ProxyConnection *)SoftBusCalloc(sizeof(struct ProxyConnection));
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, NULL, CONN_PROXY, "proxyConnection is NULL");
    proxyConnection->reference = ProxyChannelReference;
    proxyConnection->dereference = ProxyChannelDereference;
    proxyConnection->state = PROXY_CHANNEL_CONNECTING;
    proxyConnection->refCount = 1;
    proxyConnection->socketHandle = BR_INVALID_SOCKET_HANDLE;
    proxyConnection->proxyChannel.send = ProxyChannelSend;
    proxyConnection->proxyChannel.close = ProxyChannelClose;
    proxyConnection->proxyChannel.requestId = connectInfo->requestId;
    int32_t ret = connectInfo->isRealMac ?
        strcpy_s(proxyConnection->proxyChannel.brMac, BT_MAC_MAX_LEN, connectInfo->brMac) :
        strcpy_s(proxyConnection->proxyChannel.brMac, BT_MAC_MAX_LEN, connectInfo->brHashMac);
    if (ret != EOK) {
        CONN_LOGE(CONN_PROXY, "copy br mac fail, error=%{public}d", ret);
        SoftBusFree(proxyConnection);
        return NULL;
    }
    if (strcpy_s(proxyConnection->brMac, BT_MAC_LEN, connectInfo->brMac) != EOK  ||
        strcpy_s(proxyConnection->proxyChannel.uuid, UUID_STRING_LEN, connectInfo->uuid) != EOK) {
        CONN_LOGE(CONN_PROXY, "cpy br mac or uuid err");
        SoftBusFree(proxyConnection);
        return NULL;
    }
    ListInit(&proxyConnection->node);

    if (SoftBusMutexInit(&proxyConnection->lock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock fail");
        SoftBusFree(proxyConnection);
        return NULL;
    }
    return proxyConnection;
}

static uint32_t AllocateConnectionIdUnsafe(void)
{
    static uint16_t nextId = 0;

    uint32_t channelId = (CONNECT_PROXY_CHANNEL << CONNECT_TYPE_SHIFT) + (++nextId);
    struct ProxyConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->proxyConnectionList->list, struct ProxyConnection, node) {
        if (channelId == it->channelId) {
            return 0;
        }
    }
    return channelId;
}

static int32_t SaveProxyConnection(struct ProxyConnection *proxyConnection)
{
#define RETRY_MAX_NUM 100
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "lock proxyConnectionList fail");
        return ret;
    }
    uint32_t channelId = 0;
    int32_t retryNum = 0;
    do {
        channelId = AllocateConnectionIdUnsafe();
        retryNum++;
    } while (channelId == 0 && retryNum < RETRY_MAX_NUM);
    if (channelId == 0) {
        CONN_LOGE(CONN_PROXY, "allocate channelId fail");
        SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
        return SOFTBUS_CONN_PROXY_INTERNAL_ERR;
    }
    proxyConnection->channelId = channelId;
    proxyConnection->proxyChannel.channelId = channelId;
    ListAdd(&GetProxyChannelManager()->proxyConnectionList->list, &proxyConnection->node);
    proxyConnection->reference(proxyConnection);
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
    return SOFTBUS_OK;
}

static void DestoryProxyConnection(struct ProxyConnection *proxyConnection)
{
    SoftBusMutexDestroy(&proxyConnection->lock);
    SoftBusFree(proxyConnection);
}

static void PostEventByAddr(enum BrProxyLooperMsgType msgType, const char *brMac, uint64_t dalayTimeMs)
{
    char *copyAddr = (char *)SoftBusCalloc(BT_MAC_LEN);
    if (copyAddr == NULL || strcpy_s(copyAddr, BT_MAC_LEN, brMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr fail");
        SoftBusFree(copyAddr);
        return;
    }
    char anonymizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anonymizeAddress, BT_MAC_LEN, brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY, "post event=%{public}d, addr=%{public}s, delay=%{public}" PRIu64, msgType, anonymizeAddress,
        dalayTimeMs);
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, msgType, 0, 0, copyAddr, dalayTimeMs);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "post msg err");
        SoftBusFree(copyAddr);
    }
}

static void ProcessConnectFailed(ProxyConnectInfo *connectingChannel, const char *brMac, int32_t reason)
{
    CONN_LOGE(CONN_PROXY, "notify open fail reqId=%{public}u, reason=%{public}d", connectingChannel->requestId, reason);
    connectingChannel->result.onOpenFail(connectingChannel->requestId, reason, brMac);
    DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
}

static void NotifyOpenProxyChannelResult(struct ProxyConnection *proxyConnection, bool isSuccess, int32_t status)
{
    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    uint32_t requestId = connectingChannel->requestId;
    if (isSuccess) {
        CONN_LOGI(CONN_PROXY, "notify open success reqId=%{public}u, channelId=%{public}u",
            requestId, proxyConnection->channelId);
        SetProxyChannelState(proxyConnection, PROXY_CHANNEL_CONNECTED);
        proxyConnection->proxyChannel.requestId = requestId;
        AddReconnectDeviceInfoUnsafe(connectingChannel);
        connectingChannel->result.onOpenSuccess(requestId, &proxyConnection->proxyChannel);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        return;
    }

    ProcessConnectFailed(connectingChannel, proxyConnection->brMac, status);
    RemoveProxyChannelByChannelId(proxyConnection->channelId);
}

static void BrChannelConnectSuccess(uint32_t channelId)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on connect fail, calloc error context fail");
    ctx->channelId = channelId;
    ctx->isSuccess = true;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        SoftBusFree(ctx);
    }
}

static void BrChannelConnectFail(uint32_t channelId, int32_t errorCode)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on connect fail, calloc error context fail");
    ctx->channelId = channelId;
    ctx->status = errorCode;
    ctx->isSuccess = false;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        SoftBusFree(ctx);
    }
}

static void ProxyChannelConnectResultHandler(ProxyChannelNotifyContext *ctx)
{
    uint32_t channelId = ctx->channelId;
    struct ProxyConnection *connection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_PROXY, "channelId=%{public}u not found", channelId);

    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel == NULL || StrCmpIgnoreCase(connection->brMac, connectingChannel->brMac) != 0) {
        CONN_LOGE(CONN_PROXY, "no connecting info channelId=%{public}u", channelId);
        GetProxyBrConnectionManager()->disconnect(connection);
        RemoveProxyChannelByChannelId(channelId);
        connection->dereference(connection);
        return;
    }
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_TIMEOUT, channelId, 0, NULL);
    NotifyOpenProxyChannelResult(connection, ctx->isSuccess, ctx->status);
    connection->dereference(connection);
}

static struct ProxyConnection *GetProxyChannelByAddr(char *addr)
{
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, CONN_PROXY, "lock proxyConnectionList fail");
    struct ProxyConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->proxyConnectionList->list, struct ProxyConnection, node) {
        if (StrCmpIgnoreCase(addr, it->brMac) == 0) {
            it->reference(it);
            SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
            return it;
        }
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
    return NULL;
}

static struct ProxyConnection *GetProxyChannelByChannelId(uint32_t channelId)
{
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, CONN_PROXY, "lock proxyConnectionList fail");
    struct ProxyConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->proxyConnectionList->list, struct ProxyConnection, node) {
        if (it->channelId == channelId) {
            it->reference(it);
            SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
            return it;
        }
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
    return NULL;
}

static void RemoveProxyChannelByChannelId(uint32_t channelId)
{
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "lock proxyConnectionList fail");
    struct ProxyConnection *it = NULL;
    struct ProxyConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &GetProxyChannelManager()->proxyConnectionList->list,
        struct ProxyConnection, node) {
        if (it->channelId == channelId) {
            ListDelete(&it->node);
            CONN_LOGI(CONN_PROXY, "remove channel channelId=%{public}u", it->channelId);
            it->dereference(it);
            break;
        }
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
}

static void HandleConcurrentConnect(ProxyConnectInfo *connectingProxyChannel, const ProxyConnectInfo *connectInfo)
{
    if (StrCmpIgnoreCase(connectInfo->brMac, connectingProxyChannel->brMac) != 0) {
        CONN_LOGW(CONN_PROXY, "not the same device, reject");
        connectInfo->result.onOpenFail(
            connectInfo->requestId, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR, connectInfo->brMac);
        return;
    }

    if (connectInfo->isInnerRequest) {
        connectInfo->result.onOpenFail(
            connectInfo->requestId, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR, connectInfo->brMac);
        return;
    }

    // wait connect finished and reuse
    if (connectingProxyChannel->isInnerRequest) {
        connectingProxyChannel->result.onOpenFail(connectingProxyChannel->requestId,
            SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR, connectingProxyChannel->brMac);
    }
    connectingProxyChannel->result = connectInfo->result;
    connectingProxyChannel->requestId = connectInfo->requestId;
    connectingProxyChannel->isInnerRequest = connectInfo->isInnerRequest;
}

static bool IsNeedReuseOrWait(ProxyConnectInfo *connectInfo)
{
    ProxyConnectInfo *connectingProxyChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingProxyChannel != NULL) {
        CONN_LOGW(CONN_PROXY, "concurrent conflict, connecting=%{public}u/%{public}d, this=%{public}u/%{public}d",
            connectingProxyChannel->requestId, connectingProxyChannel->isAclConnected, connectInfo->requestId,
            connectInfo->isAclConnected);
        HandleConcurrentConnect(connectingProxyChannel, connectInfo);
        return true;
    }

    // reuse already exist proxy channel
    struct ProxyConnection *proxyConnection = GetProxyChannelByAddr(connectInfo->brMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, false, CONN_PROXY, "proxyConnection is null");
    ProxyChannelState state = GetProxyChannelState(proxyConnection);
    uint32_t channelId = proxyConnection->channelId;
    CONN_LOGI(CONN_PROXY, "state=%{public}d", state);
    if (state == PROXY_CHANNEL_CONNECTED) {
        CONN_LOGI(CONN_PROXY, "reuse already exist proxy channel channelId=%{public}u, reqId=%{public}u",
            channelId, connectInfo->requestId);
        proxyConnection->proxyChannel.requestId = connectInfo->requestId;
        connectInfo->result.onOpenSuccess(connectInfo->requestId, &proxyConnection->proxyChannel);
        proxyConnection->dereference(proxyConnection);
        return true;
    }
    proxyConnection->dereference(proxyConnection);
    // retry after the previous connection ends
    if (state == PROXY_CHANNEL_CONNECTING) {
        CONN_LOGI(CONN_PROXY, "reqId=%{public}u, wait channelId=%{public}u stopped",
            connectInfo->requestId, channelId);
        ProxyConnectInfo *copyConnectInfo = CopyProxyConnectInfo(connectInfo);
        CONN_CHECK_AND_RETURN_RET_LOGE(copyConnectInfo != NULL, false, CONN_PROXY, "copyProxyChannel err");
        int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL, 0, 0,
            copyConnectInfo, OPEN_PROXY_CHANNEL_WAIT_MS);
        if (ret < 0) {
            CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
            DestoryProxyConnectInfo(&copyConnectInfo);
            return false;
        }
        return true;
    }
    return false;
}

static void OpenProxyChannelTimeout(uint32_t channelId)
{
    CONN_LOGE(CONN_PROXY, "connect timeout, channelId=%{public}u", channelId);
    struct ProxyConnection *connection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_PROXY, "channelId=%{public}u not found", channelId);
    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel == NULL ||
        StrCmpIgnoreCase(connection->brMac, connectingChannel->brMac) != 0) {
        CONN_LOGE(CONN_PROXY, "connectingChannel is null, or unexpected device");
        connection->dereference(connection);
        return;
    }
    ProcessConnectFailed(connectingChannel, connection->brMac, SOFTBUS_CONN_OPEN_PROXY_TIMEOUT);
    connection->dereference(connection);
}

static ProxyConnectInfo *CopyProxyConnectInfo(ProxyConnectInfo *srcInfo)
{
    ProxyConnectInfo *destInfo = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(destInfo != NULL, NULL, CONN_PROXY, "data is NULL");
    if (memcpy_s(destInfo, sizeof(ProxyConnectInfo), srcInfo, sizeof(ProxyConnectInfo)) != EOK) {
        CONN_LOGE(CONN_PROXY, "memcpy ProxyConnectInfo fail");
        SoftBusFree(destInfo);
        return NULL;
    }
    ListInit(&destInfo->node);
    return destInfo;
}

static void AddReconnectDeviceInfoUnsafe(ProxyConnectInfo *connectInfo)
{
    ProxyConnectInfo *target = GetReconnectDeviceInfoByAddrUnsafe(connectInfo->brMac);
    if (target != NULL) {
        target->requestId = connectInfo->requestId;
        target->innerRetryNum = 0;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connectInfo->brMac, BT_MAC_LEN);
    CONN_CHECK_AND_RETURN_LOGI(target == NULL, CONN_PROXY, "aleady exist, addr=%{public}s", anomizeAddress);

    ProxyConnectInfo *info = CopyProxyConnectInfo(connectInfo);
    CONN_CHECK_AND_RETURN_LOGE(info != NULL, CONN_PROXY, "CopyProxyConnectInfo fail");
    info->isAclConnected = true;
    info->innerRetryNum = 0;
    (void)IsPairedDevice(info->brMac, true, &info->isSupportHfp);
    CONN_LOGI(CONN_PROXY, "isSupportHfp=%{public}d", info->isSupportHfp);
    ListAdd(&GetProxyChannelManager()->reconnectDeviceInfos, &info->node);
}

static ProxyConnectInfo *GetReconnectDeviceInfoByAddrUnsafe(const char *addr)
{
    ProxyConnectInfo *it = NULL;
    ProxyConnectInfo *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (StrCmpIgnoreCase(addr, it->brMac) == 0) {
            target = it;
            break;
        }
    }
    return target;
}

static void RemoveReconnectDeviceInfoByAddrUnsafe(const char *addr)
{
    ProxyConnectInfo *it = NULL;
    ProxyConnectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (StrCmpIgnoreCase(addr, it->brMac) == 0 || StrCmpIgnoreCase(addr, it->brHashMac) == 0) {
            char anomizeAddress[BT_MAC_LEN] = { 0 };
            ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, it->brMac, BT_MAC_LEN);
            CONN_LOGW(CONN_PROXY, "remove reconnect device addr=%{public}s", anomizeAddress);
            ListDelete(&it->node);
            DestoryProxyConnectInfo(&it);
            return;
        }
    }
}

static void UpdateRequestIdIfNeed(ProxyConnectInfo *connectInfo)
{
    ProxyConnectInfo *reconnectDeviceInfo = GetReconnectDeviceInfoByAddrUnsafe(connectInfo->brMac);
    if (reconnectDeviceInfo == NULL) {
        return;
    }

    if (!connectInfo->isInnerRequest) {
        reconnectDeviceInfo->requestId = connectInfo->requestId;
    } else {
        connectInfo->requestId = reconnectDeviceInfo->requestId;
    }
}

static void OpenProxyChannelHandler(ProxyConnectInfo *connectInfo)
{
    UpdateRequestIdIfNeed(connectInfo);
    if (IsNeedReuseOrWait(connectInfo)) {
        return;
    }

    GetProxyChannelManager()->proxyChannelRequestInfo = CopyProxyConnectInfo(connectInfo);
    CONN_CHECK_AND_RETURN_LOGE(GetProxyChannelManager()->proxyChannelRequestInfo != NULL,
        CONN_PROXY, "CopyProxyConnectInfo err");

    struct ProxyConnection *connection = CreateProxyConnection(connectInfo);
    if (connection == NULL) {
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        connectInfo->result.onOpenFail(connectInfo->requestId, SOFTBUS_MALLOC_ERR, connectInfo->brMac);
        return;
    }
    if (SaveProxyConnection(connection) != SOFTBUS_OK) {
        connection->dereference(connection);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        connectInfo->result.onOpenFail(connectInfo->requestId, SOFTBUS_MALLOC_ERR, connectInfo->brMac);
        return;
    }

    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_TIMEOUT,
        connection->channelId, 0, NULL, connectInfo->timeoutMs);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        RemoveProxyChannelByChannelId(connection->channelId);
        connection->dereference(connection);
        connectInfo->result.onOpenFail(connectInfo->requestId, ret, connectInfo->brMac);
        return;
    }
    CONN_LOGI(CONN_PROXY, "start connect br reqId=%{public}u, channelId=%{public}u", connectInfo->requestId,
        connection->channelId);
    ProxyBrConnectStateCallback callback = {
        .onConnectSuccess = BrChannelConnectSuccess,
        .onConnectFail = BrChannelConnectFail,
    };
    (void)GetProxyBrConnectionManager()->connect(connection, &callback);
    connection->dereference(connection);
}

static int32_t CreateProxyConnectInfo(ProxyChannelParam *param, const OpenProxyChannelCallback *callback,
    ProxyConnectInfo **connectInfo, bool isRealMac)
{
    ProxyConnectInfo *ctx = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "ctx is NULL");
    ctx->requestId = param->requestId;
    ctx->result = *callback;
    ctx->timeoutMs = param->timeoutMs;
    // the default acl is exist
    ctx->isAclConnected = true;
    ctx->isInnerRequest = false;
    ctx->isRealMac = isRealMac;

    char anomizeAddress[BT_MAC_MAX_LEN] = { 0 };
    char anomizeUuid[UUID_STRING_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeAddress, BT_MAC_MAX_LEN, param->brMac);
    ConvertAnonymizeSensitiveString(anomizeUuid, UUID_STRING_LEN, param->uuid);

    int32_t ret = isRealMac ? strcpy_s(ctx->brMac, sizeof(ctx->brMac), param->brMac)
        : strcpy_s(ctx->brHashMac, sizeof(ctx->brHashMac), param->brMac);
    if (ret != EOK) {
        CONN_LOGE(CONN_PROXY,
            "reqId=%{public}u, addr=%{public}s, uuid=%{public}s", param->requestId, anomizeAddress, anomizeUuid);
        DestoryProxyConnectInfo(&ctx);
        return SOFTBUS_STRCPY_ERR;
    }
    if (!isRealMac && GetRealMac(ctx->brMac, BT_MAC_LEN, param->brMac) != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "reqId=%{public}u, addr=%{public}s, uuid=%{public}s",
            param->requestId, anomizeAddress, anomizeUuid);
        DestoryProxyConnectInfo(&ctx);
        return SOFTBUS_CONN_PROXY_INTERNAL_ERR;
    }

    if (strcpy_s(ctx->uuid, UUID_STRING_LEN, param->uuid) != EOK) {
        CONN_LOGE(CONN_PROXY,
            "reqId=%{public}u, addr=%{public}s, uuid=%{public}s", param->requestId, anomizeAddress, anomizeUuid);
        DestoryProxyConnectInfo(&ctx);
        return SOFTBUS_STRCPY_ERR;
    }
    ListInit(&ctx->node);
    *connectInfo = ctx;
    return SOFTBUS_OK;
}

static void DestoryProxyConnectInfo(ProxyConnectInfo **connectInfo)
{
    SoftBusFree(*connectInfo);
    *connectInfo = NULL;
}

static bool IsRealMac(const char *brMac)
{
    if (strlen(brMac) != BT_MAC_LEN - 1) {
        CONN_LOGW(CONN_PROXY, "brMac length is not match, len=%{public}zu", strlen(brMac));
        return false;
    }
    int32_t macConLonPos = 3;
    for (int32_t i = 0; i < BT_MAC_LEN - 1; i++) {
        if ((i + 1) % macConLonPos == 0) {
            if (brMac[i] != ':') {
                CONN_LOGE(CONN_PROXY, "brMac format error");
                return false;
            }
        } else if (!(brMac[i] >= '0' && brMac[i] <= '9') &&
                   !(brMac[i] >= 'a' && brMac[i] <= 'f') &&
                   !(brMac[i] >= 'A' && brMac[i] <= 'F')) {
            CONN_LOGE(CONN_PROXY, "brMac format error");
            return false;
        }
    }
    return true;
}

static int32_t OpenProxyChannel(ProxyChannelParam *param, const OpenProxyChannelCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "param is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "callback is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback->onOpenSuccess != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onOpenSuccess is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback->onOpenFail != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onOpenFail is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusGetBrState() == BR_ENABLE, SOFTBUS_CONN_BR_DISABLE_ERR,
        CONN_PROXY, "br disable");
    bool isRealMac = IsRealMac(param->brMac);
    bool isPairedDevice = IsPairedDevice(param->brMac, isRealMac, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(isPairedDevice, SOFTBUS_CONN_BR_UNPAIRED,
        CONN_PROXY, "is not paired device");
    char anomizeAddress[BT_MAC_MAX_LEN] = { 0 };
    char anomizeUuid[UUID_STRING_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeAddress, BT_MAC_MAX_LEN, param->brMac);
    ConvertAnonymizeSensitiveString(anomizeUuid, UUID_STRING_LEN, param->uuid);
    CONN_LOGI(CONN_PROXY, "reqId=%{public}u, brMac=%{public}s, uuid=%{public}s, timeoutMs=%{public}" PRIu64,
        param->requestId, anomizeAddress, anomizeUuid, param->timeoutMs);

    ProxyConnectInfo *connectInfo = NULL;
    int32_t ret = CreateProxyConnectInfo(param, callback, &connectInfo, isRealMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY,
        "createProxyConnectInfo fail, ret=%{public}d", ret);
    ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL, 0, 0, connectInfo, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        DestoryProxyConnectInfo(&connectInfo);
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnProxyChannelDataReceived(uint32_t channelId, uint8_t *data, uint32_t dataLen)
{
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection fail, channelId=%{public}u", channelId);
    CONN_LOGI(CONN_PROXY, "channelId=%{public}u, dataLen=%{public}u", channelId, dataLen);
    if (g_listener.onProxyChannelDataReceived != NULL) {
        g_listener.onProxyChannelDataReceived(&proxyConnection->proxyChannel, data, dataLen);
    }
    proxyConnection->dereference(proxyConnection);
}

static void NotifyDisconnected(struct ProxyChannel *proxyChannel, int32_t reason)
{
    CONN_CHECK_AND_RETURN_LOGE(g_listener.onProxyChannelDisconnected != NULL, CONN_PROXY,
        "disconnected listener is null");
    g_listener.onProxyChannelDisconnected(proxyChannel, reason);
}

static void ProxyChannelDisconnectHandler(ProxyChannelNotifyContext *ctx)
{
    uint32_t channelId = ctx->channelId;
    int32_t reason = ctx->status;
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection fail, channelId=%{public}u", channelId);
    CONN_LOGE(CONN_PROXY, "reqId=%{public}u, channelId=%{public}u, err=%{public}d",
        proxyConnection->proxyChannel.requestId, channelId, reason);

    SetProxyChannelState(proxyConnection, PROXY_CHANNEL_DISCONNECTED);
    NotifyDisconnected(&proxyConnection->proxyChannel, reason);
    RemoveProxyChannelByChannelId(channelId);
    PostEventByAddr(MSG_OPEN_PROXY_CHANNEL_RETRY, proxyConnection->brMac, RECONNECT_AFTER_DISCONNECT_WAIT_MS);
}

static void OnProxyChannelDisconnected(uint32_t channelId, int32_t reason)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on proxy channel disconnect fail, calloc error context fail");
    ctx->channelId = channelId;
    ctx->status = reason;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_CLOSE_PROXY_DISCONNECT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        SoftBusFree(ctx);
    }
}

static int32_t RegisterProxyChannelListener(ProxyConnectListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "listener is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelDisconnected != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "Disconnected is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "DataReceived is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelReconnected != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "Reconnected is NULL");
    g_listener = *listener;
    return SOFTBUS_OK;
}

static void OnInnerReConnectSuccess(uint32_t requestId, struct ProxyChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(g_listener.onProxyChannelReconnected != NULL, CONN_PROXY, "Reconnected is NULL");
    ResetReconnectEvent(requestId, channel->brMac);
    CONN_LOGI(CONN_PROXY, "reqId=%{public}u, channelId=%{public}u", requestId, channel->channelId);
    // notify upper reconnect success
    g_listener.onProxyChannelReconnected(channel->brMac, channel);
}

static void OnInnerReConnectFailWithRetry(uint32_t requestId, int32_t reason,  const char *brMac)
{
    CONN_LOGE(CONN_PROXY, "reqId=%{public}u, reason=%{public}d, retry", requestId, reason);
    PostEventByAddr(MSG_OPEN_PROXY_CHANNEL_RETRY, brMac, 0);
}

static void OnInnerReConnectFailWithoutRetry(uint32_t requestId, int32_t reason,  const char *brMac)
{
    (void)brMac;
    CONN_LOGI(CONN_PROXY, "inner reconnect fail, reqId=%{public}u, not retry", requestId);
}


static bool IsTargetDeviceAlreadyConnected(char *brAddr)
{
    struct ProxyConnection *proxyConnection = GetProxyChannelByAddr(brAddr);
    CONN_CHECK_AND_RETURN_RET_LOGI(proxyConnection != NULL, false,
        CONN_PROXY, "not exit same proxyConnection");
    bool isValidProxyConnection = GetProxyChannelState(proxyConnection) == PROXY_CHANNEL_CONNECTED;
    proxyConnection->dereference(proxyConnection);
    return isValidProxyConnection;
}

static bool CheckNeedToRetry(char *brAddr, ProxyConnectInfo *reconnectDeviceInfo)
{
    bool isAclConnected = reconnectDeviceInfo->isAclConnected;
    CONN_LOGI(CONN_PROXY, "isAclConnected=%{public}d", isAclConnected);

    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusGetBrState() == BR_ENABLE, false, CONN_PROXY, "br disable");

    bool isAlreadyConnected = IsTargetDeviceAlreadyConnected(brAddr);
    CONN_CHECK_AND_RETURN_RET_LOGW(!isAlreadyConnected, false, CONN_PROXY, "exist already connection");

    bool isPairedDevice = IsPairedDevice(brAddr, true, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(isPairedDevice, false, CONN_PROXY, "is not paired device");
    return true;
}

static void AttemptReconnectDevice(char *brAddr)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, brAddr, BT_MAC_LEN);
    ProxyConnectInfo *reconnectDeviceInfo = GetReconnectDeviceInfoByAddrUnsafe(brAddr);
    CONN_CHECK_AND_RETURN_LOGW(reconnectDeviceInfo != NULL, CONN_PROXY,
        "not exit same addr=%{public}s need to reconnect", anomizeAddress);
    bool checkNeedToRetry = CheckNeedToRetry(brAddr, reconnectDeviceInfo);
    CONN_CHECK_AND_RETURN_LOGW(checkNeedToRetry, CONN_PROXY, "not retry");

    struct ProxyConfig config = ProxyGetRetryConfig(GetProxyConfigManager(), reconnectDeviceInfo);
    if (!config.retryable) {
        CONN_LOGE(CONN_PROXY, "retry times=%{public}u, reach policy limit, not retry more",
            reconnectDeviceInfo->innerRetryNum);
        reconnectDeviceInfo->innerRetryNum = 0;
        struct ProxyChannel proxyChannel = { 0 };
        int32_t ret = reconnectDeviceInfo->isRealMac ?
            strcpy_s(proxyChannel.brMac, BT_MAC_MAX_LEN, reconnectDeviceInfo->brMac) :
            strcpy_s(proxyChannel.brMac, BT_MAC_MAX_LEN, reconnectDeviceInfo->brHashMac);
        CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_PROXY, "cpy mac err");
        ret = strcpy_s(proxyChannel.uuid, UUID_STRING_LEN, reconnectDeviceInfo->uuid);
        CONN_CHECK_AND_RETURN_LOGE(ret == EOK, CONN_PROXY, "cpy uuid err");
        NotifyDisconnected(&proxyChannel, SOFTBUS_CONN_PROXY_RETRY_FAILED);
        return;
    }
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL,
        reconnectDeviceInfo->requestId, 0, NULL);
    ProxyConnectInfo *proxyChannelRequestInfo = CopyProxyConnectInfo(reconnectDeviceInfo);
    CONN_CHECK_AND_RETURN_LOGW(proxyChannelRequestInfo != NULL, CONN_PROXY, "CopyProxyConnectInfo fail");

    CONN_LOGI(CONN_PROXY, "start reconnect reqId=%{public}u, addr=%{public}s, times=%{public}u, delay=%{public}" PRIu64,
        proxyChannelRequestInfo->requestId, anomizeAddress, reconnectDeviceInfo->innerRetryNum, config.delayMs);
    reconnectDeviceInfo->innerRetryNum += 1;
    proxyChannelRequestInfo->result.onOpenSuccess = OnInnerReConnectSuccess;
    proxyChannelRequestInfo->result.onOpenFail = OnInnerReConnectFailWithRetry;
    proxyChannelRequestInfo->isInnerRequest = true;
    proxyChannelRequestInfo->timeoutMs = INNER_RECONNECT_TIMEOUT_MS;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL,
        0, 0, proxyChannelRequestInfo, config.delayMs);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "post msg fail, error=%{public}d", ret);
        DestoryProxyConnectInfo(&proxyChannelRequestInfo);
    }
}

static void AclStateChangedHandler(ProxyChannelAclStateContext *context)
{
    ProxyConnectInfo *reconnectDeviceInfo = GetReconnectDeviceInfoByAddrUnsafe(context->brMac);
    CONN_CHECK_AND_RETURN_LOGW(reconnectDeviceInfo != NULL, CONN_PROXY, "no reconnect device");
    reconnectDeviceInfo->innerRetryNum = 0;
    reconnectDeviceInfo->isAclConnected = (context->state == SOFTBUS_ACL_STATE_CONNECTED) ? true : false;
    if (!reconnectDeviceInfo->isAclConnected) {
        return;
    }
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_RETRY, 0, 0,
        reconnectDeviceInfo->brMac);
    CONN_LOGI(CONN_PROXY, "isSupportHfp=%{public}d", reconnectDeviceInfo->isSupportHfp);
    uint64_t delayMillis = reconnectDeviceInfo->isSupportHfp ? ACL_WAIT_HFP_DELAY_MS : 0;
    PostEventByAddr(MSG_OPEN_PROXY_CHANNEL_RETRY, reconnectDeviceInfo->brMac, delayMillis);
}

static void ProxyResetHandler(void)
{
    CONN_LOGI(CONN_PROXY, "start handle bluetooth off event");
    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel != NULL) {
        connectingChannel->result.onOpenFail(connectingChannel->requestId, SOFTBUS_CONN_BLUETOOTH_OFF,
            connectingChannel->brMac);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
    }
    ListNode notifyConnectionList;
    ListInit(&notifyConnectionList);
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "lock proxyConnectionList fail");
    struct ProxyConnection *item = NULL;
    struct ProxyConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &GetProxyChannelManager()->proxyConnectionList->list,
        struct ProxyConnection, node) {
        ListDelete(&item->node);
        ListAdd(&notifyConnectionList, &item->node);
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);

    item = NULL;
    next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &notifyConnectionList, struct ProxyConnection, node) {
        ListDelete(&item->node);
        if (GetProxyChannelState(item) != PROXY_CHANNEL_CONNECTING) {
            SetProxyChannelState(item, PROXY_CHANNEL_DISCONNECTED);
            CONN_LOGW(CONN_PROXY, "bluetooth off, notify disconnected, channelId=%{public}u", item->channelId);
            NotifyDisconnected(&item->proxyChannel, SOFTBUS_CONN_BLUETOOTH_OFF);
        }
        item->dereference(item);
    }

    ProxyConnectInfo *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        ResetReconnectEvent(it->requestId, it->brMac);
        it->innerRetryNum = 0;
    }
    // remove all open proxy channel msg, request is 0 match all
    ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL, REQUEST_ID_MATCH_ALL, 0, NULL);
}

static void ProxyRestoreHandler(void)
{
    CONN_LOGI(CONN_PROXY, "start handle bluetooth on event");
    ProxyConnectInfo *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        ProxyConnectInfo *proxyChannelRequestInfo = CopyProxyConnectInfo(it);
        if (proxyChannelRequestInfo == NULL) {
            CONN_LOGE(CONN_PROXY, "CopyProxyConnectInfo fail");
            continue;
        }

        proxyChannelRequestInfo->result.onOpenSuccess = OnInnerReConnectSuccess;
        proxyChannelRequestInfo->result.onOpenFail = OnInnerReConnectFailWithoutRetry;
        proxyChannelRequestInfo->isInnerRequest = true;
        proxyChannelRequestInfo->timeoutMs = INNER_RECONNECT_TIMEOUT_MS;
        int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL,
            0, 0, proxyChannelRequestInfo, RECONNECT_AFTER_BT_OPEN_WAIT_MS);
        if (ret < 0) {
            CONN_LOGE(CONN_PROXY, "post msg fail, error=%{public}d", ret);
            DestoryProxyConnectInfo(&proxyChannelRequestInfo);
        }
    }
}

static void ProxyDeviceUnpaired(const char *brAddr)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, brAddr, BT_MAC_LEN);
    CONN_LOGW(CONN_PROXY, "addr=%{public}s, unpaired", anomizeAddress);

    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel != NULL && StrCmpIgnoreCase(brAddr, connectingChannel->brMac) == 0) {
        connectingChannel->result.onOpenFail(connectingChannel->requestId, SOFTBUS_CONN_BR_UNPAIRED,
            connectingChannel->brMac);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
    }

    ProxyConnectInfo *target = GetReconnectDeviceInfoByAddrUnsafe(brAddr);
    CONN_CHECK_AND_RETURN_LOGE(target != NULL, CONN_PROXY, "ignore addr=%{public}s", anomizeAddress);
    struct ProxyChannel proxyChannel = { 0 };
    proxyChannel.requestId = target->requestId;
    int32_t ret = target->isRealMac ? strcpy_s(proxyChannel.brMac, BT_MAC_MAX_LEN, target->brMac) :
        strcpy_s(proxyChannel.brMac, BT_MAC_MAX_LEN, target->brHashMac);
    if (ret != EOK) {
        CONN_LOGW(CONN_PROXY, "cpy brMac err!");
    }
    ret = strcpy_s(proxyChannel.uuid, UUID_STRING_LEN, target->uuid);
    if (ret != EOK) {
        CONN_LOGW(CONN_PROXY, "cpy uuid err!");
    }
    RemoveReconnectDeviceInfoByAddrUnsafe(brAddr);
    NotifyDisconnected(&proxyChannel, SOFTBUS_CONN_BR_UNPAIRED);
}

static void OnProxyAclStateChanged(
    int32_t listenerId, const SoftBusBtAddr *btAddr, int32_t aclState, int32_t hciReason)
{
    CONN_CHECK_AND_RETURN_LOGW((aclState == SOFTBUS_ACL_STATE_CONNECTED || aclState == SOFTBUS_ACL_STATE_DISCONNECTED),
        CONN_PROXY, "ignore state=%{public}d", aclState);
    CONN_CHECK_AND_RETURN_LOGW(btAddr != NULL, CONN_PROXY, "addr is null");
    char address[BT_MAC_LEN] = { 0 };
    int32_t ret = ConvertBtMacToStr(address, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "convert binary mac address to string fail");
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);
    CONN_LOGW(CONN_PROXY, "state=%{public}d, addr=%{public}s", aclState, anomizeAddress);
    ProxyChannelAclStateContext *context =
        (ProxyChannelAclStateContext *)SoftBusCalloc(sizeof(ProxyChannelAclStateContext));
    if (context == NULL || strcpy_s(context->brMac, BT_MAC_LEN, address) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr fail");
        SoftBusFree(context);
        return;
    }
    context->state = aclState;
    ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_ACL_STATE_CHANGE, 0, 0, context, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "post msg fail, error=%{public}d", ret);
        SoftBusFree(context);
    }
}

static void OnObserverStateChanged(const char *addr, int32_t state)
{
    CONN_CHECK_AND_RETURN_LOGW((state == SOFTBUS_HFP_CONNECTED || state == SOFTBUS_DEVICE_UNPAIRED),
        CONN_PROXY, "ignore state=%{public}d", state);
    CONN_LOGI(CONN_PROXY, "state=%{public}d", state);
    CONN_CHECK_AND_RETURN_LOGW(addr != NULL, CONN_PROXY, "addr is NULL");
    if (state == SOFTBUS_HFP_CONNECTED) {
        ConnRemoveMsgFromLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_RETRY, 0, 0, (void *)addr);
    }

    enum BrProxyLooperMsgType msgType = state == SOFTBUS_HFP_CONNECTED ?
        MSG_OPEN_PROXY_CHANNEL_RETRY : MSG_PROXY_UNPAIRED;
    PostEventByAddr(msgType, addr, 0);
}

static void OnProxyBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    CONN_CHECK_AND_RETURN_LOGW(state == SOFTBUS_BR_STATE_TURN_OFF || state == SOFTBUS_BR_STATE_TURN_ON, CONN_PROXY,
        "ignore state=%{public}d", state);

    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler,
        state == SOFTBUS_BR_STATE_TURN_OFF ? MSG_PROXY_BT_TURN_OFF : MSG_PROXY_BT_TURN_ON, 0, 0, 0, 0);
    CONN_LOGI(CONN_PROXY, "post bt state change msg, state=%{public}d, ret=%{public}d", state, ret);
}

static void ProxyChannelMsgHandler(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOGW(msg != NULL, CONN_PROXY, "msg is NULL");
    switch (msg->what) {
        case MSG_OPEN_PROXY_CHANNEL:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            OpenProxyChannelHandler((ProxyConnectInfo *)msg->obj);
            break;
        case MSG_OPEN_PROXY_CHANNEL_TIMEOUT:
            OpenProxyChannelTimeout(msg->arg1);
            break;
        case MSG_OPEN_PROXY_CHANNEL_RETRY:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            AttemptReconnectDevice((char*)msg->obj);
            break;
        case MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            ProxyChannelConnectResultHandler((ProxyChannelNotifyContext *)msg->obj);
            break;
        case MSG_CLOSE_PROXY_CHANNEL:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            ProxyChannelCloseHandler(msg->arg1, (char *)msg->obj);
            break;
        case MSG_CLOSE_PROXY_DISCONNECT:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            ProxyChannelDisconnectHandler((ProxyChannelNotifyContext *)msg->obj);
            break;
        case MSG_ACL_STATE_CHANGE:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            AclStateChangedHandler((ProxyChannelAclStateContext *)msg->obj);
            break;
        case MSG_PROXY_BT_TURN_OFF:
            ProxyResetHandler();
            break;
        case MSG_PROXY_BT_TURN_ON:
            ProxyRestoreHandler();
            break;
        case MSG_PROXY_UNPAIRED:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            ProxyDeviceUnpaired((const char*)msg->obj);
            break;
        default:
            CONN_LOGW(CONN_PROXY, "receive unexpected msg, what=%{public}d", msg->what);
            break;
    }
}

static int ProxyChannelLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_OPEN_PROXY_CHANNEL_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        case MSG_OPEN_PROXY_CHANNEL: {
            if (msg->obj == NULL) {
                return COMPARE_FAILED;
            }
            ProxyConnectInfo *info = (ProxyConnectInfo *)msg->obj;
            if (ctx->arg1 == REQUEST_ID_MATCH_ALL) {
                CONN_LOGW(CONN_PROXY, "match all, request id=%{public}u", info->requestId);
                return COMPARE_SUCCESS;
            }
            return (uint64_t)(info->requestId) == ctx->arg1 ? COMPARE_SUCCESS : COMPARE_FAILED;
        }
        case MSG_OPEN_PROXY_CHANNEL_RETRY: {
            if (msg->obj == NULL || ctx->obj == NULL) {
                return COMPARE_FAILED;
            }
            bool isSameDevice = (StrCmpIgnoreCase((char *)msg->obj, (char *)ctx->obj) == 0);
            return isSameDevice ? COMPARE_SUCCESS : COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_PROXY, "fail to avoid fault silence, "
            "what=%{public}d, arg1=%{public}" PRIu64 ", arg2=%{public}" PRIu64 ", objIsNull=%{public}d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static ProxyChannelManager g_proxyChannelManager = {
    .generateRequestId = GenerateRequestId,
    .openProxyChannel = OpenProxyChannel,
    .registerProxyChannelListener = RegisterProxyChannelListener,

    .getConnectionById = GetProxyChannelByChannelId,
    .proxyChannelRequestInfo = NULL,
    .proxyConnectionList = NULL,
};

ProxyChannelManager *GetProxyChannelManager(void)
{
    return &g_proxyChannelManager;
}

int32_t ProxyChannelManagerInit(void)
{
    g_proxyChannelManager.proxyConnectionList = CreateSoftBusList();
    CONN_CHECK_AND_RETURN_RET_LOGE(GetProxyChannelManager()->proxyConnectionList != NULL, SOFTBUS_CREATE_LIST_ERR,
        CONN_INIT, "create channels list fail");
    ListInit(&(GetProxyChannelManager()->reconnectDeviceInfos));

    g_proxyChannelAsyncHandler.handler.looper = GetLooper(LOOP_TYPE_CONN);
    if (g_proxyChannelAsyncHandler.handler.looper == NULL) {
        CONN_LOGE(CONN_PROXY, "init conn ble looper fail");
        DestroySoftBusList(g_proxyChannelManager.proxyConnectionList);
        return SOFTBUS_LOOPER_ERR;
    }
    int32_t ret = SoftBusMutexInit(&g_reqIdLock, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock falied");
        DestroySoftBusList(g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    static SoftBusBtStateListener btStateListener = {
        .OnBtAclStateChanged = OnProxyAclStateChanged,
        .OnBtStateChanged = OnProxyBtStateChanged,
    };
    int32_t listenerId = -1;
    ret = SoftBusAddBtStateListener(&btStateListener, &listenerId);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "add bt listener fail, listenerId=%{public}d", listenerId);
        SoftBusMutexDestroy(&g_reqIdLock);
        DestroySoftBusList(g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    ret = RegisterHfpListener(OnObserverStateChanged);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "register hfp listener fail, ret=%{public}d", ret);
        SoftBusMutexDestroy(&g_reqIdLock);
        DestroySoftBusList(g_proxyChannelManager.proxyConnectionList);
        SoftBusRemoveBtStateListener(listenerId);
        return ret;
    }
    static ProxyEventListener listener = {
        .onDataReceived = OnProxyChannelDataReceived,
        .onDisconnected = OnProxyChannelDisconnected,
    };
    ret = GetProxyBrConnectionManager()->registerEventListener(&listener);
    CONN_LOGI(CONN_PROXY, "ret=%{public}d", ret);
    return ret;
}