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
#include "proxy_connection.h"
#include "proxy_observer.h"

#define INNER_RECONNECT_TIMEOUT_MS 5000
#define INNER_RECONNECT_RETRY_WAIT_MS 200

typedef struct {
    bool isSuccess;
    uint32_t channelId;
    int32_t status;
} ProxyChannelNotifyContext;

typedef struct {
    char brMac[BT_MAC_LEN];
    int32_t state;
} ProxyChannelAclStateContext;

enum BrConnectionLooperMsgType {
    MSG_OPEN_PROXY_CHANNEL = 100,
    MSG_OPEN_PROXY_CHANNEL_TIMEOUT,
    MSG_OPEN_PROXY_CHANNEL_RETRY,
    MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT,
    MSG_CLOSE_PROXY_CHANNEL,
    MSG_CLOSE_PROXY_DISCONNECT,
    MSG_ACL_STATE_CHANGE,
    MSG_PROXY_RESET,
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
static void RemoveReconnectDeviceInfoByAddrUnsafe(char *addr);
static ProxyConnectInfo *GetReconnectDeviceInfoByAddrUnsafe(char *addr);
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
        "lock channel failed=%{public}d", ret);
    uint32_t reqId = g_reqId++;
    SoftBusMutexUnlock(&g_reqIdLock);
    return reqId;
}

static ProxyChannelState GetProxyChannelState(struct ProxyConnection *proxyConnection)
{
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel failed. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    ProxyChannelState state = proxyConnection->state;
    SoftBusMutexUnlock(&proxyConnection->lock);
    return state;
}

static ProxyChannelState SetProxyChannelState(struct ProxyConnection *proxyConnection, ProxyChannelState state)
{
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel failed. channelId=%{public}u", proxyConnection->channelId);
    proxyConnection->state = state;
    SoftBusMutexUnlock(&proxyConnection->lock);
    return state;
}

static void ProxyChannelDereference(struct ProxyConnection *proxyConnection)
{
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel failed. channelId=%{public}u", proxyConnection->channelId);
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
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel failed. channelId=%{public}u", proxyConnection->channelId);
    proxyConnection->refCount += 1;
    SoftBusMutexUnlock(&proxyConnection->lock);
}

int32_t ProxyChannelSend(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(channel != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "channel is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "data is null");
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channel->channelId);
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, SOFTBUS_NOT_FIND, CONN_PROXY,
        "get proxyConnection failed, channelId=%{public}u", channel->channelId);
    int32_t ret = GetProxyBrConnectionManager()->send(proxyConnection, data, dataLen);
    proxyConnection->dereference(proxyConnection);
    return ret;
}

static void ProxyChannelCloseHandler(char *brAddr)
{
    RemoveReconnectDeviceInfoByAddrUnsafe(brAddr);
}

static void ProxyChannelClose(struct ProxyChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is null");
    char *copyAddr = (char *)SoftBusCalloc(BT_MAC_LEN);
    if (copyAddr == NULL || strcpy_s(copyAddr, BT_MAC_LEN, channel->brMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr failed");
        SoftBusFree(copyAddr);
        return;
    }
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_CLOSE_PROXY_CHANNEL, 0, 0, copyAddr, 0);
    if (ret < 0) {
        // fall-through
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
        SoftBusFree(copyAddr);
    }

    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channel->channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection failed, channelId=%{public}u", channel->channelId);
    SetProxyChannelState(proxyConnection, PROXY_CHANNEL_DISCONNECTING);
    ret = GetProxyBrConnectionManager()->disconnect(proxyConnection);
    CONN_LOGW(CONN_PROXY, "close proxy channel=%{public}u, ret=%{public}d", channel->channelId, ret);
    proxyConnection->dereference(proxyConnection);
}

static struct ProxyConnection *CreateProxyConnection(ProxyConnectInfo *connectInfo)
{
    struct ProxyConnection *proxyConnection = (struct ProxyConnection *)SoftBusCalloc(sizeof(struct ProxyConnection));
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, NULL, CONN_PROXY, "proxyConnection is NULL");
    proxyConnection->reference = ProxyChannelReference;
    proxyConnection->dereference = ProxyChannelDereference;
    proxyConnection->state = PROXY_CHANNEL_CONNECTING;
    proxyConnection->refCount = 1;
    proxyConnection->proxyChannel.send = ProxyChannelSend;
    proxyConnection->proxyChannel.close = ProxyChannelClose;
    proxyConnection->proxyChannel.requestId = connectInfo->requestId;
    if (strcpy_s(proxyConnection->proxyChannel.brMac, BT_MAC_LEN, connectInfo->brMac) != EOK ||
        strcpy_s(proxyConnection->proxyChannel.uuid, UUID_STRING_LEN, connectInfo->uuid) != EOK) {
        CONN_LOGE(CONN_PROXY, "cpy br mac or uuid err");
        SoftBusFree(proxyConnection);
        return NULL;
    }
    ListInit(&proxyConnection->node);

    if (SoftBusMutexInit(&proxyConnection->lock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock failed");
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
        CONN_LOGE(CONN_PROXY, "lock proxyConnectionList failed");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t channelId = 0;
    int32_t retryNum = 0;
    do {
        channelId = AllocateConnectionIdUnsafe();
        retryNum++;
    } while (channelId == 0 && retryNum < RETRY_MAX_NUM);
    if (channelId == 0) {
        CONN_LOGE(CONN_PROXY, "allocate channelId failed");
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
    RemoveProxyChannelByChannelId(proxyConnection->channelId);
    CONN_LOGI(CONN_PROXY, "notify open fail reqId=%{public}u, status=%{public}d", requestId, status);
    connectingChannel->result.onOpenFail(requestId, status);

    if (!connectingChannel->isInnerRequest) {
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        return;
    }
    // inner request retry connect after failed
    CONN_LOGI(CONN_PROXY, "inner reconnect failed, retry reqId=%{public}u", connectingChannel->requestId);
    char *copyAddr = (char *)SoftBusCalloc(BT_MAC_LEN);
    if (copyAddr == NULL || strncpy_s(copyAddr, BT_MAC_LEN, connectingChannel->brMac, BT_MAC_LEN) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr failed");
        SoftBusFree(copyAddr);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        return;
    }
    DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler,
        MSG_OPEN_PROXY_CHANNEL_RETRY, 0, 0, copyAddr, INNER_RECONNECT_RETRY_WAIT_MS);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "post msg err");
        SoftBusFree(copyAddr);
    }
}

static void BrChannelConnectSuccess(uint32_t channelId)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on connect failed, calloc error context failed");
    ctx->channelId = channelId;
    ctx->isSuccess = true;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
        SoftBusFree(ctx);
    }
}

static void BrChannelConnectFail(uint32_t channelId, int32_t errorCode)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on connect failed, calloc error context failed");
    ctx->channelId = channelId;
    ctx->status = errorCode;
    ctx->isSuccess = false;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_CONNECT_RESULT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
        SoftBusFree(ctx);
    }
}

static void ProxyChannelConnectResultHandler(ProxyChannelNotifyContext *ctx)
{
    uint32_t channelId = ctx->channelId;
    struct ProxyConnection *connection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_PROXY, "channelId=%{public}u not found", channelId);

    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel == NULL || StrCmpIgnoreCase(connection->proxyChannel.brMac, connectingChannel->brMac) != 0) {
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
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, CONN_PROXY, "lock proxyConnectionList failed");
    struct ProxyConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->proxyConnectionList->list, struct ProxyConnection, node) {
        if (StrCmpIgnoreCase(addr, it->proxyChannel.brMac) == 0) {
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
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, CONN_PROXY, "lock proxyConnectionList failed");
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
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "lock proxyConnectionList failed");
    struct ProxyConnection *it = NULL;
    struct ProxyConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &GetProxyChannelManager()->proxyConnectionList->list,
        struct ProxyConnection, node) {
        if (it->channelId == channelId) {
            ListDelete(&it->node);
            it->dereference(it);
            CONN_LOGI(CONN_PROXY, "remove channel channelId=%{public}u", it->channelId);
            break;
        }
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
}

static bool IsNeedReuseOrWait(ProxyConnectInfo *connectInfo)
{
    ProxyConnectInfo *connectingProxyChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingProxyChannel != NULL) {
        if (StrCmpIgnoreCase(connectInfo->brMac, connectingProxyChannel->brMac) == 0) {
            // wait connect finished and reuse
            connectingProxyChannel->result = connectInfo->result;
            connectingProxyChannel->requestId = connectInfo->requestId;
            CONN_LOGI(CONN_PROXY, "wait connect result reqId=%{public}u", connectInfo->requestId);
        } else {
            connectInfo->result.onOpenFail(connectInfo->requestId, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR);
        }
        return true;
    }

    // reuse already exist proxy channel
    struct ProxyConnection *proxyConnection = GetProxyChannelByAddr(connectInfo->brMac);
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyConnection != NULL, false, CONN_PROXY, "proxyConnection is null");
    ProxyChannelState state = GetProxyChannelState(proxyConnection);
    CONN_LOGI(CONN_PROXY, "state=%{public}d", state);
    if (state == PROXY_CHANNEL_CONNECTED) {
        CONN_LOGI(CONN_PROXY, "reuse already exist proxy channel channelId=%{public}u, reqId=%{public}u",
            proxyConnection->channelId, connectInfo->requestId);
        proxyConnection->proxyChannel.requestId = connectInfo->requestId;
        connectInfo->result.onOpenSuccess(connectInfo->requestId, &proxyConnection->proxyChannel);
        proxyConnection->dereference(proxyConnection);
        return true;
    }
    proxyConnection->dereference(proxyConnection);
    return false;
}

static void OpenProxyChannelTimeout(uint32_t channelId)
{
    CONN_LOGE(CONN_PROXY, "connect timeout, channelId=%{public}u", channelId);
    ProxyChannelNotifyContext ctx = {
        .channelId = channelId,
        .status = SOFTBUS_CONN_OPEN_PROXY_TIMEOUT,
        .isSuccess = false,
    };
    ProxyChannelConnectResultHandler(&ctx);
}

static ProxyConnectInfo *CopyProxyConnectInfo(ProxyConnectInfo *srcInfo)
{
    ProxyConnectInfo *destInfo = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(destInfo != NULL, NULL, CONN_PROXY, "data is NULL");
    (void)memcpy_s(destInfo, sizeof(ProxyConnectInfo), srcInfo, sizeof(ProxyConnectInfo));
    ListInit(&destInfo->node);
    return destInfo;
}

static void AddReconnectDeviceInfoUnsafe(ProxyConnectInfo *connectInfo)
{
    ProxyConnectInfo *target = GetReconnectDeviceInfoByAddrUnsafe(connectInfo->brMac);
    if (target != NULL) {
        target->requestId = connectInfo->requestId;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connectInfo->brMac, BT_MAC_LEN);
    CONN_CHECK_AND_RETURN_LOGI(target == NULL, CONN_PROXY, "aleady exist, addr=%{public}s", anomizeAddress);

    ProxyConnectInfo *info = CopyProxyConnectInfo(connectInfo);
    CONN_CHECK_AND_RETURN_LOGE(info != NULL, CONN_PROXY, "CopyProxyConnectInfo failed");
    info->isAclConnected = true;
    ListAdd(&GetProxyChannelManager()->reconnectDeviceInfos, &info->node);
}

static ProxyConnectInfo *GetReconnectDeviceInfoByAddrUnsafe(char *addr)
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

static void RemoveReconnectDeviceInfoByAddrUnsafe(char *addr)
{
    ProxyConnectInfo *it = NULL;
    ProxyConnectInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (StrCmpIgnoreCase(addr, it->brMac) == 0) {
            char anomizeAddress[BT_MAC_LEN] = { 0 };
            ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, it->brMac, BT_MAC_LEN);
            CONN_LOGW(CONN_PROXY, "remove reconnect device addr=%{public}s", anomizeAddress);
            ListDelete(&it->node);
            DestoryProxyConnectInfo(&it);
            return;
        }
    }
}

static void OpenProxyChannelHandler(ProxyConnectInfo *connectInfo)
{
    if (IsNeedReuseOrWait(connectInfo)) {
        return;
    }

    GetProxyChannelManager()->proxyChannelRequestInfo = CopyProxyConnectInfo(connectInfo);
    CONN_CHECK_AND_RETURN_LOGE(GetProxyChannelManager()->proxyChannelRequestInfo != NULL,
        CONN_PROXY, "CopyProxyConnectInfo err");

    struct ProxyConnection *connection = CreateProxyConnection(connectInfo);
    if (connection == NULL) {
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        connectInfo->result.onOpenFail(connectInfo->requestId, SOFTBUS_MALLOC_ERR);
        return;
    }
    if (SaveProxyConnection(connection) != SOFTBUS_OK) {
        connection->dereference(connection);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        connectInfo->result.onOpenFail(connectInfo->requestId, SOFTBUS_MALLOC_ERR);
        return;
    }

    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_TIMEOUT,
        connection->channelId, 0, NULL, connectInfo->timeoutMs);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
        RemoveProxyChannelByChannelId(connection->channelId);
        connection->dereference(connection);
        connectInfo->result.onOpenFail(connectInfo->requestId, ret);
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
    ProxyConnectInfo **connectInfo)
{
    ProxyConnectInfo *ctx = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(connectInfo != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "ctx is NULL");
    ctx->requestId = param->requestId;
    ctx->result = *callback;
    ctx->timeoutMs = param->timeoutMs;
    // the default acl is exist
    ctx->isAclConnected = true;
    ctx->isInnerRequest = false;

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    char anomizeUuid[UUID_STRING_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, param->brMac, BT_MAC_LEN);
    ConvertAnonymizeSensitiveString(anomizeUuid, UUID_STRING_LEN, param->uuid);
    if (strcpy_s(ctx->brMac, BT_MAC_LEN, param->brMac) != EOK ||
        strcpy_s(ctx->uuid, UUID_STRING_LEN, param->uuid) != EOK) {
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
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    char anomizeUuid[UUID_STRING_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, param->brMac, BT_MAC_LEN);
    ConvertAnonymizeSensitiveString(anomizeUuid, UUID_STRING_LEN, param->uuid);
    CONN_LOGI(CONN_PROXY, "reqId=%{public}u, brMac=%{public}s, uuid=%{public}s, timeoutMs=%{public}" PRIu64,
        param->requestId, anomizeAddress, anomizeUuid, param->timeoutMs);

    ProxyConnectInfo *connectInfo = NULL;
    int32_t ret = CreateProxyConnectInfo(param, callback, &connectInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY,
        "createProxyConnectInfo failed, ret=%{public}d", ret);
    ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL, 0, 0, connectInfo, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
        DestoryProxyConnectInfo(&connectInfo);
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnProxyChannelDataReceived(uint32_t channelId, uint8_t *data, uint32_t dataLen)
{
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection failed, channelId=%{public}u", channelId);
    CONN_LOGI(CONN_PROXY, "channelId=%{public}u, dataLen=%{public}u", channelId, dataLen);
    if (g_listener.onProxyChannelDataReceived != NULL) {
        g_listener.onProxyChannelDataReceived(&proxyConnection->proxyChannel, data, dataLen);
    }
    proxyConnection->dereference(proxyConnection);
}

static void NotifyConnectFailed(char *brMac, int32_t reason)
{
    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    CONN_CHECK_AND_RETURN_LOGE(connectingChannel != NULL, CONN_PROXY, "on connect failed, calloc error context failed");
    CONN_CHECK_AND_RETURN_LOGE(StrCmpIgnoreCase(brMac, connectingChannel->brMac) == 0, CONN_PROXY,
        "not connecting device");
    connectingChannel->result.onOpenFail(connectingChannel->requestId, reason);
    DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
}

static void ProxyChannelDisconnectHandler(ProxyChannelNotifyContext *ctx)
{
    uint32_t channelId = ctx->channelId;
    int32_t reason = ctx->status;
    struct ProxyConnection *proxyConnection = GetProxyChannelByChannelId(channelId);
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY,
        "get proxyConnection failed, channelId=%{public}u", channelId);
    CONN_LOGW(CONN_PROXY, "channelId=%{public}u, disconnected err=%{public}d", channelId, reason);
    ProxyChannelState state = GetProxyChannelState(proxyConnection);
    if (state != PROXY_CHANNEL_CONNECTING) {
        SetProxyChannelState(proxyConnection, PROXY_CHANNEL_DISCONNECTED);
        g_listener.onProxyChannelDisconnected(&proxyConnection->proxyChannel, reason);
    } else {
        NotifyConnectFailed(proxyConnection->proxyChannel.brMac, reason);
    }
    RemoveProxyChannelByChannelId(channelId);
    proxyConnection->dereference(proxyConnection);
}

static void OnProxyChannelDisconnected(uint32_t channelId, int32_t reason)
{
    ProxyChannelNotifyContext *ctx = (ProxyChannelNotifyContext *)SoftBusCalloc(sizeof(ProxyChannelNotifyContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_PROXY, "on connect failed, calloc error context failed");
    ctx->channelId = channelId;
    ctx->status = reason;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_CLOSE_PROXY_DISCONNECT, 0, 0, ctx, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "send msg failed, error=%{public}d", ret);
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
    // notify upper reconnect success
    g_listener.onProxyChannelReconnected(channel->brMac, channel);
}

static void OnInnerReConnectFail(uint32_t requestId, int32_t reason)
{
    CONN_LOGE(CONN_PROXY, "requestId=%{public}u, reason=%{public}d", requestId, reason);
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

static void AttemptReconnectDevice(char *brAddr)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, brAddr, BT_MAC_LEN);
    ProxyConnectInfo *reconnectDeviceInfo = GetReconnectDeviceInfoByAddrUnsafe(brAddr);
    CONN_CHECK_AND_RETURN_LOGW(reconnectDeviceInfo != NULL, CONN_PROXY,
        "not exit same addr=%{public}s need to reconnect", anomizeAddress);
    CONN_CHECK_AND_RETURN_LOGW(reconnectDeviceInfo->isAclConnected, CONN_PROXY, "acl is disconnect not retry");
    bool isAlreadyConnected = IsTargetDeviceAlreadyConnected(brAddr);
    CONN_CHECK_AND_RETURN_LOGI(!isAlreadyConnected, CONN_PROXY, "exist already connection");

    ProxyConnectInfo *proxyChannelRequestInfo = CopyProxyConnectInfo(reconnectDeviceInfo);
    CONN_CHECK_AND_RETURN_LOGW(proxyChannelRequestInfo != NULL, CONN_PROXY, "CopyProxyConnectInfo failed");

    proxyChannelRequestInfo->result.onOpenSuccess = OnInnerReConnectSuccess;
    proxyChannelRequestInfo->result.onOpenFail = OnInnerReConnectFail;
    proxyChannelRequestInfo->isInnerRequest = true;
    proxyChannelRequestInfo->timeoutMs = INNER_RECONNECT_TIMEOUT_MS;
    CONN_LOGI(CONN_PROXY, "start reconnect requestId=%{public}u, addr=%{public}s",
        proxyChannelRequestInfo->requestId, anomizeAddress);
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL,
        0, 0, proxyChannelRequestInfo, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "post msg failed=%{public}d", ret);
        DestoryProxyConnectInfo(&proxyChannelRequestInfo);
    }
}

static void AclStateChangedHandler(ProxyChannelAclStateContext *context)
{
    ProxyConnectInfo *reconnectDeviceInfo = GetReconnectDeviceInfoByAddrUnsafe(context->brMac);
    CONN_CHECK_AND_RETURN_LOGW(reconnectDeviceInfo != NULL, CONN_PROXY, "no reconnect device");
    reconnectDeviceInfo->isAclConnected = (context->state == SOFTBUS_ACL_STATE_CONNECTED) ? true : false;
}

static void ProxyResetHandler(void)
{
    ProxyConnectInfo *connectingChannel = GetProxyChannelManager()->proxyChannelRequestInfo;
    if (connectingChannel != NULL) {
        connectingChannel->result.onOpenFail(connectingChannel->requestId, SOFTBUS_CONN_BLUETOOTH_OFF);
        DestoryProxyConnectInfo(&GetProxyChannelManager()->proxyChannelRequestInfo);
    }
    ListNode notifyConnectionList;
    ListInit(&notifyConnectionList);
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY, "lock proxyConnectionList failed");
    struct ProxyConnection *item = NULL;
    struct ProxyConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &GetProxyChannelManager()->proxyConnectionList->list,
        struct ProxyConnection, node) {
        ListDelete(&item->node);
        ListAdd(&notifyConnectionList, &item->node);
    }
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &notifyConnectionList, struct ProxyConnection, node) {
        ListDelete(&item->node);
        if (GetProxyChannelState(item) != PROXY_CHANNEL_CONNECTING) {
            SetProxyChannelState(item, PROXY_CHANNEL_DISCONNECTED);
            CONN_LOGW(CONN_PROXY, "bluetooth off, notify disconnected, channelId=%{public}u", item->channelId);
            g_listener.onProxyChannelDisconnected(&item->proxyChannel, SOFTBUS_CONN_BLUETOOTH_OFF);
        }
        item->dereference(item);
    }
}

static void OnProxyAclStateChanged(
    int32_t listenerId, const SoftBusBtAddr *btAddr, int32_t aclState, int32_t hciReason)
{
    CONN_CHECK_AND_RETURN_LOGW((aclState == SOFTBUS_ACL_STATE_CONNECTED || aclState == SOFTBUS_ACL_STATE_DISCONNECTED),
        CONN_PROXY, "ignore state=%{public}d", aclState);
    CONN_CHECK_AND_RETURN_LOGW(btAddr != NULL, CONN_PROXY, "addr is null");
    char address[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(address, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    CONN_CHECK_AND_RETURN_LOGE(status == SOFTBUS_OK, CONN_PROXY, "convert binary mac address to string failed");
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);
    CONN_LOGW(CONN_PROXY, "state=%{public}d, addr=%{public}s", aclState, anomizeAddress);
    ProxyChannelAclStateContext *context =
        (ProxyChannelAclStateContext *)SoftBusCalloc(sizeof(ProxyChannelAclStateContext));
    if (context == NULL || strcpy_s(context->brMac, BT_MAC_LEN, address) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr failed");
        SoftBusFree(context);
        return;
    }
    context->state = aclState;
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_ACL_STATE_CHANGE, 0, 0, context, 0);
    if (ret < 0) {
        CONN_LOGE(CONN_PROXY, "post msg failed=%{public}d", ret);
        SoftBusFree(context);
    }
}

static void OnHfpConnectionStateChanged(const char *addr, int32_t state)
{
    CONN_CHECK_AND_RETURN_LOGW(state == SOFTBUS_HFP_CONNECTED, CONN_PROXY, "ignore state=%{public}d", state);
    CONN_LOGI(CONN_PROXY, "state=%{public}d", state);
    CONN_CHECK_AND_RETURN_LOGW(addr != NULL, CONN_PROXY, "addr is NULL");
    char *copyAddr = (char *)SoftBusCalloc(BT_MAC_LEN);
    if (copyAddr == NULL || strncpy_s(copyAddr, BT_MAC_LEN, addr, BT_MAC_LEN - 1) != EOK) {
        CONN_LOGE(CONN_PROXY, "copyAddr failed");
        SoftBusFree(copyAddr);
        return;
    }
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_OPEN_PROXY_CHANNEL_RETRY, 0, 0, copyAddr, 0);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "post msg failed=%{public}d", ret);
        SoftBusFree(copyAddr);
        return;
    }
}

static void OnProxyBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    CONN_CHECK_AND_RETURN_LOGW(state == SOFTBUS_BR_STATE_TURN_OFF, CONN_PROXY, "ignore state=%{public}d", state);
    int32_t ret = ConnPostMsgToLooper(&g_proxyChannelAsyncHandler, MSG_PROXY_RESET, 0, 0, 0, 0);
    CONN_LOGI(CONN_PROXY, "post msg status=%{public}d", ret);
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
            ProxyChannelCloseHandler((char *)msg->obj);
            break;
        case MSG_CLOSE_PROXY_DISCONNECT:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            ProxyChannelDisconnectHandler((ProxyChannelNotifyContext *)msg->obj);
            break;
        case MSG_ACL_STATE_CHANGE:
            CONN_CHECK_AND_RETURN_LOGW(msg->obj != NULL, CONN_PROXY, "msg->obj is NULL");
            AclStateChangedHandler((ProxyChannelAclStateContext *)msg->obj);
            break;
        case MSG_PROXY_RESET:
            ProxyResetHandler();
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
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_PROXY, "failed to avoid fault silence, "
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
        CONN_INIT, "create channels list failed");
    ListInit(&(GetProxyChannelManager()->reconnectDeviceInfos));

    g_proxyChannelAsyncHandler.handler.looper = GetLooper(LOOP_TYPE_CONN);
    if (g_proxyChannelAsyncHandler.handler.looper == NULL) {
        CONN_LOGE(CONN_PROXY, "init conn ble looper failed");
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
        CONN_LOGE(CONN_PROXY, "add bt listener failed, listenerId=%{public}d", listenerId);
        DestroySoftBusList(g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    ret = RegisterHfpListener(OnHfpConnectionStateChanged);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "register hfp listener failed, ret=%{public}d", ret);
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