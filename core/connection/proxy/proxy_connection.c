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
#include "proxy_connection.h"

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_socket.h"
#include "conn_event.h"
#include "conn_event_form.h"
#include "conn_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "wrapper_br_interface.h"

typedef struct {
    uint32_t channelId;
    ProxyBrConnectStateCallback callback;
} ProxyBrConnectContext;

static SppSocketDriver *g_sppDriver = NULL;
ProxyEventListener g_eventListener = { 0 };

static int32_t LegacyBrLoopRead(struct ProxyConnection *connection)
{
#define BUFFER_SIZE (1024 * 2)
    uint8_t *buffer = (uint8_t *)SoftBusCalloc(BUFFER_SIZE);
    CONN_CHECK_AND_RETURN_RET_LOGE(buffer != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "create buffer fail");
    uint32_t channelId = connection->channelId;
    int32_t ret = SOFTBUS_OK;
    while (true) {
        ret = SoftBusMutexLock(&connection->lock);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_PROXY, "get lock fail, channelId=%{public}u, err=%{public}d", channelId, ret);
            ret = SOFTBUS_LOCK_ERR;
            break;
        }
        int32_t socketHandle = connection->socketHandle;
        (void)SoftBusMutexUnlock(&connection->lock);
        if (socketHandle == BR_INVALID_SOCKET_HANDLE) {
            ret = BR_INVALID_SOCKET_HANDLE;
            break;
        }
        int32_t recvLen = g_sppDriver->Read(socketHandle, buffer, BUFFER_SIZE);
        if (recvLen == BR_READ_SOCKET_CLOSED) {
            CONN_LOGW(CONN_PROXY,
                "br connection read return, connection closed, channelId=%{public}u, socketHandle=%{public}d",
                channelId, socketHandle);
            ret = SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED;
            break;
        }
        if (recvLen < 0) {
            CONN_LOGE(CONN_PROXY,
                "br connection read return, channelId=%{public}u, socketHandle=%{public}d, error=%{public}d", channelId,
                socketHandle, recvLen);
            ret = SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL;
            break;
        }
        g_eventListener.onDataReceived(channelId, buffer, recvLen);
    }
    SoftBusFree(buffer);
    if (ret != SOFTBUS_OK) {
        char anomizeAddress[BT_MAC_LEN] = { 0 };
        ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->brMac, BT_MAC_LEN);
        ConnEventExtra extra = {
            .peerBrMac = anomizeAddress,
            .connectionId = (int32_t)connection->socketHandle,
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
        };
        CONN_EVENT(EVENT_STAGE_BR_PROXY, EVENT_STAGE_CONNECT_DISCONNECTED, extra);
    }
    return ret;
}

static void BrConnectCallback(const BdAddr *bdAddr, BtUuid uuid, int32_t status, int32_t result)
{
    (void)bdAddr;
    (void)uuid;
    (void)status;
    (void)result;
}

static int32_t StartClientConnect(struct ProxyConnection *connection)
{
    uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };
    int32_t ret = ConvertBtMacToBinary(connection->brMac, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
        ret, CONN_PROXY, "convert btMac to binary fail, error=%{public}d", ret);
    BtSocketConnectionCallback callback = {
        .connStateCb = BrConnectCallback,
    };
    (void)g_sppDriver->UpdatePriority(binaryAddr, CONN_BR_CONNECT_PRIORITY_NO_REFUSE_FREQUENT_CONNECT);
    int32_t socketHandle = g_sppDriver->Connect(connection->proxyChannel.uuid, binaryAddr, &callback);
    if (socketHandle < 0) {
        CONN_LOGE(CONN_PROXY, "connect fail, socketHandle=%{public}d", socketHandle);
        char anomizeAddress[BT_MAC_LEN] = { 0 };
        ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->brMac, BT_MAC_LEN);
        ConnEventExtra extra = {
            .peerBrMac = anomizeAddress,
            .connectionId = (int32_t)connection->socketHandle,
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL,
        };
        CONN_EVENT(EVENT_STAGE_BR_PROXY, EVENT_STAGE_CONNECT_START, extra);
        return SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL;
    }
    if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "get lock fail, connId=%{public}u", connection->channelId);
        g_sppDriver->DisConnect(socketHandle);
        return SOFTBUS_LOCK_ERR;
    }

    if (connection->state != PROXY_CHANNEL_CONNECTING) {
        CONN_LOGE(CONN_PROXY,
            "channelId=%{public}u, unexpectedState=%{public}d", connection->channelId, connection->state);
        g_sppDriver->DisConnect(socketHandle);
        connection->state = PROXY_CHANNEL_DISCONNECTED;
        (void)SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
    }
    connection->socketHandle = socketHandle;
    (void)SoftBusMutexUnlock(&connection->lock);
    CONN_LOGI(CONN_PROXY, "connect success, socketHandle=%{public}d", socketHandle);
    return SOFTBUS_OK;
}

static void *ProxyBrClientConnect(void *data)
{
    const char *name = "Proxy_Conn";
    SoftBusThread threadSelf = SoftBusThreadGetSelf();
    SoftBusThreadSetName(threadSelf, name);
    ProxyBrConnectContext *ctx = (ProxyBrConnectContext *)(data);
    CONN_CHECK_AND_RETURN_RET_LOGW(ctx != NULL, NULL, CONN_PROXY, "ctx is null");
    uint32_t channelId = ctx->channelId;
    ProxyBrConnectStateCallback callback = ctx->callback;
    SoftBusFree(data);
    CONN_CHECK_AND_RETURN_RET_LOGE(callback.onConnectSuccess != NULL, NULL, CONN_PROXY,
        "onConnectSuccess is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback.onConnectFail != NULL, NULL, CONN_PROXY,
        "onConnectFail is null");
    struct ProxyConnection *connection = GetProxyChannelManager()->getConnectionById(channelId);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        connection != NULL, NULL, CONN_PROXY, "connection is null, channelId=%{public}u", channelId);
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_PROXY,
        "start legacy br connect, channelId=%{public}u, addr=%{public}s", channelId, anomizeAddress);
    int32_t ret = SOFTBUS_OK;
    do {
        ret = StartClientConnect(connection);
        if (ret != SOFTBUS_OK) {
            callback.onConnectFail(connection->channelId, ret);
            break;
        }
        callback.onConnectSuccess(connection->channelId);
        ret = LegacyBrLoopRead(connection);
        CONN_LOGW(CONN_PROXY, "client loop read exit, channelId=%{public}u, socketHandle=%{public}d, error=%{public}d",
            connection->channelId, connection->socketHandle, ret);
        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CONN_LOGE(CONN_PROXY, "lock connection fail, channelId=%{public}u", connection->channelId);
            g_sppDriver->DisConnect(connection->socketHandle);
            g_eventListener.onDisconnected(connection->channelId, SOFTBUS_LOCK_ERR);
            break;
        }
        if (connection->socketHandle != BR_INVALID_SOCKET_HANDLE) {
            g_sppDriver->DisConnect(connection->socketHandle);
            connection->socketHandle = BR_INVALID_SOCKET_HANDLE;
        }
        connection->state = PROXY_CHANNEL_DISCONNECTED;
        (void)SoftBusMutexUnlock(&connection->lock);
        g_eventListener.onDisconnected(connection->channelId, ret);
    } while (false);
    connection->dereference(connection);
    return NULL;
}

int32_t ProxyBrConnect(struct ProxyConnection *connection, const ProxyBrConnectStateCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY,
        "connection is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY,
        "callback is null");
    ProxyBrConnectContext *ctx = (ProxyBrConnectContext *)SoftBusCalloc(sizeof(ProxyBrConnectContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_LOCK_ERR, CONN_PROXY,
        "calloc fail, connId=%{public}u", connection->channelId);
    ctx->channelId = connection->channelId;
    ctx->callback = *callback;
    int32_t ret = ConnStartActionAsync(ctx, ProxyBrClientConnect, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "start connect thread fail, connId=%{public}u, error=%{public}d",
            connection->channelId, ret);
        SoftBusFree(ctx);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t Disconnect(struct ProxyConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL,
                                   SOFTBUS_INVALID_PARAM, CONN_PROXY, "connection is null");
    int32_t ret = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY,
        "br disconnect lock fail, connId=%{public}u, error=%{public}d", connection->channelId, ret);
    int32_t socketHandle = connection->socketHandle;
    if (connection->socketHandle == BR_INVALID_SOCKET_HANDLE) {
        connection->state = PROXY_CHANNEL_DISCONNECTED;
        SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_OK;
    }
    connection->socketHandle = BR_INVALID_SOCKET_HANDLE;
    connection->state = PROXY_CHANNEL_DISCONNECTED;
    SoftBusMutexUnlock(&connection->lock);
    // ensure that the underlayer schedules read/write before disconnection
    SoftBusSleepMs(WAIT_DISCONNECT_TIME_MS);
    return g_sppDriver->DisConnect(socketHandle);
}

static int32_t Send(struct ProxyConnection *connection, const uint8_t *data, uint32_t dataLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL,
                                   SOFTBUS_INVALID_PARAM, CONN_PROXY, "connection is null");
    int32_t ret = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY,
        "lock connection fail, channelId=%{public}u, error=%{public}d", connection->channelId, ret);
    if (connection->state != PROXY_CHANNEL_CONNECTED) {
        CONN_LOGE(CONN_PROXY, "connection is not ready, currentState=%{public}d", connection->state);
        SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusMutexUnlock(&connection->lock);

    int32_t waitWriteLen = (int32_t)dataLen;
    while (waitWriteLen > 0) {
        int32_t ret = SoftBusMutexLock(&connection->lock);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
        int32_t socketHandle = connection->socketHandle;
        SoftBusMutexUnlock(&connection->lock);

        if (socketHandle == BR_INVALID_SOCKET_HANDLE) {
            CONN_LOGE(CONN_PROXY, "invalid handle");
            return SOFTBUS_INVALID_PARAM;
        }
        int32_t written = g_sppDriver->Write(socketHandle, data, waitWriteLen);
        if (written < 0) {
            CONN_LOGE(CONN_PROXY,
                "send data fail, channelId=%{public}u, totalLen=%{public}u, waitWriteLen=%{public}d, "
                "alreadyWriteLen=%{public}d, error=%{public}d",
                connection->channelId, dataLen, waitWriteLen, dataLen - waitWriteLen, written);
            char anomizeAddress[BT_MAC_LEN] = { 0 };
            ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->brMac, BT_MAC_LEN);
            ConnEventExtra extra = {
                .peerBrMac = anomizeAddress,
                .connectionId = (int32_t)connection->socketHandle,
                .result = EVENT_STAGE_RESULT_FAILED,
                .errcode = SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL,
            };
            CONN_EVENT(EVENT_STAGE_BR_PROXY, EVENT_STAGE_CONNECT_SEND_BASIC_INFO, extra);
            return SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL;
        }
        data += written;
        waitWriteLen -= written;
    }
    return SOFTBUS_OK;
}

int32_t RegisterEventListener(const ProxyEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onDisconnected != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onDisconnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onDataReceived is null");
    g_eventListener = *listener;
    g_sppDriver = InitSppSocketDriver();
    CONN_CHECK_AND_RETURN_RET_LOGE(g_sppDriver != NULL, SOFTBUS_CONN_PROXY_INTERNAL_ERR, CONN_INIT,
        "init spp socket driver fail");
    return SOFTBUS_OK;
}

ProxyBrConnectionManager g_proxyBrConnection = {
    .connect = ProxyBrConnect,
    .disconnect = Disconnect,
    .send = Send,
    .registerEventListener = RegisterEventListener,
};

ProxyBrConnectionManager *GetProxyBrConnectionManager(void)
{
    return &g_proxyBrConnection;
}