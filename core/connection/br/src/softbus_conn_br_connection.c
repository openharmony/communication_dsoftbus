/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_conn_br_connection.h"

#include "securec.h"

#include "bus_center_decision_center.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_common.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define UUID "8ce255c0-200a-11e0-ac64-0800200c9a66"

typedef struct {
    int32_t socketHandle;
} ServerServeContext;

typedef struct {
    uint32_t connectionId;
} ClientConnectContext;

typedef struct {
    uint32_t traceId;
    // protect variable access below
    SoftBusMutex mutex;
    bool available;
    int32_t serverId;
} ServerState;

enum BrConnectionLooperMsgType {
    MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT = 100,
    MSG_CONNECTION_RETRY_NOTIFY_REFERENCE,
    MSG_CONNECTION_REPORT_CONNECT_EXCEPTION,
};

static void BrConnectionMsgHandler(SoftBusMessage *msg);
static int BrCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args);

static ConnBrEventListener g_eventListener = { 0 };
static SppSocketDriver *g_sppDriver = NULL;
static ServerState *g_serverState = NULL;
static SoftBusHandlerWrapper g_brConnectionAsyncHandler = {
    .handler = {
        .name = (char *)"BrConnectionAsyncHandler",
        .HandleMessage = BrConnectionMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BrCompareConnectionLooperEventFunc,
};

static int32_t g_readBufferCapacity = -1;
static int32_t g_mtuSize = -1;
static int32_t LoopRead(uint32_t connectionId, int32_t socketHandle)
{
    LimitedBuffer *buffer = NULL;
    int32_t status = ConnNewLimitedBuffer(&buffer, g_readBufferCapacity);
    if (status != SOFTBUS_OK) {
        return status;
    }

    while (true) {
        uint8_t *data = NULL;
        int32_t dataLen = ConnBrTransReadOneFrame(connectionId, socketHandle, buffer, &data);
        if (dataLen < 0) {
            status = dataLen;
            break;
        }
        g_eventListener.onDataReceived(connectionId, data, dataLen);
    }
    ConnDeleteLimitedBuffer(&buffer);
    return status;
}

static void BrConnectStatusCallback(const char *addr, int32_t result, int32_t status)
{
    uint64_t u64Mac = 0;
    if (result != SOFTBUS_OK && ConvertBtMacToU64(addr, BT_MAC_LEN, &u64Mac) == SOFTBUS_OK) {
        ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_REPORT_CONNECT_EXCEPTION,
            u64Mac, result, NULL, 0);
    }
    ConnBrConnection *connection = ConnBrGetConnectionByAddr(addr, CONN_SIDE_CLIENT);
    if (connection == NULL) {
        CLOGE("connection not exist, addr %02X:%02X:***%02X, result = %d, status = %d",
            addr[MAC_FIRST_INDEX], addr[MAC_ONE_INDEX], addr[MAC_FIVE_INDEX], result, status);
        return;
    }
    BrUnderlayerStatus *callbackStatus = (BrUnderlayerStatus *)SoftBusCalloc(sizeof(BrUnderlayerStatus));
    if (callbackStatus == NULL) {
        CLOGE("calloc failed, connection id = %u", connection->connectionId);
        ConnBrReturnConnection(&connection);
        return;
    }
    ListInit(&callbackStatus->node);
    callbackStatus->status = status;
    callbackStatus->result = result;
    ListAdd(&connection->connectProcessStatus->list, &callbackStatus->node);
    CLOGD("br on client connected callback, connection id = %u, result = %d, status = %d", connection->connectionId,
        result, status);
    ConnBrReturnConnection(&connection);
}

static void *StartClientConnect(void *connectCtx)
{
    ClientConnectContext *ctx = (ClientConnectContext *)connectCtx;
    uint32_t connectionId = ctx->connectionId;
    SoftBusFree(ctx);
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("connection not exist, conn id=%u", connectionId);
        g_eventListener.onClientConnectFailed(connectionId, SOFTBUS_CONN_BR_INTERNAL_ERR);
        return NULL;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CLOGI("conn id=%u, address=%s", connectionId, anomizeAddress);
    do {
        uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };
        int32_t status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
        if (status != SOFTBUS_OK) {
            CLOGE("convert string mac to binary fail, conn id=%u, address=%s, error=%d",
                connection->connectionId, anomizeAddress, status);
            g_eventListener.onClientConnectFailed(connection->connectionId, SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR);
            break;
        }
        int32_t socketHandle = g_sppDriver->Connect(UUID, binaryAddr);
        if (socketHandle == INVALID_SOCKET_HANDLE) {
            CLOGE("underlayer bluetooth connect failed, conn id=%u, address=%s",
                connection->connectionId, anomizeAddress);
            g_eventListener.onClientConnectFailed(connection->connectionId, SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL);
            break;
        }
        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CLOGE("get lock failed, conn id=%u, address=%s", connection->connectionId, anomizeAddress);
            g_sppDriver->DisConnect(socketHandle);
            g_eventListener.onClientConnectFailed(connection->connectionId, SOFTBUS_LOCK_ERR);
            break;
        }
        if (connection->state != BR_CONNECTION_STATE_CONNECTING) {
            CLOGE("unexpected state, conn id=%u, address=%s, state=%d",
                connection->connectionId, anomizeAddress, connection->state);
            g_sppDriver->DisConnect(socketHandle);
            connection->state = BR_CONNECTION_STATE_CLOSED;
            (void)SoftBusMutexUnlock(&connection->lock);
            g_eventListener.onClientConnectFailed(connection->connectionId, SOFTBUS_CONN_BR_INTERNAL_ERR);
            break;
        }
        connection->socketHandle = socketHandle;
        connection->state = BR_CONNECTION_STATE_CONNECTED;
        (void)SoftBusMutexUnlock(&connection->lock);

        CLOGI("connect ok, id=%u, address=%s, socket=%d", connection->connectionId, anomizeAddress, socketHandle);
        g_eventListener.onClientConnected(connection->connectionId);
        status = LoopRead(connection->connectionId, socketHandle);
        CLOGD("br client loop read exit, connection id=%u, address=%s, socket handle=%d, error=%d",
            connection->connectionId, anomizeAddress, socketHandle, status);

        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CLOGE("get lock failed, conn id=%u, address=%s", connection->connectionId, anomizeAddress);
            g_eventListener.onConnectionException(connection->connectionId, SOFTBUS_LOCK_ERR);
            break;
        }
        if (connection->socketHandle != INVALID_SOCKET_HANDLE) {
            g_sppDriver->DisConnect(connection->socketHandle);
            connection->socketHandle = INVALID_SOCKET_HANDLE;
        }
        connection->state = (status == SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED ? BR_CONNECTION_STATE_CLOSED :
                                                                                BR_CONNECTION_STATE_EXCEPTION);
        (void)SoftBusMutexUnlock(&connection->lock);
        g_eventListener.onConnectionException(connection->connectionId, status);
    } while (false);
    ConnBrReturnConnection(&connection);
    return NULL;
}

static void *StartServerServe(void *serveCtx)
{
    ServerServeContext *ctx = (ServerServeContext *)serveCtx;
    int32_t socketHandle = ctx->socketHandle;
    SoftBusFree(ctx);
    BluetoothRemoteDevice remote;
    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    int32_t status = g_sppDriver->GetRemoteDeviceInfo(socketHandle, &remote);
    if (status != SOFTBUS_OK) {
        CLOGE("GetRemoteDeviceInfo failed, socket=%u, error=%d", socketHandle, status);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    char mac[BT_MAC_LEN] = { 0 };
    status = ConvertBtMacToStr(mac, BT_MAC_LEN, (uint8_t *)remote.mac, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("ConvertBtMacToStr failed, socket=%u, error=%d", socketHandle, status);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_SERVER, socketHandle);
    if (connection == NULL) {
        CLOGE("create connection failed, socket=%u, error=%d", socketHandle, status);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    status = ConnBrSaveConnection(connection);
    if (status != SOFTBUS_OK) {
        CLOGE("ConnBrSaveConnection failed, socket=%u, error=%d", socketHandle, status);
        g_sppDriver->DisConnect(socketHandle);
        ConnBrFreeConnection(connection);
        return NULL;
    }
    do {
        CLOGI("conn id=%u, socket=%d", connection->connectionId, socketHandle);
        g_eventListener.onServerAccepted(connection->connectionId);
        status = LoopRead(connection->connectionId, socketHandle);
        CLOGD("loop read exit, conn id=%u, socket=%d, status=%d", connection->connectionId, socketHandle, status);

        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CLOGE("get lock failed, conn id=%u, socket=%d", connection->connectionId, socketHandle);
            g_sppDriver->DisConnect(socketHandle);
            g_eventListener.onConnectionException(connection->connectionId, SOFTBUS_LOCK_ERR);
            break;
        }
        if (connection->socketHandle != INVALID_SOCKET_HANDLE) {
            g_sppDriver->DisConnect(socketHandle);
            connection->socketHandle = INVALID_SOCKET_HANDLE;
        }
        connection->state = (status == SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED ? BR_CONNECTION_STATE_CLOSED :
                                                                                BR_CONNECTION_STATE_EXCEPTION);
        (void)SoftBusMutexUnlock(&connection->lock);
        g_eventListener.onConnectionException(connection->connectionId, status);
    } while (false);
    ConnBrReturnConnection(&connection);
    return NULL;
}

ConnBrConnection *ConnBrCreateConnection(const char *addr, ConnSideType side, int32_t socketHandle)
{
    CONN_CHECK_AND_RETURN_RET_LOG(addr != NULL, NULL, "br creat connection: addr is NULL");
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, NULL, "calloc br conn failed");
    SoftBusList *list = CreateSoftBusList();
    if (list == NULL) {
        CLOGE("create softbus list failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->connectProcessStatus = list;
    ListInit(&connection->node);
    // the final connectionId value is allocate on saving global
    connection->connectionId = 0;
    connection->side = side;
    if (strcpy_s(connection->addr, BT_MAC_LEN, addr) != EOK) {
        CLOGE("copy address failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->mtu = (uint32_t)g_mtuSize;
    if (SoftBusMutexInit(&connection->lock, NULL) != SOFTBUS_OK) {
        CLOGE("init lock failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->socketHandle = socketHandle;
    connection->state = (side == CONN_SIDE_CLIENT ? BR_CONNECTION_STATE_CONNECTING : BR_CONNECTION_STATE_CONNECTED);
    // br connection do not need exchange connection reference when establish first time, so the init value is 1
    connection->connectionRc = 1;
    connection->objectRc = 1;
    connection->window = DEFAULT_WINDOW;
    connection->sequence = 0;
    connection->waitSequence = 0;
    connection->ackTimeoutCount = 0;
    return connection;
}

void ConnBrFreeConnection(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOG(connection != NULL, "br free connection: connection is NULL");
    if (connection->connectProcessStatus == NULL) {
        CLOGE("connectProcessStatus is NULL");
        SoftBusFree(connection);
        return;
    }
    SoftBusMutexDestroy(&connection->lock);
    BrUnderlayerStatus *item = NULL;
    BrUnderlayerStatus *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &connection->connectProcessStatus->list, BrUnderlayerStatus, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    DestroySoftBusList(connection->connectProcessStatus);
    SoftBusFree(connection);
}

// connect peer as client
int32_t ConnBrConnect(ConnBrConnection *connection)
{
    ClientConnectContext *ctx = (ClientConnectContext *)SoftBusCalloc(sizeof(ClientConnectContext));
    CONN_CHECK_AND_RETURN_RET_LOG(ctx != NULL, SOFTBUS_LOCK_ERR,
        "br client connect: calloc failed, conn id=%u", connection->connectionId);
    ctx->connectionId = connection->connectionId;
    int32_t status = ConnStartActionAsync(ctx, StartClientConnect);
    if (status != SOFTBUS_OK) {
        CLOGE("start connect thread failed, conn id=%u, error=%d", connection->connectionId, status);
        SoftBusFree(ctx);
        return status;
    }
    return SOFTBUS_OK;
}

int32_t ConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "br update connection ref: lock failed, conn id=%u, delta=%d", connection->connectionId, delta);
    connection->connectionRc += delta;
    int32_t localRc = connection->connectionRc;
    CLOGI("conn id=%u, side=%d, delta=%d, new ref=%d", connection->connectionId, connection->side, delta, localRc);
    if (localRc <= 0) {
        connection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
        ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
            connection->connectionId, 0, NULL, WAIT_BR_NEGOTIATION_CLOSING_TIMEOUT_MILLIS);
    }
    (void)SoftBusMutexUnlock(&connection->lock);

    int32_t flag = delta >= 0 ? CONN_HIGH : CONN_LOW;
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connection->connectionId,
        .flag = flag,
        .method = BR_METHOD_NOTIFY_REQUEST,
        .referenceRequest = {
            .delta = delta,
            .referenceNumber = localRc,
        },
    };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    if (seq < 0) {
        CLOGE("connection %u request message failed, ret=%d", connection->connectionId, (int32_t)seq);
        return (int32_t)seq;
    }
    return ConnBrPostBytes(connection->connectionId, data, dataLen, 0, flag, MODULE_CONNECTION, seq);
}

int32_t ConnBrDisconnectNow(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "br disconnect now: lock failed, conn id=%u", connection->connectionId);
    int32_t status = SOFTBUS_OK;
    if (connection->socketHandle != INVALID_SOCKET_HANDLE) {
        status = g_sppDriver->DisConnect(connection->socketHandle);
        connection->socketHandle = INVALID_SOCKET_HANDLE;
    }
    connection->state = BR_CONNECTION_STATE_CLOSED;
    SoftBusMutexUnlock(&connection->lock);
    return status;
}

int32_t ConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json)
{
    int32_t delta = 0;
    int32_t peerRc = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_DELTA, &delta) ||
        !GetJsonObjectSignedNumberItem(json, KEY_REFERENCE_NUM, &peerRc)) {
        CLOGE("connection %u: parse delta or ref failed, delta=%d, peerRc=%d",
            connection->connectionId, delta, peerRc);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("connection %u: lock failed, error=%d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    connection->connectionRc += delta;
    int32_t localRc = connection->connectionRc;

    CLOGI("conn id=%u, delta=%d, peerRc=%d, localRc=%d", connection->connectionId, delta, peerRc, localRc);
    if (peerRc > 0) {
        if (localRc == 0) {
            ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_RETRY_NOTIFY_REFERENCE,
                connection->connectionId, 0, NULL, RETRY_NOTIFY_REFERENCE_DELAY_MILLIS);
        }
        (void)SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_OK;
    }
    if (localRc <= 0) {
        connection->state = BR_CONNECTION_STATE_CLOSING;
        (void)SoftBusMutexUnlock(&connection->lock);
        ConnBrDisconnectNow(connection);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&connection->lock);

    int32_t flag = CONN_HIGH;
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connection->connectionId,
        .flag = flag,
        .method = BR_METHOD_NOTIFY_RESPONSE,
        .referenceResponse = {
            .referenceNumber = localRc,
        },
    };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    if (seq < 0) {
        CLOGE("connection %u reply message faild, ret=%d", connection->connectionId, (int32_t)seq);
        return (int32_t)seq;
    }
    return ConnBrPostBytes(connection->connectionId, data, dataLen, 0, flag, MODULE_CONNECTION, seq);
}

int32_t ConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json)
{
    int32_t peerRc = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_REFERENCE_NUM, &peerRc)) {
        CLOGE("connection %u: parse delta or ref failed", connection->connectionId);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("connection %u: get lock failed, error=%d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }

    CLOGI(
        "connection %u: peerRc=%d, localRc=%d, current state=%d",
        connection->connectionId, peerRc, connection->connectionRc, connection->state);
    if (peerRc > 0 && connection->state == BR_CONNECTION_STATE_CLOSING) {
        ConnRemoveMsgFromLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
            connection->connectionId, 0, NULL);
        connection->state = BR_CONNECTION_STATE_CONNECTED;
        g_eventListener.onConnectionResume(connection->connectionId);
    }
    (void)SoftBusMutexUnlock(&connection->lock);
    return SOFTBUS_OK;
}

static void *ListenTask(void *arg)
{
#define BR_ACCEPET_WAIT_TIME 1000
    ServerState *serverState = (ServerState *)arg;
    CLOGI("trace id=%u", serverState->traceId);
    const char *name = "BrManagerInsecure";
    int32_t status = SOFTBUS_OK;
    while (true) {
        status = SoftBusMutexLock(&serverState->mutex);
        if (status != SOFTBUS_OK) {
            CLOGE("lock failed, exit listen task, trace id=%u, error=%d", serverState->traceId, status);
            break;
        }
        if (!serverState->available) {
            CLOGW("server closed, exit listen task, trace id=%u", serverState->traceId);
            SoftBusMutexUnlock(&serverState->mutex);
            break;
        }
        if (serverState->serverId != -1) {
            g_sppDriver->CloseSppServer(serverState->serverId);
            serverState->serverId = -1;
        }
        (void)SoftBusMutexUnlock(&serverState->mutex);
        int32_t serverId = g_sppDriver->OpenSppServer(name, strlen(name), UUID, 0);
        if (serverId == -1) {
            CLOGE("open br server failed, trace id=%u, retry after %d ms", serverState->traceId, BR_ACCEPET_WAIT_TIME);
            SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
            continue;
        }
        CLOGI("open br server ok, trace id=%u, server id=%d", serverState->traceId, serverId);
        status = SoftBusMutexLock(&serverState->mutex);
        if (status != SOFTBUS_OK) {
            CLOGE("lock failed, exit listen task, trace id=%u, error=%d", serverState->traceId, status);
            g_sppDriver->CloseSppServer(serverId);
            break;
        }
        if (!serverState->available) {
            CLOGW("server closed during create socket period, exit listen task trace id=%u", serverState->traceId);
            g_sppDriver->CloseSppServer(serverId);
            break;
        }
        serverState->serverId = serverId;
        (void)SoftBusMutexUnlock(&serverState->mutex);
        while (true) {
            int32_t socketHandle = g_sppDriver->Accept(serverId);
            if (socketHandle == SOFTBUS_ERR) {
                CLOGE("accept failed, trace id=%u, server id:%d", serverState->traceId, serverId);
                break;
            }
            ServerServeContext *ctx = (ServerServeContext *)SoftBusCalloc(sizeof(ServerServeContext));
            if (ctx == NULL) {
                CLOGE("calloc serve context failed, trace id=%u, server id=%d, socket handle=%d",
                    serverState->traceId, serverId, socketHandle);
                g_sppDriver->DisConnect(socketHandle);
                continue;
            }
            ctx->socketHandle = socketHandle;
            status = ConnStartActionAsync(ctx, StartServerServe);
            if (status != SOFTBUS_OK) {
                CLOGE("start serve thread failed, trace id=%u, server id=%d, socket=%d, error=%d",
                    serverState->traceId, serverId, socketHandle, status);
                SoftBusFree(ctx);
                g_sppDriver->DisConnect(socketHandle);
                continue;
            }
            CLOGI("accept incoming connection, trace id=%u, server id=%d, socket=%d",
                serverState->traceId, serverId, socketHandle);
        }
    }
    CLOGI("br server listen exit, trace id=%u", serverState->traceId);
    (void)SoftBusMutexDestroy(&serverState->mutex);
    SoftBusFree(serverState);
    return NULL;
}

int32_t ConnBrStartServer(void)
{
    static uint32_t traceIdGenerator = 0;

    if (g_serverState != NULL) {
        CLOGW("server already started, skip");
        return SOFTBUS_OK;
    }
    ServerState *serverState = (ServerState *)SoftBusCalloc(sizeof(ServerState));
    CONN_CHECK_AND_RETURN_RET_LOG(serverState != NULL, SOFTBUS_MEM_ERR, "calloc server state failed");
    serverState->traceId = traceIdGenerator++;
    int32_t status = SoftBusMutexInit(&serverState->mutex, NULL);
    if (status != SOFTBUS_OK) {
        CLOGE("init mutex failed, error=%d", status);
        SoftBusFree(serverState);
        return status;
    }
    serverState->available = true;
    serverState->serverId = -1;
    status = ConnStartActionAsync(serverState, ListenTask);
    if (status != SOFTBUS_OK) {
        CLOGE("start br server failed: error=%d", status);
        (void)SoftBusMutexDestroy(&serverState->mutex);
        SoftBusFree(serverState);
        return status;
    }
    g_serverState = serverState;
    CLOGI("start ok, trace id=%u", serverState->traceId);
    return SOFTBUS_OK;
}

int32_t ConnBrStopServer(void)
{
    if (g_serverState == NULL) {
        CLOGE("server not started yet, skip");
        return SOFTBUS_OK;
    }
    int32_t status = SoftBusMutexLock(&g_serverState->mutex);
    if (status != SOFTBUS_OK) {
        CLOGE("lock failed, error=%d", status);
        return status;
    }
    CLOGI("trace id=%u", g_serverState->traceId);
    g_serverState->available = false;
    if (g_serverState->serverId != -1) {
        g_sppDriver->CloseSppServer(g_serverState->serverId);
        g_serverState->serverId = -1;
    }
    (void)SoftBusMutexUnlock(&g_serverState->mutex);
    g_serverState = NULL;
    return SOFTBUS_OK;
}

static void WaitNegotiationClosingTimeoutHandler(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "WaitNegotiationClosingTimeoutHandler: connection not exist, id=%u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("lock failed, conn id=%u, error=%d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return;
    }
    enum ConnBrConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    CLOGD("conn id=%u, state=%d", connectionId, state);
    if (state == BR_CONNECTION_STATE_NEGOTIATION_CLOSING) {
        ConnBrDisconnectNow(connection);
    }
    ConnBrReturnConnection(&connection);
}

static void RetryNotifyReferenceHandler(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "RetryNotifyReferenceHandler: connection not exist, id=%u", connectionId);
    ConnBrUpdateConnectionRc(connection, 0);
    ConnBrReturnConnection(&connection);
}

static void ReportConnectExceptionHandler(uint64_t u64Mac, int32_t errorCode)
{
    ConnectOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    option.type = CONNECT_BR;
    int32_t ret = ConvertU64MacToStr(u64Mac, option.brOption.brMac, BT_MAC_LEN);
    if (ret != SOFTBUS_OK) {
        CLOGE("ConvertU64MacToStr faild, ret=%d", ret);
        return;
    }
    LnnDCReportConnectException(&option, errorCode);
}

static void BrConnectionMsgHandler(SoftBusMessage *msg)
{
    switch (msg->what) {
        case MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT:
            WaitNegotiationClosingTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_RETRY_NOTIFY_REFERENCE:
            RetryNotifyReferenceHandler((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_REPORT_CONNECT_EXCEPTION:
            ReportConnectExceptionHandler(msg->arg1, (int32_t)msg->arg2);
            break;
        default:
            CLOGE("receive unexpected msg, what=%d", msg->what);
            break;
    }
}

static int BrCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CLOGE("failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t InitProperty()
{
    int32_t capacity = -1;
    int32_t mtu = -1;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH, (unsigned char *)&capacity, sizeof(capacity)) !=
        SOFTBUS_OK) {
        CLOGE("get br buffer capacity config fail");
        return SOFTBUS_ERR;
    }
    if (capacity <= 0 || capacity > MAX_BR_READ_BUFFER_CAPACITY) {
        CLOGE("br buffer capacity is invalid, capacity=%d", capacity);
        return SOFTBUS_ERR;
    }
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN, (unsigned char *)&mtu, sizeof(mtu)) != SOFTBUS_OK) {
        CLOGE("get br mtu config fail");
        return SOFTBUS_ERR;
    }
    if (mtu <= 0 || mtu > MAX_BR_MTU_SIZE) {
        CLOGE("br mtu is invalid, mtu=%d", mtu);
        return SOFTBUS_ERR;
    }
    CLOGD("init br config success, read buffer capacity=%d, mtu size=%d", capacity, mtu);
    g_readBufferCapacity = capacity;
    g_mtuSize = mtu;
    return SOFTBUS_OK;
}

int32_t ConnBrConnectionMuduleInit(SoftBusLooper *looper, SppSocketDriver *sppDriver, ConnBrEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        looper != NULL, SOFTBUS_INVALID_PARAM, "br connection init failed: looper is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        sppDriver != NULL, SOFTBUS_INVALID_PARAM, "br connection init failed: spp driver is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        listener != NULL, SOFTBUS_INVALID_PARAM, "br connection init failed: event listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerAccepted != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnServerAccepted is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientConnected != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnClientConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientConnectFailed != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnClientFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnDataReceived, is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onConnectionException != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnConnectionException is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onConnectionResume != NULL, SOFTBUS_INVALID_PARAM,
        "br connection init failed: listener OnConnectionResume is null");

    int32_t status = InitProperty();
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, "br connection init failed: init property failed");
    static BrUnderlayerCallback brConnectionCallback = {
        .ConnectStatusCallback = BrConnectStatusCallback,
    };
    status = SoftBusRegisterBrCallback(&brConnectionCallback);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, "br connection init failed: register callback failed");
    g_brConnectionAsyncHandler.handler.looper = looper;
    g_sppDriver = sppDriver;
    g_eventListener = *listener;
    return SOFTBUS_OK;
}
