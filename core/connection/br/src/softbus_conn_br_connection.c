/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_common.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_socket.h"
#include "conn_event.h"

#define UUID "8ce255c0-200a-11e0-ac64-0800200c9a66"

typedef struct {
    int32_t delta;
    int32_t peerRc;
} ReferenceCount;

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
    MSG_CONNECTION_OCCUPY_RELEASE,
    MSG_CONNECTION_UPDATE_LOCAL_RC,
    MSG_CONNECTION_UPDATE_PEER_RC,
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
static int32_t LoopRead(ConnBrConnection *connection)
{
    LimitedBuffer *buffer = NULL;
    int32_t status = ConnNewLimitedBuffer(&buffer, g_readBufferCapacity);
    if (status != SOFTBUS_OK) {
        return status;
    }

    while (true) {
        status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "try to get lock failed, connId=%{public}u, err=%{public}d",
                connection->connectionId, status);
            break;
        }
        int32_t socketHandle = connection->socketHandle;
        (void)SoftBusMutexUnlock(&connection->lock);
        if (socketHandle == INVALID_SOCKET_HANDLE) {
            CONN_LOGE(CONN_BLE, "socketHandle=%{public}d", socketHandle);
            status = INVALID_SOCKET_HANDLE;
            break;
        }
        uint8_t *data = NULL;
        int32_t dataLen = ConnBrTransReadOneFrame(connection->connectionId, socketHandle, buffer, &data);
        if (dataLen < 0) {
            status = dataLen;
            break;
        }
        g_eventListener.onDataReceived(connection->connectionId, data, dataLen);
    }
    ConnDeleteLimitedBuffer(&buffer);
    return status;
}

static void BrConnectStatusCallback(const BdAddr *bdAddr, BtUuid uuid, int32_t status, int32_t result)
{
    char copyMac[BT_MAC_LEN] = { 0 };
    int32_t ret = ConvertBtMacToStr(copyMac, BT_MAC_LEN, bdAddr->addr, sizeof(bdAddr->addr));
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BR,
        "convert mac failed, result=%{public}d, status=%{public}d", result, status);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, copyMac, BT_MAC_LEN);

    uint64_t u64Mac = 0;
    if (result != SOFTBUS_OK && ConvertBtMacToU64(copyMac, BT_MAC_LEN, &u64Mac) == SOFTBUS_OK) {
        ConnPostMsgToLooper(
            &g_brConnectionAsyncHandler, MSG_CONNECTION_REPORT_CONNECT_EXCEPTION, u64Mac, result, NULL, 0);
    }

    ConnBrConnection *connection = ConnBrGetConnectionByAddr(copyMac, CONN_SIDE_CLIENT);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BR,
        "connection not exist, mac=%{public}s, result=%{public}d, status=%{public}d",
        anomizeAddress, result, status);
    BrUnderlayerStatus *callbackStatus = (BrUnderlayerStatus *)SoftBusCalloc(sizeof(BrUnderlayerStatus));
    if (callbackStatus == NULL) {
        CONN_LOGE(CONN_BR,
            "calloc failed, mac=%{public}s, result=%{public}d, status=%{public}d", anomizeAddress, result, status);
        ConnBrReturnConnection(&connection);
        return;
    }
    ListInit(&callbackStatus->node);
    callbackStatus->status = status;
    callbackStatus->result = result;
    ListAdd(&connection->connectProcessStatus->list, &callbackStatus->node);
    CONN_LOGD(CONN_BR, "br on connect calback, mac=%{public}s, connId=%{public}d, result=%{public}d, "
        "status=%{public}d", anomizeAddress, connection->connectionId, result, status);
    ConnBrReturnConnection(&connection);
}

static int32_t StartBrClientConnect(ConnBrConnection *connection, const char *anomizeAddress)
{
    uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };
    int32_t status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "convert string mac to binary fail, connId=%{public}u, address=%{public}s, "
            "error=%{public}d", connection->connectionId, anomizeAddress, status);
        return SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR;
    }
    BtSocketConnectionCallback callback = {
        .connStateCb = BrConnectStatusCallback,
    };
    int32_t socketHandle = g_sppDriver->Connect(UUID, binaryAddr, &callback);
    if (socketHandle <= INVALID_SOCKET_HANDLE) {
        CONN_LOGE(CONN_BR, "underlayer bluetooth connect failed, connId=%{public}u, address=%{public}s",
            connection->connectionId, anomizeAddress);
        int32_t errCode = socketHandle;
        ConnAlarmExtra extraAlarm = {
            .linkType = CONNECT_BR,
            .errcode = errCode,
        };
        CONN_ALARM(CONNECTION_FAIL_ALARM, MANAGE_ALARM_TYPE, extraAlarm);
        return errCode;
    }
    if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "get lock failed, connId=%{public}u, address=%{public}s", connection->connectionId,
            anomizeAddress);
        g_sppDriver->DisConnect(socketHandle);
        return SOFTBUS_LOCK_ERR;
    }
    if (connection->state != BR_CONNECTION_STATE_CONNECTING) {
        CONN_LOGE(CONN_BR, "unexpected state, connId=%{public}u, address=%{public}s, state=%{public}d",
            connection->connectionId, anomizeAddress, connection->state);
        g_sppDriver->DisConnect(socketHandle);
        connection->state = BR_CONNECTION_STATE_CLOSED;
        (void)SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
    }
    connection->socketHandle = socketHandle;
    connection->state = BR_CONNECTION_STATE_CONNECTED;
    (void)SoftBusMutexUnlock(&connection->lock);
    return SOFTBUS_OK;
}

static void *StartClientConnect(void *connectCtx)
{
    ClientConnectContext *ctx = (ClientConnectContext *)connectCtx;
    uint32_t connectionId = ctx->connectionId;
    SoftBusFree(ctx);
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BR, "connection not exist, connId=%{public}u", connectionId);
        g_eventListener.onClientConnectFailed(connectionId, SOFTBUS_CONN_BR_INTERNAL_ERR);
        return NULL;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CONN_LOGI(CONN_BR, "connId=%{public}u, address=%{public}s", connectionId, anomizeAddress);
    do {
        int ret = StartBrClientConnect(connection, anomizeAddress);
        if (ret != SOFTBUS_OK) {
            CONN_LOGI(CONN_BR, "connId=%{public}u, error=%{public}d", connectionId, ret);
            g_eventListener.onClientConnectFailed(connection->connectionId, ret);
            break;
        }

        CONN_LOGI(CONN_BR, "connect ok, id=%{public}u, address=%{public}s, socket=%{public}d",
            connection->connectionId, anomizeAddress, connection->socketHandle);
        g_eventListener.onClientConnected(connection->connectionId);
        ret = LoopRead(connection);
        CONN_LOGD(CONN_BR, "br client loop read exit, connId=%{public}u, address=%{public}s, socketHandle=%{public}d, "
            "error=%{public}d", connection->connectionId, anomizeAddress, connection->socketHandle, ret);

        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "get lock failed, connId=%{public}u, address=%{public}s", connection->connectionId,
                anomizeAddress);
            g_eventListener.onConnectionException(connection->connectionId, SOFTBUS_LOCK_ERR);
            break;
        }
        if (connection->socketHandle != INVALID_SOCKET_HANDLE) {
            g_sppDriver->DisConnect(connection->socketHandle);
            connection->socketHandle = INVALID_SOCKET_HANDLE;
        }
        connection->state = (ret == SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED ? BR_CONNECTION_STATE_CLOSED :
                                                                                BR_CONNECTION_STATE_EXCEPTION);
        (void)SoftBusMutexUnlock(&connection->lock);
        g_eventListener.onConnectionException(connection->connectionId, ret);
    } while (false);
    ConnBrReturnConnection(&connection);
    return NULL;
}

static ConnBrConnection *CreateAndSaveConnection(int32_t socketHandle)
{
    BluetoothRemoteDevice remote;
    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    int32_t ret = g_sppDriver->GetRemoteDeviceInfo(socketHandle, &remote);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "GetRemoteDeviceInfo failed, socket=%{public}u, error=%{public}d", socketHandle, ret);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    char mac[BT_MAC_LEN] = { 0 };
    ret = ConvertBtMacToStr(mac, BT_MAC_LEN, (uint8_t *)remote.mac, BT_ADDR_LEN);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "ConvertBtMacToStr failed, socket=%{public}u, error=%{public}d", socketHandle, ret);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_SERVER, socketHandle);
    if (connection == NULL) {
        CONN_LOGE(CONN_BR, "create connection failed, socket=%{public}u, error=%{public}d", socketHandle, ret);
        g_sppDriver->DisConnect(socketHandle);
        return NULL;
    }
    ret = ConnBrSaveConnection(connection);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "ConnBrSaveConnection failed, socket=%{public}u, error=%{public}d", socketHandle, ret);
        g_sppDriver->DisConnect(socketHandle);
        ConnBrFreeConnection(connection);
        return NULL;
    }
    return connection;
}

static void *StartServerServe(void *serveCtx)
{
    ServerServeContext *ctx = (ServerServeContext *)serveCtx;
    int32_t socketHandle = ctx->socketHandle;
    SoftBusFree(ctx);
    ConnBrConnection *connection = CreateAndSaveConnection(socketHandle);
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL, NULL, CONN_BR, "connection is not exist");
    do {
        CONN_LOGI(CONN_BR, "connId=%{public}u, socket=%{public}d", connection->connectionId, socketHandle);
        g_eventListener.onServerAccepted(connection->connectionId);
        int32_t ret = LoopRead(connection);
        CONN_LOGD(CONN_BR, "loop read exit, connId=%{public}u, socket=%{public}d, ret=%{public}d",
            connection->connectionId, socketHandle, ret);
        ret = SoftBusMutexLock(&connection->lock);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "get lock failed, connId=%{public}u, socket=%{public}d, err=%{public}d",
                connection->connectionId, socketHandle, ret);
            g_sppDriver->DisConnect(socketHandle);
            connection->socketHandle = INVALID_SOCKET_HANDLE;
            g_eventListener.onConnectionException(connection->connectionId, ret);
            break;
        }
        if (connection->socketHandle != INVALID_SOCKET_HANDLE) {
            g_sppDriver->DisConnect(socketHandle);
            connection->socketHandle = INVALID_SOCKET_HANDLE;
        }
        connection->state = (ret == SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED ? BR_CONNECTION_STATE_CLOSED :
                                                                                BR_CONNECTION_STATE_EXCEPTION);
        (void)SoftBusMutexUnlock(&connection->lock);
        g_eventListener.onConnectionException(connection->connectionId, ret);
    } while (false);
    ConnBrReturnConnection(&connection);
    return NULL;
}

ConnBrConnection *ConnBrCreateConnection(const char *addr, ConnSideType side, int32_t socketHandle)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(addr != NULL, NULL, CONN_BR, "br creat connection: addr is NULL");
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL, NULL, CONN_BR, "calloc br conn failed");
    SoftBusList *list = CreateSoftBusList();
    if (list == NULL) {
        CONN_LOGE(CONN_BR, "create softbus list failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->connectProcessStatus = list;
    ListInit(&connection->node);
    // the final connectionId value is allocate on saving global
    connection->connectionId = 0;
    connection->side = side;
    if (strcpy_s(connection->addr, BT_MAC_LEN, addr) != EOK) {
        CONN_LOGE(CONN_BR, "copy address failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->mtu = (uint32_t)g_mtuSize;
    if (SoftBusMutexInit(&connection->lock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "init lock failed");
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
    connection->retryCount = 0;
    return connection;
}

void ConnBrOccupy(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BR, "conn is NULL");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, CONN_BR,
        "lock failed, connId=%{public}u", connection->connectionId);
    ConnRemoveMsgFromLooper(
        &g_brConnectionAsyncHandler, MSG_CONNECTION_OCCUPY_RELEASE, connection->connectionId, 0, NULL);
    int32_t ret = ConnPostMsgToLooper(&g_brConnectionAsyncHandler,
        MSG_CONNECTION_OCCUPY_RELEASE, connection->connectionId, 0, NULL, WAIT_TIMEOUT_OCCUPY);
    if (ret != SOFTBUS_OK) {
        CONN_LOGW(CONN_BR, "post msg failed, connId=%{public}u, err=%{public}d", connection->connectionId, ret);
        (void)SoftBusMutexUnlock(&connection->lock);
        return;
    }
    connection->isOccupied = true;
    (void)SoftBusMutexUnlock(&connection->lock);
}

void ConnBrFreeConnection(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR, "br free connection: connection is NULL");
    if (connection->connectProcessStatus == NULL) {
        CONN_LOGW(CONN_BR, "connectProcessStatus is NULL");
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
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_LOCK_ERR, CONN_BR,
        "br client connect: calloc failed, connId=%{public}u", connection->connectionId);
    ctx->connectionId = connection->connectionId;
    int32_t status = ConnStartActionAsync(ctx, StartClientConnect, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "start connect thread failed, connId=%{public}u, error=%{public}d", connection->connectionId,
            status);
        SoftBusFree(ctx);
        return status;
    }
    return SOFTBUS_OK;
}

static int32_t NotifyUpdateConnectionRc(uint32_t connectionId, int32_t delta)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BR, "conn not exist, id=%{public}u", connectionId);
    if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
        CONN_LOGI(CONN_BR, "lock failed, connId=%{public}u, delta=%{public}d", connectionId, delta);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_LOCK_ERR;
    }
    connection->connectionRc += delta;
    CONN_LOGI(CONN_BR, "connId=%{public}u, side=%{public}d, delta=%{public}d, newRef=%{public}d", connectionId,
        connection->side, delta, connection->connectionRc);
    if (connection->connectionRc <= 0) {
        connection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
        ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT, connectionId,
            0, NULL, WAIT_BR_NEGOTIATION_CLOSING_TIMEOUT_MILLIS);
    }
    (void)SoftBusMutexUnlock(&connection->lock);
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connectionId,
        .flag = delta >= 0 ? CONN_HIGH : CONN_LOW,
        .method = BR_METHOD_NOTIFY_REQUEST,
        .referenceRequest = {
            .delta = delta,
            .referenceNumber = connection->connectionRc,
        },
    };
    ConnEventExtra extra = {
        .connectionId = (int32_t)connectionId,
        .connRcDelta = delta,
        .connRc = connection->connectionRc,
        .peerBrMac = connection->addr,
        .linkType = CONNECT_BR,
    };
    ConnBrReturnConnection(&connection);
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    if (seq < 0) {
        CONN_LOGE(CONN_BR, "request message failed, connId=%{public}u, ret=%{public}d", connectionId, (int32_t)seq);
        extra.errcode = (int32_t)seq;
        extra.result = EVENT_STAGE_RESULT_FAILED;
        CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_UPDATE_CONNECTION_RC, extra);
        return (int32_t)seq;
    }
    extra.errcode = ConnBrPostBytes(connectionId, data, dataLen, 0, ctx.flag, MODULE_CONNECTION, seq);
    extra.result = extra.errcode == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_UPDATE_CONNECTION_RC, extra);
    return extra.errcode;
}

static int32_t BrUpdateConnectionRc(uint32_t connectionId, int32_t delta)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BR, "conn not exist, id=%{public}u", connectionId);
    
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_LOCK_ERR;
    }
    bool isOccupied = connection->isOccupied;
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBrReturnConnection(&connection);

    if (delta < 0 && isOccupied) {
        CONN_LOGI(CONN_BR, "is occupied, process later, connId=%{public}u", connectionId);
        status = ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_UPDATE_LOCAL_RC, connectionId, delta,
            NULL, WAIT_TIMEOUT_TRY_AGAIN);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "post msg failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
            return status;
        }
        return SOFTBUS_OK;
    }
    return NotifyUpdateConnectionRc(connectionId, delta);
}

int32_t ConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(connection, SOFTBUS_INVALID_PARAM, CONN_BR, "conn is null");
    return BrUpdateConnectionRc(connection->connectionId, delta);
}

int32_t ConnBrDisconnectNow(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BR,
        "br disconnect now: lock failed, connId=%{public}u", connection->connectionId);
    int32_t socketHandle = connection->socketHandle;
    if (socketHandle == INVALID_SOCKET_HANDLE) {
        connection->state = BR_CONNECTION_STATE_CLOSED;
        SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_OK;
    }
    connection->socketHandle = INVALID_SOCKET_HANDLE;
    connection->state = BR_CONNECTION_STATE_CONNECTING;
    SoftBusMutexUnlock(&connection->lock);
    // ensure that the underlayer schedules read/write before disconnection
    SoftBusSleepMs(WAIT_DISCONNECT_TIME_MS);
    int32_t ret = g_sppDriver->DisConnect(socketHandle);
    CONN_LOGI(CONN_BR, "disConnect connId=%{public}u, socketHandle=%{public}d, status=%{public}d",
        connection->connectionId, socketHandle, ret);
    ret = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_BR,
        "lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, ret);
    connection->state = BR_CONNECTION_STATE_CLOSED;
    SoftBusMutexUnlock(&connection->lock);
    return ret;
}

static int32_t BrPostReplyMessage(uint32_t connectionId, int32_t localRc)
{
    int32_t flag = CONN_HIGH;
    BrCtlMessageSerializationContext ctx = {
        .connectionId = connectionId,
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
        CONN_LOGE(CONN_BR, "reply message faild, connectionId=%{public}u, ret=%{public}d", connectionId, (int32_t)seq);
        return (int32_t)seq;
    }
    return ConnBrPostBytes(connectionId, data, dataLen, 0, flag, MODULE_CONNECTION, seq);
}

static int32_t NotifyReferenceRequest(uint32_t connectionId, int32_t delta, int32_t peerRc)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL,
        SOFTBUS_INVALID_PARAM, CONN_BR, "conn not exist, id=%{public}u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_LOCK_ERR;
    }
    connection->connectionRc += delta;
    int32_t localRc = connection->connectionRc;
    CONN_LOGI(CONN_BR, "connId=%{public}u, delta=%{public}d, peerRc=%{public}d, localRc=%{public}d", connectionId,
        delta, peerRc, localRc);
    if (peerRc > 0) {
        if (localRc == 0) {
            ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_RETRY_NOTIFY_REFERENCE, connectionId, 0,
                NULL, RETRY_NOTIFY_REFERENCE_DELAY_MILLIS);
        }
        if (connection->state == BR_CONNECTION_STATE_NEGOTIATION_CLOSING) {
            ConnRemoveMsgFromLooper(
                &g_brConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT, connectionId, 0, NULL);
            connection->state = BR_CONNECTION_STATE_CONNECTED;
            g_eventListener.onConnectionResume(connectionId);
        }
        (void)SoftBusMutexUnlock(&connection->lock);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_OK;
    }
    if (localRc <= 0) {
        connection->state = BR_CONNECTION_STATE_CLOSING;
        (void)SoftBusMutexUnlock(&connection->lock);
        ConnBrDisconnectNow(connection);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBrReturnConnection(&connection);
    return BrPostReplyMessage(connectionId, localRc);
}

static void BrOnOccupyRelease(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BR, "conn not exist, id=%{public}u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return;
    }
    connection->isOccupied = false;
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBrReturnConnection(&connection);
}

static int32_t BrOnReferenceRequest(uint32_t connectionId, ReferenceCount *referenceCount)
{
    int32_t delta = referenceCount->delta;
    int32_t peerRc = referenceCount->peerRc;
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL,
        SOFTBUS_INVALID_PARAM, CONN_BR, "conn not exist, id=%{public}u", connectionId);

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return SOFTBUS_LOCK_ERR;
    }
    bool isOccupied =  connection->isOccupied;
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBrReturnConnection(&connection);

    if (delta < 0 && isOccupied) {
        CONN_LOGI(CONN_BR, "is occupied, request process later, connectionId=%{public}u", connectionId);
        ReferenceCount *referenceParam = (ReferenceCount *)SoftBusMalloc(sizeof(ReferenceCount));
        if (referenceParam == NULL) {
            CONN_LOGE(CONN_BR, "malloc buffer failed, connectionId=%{public}u", connectionId);
            return SOFTBUS_MALLOC_ERR;
        }
        referenceParam->delta = delta;
        referenceParam->peerRc = peerRc;

        int32_t ret = ConnPostMsgToLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_UPDATE_PEER_RC,
            connectionId, 0, referenceParam, WAIT_TIMEOUT_TRY_AGAIN);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "post msg failed, connectionId=%{public}u, error=%{public}d", connectionId, ret);
            SoftBusFree(referenceParam);
            return ret;
        }
        return SOFTBUS_OK;
    }
    return NotifyReferenceRequest(connectionId, delta, peerRc);
}

int32_t ConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json)
{
    int32_t delta = 0;
    int32_t peerRc = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_DELTA, &delta) ||
        !GetJsonObjectSignedNumberItem(json, KEY_REFERENCE_NUM, &peerRc)) {
        CONN_LOGE(CONN_BR, "parse delta or ref failed, connectionId=%{public}u, delta=%{public}d, peerRc=%{public}d",
            connection->connectionId, delta, peerRc);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ReferenceCount referenceCount = {
        .delta = delta,
        .peerRc = peerRc,
    };
    return BrOnReferenceRequest(connection->connectionId, &referenceCount);
}

int32_t ConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BR, "invalid param");
    int32_t peerRc = 0;
    if (!GetJsonObjectSignedNumberItem(json, KEY_REFERENCE_NUM, &peerRc)) {
        CONN_LOGE(CONN_BR, "parse delta or ref failed. connectionId=%{public}u", connection->connectionId);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "get lock failed, connectionId=%{public}u, error=%{public}d", connection->connectionId,
            status);
        return SOFTBUS_LOCK_ERR;
    }

    CONN_LOGI(CONN_BR, "connectionId=%{public}u, peerRc=%{public}d, localRc=%{public}d, currentState=%{public}d",
        connection->connectionId, peerRc, connection->connectionRc, connection->state);
    if (peerRc > 0 && connection->state == BR_CONNECTION_STATE_NEGOTIATION_CLOSING) {
        ConnRemoveMsgFromLooper(&g_brConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
            connection->connectionId, 0, NULL);
        connection->state = BR_CONNECTION_STATE_CONNECTED;
        g_eventListener.onConnectionResume(connection->connectionId);
    }
    (void)SoftBusMutexUnlock(&connection->lock);
    return SOFTBUS_OK;
}

static int32_t CheckBrServerStateAndOpenSppServer(ServerState *serverState)
{
#define BR_ACCEPET_WAIT_TIME 1000
    const char *name = "BrManagerInsecure";
    int32_t status = SoftBusMutexLock(&serverState->mutex);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, exit listen task, traceId=%{public}u, error=%{public}d",
            serverState->traceId, status);
        return SOFTBUS_LOCK_ERR;
    }
    if (!serverState->available) {
        CONN_LOGW(CONN_BR, "server closed, exit listen task, traceId=%{public}u", serverState->traceId);
        SoftBusMutexUnlock(&serverState->mutex);
        return SOFTBUS_INVALID_PARAM;
    }
    if (serverState->serverId != -1) {
        g_sppDriver->CloseSppServer(serverState->serverId);
        serverState->serverId = -1;
    }
    (void)SoftBusMutexUnlock(&serverState->mutex);
    int32_t serverId = g_sppDriver->OpenSppServer(name, (int32_t)strlen(name), UUID, 0);
    if (serverId == -1) {
        CONN_LOGE(CONN_BR,
            "open br server failed, retry after some times, retryDelay=%{public}d, traceId=%{public}u",
            BR_ACCEPET_WAIT_TIME, serverState->traceId);
        SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
        return SOFTBUS_CONN_BR_RETRY_OPEN_SERVER;
    }
    CONN_LOGI(CONN_BR, "open br server ok, traceId=%{public}u, serverId=%{public}d", serverState->traceId,
        serverId);
    status = SoftBusMutexLock(&serverState->mutex);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, exit listen task, traceId=%{public}u, error=%{public}d",
            serverState->traceId, status);
        g_sppDriver->CloseSppServer(serverId);
        return SOFTBUS_LOCK_ERR;
    }
    if (!serverState->available) {
        CONN_LOGW(CONN_BR, "server closed during create socket period, exit listen task. traceId=%{public}u",
            serverState->traceId);
        g_sppDriver->CloseSppServer(serverId);
        (void)SoftBusMutexUnlock(&serverState->mutex);
        return SOFTBUS_INVALID_PARAM;
    }
    serverState->serverId = serverId;
    (void)SoftBusMutexUnlock(&serverState->mutex);
    return SOFTBUS_OK;
}

static void *ListenTask(void *arg)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(arg != NULL, NULL, CONN_BR, "invalid param");
    ServerState *serverState = (ServerState *)arg;
    CONN_CHECK_AND_RETURN_RET_LOGE(serverState != NULL, NULL, CONN_BLE, "serverState is null");
    CONN_LOGI(CONN_BR, "traceId=%{public}u", serverState->traceId);
    int32_t status = SOFTBUS_OK;
    while (true) {
        status= CheckBrServerStateAndOpenSppServer(serverState);
        if (status == SOFTBUS_CONN_BR_RETRY_OPEN_SERVER) {
            continue;
        }
        if (status != SOFTBUS_OK) {
            break;
        }
        CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&serverState->mutex) == SOFTBUS_OK,
            NULL, CONN_BLE, "lock failed");
        int32_t serverId = serverState->serverId;
        (void)SoftBusMutexUnlock(&serverState->mutex);
        while (true) {
            int32_t socketHandle = g_sppDriver->Accept(serverId);
            if (socketHandle == SOFTBUS_CONN_BR_SPP_SERVER_ERR) {
                CONN_LOGE(CONN_BR, "accept failed, traceId=%{public}u, serverId=%{public}d", serverState->traceId,
                    serverId);
                break;
            }
            ServerServeContext *ctx = (ServerServeContext *)SoftBusCalloc(sizeof(ServerServeContext));
            if (ctx == NULL) {
                CONN_LOGE(CONN_BR, "calloc serve context failed, traceId=%{public}u, serverId=%{public}d, "
                    "socketHandle=%{public}d", serverState->traceId, serverId, socketHandle);
                g_sppDriver->DisConnect(socketHandle);
                continue;
            }
            ctx->socketHandle = socketHandle;
            status = ConnStartActionAsync(ctx, StartServerServe, NULL);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_BR, "start serve thread failed, traceId=%{public}u, serverId=%{public}d, "
                    "socket=%{public}d, error=%{public}d", serverState->traceId, serverId, socketHandle, status);
                SoftBusFree(ctx);
                g_sppDriver->DisConnect(socketHandle);
                continue;
            }
            CONN_LOGI(CONN_BR, "accept incoming connection, traceId=%{public}u, serverId=%{public}d, socket=%{public}d",
                serverState->traceId, serverId, socketHandle);
        }
    }
    CONN_LOGI(CONN_BR, "br server listen exit, traceId=%{public}u", serverState->traceId);
    (void)SoftBusMutexDestroy(&serverState->mutex);
    SoftBusFree(serverState);
    return NULL;
}

int32_t ConnBrStartServer(void)
{
    static uint32_t traceIdGenerator = 0;

    if (g_serverState != NULL) {
        CONN_LOGW(CONN_BR, "server already started, skip");
        return SOFTBUS_OK;
    }
    ServerState *serverState = (ServerState *)SoftBusCalloc(sizeof(ServerState));
    CONN_CHECK_AND_RETURN_RET_LOGE(serverState != NULL, SOFTBUS_MEM_ERR, CONN_BR, "calloc server state failed");
    serverState->traceId = traceIdGenerator++;
    int32_t status = SoftBusMutexInit(&serverState->mutex, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "init mutex failed, error=%{public}d", status);
        SoftBusFree(serverState);
        return status;
    }
    serverState->available = true;
    serverState->serverId = -1;
    status = ConnStartActionAsync(serverState, ListenTask, "BrListen_Tsk");
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "start br server failed: error=%{public}d", status);
        (void)SoftBusMutexDestroy(&serverState->mutex);
        SoftBusFree(serverState);
        return status;
    }
    g_serverState = serverState;
    CONN_LOGI(CONN_BR, "start ok, traceId=%{public}u", serverState->traceId);
    return SOFTBUS_OK;
}

int32_t ConnBrStopServer(void)
{
    if (g_serverState == NULL) {
        CONN_LOGE(CONN_BR, "server not started yet, skip");
        return SOFTBUS_OK;
    }
    int32_t status = SoftBusMutexLock(&g_serverState->mutex);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, error=%{public}d", status);
        return status;
    }
    CONN_LOGI(CONN_BR, "traceId=%{public}u", g_serverState->traceId);
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
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR,
        "WaitNegotiationClosingTimeoutHandler: connection not exist, id=%{public}u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock failed, connId=%{public}u, error=%{public}d", connectionId, status);
        ConnBrReturnConnection(&connection);
        return;
    }
    enum ConnBrConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    CONN_LOGD(CONN_BR, "connId=%{public}u, state=%{public}d", connectionId, state);
    if (state == BR_CONNECTION_STATE_NEGOTIATION_CLOSING) {
        ConnBrDisconnectNow(connection);
    }
    ConnBrReturnConnection(&connection);
}

static void RetryNotifyReferenceHandler(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR,
        "RetryNotifyReferenceHandler: connection not exist, connectionId=%{public}u", connectionId);
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
        CONN_LOGE(CONN_BR, "ConvertU64MacToStr faild, ret=%{public}d", ret);
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
        case MSG_CONNECTION_OCCUPY_RELEASE:
            BrOnOccupyRelease((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_UPDATE_LOCAL_RC:
            BrUpdateConnectionRc((uint32_t)msg->arg1, (int32_t)msg->arg2);
            break;
        case MSG_CONNECTION_UPDATE_PEER_RC:
            BrOnReferenceRequest((uint32_t)msg->arg1, (ReferenceCount *)msg->obj);
            break;
        default:
            CONN_LOGW(CONN_BR, "receive unexpected msg, what=%{public}d", msg->what);
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
        case MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT:
        case MSG_CONNECTION_UPDATE_PEER_RC:
        case MSG_CONNECTION_OCCUPY_RELEASE:
        case MSG_CONNECTION_UPDATE_LOCAL_RC: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_BR,
            "failed to avoid fault silence, "
            "what=%{public}d, arg1=%{public}" PRIu64 ", arg2=%{public}" PRIu64 ", objIsNull=%{public}d",
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
        CONN_LOGE(CONN_INIT, "get br buffer capacity config fail");
        return SOFTBUS_NO_INIT;
    }
    if (capacity <= 0 || capacity > MAX_BR_READ_BUFFER_CAPACITY) {
        CONN_LOGE(CONN_INIT, "br buffer capacity is invalid, capacity=%{public}d", capacity);
        return SOFTBUS_NO_INIT;
    }
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN, (unsigned char *)&mtu, sizeof(mtu)) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "get br mtu config fail");
        return SOFTBUS_NO_INIT;
    }
    if (mtu <= 0 || mtu > MAX_BR_MTU_SIZE) {
        CONN_LOGE(CONN_INIT, "br mtu is invalid, mtu=%{public}d", mtu);
        return SOFTBUS_NO_INIT;
    }
    CONN_LOGD(CONN_INIT, "init br config success, read buffer capacity=%{public}d, mtu=%{public}d", capacity, mtu);
    g_readBufferCapacity = capacity;
    g_mtuSize = mtu;
    return SOFTBUS_OK;
}

int32_t ConnBrConnectionMuduleInit(SoftBusLooper *looper, SppSocketDriver *sppDriver, ConnBrEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(looper != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: looper is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(sppDriver != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: spp driver is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: event listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerAccepted != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnServerAccepted is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientConnected != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnClientConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientConnectFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnClientFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataReceived != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnDataReceived, is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectionException != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnConnectionException is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectionResume != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: listener OnConnectionResume is null");

    int32_t status = InitProperty();
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "br connection init failed: init property failed");
    g_brConnectionAsyncHandler.handler.looper = looper;
    g_sppDriver = sppDriver;
    g_eventListener = *listener;
    return SOFTBUS_OK;
}
