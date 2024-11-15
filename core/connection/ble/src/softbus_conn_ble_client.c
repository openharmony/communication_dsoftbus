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

#include "softbus_conn_ble_client.h"

#include "securec.h"

#include "conn_log.h"
#include "message_handler.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"
#include "conn_event.h"
#include "softbus_utils.h"

#define INVALID_GATTC_ID (-1)

enum ClientLoopMsgType {
    MSG_CLIENT_CONNECTED = 300,
    MSG_CLIENT_SERVICE_SEARCHED,
    MSG_CLIENT_NOTIFICATED,
    MSG_CLIENT_DISCONNECTED,
    MSG_CLIENT_MTU_SETTED,
    MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT,
    MSG_CLIENT_WAIT_FAST_CONNECT_TIMEOUT,
};

typedef struct {
    CommonStatusContext common;
    int32_t mtuSize;
} MtuConfiguredContext;

static int32_t NotificatedConnHandler(int32_t underlayerHandle, ConnBleConnection *connection);
static int32_t NotificatedNetHandler(int32_t underlayerHandle, ConnBleConnection *connection);
static void BleGattClientMsgHandler(SoftBusMessage *msg);
static int BleCompareGattClientLooperEventFunc(const SoftBusMessage *msg, void *args);
static int32_t RetrySearchService(ConnBleConnection *connection, enum RetrySearchServiceReason reason);
static void BleGattcConnStateCallback(int32_t underlayerHandle, int32_t state, int32_t status);
static void BleGattcSearchServiceCallback(int32_t underlayerHandle, int32_t status);
static void BleGattcRegisterNotificationCallback(int32_t underlayerHandle, int32_t status);
static void BleGattcNotificationReceiveCallback(int32_t underlayerHandle, SoftBusGattcNotify *param, int32_t status);
static void BleGattcConfigureMtuSizeCallback(int32_t underlayerHandle, int32_t mtuSize, int32_t status);
static ConnBleClientEventListener g_clientEventListener = { 0 };
static SoftBusGattcCallback g_gattcCallback = {
    .connectionStateCallback = BleGattcConnStateCallback,
    .serviceCompleteCallback = BleGattcSearchServiceCallback,
    .registNotificationCallback = BleGattcRegisterNotificationCallback,
    .notificationReceiveCallback = BleGattcNotificationReceiveCallback,
    .configureMtuSizeCallback = BleGattcConfigureMtuSizeCallback,
};
static SoftBusHandlerWrapper g_bleGattClientAsyncHandler = {
    .handler = {
        .name = "BleGattClientAsyncHandler",
        .HandleMessage = BleGattClientMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BleCompareGattClientLooperEventFunc,
};

static int32_t UpdateBleConnectionStateInOrder(
    ConnBleConnection *connection, enum ConnBleConnectionState expectedState, enum ConnBleConnectionState nextState)
{
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }

    if (connection->state != expectedState) {
        CONN_LOGW(CONN_BLE, "unexpected state, actualState=%{public}d, expectedState=%{public}d, nextState=%{public}d",
            connection->state, expectedState, nextState);
        (void)SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR;
    }
    connection->state = nextState;
    (void)SoftBusMutexUnlock(&connection->lock);
    return SOFTBUS_OK;
}

static int32_t SetConnectionHandleAndState(ConnBleConnection *connection, int32_t underlayerHandle)
{
    int32_t ret = SoftBusMutexLock(&connection->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "client connection lock failed, connectionId=%{public}u, err=%{public}d",
            connection->connectionId, ret);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return SOFTBUS_LOCK_ERR;
    }
    connection->underlayerHandle = underlayerHandle;
    connection->state = BLE_CONNECTION_STATE_CONNECTING;
    (void)SoftBusMutexUnlock(&connection->lock);
    CONN_LOGI(CONN_BLE,
        "ble client connect. connectionId=%{public}u, handle=%{public}d, fastestConnectEnable=%{public}d",
        connection->connectionId, underlayerHandle, connection->fastestConnectEnable);
    return SOFTBUS_OK;
}

int32_t ConnGattClientConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble client connect failed: invalid param, connection is null");

    SoftBusBtAddr binaryAddr = { 0 };
    int32_t status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, status, CONN_BLE, "client connect failed: convert string mac "
        "to binary fail, connectionId=%{public}u, err=%{public}d", connection->connectionId, status);
    int32_t underlayerHandle = SoftbusGattcRegister();
    CONN_CHECK_AND_RETURN_RET_LOGW(underlayerHandle != INVALID_GATTC_ID, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_ERR,
        CONN_BLE, "ble client connect failed: underlayer register failed, underlayerHandle=%{public}d",
        underlayerHandle);
    status = SoftbusGattcRegisterCallback(&g_gattcCallback, underlayerHandle);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, status, CONN_BLE, "client connect %{public}u failed:register "
        "callback fail, err=%{public}d", connection->connectionId, status);
    bool setFastestConn = true;
    if (connection->fastestConnectEnable && SoftbusGattcSetFastestConn(underlayerHandle) != SOFTBUS_OK) {
        setFastestConn = false;
        CONN_LOGW(CONN_BLE, "enable ble fastest connection failed, it is not a big deal, go ahead");
    }
    ConnEventExtra extra = {
        .peerBleMac = connection->addr,
        .connectionId = (int32_t)connection->connectionId,
        .result = EVENT_STAGE_RESULT_OK
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, extra);

    if (connection->fastestConnectEnable && setFastestConn) {
        status = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_WAIT_FAST_CONNECT_TIMEOUT,
            connection->connectionId, 0, 0, BLE_FAST_CONNECT_TIMEOUT);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "post msg to looper failed: connection id=%{public}u, "
                "underlayer handler handle=%{public}d, error=%{public}d",
                connection->connectionId, underlayerHandle, status);
        }
    }
    status = SoftbusGattcConnect(underlayerHandle, &binaryAddr);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "client connect failed: underlayer connect failed, connectionId=%{public}u, err=%{public}d",
            connection->connectionId, status);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR;
    }

    return SetConnectionHandleAndState(connection, underlayerHandle);
}

static void BleGattcConnStateCallback(int32_t underlayerHandle, int32_t state, int32_t status)
{
    CONN_LOGI(CONN_BLE, "gatt client callback, state changed, handle=%{public}d, state=%{public}d, status=%{public}d",
        underlayerHandle, state, status);
    if (state != SOFTBUS_BT_CONNECT && state != SOFTBUS_BT_DISCONNECT) {
        return;
    }

    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE,
            "ble client connected msg handler failed: connection not exist, "
            "underlayer handle=%{public}d", underlayerHandle);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return;
    }
    if (state == SOFTBUS_BT_DISCONNECT && connection->state == BLE_CONNECTION_STATE_CONNECTING) {
        CONN_LOGI(CONN_BLE, "unable to scan broadcast for 3 seconds during ble connection, failed. Waiting for retry, "
            "connId=%{public}u", connection->connectionId);
        int32_t ret = SoftBusMutexLock(&connection->lock);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE,
                "try to lock failed, connId=%{public}u, error=%{public}d", connection->connectionId, ret);
            (void)SoftbusGattcUnRegister(underlayerHandle);
            ConnBleReturnConnection(&connection);
            return;
        }
        connection->underlayerFastConnectFailedScanFailure = true;
        (void)SoftBusMutexUnlock(&connection->lock);
    }
    ConnRemoveMsgFromLooper(
        &g_bleGattClientAsyncHandler, MSG_CLIENT_WAIT_FAST_CONNECT_TIMEOUT, connection->connectionId, 0, NULL);
    ConnBleReturnConnection(&connection);

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE, "connection state changed handle failed: calloc failed, "
        "handle=%{public}d, status=%{public}d", underlayerHandle, status);
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;
    enum ClientLoopMsgType what = state == SOFTBUS_BT_CONNECT ? MSG_CLIENT_CONNECTED : MSG_CLIENT_DISCONNECTED;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, what, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "connection state changed handle failed: post msg to looper failed: handle=%{public}d, "
            "state=%{public}d, status=%{public}d, err=%{public}d", underlayerHandle, state, status, rc);
        SoftBusFree(ctx);
    }
}

static void ConnectedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGW(CONN_BLE, "connection not exist, handle=%{public}d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "not connect, connId=%{public}u, handle=%{public}d, status=%{public}d",
                connection->connectionId, ctx->underlayerHandle, ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_FAIL;
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_CONNECTING, BLE_CONNECTION_STATE_CONNECTED);
        if (rc != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
                connection->connectionId, ctx->underlayerHandle, rc);
            break;
        }
        rc = SoftbusGattcSearchServices(ctx->underlayerHandle);
        if (rc != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE,
                "underlay search service failed, connId=%{public}u, handle=%{public}d, status=%{public}d",
                connection->connectionId, ctx->underlayerHandle, rc);
            if (RetrySearchService(connection, BLE_CLIENT_SEARCH_SERVICE_ERR) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            } else {
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_ERR;
            }
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_CONNECTED, BLE_CONNECTION_STATE_SERVICE_SEARCHING);
        if (rc != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE,
                "update connection state failed, connId=%{public}u, underlayerHandle=%{public}d, err=%{public}d",
                connection->connectionId, ctx->underlayerHandle, rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    }
    ConnBleReturnConnection(&connection);
}

static void ClientWaitFastConnectTimeoutMsgHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "connection not exist, connId=%{public}u", connectionId);
    CONN_LOGI(CONN_BLE, "connect failed, connId=%{public}u", connectionId);
    int32_t rc = SOFTBUS_CONN_BLE_CONNECT_TIMEOUT_ERR;
    do {
        int32_t status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, error=%{public}d", connectionId, status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        connection->state = BLE_CONNECTION_STATE_CLOSED;
        (void)SoftBusMutexUnlock(&connection->lock);
    } while (false);
    g_clientEventListener.onClientFailed(connectionId, rc);
    ConnBleReturnConnection(&connection);
}

static int32_t RetrySearchService(ConnBleConnection *connection, enum RetrySearchServiceReason reason)
{
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, reason=%{public}d, err=%{public}d",
            connection->connectionId, reason, status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t state = connection->state;
    if (state >= BLE_CONNECTION_STATE_CONNECTED && state < BLE_CONNECTION_STATE_NET_NOTIFICATED &&
        connection->retrySearchServiceCnt < BLE_CLIENT_MAX_RETRY_SEARCH_SERVICE_TIMES) {
        // back to connect state
        connection->state = BLE_CONNECTION_STATE_CONNECTED;
    }
    connection->retrySearchServiceCnt += 1;
    int32_t retrySearchServiceCnt = connection->retrySearchServiceCnt;
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    if (state >= BLE_CONNECTION_STATE_NET_NOTIFICATED ||
        retrySearchServiceCnt > BLE_CLIENT_MAX_RETRY_SEARCH_SERVICE_TIMES) {
        CONN_LOGW(CONN_BLE, "retry search service just ignore. "
            "state=%{public}d, count=%{public}d, connId=%{public}u, handle=%{public}d, reason=%{public}d",
            state, retrySearchServiceCnt, connection->connectionId, underlayerHandle, reason);
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }

    status = SoftbusGattcRefreshServices(underlayerHandle);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "fresh service failed, connId=%{public}u, handle=%{public}d, reason=%{public}d, "
            "err=%{public}d", connection->connectionId, underlayerHandle, reason, status);
        return status;
    }
    status = SoftbusGattcSearchServices(underlayerHandle);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "search service failed, connId=%{public}u, handle=%{public}d, reason=%{public}d, "
            "err=%{public}d", connection->connectionId, underlayerHandle, reason, status);
        return status;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_CONNECTED, BLE_CONNECTION_STATE_SERVICE_SEARCHING);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, " update connection state failed, connId=%{public}u, underlayerHandle=%{public}d, "
            "reason=%{public}d, error=%{public}d", connection->connectionId, underlayerHandle, reason, status);
        return status;
    }
    CONN_LOGW(CONN_BLE, "connId=%{public}u, handle=%{public}d, reason=%{public}d",
        connection->connectionId, underlayerHandle, reason);
    return SOFTBUS_OK;
}

static void BleGattcSearchServiceCallback(int32_t underlayerHandle, int32_t status)
{
    CONN_LOGI(CONN_BLE,
        "gatt client callback, service searched, handle=%{public}d, status=%{public}d", underlayerHandle, status);

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    if (ctx == NULL) {
        CONN_LOGE(CONN_BLE, "service searched handle failed: calloc failed, handle=%{public}d, status=%{public}d",
            underlayerHandle, status);
        return;
    }
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_SERVICE_SEARCHED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "post msg to looper failed: handle=%{public}d, status=%{public}d, err=%{public}d",
            underlayerHandle, status, rc);
        SoftBusFree(ctx);
    }
}

static int32_t GattcGetServiceAndRegisterNotification(ConnBleConnection *connection, const CommonStatusContext *ctx)
{
    SoftBusBtUuid serviceUuid = {
        .uuid = (char *)SOFTBUS_SERVICE_UUID,
        .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
    };
    int32_t rc = SoftbusGattcGetService(ctx->underlayerHandle, &serviceUuid);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "underlay get service failed, connId=%{public}u, handle=%{public}d, error=%{public}d",
            connection->connectionId, ctx->underlayerHandle, rc);
        if (RetrySearchService(connection, BLE_CLIENT_GET_SERVICE_ERR) == SOFTBUS_OK) {
            rc = SOFTBUS_OK;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_GET_SERVICE_ERR;
        }
        return rc;
    }
    SoftBusBtUuid connCharacteristicUuid = {
        .uuid = (char *)SOFTBUS_CHARA_BLECONN_UUID,
        .uuidLen = strlen(SOFTBUS_CHARA_BLECONN_UUID),
    };
    SoftBusBtUuid descriptorUuid = {
        .uuid = (char *)SOFTBUS_DESCRIPTOR_CONFIGURE_UUID,
        .uuidLen = strlen(SOFTBUS_DESCRIPTOR_CONFIGURE_UUID),
    };
    rc = SoftbusGattcRegisterNotification(
        ctx->underlayerHandle, &serviceUuid, &connCharacteristicUuid, &descriptorUuid);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "underlay register conn characteristic notification failed, connId=%{public}u, "
            "handle=%{public}d, err=%{public}d", connection->connectionId, ctx->underlayerHandle, rc);
        if (RetrySearchService(connection, BLE_CLIENT_REGISTER_NOTIFICATION_ERR) == SOFTBUS_OK) {
            rc = SOFTBUS_OK;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR;
        }
        return rc;
    }
    rc = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_SERVICE_SEARCHED, BLE_CONNECTION_STATE_CONN_NOTIFICATING);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, ctx->underlayerHandle, rc);
        return rc;
    }
    return SOFTBUS_OK;
}

static void SearchedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGW(CONN_BLE, "connection not exist, handle=%{public}d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "search service failed, connId=%{public}u, handle=%{public}d, status=%{public}d",
                connection->connectionId, ctx->underlayerHandle, ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_FAIL;
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_SERVICE_SEARCHING, BLE_CONNECTION_STATE_SERVICE_SEARCHED);
        if (rc != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
                connection->connectionId, ctx->underlayerHandle, rc);
            break;
        }
        rc = GattcGetServiceAndRegisterNotification(connection, ctx);
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    }
    ConnBleReturnConnection(&connection);
}

static void BleGattcRegisterNotificationCallback(int32_t underlayerHandle, int32_t status)
{
    CONN_LOGI(CONN_BLE, "gatt client callback, notification registered, handle=%{public}d, status=%{public}d",
        underlayerHandle, status);

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    if (ctx == NULL) {
        CONN_LOGE(CONN_BLE, "calloc failed, handle=%{public}d, status=%{public}d", underlayerHandle, status);
        return;
    }
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;

    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_NOTIFICATED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "post msg to looper failed: handle=%{public}d, status=%{public}d, err=%{public}d",
            underlayerHandle, status, rc);
        SoftBusFree(ctx);
    }
}

static int32_t SwitchNotifacatedHandler(
    enum ConnBleConnectionState state, const CommonStatusContext *ctx, ConnBleConnection *connection)
{
    int32_t rc = SOFTBUS_OK;
    switch (state) {
        case BLE_CONNECTION_STATE_CONN_NOTIFICATING:
            rc = NotificatedConnHandler(ctx->underlayerHandle, connection);
            if (rc == SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR &&
                RetrySearchService(connection, BLE_CLIENT_REGISTER_NOTIFICATION_ERR) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            }
            break;
        case BLE_CONNECTION_STATE_NET_NOTIFICATING:
            rc = NotificatedNetHandler(ctx->underlayerHandle, connection);
            break;
        default:
            CONN_LOGW(CONN_BLE, "unexpected state, currentState=%{public}d", connection->state);
            rc = SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR;
            break;
    }
    return rc;
}

static void NotificatedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGW(CONN_BLE, "connection not exist, handle=%{public}d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "register notification failed, connId=%{public}u, handle=%{public}d, status=%{public}d",
                connection->connectionId, ctx->underlayerHandle, ctx->status);
            if (RetrySearchService(connection, BLE_CLIENT_REGISTER_NOTIFICATION_FAIL) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            } else {
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_FAIL;
            }
            break;
        }
        rc = SoftBusMutexLock(&connection->lock);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        enum ConnBleConnectionState state = connection->state;
        (void)SoftBusMutexUnlock(&connection->lock);
        rc = SwitchNotifacatedHandler(state, ctx, connection);
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    }
    ConnBleReturnConnection(&connection);
}

static int32_t NotificatedConnHandler(int32_t underlayerHandle, ConnBleConnection *connection)
{
    int32_t status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_CONN_NOTIFICATING, BLE_CONNECTION_STATE_CONN_NOTIFICATED);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, underlayerHandle, status);
        return status;
    }

    SoftBusBtUuid serviceUuid = {
        .uuid = (char *)SOFTBUS_SERVICE_UUID,
        .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
    };
    SoftBusBtUuid netUuid = {
        .uuid = (char *)SOFTBUS_CHARA_BLENET_UUID,
        .uuidLen = strlen(SOFTBUS_CHARA_BLENET_UUID),
    };
    SoftBusBtUuid descriptorUuid = {
        .uuid = (char *)SOFTBUS_DESCRIPTOR_CONFIGURE_UUID,
        .uuidLen = strlen(SOFTBUS_DESCRIPTOR_CONFIGURE_UUID),
    };
    status = SoftbusGattcRegisterNotification(underlayerHandle, &serviceUuid, &netUuid, &descriptorUuid);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "register conn characteristic notification failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, underlayerHandle, status);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_CONN_NOTIFICATED, BLE_CONNECTION_STATE_NET_NOTIFICATING);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, underlayerHandle, status);
    }
    return status;
}

static int32_t NotificatedNetHandler(int32_t underlayerHandle, ConnBleConnection *connection)
{
    int32_t status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_NET_NOTIFICATING, BLE_CONNECTION_STATE_NET_NOTIFICATED);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, underlayerHandle, status);
        return status;
    }
    status = SoftbusGattcConfigureMtuSize(underlayerHandle, DEFAULT_MTU_SIZE);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "configure mtu failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
            connection->connectionId, underlayerHandle, status);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_ERR;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_NET_NOTIFICATED, BLE_CONNECTION_STATE_MTU_SETTING);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, error=%{public}d",
            connection->connectionId, underlayerHandle, status);
    }
    return status;
}

static void BleGattcConfigureMtuSizeCallback(int32_t underlayerHandle, int32_t mtuSize, int32_t status)
{
    CONN_LOGI(CONN_BLE, "gatt client callback, MTU configured, handle=%{public}d, mtu=%{public}d, status=%{public}d",
        underlayerHandle, mtuSize, status);
    MtuConfiguredContext *ctx = (MtuConfiguredContext *)SoftBusCalloc(sizeof(MtuConfiguredContext));
    if (ctx == NULL) {
        CONN_LOGE(CONN_BLE, "calloc mtu failed, handle=%{public}d, mtu=%{public}d, status=%{public}d", underlayerHandle,
            mtuSize, status);
        return;
    }
    ctx->common.underlayerHandle = underlayerHandle;
    ctx->common.status = status;
    ctx->mtuSize = mtuSize;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_MTU_SETTED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE,
            "post msg to looper failed: handle=%{public}d, mtu=%{public}d, status=%{public}d, err=%{public}d",
            underlayerHandle, mtuSize, status, rc);
        SoftBusFree(ctx);
    }
}

static void MtuSettedMsgHandler(const MtuConfiguredContext *ctx)
{
    int32_t underlayerHandle = ctx->common.underlayerHandle;
    int32_t status = ctx->common.status;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGW(CONN_BLE, "connection not exist, handle=%{public}d", underlayerHandle);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (status != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "register notification failed, connId=%{public}u, handle=%{public}d, status=%{public}d",
                connection->connectionId, underlayerHandle, status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_FAIL;
            break;
        }

        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_MTU_SETTING, BLE_CONNECTION_STATE_MTU_SETTED);
        if (rc != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "update connection state failed, connId=%{public}u, handle=%{public}d, err=%{public}d",
                connection->connectionId, underlayerHandle, status);
            break;
        }
        rc = SoftBusMutexLock(&connection->lock);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        connection->mtu = ctx->mtuSize;
        (void)SoftBusMutexUnlock(&connection->lock);
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    } else {
        g_clientEventListener.onClientConnected(connection->connectionId);
    }
    ConnBleReturnConnection(&connection);
}

int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble client connection disconnect failed: invalid param, connection is null");
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock failed, err=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    connection->state =
        underlayerHandle == INVALID_UNDERLAY_HANDLE ? BLE_CONNECTION_STATE_CLOSED : BLE_CONNECTION_STATE_CLOSING;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        CONN_LOGD(CONN_BLE, "ble client connection disconnect, handle is valid, repeat disconnect? just report close. "
            "connectionId=%{public}u", connection->connectionId);
        g_clientEventListener.onClientConnectionClosed(connection->connectionId, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    status = SoftbusBleGattcDisconnect(underlayerHandle, refreshGatt);
    if (status != SOFTBUS_OK || !grace) {
        (void)SoftbusGattcUnRegister(underlayerHandle);
        g_clientEventListener.onClientConnectionClosed(
            connection->connectionId, SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR);
    } else {
        ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT, connection->connectionId,
            0, NULL, UNDERLAY_CONNECTION_DISCONNECT_TIMEOUT);
    }
    CONN_LOGI(CONN_BLE,
        "ble client disconnect, connectionId=%{public}u, handle=%{public}d, grace=%{public}d, refreshGatt=%{public}d, "
        "err=%{public}d",
        connection->connectionId, underlayerHandle, grace, refreshGatt, status);
    return status;
}

static void DisconnectedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "connection not exist, handle=%{public}d", ctx->underlayerHandle);
        return;
    }
    uint32_t connectionId = connection->connectionId;
    ConnRemoveMsgFromLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT, connectionId, 0, NULL);
    (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
    int32_t rc = SOFTBUS_OK;
    enum ConnBleConnectionState state = BLE_CONNECTION_STATE_INVALID;
    do {
        int32_t status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u, err=%{public}d", connectionId, status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        state = connection->state;
        connection->state = BLE_CONNECTION_STATE_CLOSED;
        (void)SoftBusMutexUnlock(&connection->lock);
    } while (false);
    ConnBleReturnConnection(&connection);
    if (state < BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO) {
        g_clientEventListener.onClientFailed(connectionId, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_FAIL);
    } else {
        g_clientEventListener.onClientConnectionClosed(connectionId, rc);
    }
}

static void ClientWaitDiconnetTimeoutMsgHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "ble client wait disconnect timeout handler failed: connection not exist, connId=%{public}u", connectionId);
    CONN_LOGI(CONN_BLE, "ble client disconnect wait timeout, connId=%{public}u", connectionId);
    do {
        int32_t status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u, error=%{public}d", connectionId, status);
            break;
        }
        int32_t underlayerHandle = connection->underlayerHandle;
        (void)SoftBusMutexUnlock(&connection->lock);
        (void)SoftbusGattcUnRegister(underlayerHandle);
    } while (false);
    ConnBleReturnConnection(&connection);
    g_clientEventListener.onClientConnectionClosed(connectionId, SOFTBUS_CONN_BLE_DISCONNECT_WAIT_TIMEOUT_ERR);
}

static void BleGattcNotificationReceiveCallback(int32_t underlayerHandle, SoftBusGattcNotify *param, int32_t status)
{
    CONN_LOGI(CONN_BLE, "receive gatt data, handle=%{public}d, len=%{public}u", underlayerHandle, param->dataLen);
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "connection not exist");
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "status error, connId=%{public}u, handle=%{public}d, status=%{public}d",
            connection->connectionId, underlayerHandle, status);
        ConnBleReturnConnection(&connection);
        return;
    }

    bool isConnCharacteristic = false;
    if (memcmp(param->charaUuid.uuid, SOFTBUS_CHARA_BLECONN_UUID, param->charaUuid.uuidLen) == 0) {
        isConnCharacteristic = true;
    } else if (memcmp(param->charaUuid.uuid, SOFTBUS_CHARA_BLENET_UUID, param->charaUuid.uuidLen) == 0) {
        isConnCharacteristic = false;
    } else {
        CONN_LOGE(CONN_BLE,
            "notification receive failed: not NET or CONN characteristic, connId=%{public}u, handle=%{public}d",
            connection->connectionId, underlayerHandle);
        ConnAuditExtra extra = {
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .connectionId = connection->connectionId,
            .errcode = SOFTBUS_CONN_BLE_RECV_MSG_ERROR,
        };
        CONN_AUDIT(STATS_SCENE_CONN_BT_RECV_FAILED, extra);
        ConnBleReturnConnection(&connection);
        return;
    }
    uint32_t valueLen = 0;
    uint8_t *value =
        ConnGattTransRecv(connection->connectionId, param->data, param->dataLen, &connection->buffer, &valueLen);
    if (value == NULL) {
        ConnBleReturnConnection(&connection);
        return;
    }
    g_clientEventListener.onClientDataReceived(connection->connectionId, isConnCharacteristic, value, valueLen);
    ConnBleReturnConnection(&connection);
}

static char *GetBleAttrUuid(int32_t module)
{
    if (module == MODULE_BLE_NET) {
        return SOFTBUS_CHARA_BLENET_UUID;
    } else {
        return SOFTBUS_CHARA_BLECONN_UUID;
    }
}

int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble client send data failed, invalia param, connection is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(
        data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "ble client send data failed, invalia param, data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(
        dataLen != 0, SOFTBUS_INVALID_PARAM, CONN_BLE, "ble client send data failed, invalia param, data len is 0");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "ble client send data failed, try to get connection lock failed, connId=%{public}u, err=%{public}d",
        connection->connectionId, status);
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    char *characteristicUuid = GetBleAttrUuid(module);
    SoftBusGattcData gattcData = {
        .serviceUuid = {
            .uuid = SOFTBUS_SERVICE_UUID,
            .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
        },
        .characterUuid = {
            .uuid = characteristicUuid,
            .uuidLen = strlen(characteristicUuid),
        },
        .value = data,
        .valueLen = dataLen,
        .writeType = SOFTBUS_GATT_WRITE_NO_RSP,
    };
    return SoftbusGattcWriteCharacteristic(underlayerHandle, &gattcData);
}

int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble client update priority failed, invalia param, connection is null");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "ble client update priority failed, try to get connection lock failed, "
        "connectionId=%{public}u, error=%{public}d",
        connection->connectionId, status);
    int32_t underlayerHandle = connection->underlayerHandle;
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);

    if (state < BLE_CONNECTION_STATE_CONNECTED || state > BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO) {
        CONN_LOGW(CONN_BLE, "current connection state not support update priority, connId=%{public}u, err=%{public}d",
            connection->connectionId, state);
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }

    SoftbusBleGattPriority gattPriority;
    switch (priority) {
        case CONN_BLE_PRIORITY_BALANCED:
            gattPriority = SOFTBUS_GATT_PRIORITY_BALANCED;
            break;
        case CONN_BLE_PRIORITY_HIGH:
            gattPriority = SOFTBUS_GATT_PRIORITY_HIGH;
            break;
        case CONN_BLE_PRIORITY_LOW_POWER:
            gattPriority = SOFTBUS_GATT_PRIORITY_LOW_POWER;
            break;
        default:
            CONN_LOGW(CONN_BLE, "connId=%{public}u, unknownPriority=%{public}d", connection->connectionId, priority);
            return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "convert string mac to binary fail, connId=%{public}u, err=%{public}d",
            connection->connectionId, status);
        return status;
    }

    int32_t ret = SoftbusGattcSetPriority(underlayerHandle, &binaryAddr, gattPriority);
    return ret;
}

static void BleGattClientMsgHandler(SoftBusMessage *msg)
{
    switch (msg->what) {
        case MSG_CLIENT_CONNECTED:
            ConnectedMsgHandler((CommonStatusContext *)msg->obj);
            break;
        case MSG_CLIENT_SERVICE_SEARCHED:
            SearchedMsgHandler((CommonStatusContext *)msg->obj);
            break;
        case MSG_CLIENT_NOTIFICATED:
            NotificatedMsgHandler((CommonStatusContext *)msg->obj);
            break;
        case MSG_CLIENT_DISCONNECTED:
            DisconnectedMsgHandler((CommonStatusContext *)msg->obj);
            break;
        case MSG_CLIENT_MTU_SETTED:
            MtuSettedMsgHandler((MtuConfiguredContext *)msg->obj);
            break;
        case MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT:
            ClientWaitDiconnetTimeoutMsgHandler((uint32_t)msg->arg1);
            break;
        case MSG_CLIENT_WAIT_FAST_CONNECT_TIMEOUT:
            ClientWaitFastConnectTimeoutMsgHandler((uint32_t)msg->arg1);
            break;
        default:
            CONN_LOGW(CONN_BLE,
                "ATTENTION, ble gatt client looper receive unexpected msg just ignore, FIX "
                "it quickly. what=%{public}d",
                msg->what);
            break;
    }
}

static int BleCompareGattClientLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT:
        case MSG_CLIENT_WAIT_FAST_CONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_BLE,
            "compare failed to avoid fault silence, what=%{public}d, arg1=%{public}" PRIu64 ", arg2=%{public}" PRIu64
            ", objIsNull=%{public}d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        looper != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT, "init ble client failed: invalid param, looper is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(
        listener != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT, "init ble client failed: invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientConnected != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble client failed: invalid param, listener onClientConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble client failed: invalid param, listener onClientFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientDataReceived != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble client failed: invalid param, listener onClientDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onClientConnectionClosed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble client failed: invalid param, listener onClientConnectionClosed is null");
    int32_t status = InitSoftbusAdapterClient();
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, status, CONN_INIT,
        "init softbus adapter failed, err=%{public}d", status);
    g_bleGattClientAsyncHandler.handler.looper = looper;
    g_clientEventListener = *listener;

    return SOFTBUS_OK;
}
