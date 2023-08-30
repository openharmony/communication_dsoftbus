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

#include "message_handler.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

#define INVALID_GATTC_ID (-1)
#define DEFAULT_MTU_SIZE 512

enum ClientLoopMsgType {
    MSG_CLIENT_CONNECTED = 300,
    MSG_CLIENT_SERVICE_SEARCHED,
    MSG_CLIENT_NOTIFICATED,
    MSG_CLIENT_DISCONNECTED,
    MSG_CLIENT_MTU_SETTED,
    MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT,
};

enum RetrySearchServiceReason {
    BLE_CLIENT_REGISTER_NOTIFICATION_ERR,
    BLE_CLIENT_REGISTER_NOTIFICATION_FAIL,
    BLE_CLIENT_SEARCH_SERVICE_ERR,
    BLE_CLIENT_GET_SERVICE_ERR,
};

typedef struct {
    int32_t underlayerHandle;
    int32_t status;
} CommonStatusContext;

typedef struct {
    CommonStatusContext common;
    int32_t mtuSize;
} MtuConfiguredContext;

static int32_t NotificatedConnHandler(int32_t underlayerHandle, ConnBleConnection *connection);
static int32_t NotificatedNetHandler(int32_t underlayerHandle, ConnBleConnection *connection);
static void BleGattClientMsgHandler(SoftBusMessage *msg);
static int BleCompareGattClientLooperEventFunc(const SoftBusMessage *msg, void *args);
static int32_t RetrySearchService(ConnBleConnection *connection, enum RetrySearchServiceReason reason);
static ConnBleClientEventListener g_clientEventListener = { 0 };
static SoftBusHandlerWrapper g_bleGattClientAsyncHandler = {
    .handler = {
        .name = (char *)"BleGattClientAsyncHandler",
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
        CLOGE("lock failed, connId=%u, err=%d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }

    if (connection->state != expectedState) {
        CLOGE("unexpected state, actual state=%d, expected state=%d, next state=%d", connection->state, expectedState,
            nextState);
        (void)SoftBusMutexUnlock(&connection->lock);
        return SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR;
    }
    connection->state = nextState;
    (void)SoftBusMutexUnlock(&connection->lock);
    return SOFTBUS_OK;
}

int32_t ConnGattClientConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR,
        "ble client connect failed: invalid param, connection is null");

    SoftBusBtAddr binaryAddr = { 0 };
    int32_t status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("client connect %u failed: convert string mac to binary fail, err=%d", connection->connectionId, status);
        return status;
    }
    int32_t underlayerHandle = SoftbusGattcRegister();
    CONN_CHECK_AND_RETURN_RET_LOG(underlayerHandle != INVALID_GATTC_ID, SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_ERR,
        "ble client connect failed: underlayer register failed, underlayer handle=%d", underlayerHandle);
    if (connection->fastestConnectEnable && SoftbusGattcSetFastestConn(underlayerHandle) != SOFTBUS_OK) {
        CLOGW("enable ble fastest connection failed, it is not a big deal, go ahead");
    }
    status = SoftbusGattcConnect(underlayerHandle, &binaryAddr);
    if (status != SOFTBUS_OK) {
        CLOGE("client connect %u failed: underlayer connect failed, err=%d", connection->connectionId, status);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR;
    }

    status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("client connection %u lock failed, err=%d", connection->connectionId, status);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return SOFTBUS_LOCK_ERR;
    }
    connection->underlayerHandle = underlayerHandle;
    connection->state = BLE_CONNECTION_STATE_CONNECTING;
    (void)SoftBusMutexUnlock(&connection->lock);
    CLOGI("ble client connect %u, handle=%d, fastest enable=%d", connection->connectionId, underlayerHandle,
        connection->fastestConnectEnable);
    return SOFTBUS_OK;
}

static void BleGattcConnStateCallback(int32_t underlayerHandle, int32_t state, int32_t status)
{
    CLOGI("gatt client callback, state changed, handle=%d, state=%d ,status=%d", underlayerHandle, state, status);
    if (state != SOFTBUS_BT_CONNECT && state != SOFTBUS_BT_DISCONNECT) {
        return;
    }

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    if (ctx == NULL) {
        CLOGE("connection state changed handle failed: calloc failed, handle=%d ,status=%d", underlayerHandle, status);
        return;
    }
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;
    enum ClientLoopMsgType what = state == SOFTBUS_BT_CONNECT ? MSG_CLIENT_CONNECTED : MSG_CLIENT_DISCONNECTED;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, what, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CLOGE("connection state changed handle failed: post msg to looper failed: handle=%d, "
              "state=%d ,status=%d, err=%d", underlayerHandle, state, status, rc);
        SoftBusFree(ctx);
    }
}

static void ConnectedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CLOGE("not connect, connId=%u, handle=%d, status=%d", connection->connectionId, ctx->underlayerHandle,
                ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_FAIL;
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_CONNECTING, BLE_CONNECTION_STATE_CONNECTED);
        if (rc != SOFTBUS_OK) {
            CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
                ctx->underlayerHandle, rc);
            break;
        }
        rc = SoftbusGattcSearchServices(ctx->underlayerHandle);
        if (rc != SOFTBUS_OK) {
            CLOGE("underlay search service failed, connId=%u, handle=%d, status=%d", connection->connectionId,
                ctx->underlayerHandle, rc);
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
            CLOGE("update connection state failed, connection id=%u, underlayer handle=%d, err=%d",
                connection->connectionId, ctx->underlayerHandle, rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    }
    ConnBleReturnConnection(&connection);
}

static int32_t RetrySearchService(ConnBleConnection *connection, enum RetrySearchServiceReason reason)
{
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("try to lock failed, connId=%u, reason=%d, err=%d", connection->connectionId, reason, status);
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
        CLOGE("state=%d, retry search service count=%d, connId=%u, handle=%d, reason=%d, just ignore.", state,
            retrySearchServiceCnt, connection->connectionId, underlayerHandle, reason);
        return SOFTBUS_ERR;
    }

    status = SoftbusGattcRefreshServices(underlayerHandle);
    if (status != SOFTBUS_OK) {
        CLOGE("fresh service failed, connId=%u, handle=%d, reason=%d, err=%d,", connection->connectionId,
            underlayerHandle, reason, status);
        return status;
    }
    status = SoftbusGattcSearchServices(underlayerHandle);
    if (status != SOFTBUS_OK) {
        CLOGE("search service failed, connId=%u, handle=%d, reason=%d, err=%d,", connection->connectionId,
            underlayerHandle, reason, status);
        return status;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_CONNECTED, BLE_CONNECTION_STATE_SERVICE_SEARCHING);
    if (status != SOFTBUS_OK) {
        CLOGE("retry search service failed: update connection state failed, connection id=%u, "
              "underlayer handle=%d, reason=%d, error=%d",
            connection->connectionId, underlayerHandle, reason, status);
        return status;
    }
    CLOGW("retry search service, connId=%u, handle=%d, reason=%d", connection->connectionId, underlayerHandle, reason);
    return SOFTBUS_OK;
}

static void BleGattcSearchServiceCallback(int32_t underlayerHandle, int32_t status)
{
    CLOGI("gatt client callback, service searched, handle=%d, status=%d", underlayerHandle, status);

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    if (ctx == NULL) {
        CLOGE("service searched handle failed: calloc failed, handle=%d ,status=%d", underlayerHandle, status);
        return;
    }
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_SERVICE_SEARCHED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CLOGE("post msg to looper failed: handle=%d, status=%d, err=%d", underlayerHandle, status, rc);
        SoftBusFree(ctx);
    }
}

static void SearchedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CLOGE("search service failed, connId=%u, handle=%d, status=%d", connection->connectionId,
                ctx->underlayerHandle, ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_FAIL;
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_SERVICE_SEARCHING, BLE_CONNECTION_STATE_SERVICE_SEARCHED);
        if (rc != SOFTBUS_OK) {
            CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
                ctx->underlayerHandle, rc);
            break;
        }
        SoftBusBtUuid serviceUuid = {
            .uuid = (char *)SOFTBUS_SERVICE_UUID,
            .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
        };
        rc = SoftbusGattcGetService(ctx->underlayerHandle, &serviceUuid);
        if (rc != SOFTBUS_OK) {
            CLOGE("underlay get service failed, connId=%u, handle=%d, error=%d", connection->connectionId,
                ctx->underlayerHandle, rc);
            if (RetrySearchService(connection, BLE_CLIENT_GET_SERVICE_ERR) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            } else {
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_GET_SERVICE_ERR;
            }
            break;
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
            CLOGE("underlay register conn characteristic notification failed, connId=%u, handle=%d, err=%d",
                connection->connectionId, ctx->underlayerHandle, rc);
            if (RetrySearchService(connection, BLE_CLIENT_REGISTER_NOTIFICATION_ERR) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            } else {
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR;
            }
            break;
        }
        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_SERVICE_SEARCHED, BLE_CONNECTION_STATE_CONN_NOTIFICATING);
        if (rc != SOFTBUS_OK) {
            CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
                ctx->underlayerHandle, rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        g_clientEventListener.onClientFailed(connection->connectionId, rc);
    }
    ConnBleReturnConnection(&connection);
}

static void BleGattcRegisterNotificationCallback(int32_t underlayerHandle, int32_t status)
{
    CLOGI("gatt client callback, notification registered, handle=%d, status=%d", underlayerHandle, status);

    CommonStatusContext *ctx = (CommonStatusContext *)SoftBusCalloc(sizeof(CommonStatusContext));
    if (ctx == NULL) {
        CLOGE("calloc failed, handle=%d ,status=%d", underlayerHandle, status);
        return;
    }
    ctx->underlayerHandle = underlayerHandle;
    ctx->status = status;

    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_NOTIFICATED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CLOGE("post msg to looper failed: handle=%d, status=%d, err=%d", underlayerHandle, status, rc);
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
            CLOGE("unexpected state, current state=%d", connection->state);
            rc = SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR;
            break;
    }
    return rc;
}
static void NotificatedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", ctx->underlayerHandle);
        (void)SoftbusGattcUnRegister(ctx->underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            CLOGE("register notification failed, connId=%u, handle=%d, status=%d", connection->connectionId,
                ctx->underlayerHandle, ctx->status);
            if (RetrySearchService(connection, BLE_CLIENT_REGISTER_NOTIFICATION_FAIL) == SOFTBUS_OK) {
                rc = SOFTBUS_OK;
            } else {
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_FAIL;
            }
            break;
        }
        rc = SoftBusMutexLock(&connection->lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("lock failed, connId=%u, err=%d", connection->connectionId, rc);
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
        CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
            underlayerHandle, status);
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
        CLOGE("register conn characteristic notification failed, connId=%u, handle=%d, err=%d",
            connection->connectionId, underlayerHandle, status);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_CONN_NOTIFICATED, BLE_CONNECTION_STATE_NET_NOTIFICATING);
    if (status != SOFTBUS_OK) {
        CLOGE("update connection state failed, connId=%u, underlayer handle=%d, error=%d", connection->connectionId,
            underlayerHandle, status);
    }
    return status;
}

static int32_t NotificatedNetHandler(int32_t underlayerHandle, ConnBleConnection *connection)
{
    int32_t status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_NET_NOTIFICATING, BLE_CONNECTION_STATE_NET_NOTIFICATED);
    if (status != SOFTBUS_OK) {
        CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
            underlayerHandle, status);
        return status;
    }
    status = SoftbusGattcConfigureMtuSize(underlayerHandle, DEFAULT_MTU_SIZE);
    if (status != SOFTBUS_OK) {
        CLOGE("configure mtu failed, connId=%u, handle=%d, err=%d", connection->connectionId, underlayerHandle, status);
        return SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_ERR;
    }
    status = UpdateBleConnectionStateInOrder(
        connection, BLE_CONNECTION_STATE_NET_NOTIFICATED, BLE_CONNECTION_STATE_MTU_SETTING);
    if (status != SOFTBUS_OK) {
        CLOGE("update connection state failed, connId=%u, handle=%d, error=%d", connection->connectionId,
            underlayerHandle, status);
    }
    return status;
}

static void BleGattcConfigureMtuSizeCallback(int32_t underlayerHandle, int32_t mtuSize, int32_t status)
{
    CLOGI("gatt client callback, MTU configured, handle=%d, mtu=%d, status=%d", underlayerHandle, mtuSize, status);
    MtuConfiguredContext *ctx = (MtuConfiguredContext *)SoftBusCalloc(sizeof(MtuConfiguredContext));
    if (ctx == NULL) {
        CLOGE("calloc mtu failed, handle=%d, mtu=%d, status=%d", underlayerHandle, mtuSize, status);
        return;
    }
    ctx->common.underlayerHandle = underlayerHandle;
    ctx->common.status = status;
    ctx->mtuSize = mtuSize;
    int32_t rc = ConnPostMsgToLooper(&g_bleGattClientAsyncHandler, MSG_CLIENT_MTU_SETTED, 0, 0, ctx, 0);
    if (rc != SOFTBUS_OK) {
        CLOGE("post msg to looper failed: handle=%d, mtu=%d, status=%d, err=%d", underlayerHandle, mtuSize,
            status, rc);
        SoftBusFree(ctx);
    }
}

static void MtuSettedMsgHandler(const MtuConfiguredContext *ctx)
{
    int32_t underlayerHandle = ctx->common.underlayerHandle;
    int32_t status = ctx->common.status;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", underlayerHandle);
        (void)SoftbusGattcUnRegister(underlayerHandle);
        return;
    }
    int32_t rc = SOFTBUS_OK;
    do {
        if (status != SOFTBUS_OK) {
            CLOGE("register notification failed, connId=%u, handle=%d, status=%d", connection->connectionId,
                underlayerHandle, status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_FAIL;
            break;
        }

        rc = UpdateBleConnectionStateInOrder(
            connection, BLE_CONNECTION_STATE_MTU_SETTING, BLE_CONNECTION_STATE_MTU_SETTED);
        if (rc != SOFTBUS_OK) {
            CLOGE("update connection state failed, connId=%u, handle=%d, err=%d", connection->connectionId,
                underlayerHandle, status);
            break;
        }
        rc = SoftBusMutexLock(&connection->lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("lock failed, connId=%u, err=%d", connection->connectionId, rc);
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
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR,
        "ble client connection disconnect failed: invalid param, connection is null");
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("lock failed, err=%d", status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    connection->state =
        underlayerHandle == INVALID_UNDERLAY_HANDLE ? BLE_CONNECTION_STATE_CLOSED : BLE_CONNECTION_STATE_CLOSING;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        CLOGD("ble client connection %u disconnect, handle is valid, repeat disconnect? just report close",
            connection->connectionId);
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
    CLOGI("ble client connection %u disconnect, handle=%d, grace=%d, refresh gatt=%d err=%d", connection->connectionId,
        underlayerHandle, grace, refreshGatt, status);
    return status;
}

static void DisconnectedMsgHandler(const CommonStatusContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(ctx->underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", ctx->underlayerHandle);
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
            CLOGE("lock failed, connId=%u, err=%d", connectionId, status);
            rc = SOFTBUS_LOCK_ERR;
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
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "ble client wait disconnect timeout handler failed: connnection not exist, connId=%u", connectionId);
    CLOGI("ble client disconnect wait timeout, connId=%u", connectionId);
    do {
        int32_t status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CLOGE("lock failed, connId=%u, error=%d", connectionId, status);
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
    CLOGE("receive gatt data, handle=%d, len=%u", underlayerHandle, param->dataLen);
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_CLIENT, BLE_GATT);
    if (connection == NULL) {
        CLOGE("connection not exist, handle=%d", underlayerHandle);
        return;
    }
    if (status != SOFTBUS_OK) {
        CLOGE("notification receive failed: status error, connId=%u, handle=%d, status=%d", connection->connectionId,
            underlayerHandle, status);
        ConnBleReturnConnection(&connection);
        return;
    }

    bool isConnCharacteristic = false;
    if (memcmp(param->charaUuid.uuid, SOFTBUS_CHARA_BLECONN_UUID, param->charaUuid.uuidLen) == 0) {
        isConnCharacteristic = true;
    } else if (memcmp(param->charaUuid.uuid, SOFTBUS_CHARA_BLENET_UUID, param->charaUuid.uuidLen) == 0) {
        isConnCharacteristic = false;
    } else {
        CLOGE("notification receive failed: not NET or CONN characteristic, connId=%u, handle=%d",
            connection->connectionId, underlayerHandle);
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
        return (char *)SOFTBUS_CHARA_BLENET_UUID;
    } else {
        return (char *)SOFTBUS_CHARA_BLECONN_UUID;
    }
}

int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        connection != NULL, SOFTBUS_INVALID_PARAM, "ble client send data failed, invalia param, connection is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        data != NULL, SOFTBUS_INVALID_PARAM, "ble client send data failed, invalia param, data is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        dataLen != 0, SOFTBUS_INVALID_PARAM, "ble client send data failed, invalia param, data len is 0");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOG(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ble client send data failed, try to get connection lock failed, connId=%u, err=%d", connection->connectionId,
        status);
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    char *characteristicUuid = GetBleAttrUuid(module);
    SoftBusGattcData gattcData = {
        .serviceUuid = {
            .uuid = (char *)SOFTBUS_SERVICE_UUID,
            .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
        },
        .characterUuid = {
            .uuid = characteristicUuid,
            .uuidLen = strlen(characteristicUuid),
        },
        .value = data,
        .valueLen = dataLen,
    };
    return SoftbusGattcWriteCharacteristic(underlayerHandle, &gattcData);
}

int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_INVALID_PARAM,
        "ble client update priority failed, invalia param, connection is null");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOG(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ble client update priority failed, try to get connection lock failed, connection id=%u, error=%d",
        connection->connectionId, status);
    int32_t underlayerHandle = connection->underlayerHandle;
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);

    if (state < BLE_CONNECTION_STATE_CONNECTED || state > BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO) {
        CLOGE("current connection state not support update priority, connId=%u, err=%d",
            connection->connectionId, state);
        return SOFTBUS_ERR;
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
            CLOGE("connId=%u, unknown priority: %d", connection->connectionId, priority);
            return SOFTBUS_ERR;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("convert string mac to binary fail, connId=%u, err=%d", connection->connectionId, status);
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
        default:
            CLOGE("ATTENTION, ble gatt client looper receive unexpected msg, what=%d, just ignore, FIX it quickly.",
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
        case MSG_CLIENT_WAIT_DISCONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CLOGE("compare failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        looper != NULL, SOFTBUS_INVALID_PARAM, "init ble client failed: invalid param, looper is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        listener != NULL, SOFTBUS_INVALID_PARAM, "init ble client failed: invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientConnected != NULL, SOFTBUS_INVALID_PARAM,
        "init ble client failed: invalid param, listener onClientConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientFailed != NULL, SOFTBUS_INVALID_PARAM,
        "init ble client failed: invalid param, listener onClientFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        "init ble client failed: invalid param, listener onClientDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onClientConnectionClosed != NULL, SOFTBUS_INVALID_PARAM,
        "init ble client failed: invalid param, listener onClientConnectionClosed is null");

    static SoftBusGattcCallback gattcCallback = {
        .ConnectionStateCallback = BleGattcConnStateCallback,
        .ServiceCompleteCallback = BleGattcSearchServiceCallback,
        .RegistNotificationCallback = BleGattcRegisterNotificationCallback,
        .NotificationReceiveCallback = BleGattcNotificationReceiveCallback,
        .ConfigureMtuSizeCallback = BleGattcConfigureMtuSizeCallback,
    };
    SoftbusGattcRegisterCallback(&gattcCallback);

    g_bleGattClientAsyncHandler.handler.looper = looper;
    g_clientEventListener = *listener;
    return SOFTBUS_OK;
}
