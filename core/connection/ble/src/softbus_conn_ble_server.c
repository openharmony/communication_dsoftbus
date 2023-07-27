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

#include "softbus_conn_ble_server.h"

#include "securec.h"

#include "message_handler.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"

enum GattServerState {
    BLE_SERVER_STATE_INITIAL = 0,
    BLE_SERVER_STATE_SERVICE_ADDING,
    BLE_SERVER_STATE_SERVICE_ADDED,
    BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING,
    BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDED,
    BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING,
    BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED,
    BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING,
    BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDED,
    BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING,
    BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED,
    BLE_SERVER_STATE_SERVICE_STARTING,
    BLE_SERVER_STATE_SERVICE_STARTED,
    BLE_SERVER_STATE_SERVICE_STOPPING,
    BLE_SERVER_STATE_SERVICE_STOPPED,
    BLE_SERVER_STATE_SERVICE_DELETING,
    BLE_SERVER_STATE_SERVICE_DELETED,
    BLE_SERVER_STATE_MAX
};

typedef struct {
    SoftBusMutex lock;
    enum GattServerState state;
    int32_t serviceHandle;
    int32_t connCharacteristicHandle;
    int32_t connDescriptorHandle;
    int32_t netCharacteristicHandle;
    int32_t netDescriptorHandle;
} BleServerState;

typedef struct {
    int32_t status;
    SoftBusBtUuid uuid;
    int32_t srvcHandle;
} ServiceAddMsgContext;

typedef struct {
    int32_t status;
    SoftBusBtUuid uuid;
    int32_t srvcHandle;
    int32_t characteristicHandle;
} CharacteristicAddMsgContext;

typedef struct {
    int32_t status;
    SoftBusBtUuid uuid;
    int32_t srvcHandle;
    int32_t descriptorHandle;
} DescriptorAddMsgContext;

typedef struct {
    int32_t status;
    int32_t srvcHandle;
} CommonStatusMsgContext;

enum ServerLoopMsgType {
    MSG_SERVER_SERVICE_ADDED = 200,
    MSG_SERVER_CHARACTERISTIC_ADDED,
    MSG_SERVER_DESCRIPTOR_ADDED,
    MSG_SERVER_SERVICE_STARTED,
    MSG_SERVER_SERVICE_STOPED,
    MSG_SERVER_SERVICE_DELETED,
    MSG_SERVER_WAIT_START_SERVER_TIMEOUT,
    MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT,
    MSG_SERVER_WAIT_MTU_TIMEOUT,
    MSG_SERVER_WAIT_DICONNECT_TIMEOUT,
};

static int32_t BleNetDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx);
static int32_t BleConnDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx);
static int32_t BleRegisterGattServerCallback(void);
static void BleGattServerMsgHandler(SoftBusMessage *msg);
static int BleCompareGattServerLooperEventFunc(const SoftBusMessage *msg, void *args);

static const int32_t MAX_SERVICE_CHAR_NUM = 8;
static SoftBusHandlerWrapper g_bleGattServerAsyncHandler = {
    .handler = {
        .name = "BleGattServerAsyncHandler",
        .HandleMessage = BleGattServerMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BleCompareGattServerLooperEventFunc,
};
static ConnBleServerEventListener g_serverEventListener = { 0 };
static BleServerState g_serverState = {
    .state = BLE_SERVER_STATE_INITIAL,
    .serviceHandle = -1,
    .connCharacteristicHandle = -1,
    .connDescriptorHandle = -1,
    .netCharacteristicHandle = -1,
    .netDescriptorHandle = -1,
};

static int32_t UpdateBleServerStateInOrder(enum GattServerState expectedState, enum GattServerState nextState)
{
    int32_t status = SoftBusMutexLock(&g_serverState.lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! update ble server state in order failed: try to get lock failed, error=%d",
            status);
        return SOFTBUS_LOCK_ERR;
    }

    if (g_serverState.state != expectedState) {
        CLOGE("update ble server state in order failed: actual state=%d, expected state=%d, next state=%d",
            g_serverState.state, expectedState, nextState);
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        return SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR;
    }
    g_serverState.state = nextState;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    return SOFTBUS_OK;
}

static void ResetServerState()
{
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_serverState.lock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! ble reset server state failed, try to lock failed");
    int32_t serviceHandle = g_serverState.serviceHandle;
    g_serverState.state = BLE_SERVER_STATE_INITIAL;
    g_serverState.serviceHandle = -1;
    g_serverState.connCharacteristicHandle = -1;
    g_serverState.connDescriptorHandle = -1;
    g_serverState.netCharacteristicHandle = -1;
    g_serverState.netDescriptorHandle = -1;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    if (serviceHandle != -1) {
        SoftBusGattsDeleteService(serviceHandle);
    }
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
    SoftBusUnRegisterGattsCallbacks();
}

int32_t ConnGattServerStartService(void)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_serverState.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ATTENTION UNEXPECTED ERROR! ble server start service failed: try to lock failed");
    enum GattServerState state = g_serverState.state;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    if (state == BLE_SERVER_STATE_SERVICE_STARTED) {
        return SOFTBUS_OK;
    }
    ResetServerState();

    int32_t status = BleRegisterGattServerCallback();
    if (status != SOFTBUS_OK) {
        CLOGE("ble server start service failed: register underlayer callback failed, error=%d", status);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_REGISTER_CALLBACK_ERR;
    }
    status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_INITIAL, BLE_SERVER_STATE_SERVICE_ADDING);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server start service failed: update server state failed, error=%d", status);
        return status;
    }
    SoftBusBtUuid uuid = {
        .uuid = SOFTBUS_SERVICE_UUID,
        .uuidLen = strlen(SOFTBUS_SERVICE_UUID),
    };
    status = SoftBusGattsAddService(uuid, true, MAX_SERVICE_CHAR_NUM);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server start service failed: underlayer add service failed, error=%d", status);
        ResetServerState();
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR;
    }
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL,
        SERVER_WAIT_START_SERVER_TIMEOUT_MILLIS);
    return SOFTBUS_OK;
}

static void BleServiceAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle)
{
    CLOGI("receive gatt server callback, server added, service handle=%u, status=%d", srvcHandle, status);
    ServiceAddMsgContext *ctx = SoftBusCalloc(sizeof(ServiceAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "receive gatt server callback, server added handle failed: calloc service add msg context failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("receive gatt server callback, server added handle failed: memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, server added handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceAddMsgHandler(const ServiceAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->uuid.uuidLen != strlen(SOFTBUS_SERVICE_UUID) ||
            memcmp(ctx->uuid.uuid, SOFTBUS_SERVICE_UUID, ctx->uuid.uuidLen) != 0) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_SERVICE_ERR;
            CLOGE("ble service added msg handler failed: unkown service id, error=%d", rc);
            break;
        }
        if (ctx->status != SOFTBUS_OK) {
            CLOGE("ble service added msg handler failed: underlay returned status is not success, status=%d",
                ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_FAIL;
            break;
        }
        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! ble service added msg handler failed: try to lock failed, error=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        g_serverState.serviceHandle = ctx->srvcHandle;
        (void)SoftBusMutexUnlock(&g_serverState.lock);

        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDING, BLE_SERVER_STATE_SERVICE_ADDED);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble service added msg handler failed: update server state failed, error=%d", rc);
            break;
        }
        SoftBusBtUuid uuid = {
            .uuid = SOFTBUS_CHARA_BLENET_UUID,
            .uuidLen = strlen(SOFTBUS_CHARA_BLENET_UUID),
        };
        rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid,
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE,
            SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble service added msg handler failed: underlayer add characteristic failed, error=%d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDED, BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble service added msg handler failed: update server state failed, error=%d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState();
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        g_serverEventListener.onServerStarted(BLE_GATT, rc);
    }
}

static void BleCharacteristicAddCallback(
    int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t characteristicHandle)
{
    CLOGI("receive gatt server callback, characteristic added, service handle=%u, characteristic handle status=%d",
        srvcHandle, characteristicHandle, status);
    CharacteristicAddMsgContext *ctx = SoftBusCalloc(sizeof(CharacteristicAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL,
        "receive gatt server callback, characteristic added handle failed: calloc characteristic add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("receive gatt server callback, characteristic added handle failed: memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->characteristicHandle = characteristicHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_CHARACTERISTIC_ADDED, 0, 0, ctx, 0) !=
        SOFTBUS_OK) {
        CLOGE("receive gatt server callback, characteristic added handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleCharacteristicAddMsgHandler(const CharacteristicAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        enum GattServerState expect;
        enum GattServerState next;
        enum GattServerState nextNext;
        bool isConnCharacterisic = false;
        if (ctx->uuid.uuidLen == strlen(SOFTBUS_CHARA_BLENET_UUID) &&
            memcmp(ctx->uuid.uuid, SOFTBUS_CHARA_BLENET_UUID, ctx->uuid.uuidLen) == 0) {
            expect = BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING;
            next = BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDED;
            nextNext = BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING;
            isConnCharacterisic = false;
        } else if (ctx->uuid.uuidLen == strlen(SOFTBUS_CHARA_BLECONN_UUID) &&
            memcmp(ctx->uuid.uuid, SOFTBUS_CHARA_BLECONN_UUID, ctx->uuid.uuidLen) == 0) {
            expect = BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING;
            next = BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDED;
            nextNext = BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING;
            isConnCharacterisic = true;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_CHARACTERISTIC_ERR;
            CLOGE("characteristic added msg handler failed: unkown characteristic, error=%d", rc);
            break;
        }
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_FAIL;
            CLOGE(
                "characteristic added msg handler failed: underlayer return status is not success, status=%d, error=%d",
                ctx->status, rc);
            break;
        }

        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! characteristic added msg handler failed: try to lock failed, error=%d",
                rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        if (ctx->srvcHandle != g_serverState.serviceHandle) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("characteristic added msg handler failed: service handle is different, context service handle=%d, "
                  "server service handle=%d, error=%d",
                ctx->srvcHandle, g_serverState.serviceHandle, rc);
            break;
        }
        if (isConnCharacterisic) {
            g_serverState.connCharacteristicHandle = ctx->characteristicHandle;
        } else {
            g_serverState.netCharacteristicHandle = ctx->characteristicHandle;
        }
        (void)SoftBusMutexUnlock(&g_serverState.lock);

        rc = UpdateBleServerStateInOrder(expect, next);
        if (rc != SOFTBUS_OK) {
            CLOGE("characteristic added msg handler failed: update server state failed, error=%d", rc);
            break;
        }

        SoftBusBtUuid uuid = {
            .uuid = SOFTBUS_DESCRIPTOR_CONFIGURE_UUID,
            .uuidLen = strlen(SOFTBUS_DESCRIPTOR_CONFIGURE_UUID),
        };
        rc = SoftBusGattsAddDescriptor(
            ctx->srvcHandle, uuid, SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
        if (rc != SOFTBUS_OK) {
            CLOGE("characteristic added msg handler failed: underlayer add decriptor failed, error=%d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_ERR;
            break;
        }
        rc = UpdateBleServerStateInOrder(next, nextNext);
        if (rc != SOFTBUS_OK) {
            CLOGE("characteristic added msg handler failed: update server state failed, error=%d", rc);
            break;
        }
    } while (false);
    if (rc != SOFTBUS_OK) {
        ResetServerState();
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        g_serverEventListener.onServerStarted(BLE_GATT, rc);
    }
}

static void BleDescriptorAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t descriptorHandle)
{
    CLOGI("receive gatt server callback, descriptor added, service handle=%u, descriptor handle=%d, status=%d",
        srvcHandle, descriptorHandle, status);
    DescriptorAddMsgContext *ctx = SoftBusCalloc(sizeof(DescriptorAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "receive gatt server callback, descriptor added handle failed: calloc descriptor add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("receive gatt server callback, descriptor added handle failed: memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->descriptorHandle = descriptorHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_DESCRIPTOR_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, descriptor added handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->uuid.uuidLen != strlen(SOFTBUS_DESCRIPTOR_CONFIGURE_UUID) ||
            memcmp(ctx->uuid.uuid, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID, ctx->uuid.uuidLen) != 0) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_DESCRIPTOR_ERR;
            CLOGE("descriptor added msg handler failed: unkown desciptor uuid, error=%d", rc);
            break;
        }
        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! descriptor added msg handler failed: try to lock failed, error=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        bool isConnDescriptor = false;
        if (g_serverState.netDescriptorHandle == -1) {
            isConnDescriptor = false;
        } else if (g_serverState.connDescriptorHandle == -1) {
            isConnDescriptor = true;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_HANDLE_MISMATCH_ERR;
        }
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("descriptor added msg handler failed: descriptor handle mismatch, error=%d", rc);
            break;
        }
        rc = isConnDescriptor ? BleConnDescriptorAddMsgHandler(ctx) : BleNetDescriptorAddMsgHandler(ctx);
    } while (false);
    if (rc != SOFTBUS_OK) {
        ResetServerState();
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        g_serverEventListener.onServerStarted(BLE_GATT, rc);
    }
}

static int32_t BleNetDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CLOGE(
            "net desciptor added msg handler failed: underlayer return status is not success, status=%d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serverState.lock);
    if (rc != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! net desciptor added msg handler failed: try to lock failed, error=%d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    g_serverState.netDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING, BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED);
    if (rc != SOFTBUS_OK) {
        CLOGE("net desciptor added msg handler failed: update server state failed, error=%d", ctx->status);
        return rc;
    }
    SoftBusBtUuid uuid = {
        .uuid = SOFTBUS_CHARA_BLECONN_UUID,
        .uuidLen = strlen(SOFTBUS_CHARA_BLECONN_UUID),
    };
    rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid,
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE,
        SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
    if (rc != SOFTBUS_OK) {
        CLOGE("net desciptor added msg handler failed: underlayer add characteristic failed, error=%d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
    }
    rc =
        UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED, BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING);
    if (rc != SOFTBUS_OK) {
        CLOGE("net desciptor added msg handler failed: update server state failed, error=%d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static int32_t BleConnDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CLOGE(
            "conn desciptor added msg handler failed: underlayer return status is not success, status=%d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serverState.lock);
    if (rc != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! conn desciptor added msg handler failed: try to lock failed, error=%d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    g_serverState.connDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING, BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED);
    if (rc != SOFTBUS_OK) {
        CLOGE("conn desciptor added msg handler failed: update server state failed, error=%d", ctx->status);
        return rc;
    }
    rc = SoftBusGattsStartService(ctx->srvcHandle);
    if (rc != SOFTBUS_OK) {
        CLOGE("conn desciptor added msg handler failed: underlayer start service failed, error=%d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_ERR;
    }
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED, BLE_SERVER_STATE_SERVICE_STARTING);
    if (rc != SOFTBUS_OK) {
        CLOGE("conn desciptor added msg handler failed: update server state failed, error=%d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static void BleServiceStartCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("receive gatt server callback, service start, service handle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL,
        "receive gatt server callback, service start handle failed: calloc service start status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STARTED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, service start handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceStartMsgHandler(const CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_FAIL;
            CLOGE("ble server started msg handler failed: underlayer return status is not success, status=%d",
                ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE(
                "ATTENTION UNEXPECTED ERROR! ble server started msg handler failed: try to lock failed, error=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        int32_t serviceHandle = g_serverState.serviceHandle;
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        if (serviceHandle != ctx->srvcHandle) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("ble server started msg handler failed: underlayer service handle mismatch, error=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTING, BLE_SERVER_STATE_SERVICE_STARTED);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble server started msg handler failed: update server state failed, error=%d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState();
    }
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
    g_serverEventListener.onServerStarted(BLE_GATT, rc);
}

static void BleServerWaitStartServerTimeoutHandler(void)
{
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&g_serverState.lock);
        if (status != SOFTBUS_OK) {
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        enum GattServerState state = g_serverState.state;
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        if (state != BLE_SERVER_STATE_SERVICE_STARTED) {
            status = SOFTBUS_CONN_BLE_SERVER_START_SERVER_TIMEOUT_ERR;
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ResetServerState();
        g_serverEventListener.onServerStarted(BLE_GATT, SOFTBUS_CONN_BLE_SERVER_START_SERVER_TIMEOUT_ERR);
    }
}

// server acceoped(be connected) not need switch thread, as it just save the connnection globally
static void BleConnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CLOGI("receive gatt server callback, server connected, underlayer handle=%u, address=%02X:*:*:*:%02X:%02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);

    char address[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(address, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, server connected handle failed, convert binary mac address to string "
              "failed, address=%02X:*:*:*:%02X:%02X, error=%d,",
            status, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);

    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection != NULL) {
        CLOGI("receive gatt server callback, server connected handle trace, connection exist, ignore, connection "
              "id=%u, address=%s",
            connection->connectionId, anomizeAddress);
        ConnBleReturnConnection(&connection);
        return;
    }
    connection = ConnBleCreateConnection(address, BLE_GATT, CONN_SIDE_SERVER, underlayerHandle, false);
    if (connection == NULL) {
        CLOGE("receive gatt server callback, server connected handle failed: create connection failed, disconnect this "
              "connection, address=%s",
            anomizeAddress);
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        return;
    }
    status = ConnBleSaveConnection(connection);
    if (status != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, server connected handle failed, disconnect this connection, address=%s, "
              "error=%d",
            anomizeAddress, status);
        ConnBleReturnConnection(&connection);
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        return;
    }
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, connection->connectionId, 0, NULL,
        SERVER_WAIT_MTU_TIMEOUT_MILLIS);
    ConnBleReturnConnection(&connection);
}

static void BleMtuChangeCallback(int32_t underlayerHandle, int32_t mtu)
{
    CLOGI("receive gatt server callback, mtu changed, underlayer handle=%d, mtu=%d", underlayerHandle, mtu);
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection == NULL) {
        CLOGE("receive gatt server callback, mtu changed failed, connection not exist, underlayer handle=%d",
            underlayerHandle);
        return;
    }
    ConnRemoveMsgFromLooper(
        &g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, connection->connectionId, 0, NULL);

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, mtu changed failed, connection id=%u, error=%d", connection->connectionId,
            status);
        if (ConnGattServerDisconnect(connection) != SOFTBUS_OK) {
            // if failed, notify connect disconnet directly, manager will remove connection
            g_serverEventListener.onServerConnectionClosed(
                connection->connectionId, SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR);
            ConnBleReturnConnection(&connection);
            return;
        }
    }
    connection->mtu = mtu;
    connection->state = BLE_CONNECTION_STATE_MTU_SETTED;
    (void)SoftBusMutexUnlock(&connection->lock);
    g_serverEventListener.onServerAccepted(connection->connectionId);
    ConnBleReturnConnection(&connection);
}

static void BleServerWaitMtuTimeoutHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "ble server wait mtu timeout handle failed: connection not exist, connection id=%u", connectionId);
    int32_t status = ConnGattServerDisconnect(connection);
    CLOGI("ble server wait mtu timeout, disconnect connection, connection id=%u, status=%d", connectionId, status);
    ConnBleReturnConnection(&connection);
}

int32_t ConnGattServerStopService(void)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_serverState.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ATTENTION UNEXPECTED ERROR! ble server stop service failed, try to lock failed");
    enum GattServerState state = g_serverState.state;
    int32_t serviceHandle = g_serverState.serviceHandle;
    (void)SoftBusMutexUnlock(&g_serverState.lock);
    if (state == BLE_SERVER_STATE_INITIAL) {
        return SOFTBUS_OK;
    }

    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL,
        SERVER_WAIT_STOP_SERVER_TIMEOUT_MILLIS);

    int32_t status = SOFTBUS_OK;
    do {
        if (state == BLE_SERVER_STATE_SERVICE_STARTED) {
            status = SoftBusGattsStopService(serviceHandle);
            if (status != SOFTBUS_OK) {
                CLOGE("ble server stop service failed: underlayer stop service failed, error=%d", status);
                state = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_ERR;
                break;
            }
            status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTED, BLE_SERVER_STATE_SERVICE_STOPPING);
            if (status != SOFTBUS_OK) {
                CLOGE("ble server stop service failed: update server state failed, error=%d", status);
                break;
            }
        } else {
            status = SoftBusGattsDeleteService(serviceHandle);
            if (status != SOFTBUS_OK) {
                CLOGE("ble server stop service failed: underlayer delete service failed, error=%d", status);
                break;
            }
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        ResetServerState();
        g_serverEventListener.onServerClosed(BLE_GATT, status);
        status = SOFTBUS_OK;
    }
    return status;
}

static void BleServiceStopCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("receive gatt server callback, service stop, service handle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "receive gatt server callback, service stop handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STOPED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, service stop handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceStopMsgHandler(CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_FAIL;
            CLOGE("ble server stopped service msg handler failed: underlayer return status is not success, status=%d",
                ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! ble server stopped service msg handler failed: try to lock failed, "
                  "status=%d",
                ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        int32_t serviceHandle = g_serverState.serviceHandle;
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        if (serviceHandle != ctx->srvcHandle) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("ble server stopped service msg handler failed: underlayer service handle mismatch, error=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPING, BLE_SERVER_STATE_SERVICE_STOPPED);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble server stopped service msg handler failed: update server state failed, error=%d", rc);
            break;
        }
        rc = SoftBusGattsDeleteService(serviceHandle);
        if (rc != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR;
            CLOGE("ble server stopped service msg handler failed: underlay delete service failed, error=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPED, BLE_SERVER_STATE_SERVICE_DELETING);
        if (rc != SOFTBUS_OK) {
            CLOGE("ble server stopped service msg handler failed: update server state failed, error=%d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState();
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
        g_serverEventListener.onServerClosed(BLE_GATT, rc);
    }
}

static void BleServiceDeleteCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("receive gatt server callback, service deleted, service handle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL,
        "receive gatt server callback, service deleted handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_DELETED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("receive gatt server callback, service deleted handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceDeleteMsgHandler(const CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    do {
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_FAIL;
            CLOGE("ble server delete service msg handler failed: underlayer return status is not success, status=%d",
                ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serverState.lock);
        if (rc != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! ble server delete service msg handler failed: try to lock failed, "
                  "status=%d",
                ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        if (g_serverState.serviceHandle != ctx->srvcHandle) {
            (void)SoftBusMutexUnlock(&g_serverState.lock);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("ble server delete service msg handler failed: underlayer service handle mismatch, error=%d", rc);
            break;
        }
        g_serverState.state = BLE_SERVER_STATE_INITIAL;
        g_serverState.serviceHandle = -1;
        g_serverState.connCharacteristicHandle = -1;
        g_serverState.connDescriptorHandle = -1;
        g_serverState.netCharacteristicHandle = -1;
        g_serverState.netDescriptorHandle = -1;
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        SoftBusUnRegisterGattsCallbacks();
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState();
    }
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
    g_serverEventListener.onServerClosed(BLE_GATT, rc);
}

static void BleServerWaitStopServerTimeoutHandler(void)
{
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&g_serverState.lock);
        if (status != SOFTBUS_OK) {
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        enum GattServerState state = g_serverState.state;
        (void)SoftBusMutexUnlock(&g_serverState.lock);
        if (state != BLE_SERVER_STATE_INITIAL) {
            status = SOFTBUS_CONN_BLE_SERVER_STOP_SERVER_TIMEOUT_ERR;
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ResetServerState();
        g_serverEventListener.onServerClosed(BLE_GATT, SOFTBUS_CONN_BLE_SERVER_STOP_SERVER_TIMEOUT_ERR);
    }
}

static int32_t GetBleAttrHandle(int32_t module)
{
    return (module == MODULE_BLE_NET) ? g_serverState.netCharacteristicHandle : g_serverState.connCharacteristicHandle;
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        connection != NULL, SOFTBUS_INVALID_PARAM, "ble server send data failed, invalia param, connection is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        data != NULL, SOFTBUS_INVALID_PARAM, "ble server send data failed, invalia param, data is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        dataLen != 0, SOFTBUS_INVALID_PARAM, "ble server send data failed, invalia param, data len is 0");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOG(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ble server send data failed, try to get connection lock failed, connection id=%u, error=%d",
        connection->connectionId, status);
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    SoftBusGattsNotify notify = {
        .connectId = underlayerHandle,
        .attrHandle = GetBleAttrHandle(module),
        .confirm = 0,
        .valueLen = dataLen,
        .value = (char *)data,
    };
    return SoftBusGattsSendNotify(&notify);
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR,
        "ble server connection connect failed: invalid param, connection is null");
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! ble server connection %u connect failed, try to lock failed, error=%d",
            connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        CLOGE("ble server connection %u connect failed, underlay handle is invalid", connection->connectionId);
        return SOFTBUS_ERR;
    }
    status = SoftBusGattsConnect(underlayerHandle);
    CLOGI("ble server connection %u connect, underlayer handle=%d, status=%d", connection->connectionId,
        underlayerHandle, status);
    return status;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR,
        "ble server connection disconnect failed: invalid param, connection is null");

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! ble server connection %u disconnect failed, try to lock failed, error=%d",
            connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    connection->state =
        underlayerHandle == INVALID_UNDERLAY_HANDLE ? BLE_CONNECTION_STATE_CLOSED : BLE_CONNECTION_STATE_CLOSING;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        g_serverEventListener.onServerConnectionClosed(connection->connectionId, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server connection %u disconnect failed: convert string mac to binary fail, error=%d",
            connection->connectionId, status);
        return status;
    }
    status = SoftBusGattsDisconnect(binaryAddr, underlayerHandle);
    if (status != SOFTBUS_OK) {
        g_serverEventListener.onServerConnectionClosed(
            connection->connectionId, SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR);
    } else {
        ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_DICONNECT_TIMEOUT, connection->connectionId,
            0, NULL, UNDERLAY_CONNECTION_DISCONNECT_TIMEOUT);
    }
    CLOGI("ble server connection %u disconnect, underlayer handle=%d, status=%d", connection->connectionId,
        underlayerHandle, status);
    return status;
}

static void BleDisconnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CLOGI("receive gatt server callback, server disconnected, underlayer handle=%u, address=%02X:*:*:*:%02X:%02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);

    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "receive gatt server callback, server disconnected handle failed, connection not exist, underlayer handle=%u, "
        "address=%02X:*:*:*:%02X:%02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
    uint32_t connectionId = connection->connectionId;
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_DICONNECT_TIMEOUT, connectionId, 0, NULL);
    ConnBleReturnConnection(&connection);
    g_serverEventListener.onServerConnectionClosed(connectionId, SOFTBUS_OK);
}

static void BleServerWaitDisconnectTimeoutHandler(uint32_t connectionId)
{
    CLOGI("ble server wait disconnect timeout handler, disconnect wait timeout, connection id=%u", connectionId);
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "ble server wait disconnect timeout handler failed: connnection not exist, connection id=%u", connectionId);
    ConnBleReturnConnection(&connection);
    g_serverEventListener.onServerConnectionClosed(connectionId, SOFTBUS_CONN_BLE_DISCONNECT_WAIT_TIMEOUT_ERR);
}

static void BleRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    CLOGI("receive gatt server callback, request read, underlayer handle=%d, attribute handle=%d", readCbPara.connId,
        readCbPara.transId);
    SoftBusGattsResponse response = {
        .connectId = readCbPara.connId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = readCbPara.transId,
        .valueLen = strlen("not support!") + 1,
        .value = "not support!",
    };
    SoftBusGattsSendResponse(&response);
}

static void BleSendGattRsp(SoftBusGattWriteRequest *request)
{
    SoftBusGattsResponse response = {
        .connectId = request->connId,
        .transId = request->transId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = request->attrHandle,
        .offset = request->offset,
        .valueLen = request->length,
        .value = (char *)request->value,
    };
    int32_t ret = SoftBusGattsSendResponse(&response);
    CLOGI("send gatt response, handle: %d, ret: %d", request->attrHandle, ret);
}

static void BleRequestWriteCallback(SoftBusGattWriteRequest writeCbPara)
{
    CLOGI("receive gatt server callback, request write, underlayer handle=%d, attribute handle=%d, need rsp=%d",
        writeCbPara.connId, writeCbPara.attrHandle, writeCbPara.needRsp);

    if (writeCbPara.needRsp) {
        BleSendGattRsp(&writeCbPara);
    }
    if (writeCbPara.attrHandle == g_serverState.netDescriptorHandle ||
        writeCbPara.attrHandle == g_serverState.connDescriptorHandle) {
        return;
    }
    int32_t underlayerHandle = writeCbPara.connId;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection == NULL) {
        CLOGE("receive gatt server callback, request write failed: connection not exist,  underlayer handle=%d",
            underlayerHandle);
        return;
    }

    bool isConnCharacteristic = false;
    if (writeCbPara.attrHandle == g_serverState.netCharacteristicHandle) {
        isConnCharacteristic = false;
    } else if (writeCbPara.attrHandle == g_serverState.connCharacteristicHandle) {
        isConnCharacteristic = true;
    } else {
        CLOGE("receive gatt server callback, request write failed: not NET or CONN characteristic,  "
              "connection id=%u, underlayer handle=%d, attr handle=%d, net charateristic handle=%d, conn charateristic ",
            connection->connectionId, underlayerHandle, g_serverState.netCharacteristicHandle,
            g_serverState.connCharacteristicHandle);
        ConnBleReturnConnection(&connection);
        return;
    }

    uint32_t valueLen = 0;
    uint8_t *value = ConnGattTransRecv(
        connection->connectionId, writeCbPara.value, writeCbPara.length, &connection->buffer, &valueLen);
    if (value == NULL) {
        ConnBleReturnConnection(&connection);
        return;
    }
    g_serverEventListener.onServerDataReceived(connection->connectionId, isConnCharacteristic, value, valueLen);
    ConnBleReturnConnection(&connection);
}

static void BleResponseConfirmationCallback(int32_t status, int32_t handle)
{
    CLOGI("receive gatt server callback, response confirmation, status=%d, handle=%d", status, handle);
}

static void BleNotifySentCallback(int32_t connId, int32_t status)
{
    CLOGI("receive gatt server callback, notify sent, connId=%d, status=%d", connId, status);
}

static void BleGattServerMsgHandler(SoftBusMessage *msg)
{
    switch (msg->what) {
        case MSG_SERVER_SERVICE_ADDED:
            BleServiceAddMsgHandler((ServiceAddMsgContext *)msg->obj);
            break;
        case MSG_SERVER_CHARACTERISTIC_ADDED:
            BleCharacteristicAddMsgHandler((CharacteristicAddMsgContext *)msg->obj);
            break;
        case MSG_SERVER_DESCRIPTOR_ADDED:
            BleDescriptorAddMsgHandler((DescriptorAddMsgContext *)msg->obj);
            break;
        case MSG_SERVER_SERVICE_STARTED:
            BleServiceStartMsgHandler((CommonStatusMsgContext *)msg->obj);
            break;
        case MSG_SERVER_SERVICE_STOPED:
            BleServiceStopMsgHandler((CommonStatusMsgContext *)msg->obj);
            break;
        case MSG_SERVER_SERVICE_DELETED:
            BleServiceDeleteMsgHandler((CommonStatusMsgContext *)msg->obj);
            break;
        case MSG_SERVER_WAIT_START_SERVER_TIMEOUT:
            BleServerWaitStartServerTimeoutHandler();
            break;
        case MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT:
            BleServerWaitStopServerTimeoutHandler();
            break;
        case MSG_SERVER_WAIT_MTU_TIMEOUT:
            BleServerWaitMtuTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_SERVER_WAIT_DICONNECT_TIMEOUT:
            BleServerWaitDisconnectTimeoutHandler((uint32_t)msg->arg1);
            break;
        default:
            CLOGE("ATTENTION, ble gatt server looper receive unexpected msg, what=%d, just ignore, FIX it quickly.",
                msg->what);
            break;
    }
}

static int BleCompareGattServerLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_SERVER_WAIT_MTU_TIMEOUT:
        case MSG_SERVER_WAIT_DICONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CLOGE("ble compare gatt server looper event failed: there is compare context value not use, forgot implement? "
              "compare failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t BleRegisterGattServerCallback(void)
{
    static SoftBusGattsCallback bleGattsCallback = {
        .ServiceAddCallback = BleServiceAddCallback,
        .CharacteristicAddCallback = BleCharacteristicAddCallback,
        .DescriptorAddCallback = BleDescriptorAddCallback,
        .ServiceStartCallback = BleServiceStartCallback,
        .ServiceStopCallback = BleServiceStopCallback,
        .ServiceDeleteCallback = BleServiceDeleteCallback,
        .ConnectServerCallback = BleConnectServerCallback,
        .DisconnectServerCallback = BleDisconnectServerCallback,
        .RequestReadCallback = BleRequestReadCallback,
        .RequestWriteCallback = BleRequestWriteCallback,
        .ResponseConfirmationCallback = BleResponseConfirmationCallback,
        .NotifySentCallback = BleNotifySentCallback,
        .MtuChangeCallback = BleMtuChangeCallback,
    };
    return SoftBusRegisterGattsCallbacks(&bleGattsCallback);
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        looper != NULL, SOFTBUS_INVALID_PARAM, "init ble server failed, invalid param, looper is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        listener != NULL, SOFTBUS_INVALID_PARAM, "init ble server failed, invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerStarted != NULL, SOFTBUS_INVALID_PARAM,
        "init ble server failed, invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerClosed != NULL, SOFTBUS_INVALID_PARAM,
        "init ble server failed, invalid param, listener onServerClosed is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerAccepted != NULL, SOFTBUS_INVALID_PARAM,
        "init ble server failed, invalid param, listener onServerAccepted is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        "init ble server failed, invalid param, listener onServerDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOG(listener->onServerConnectionClosed != NULL, SOFTBUS_INVALID_PARAM,
        "init ble server failed, invalid param, listener onServerConnectionClosed is null");

    int32_t status = SoftBusMutexInit(&g_serverState.lock, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, status, "init ble server failed: init server state lock failed, error=%d", status);
    g_bleGattServerAsyncHandler.handler.looper = looper;
    g_serverEventListener = *listener;
    return SOFTBUS_OK;
}