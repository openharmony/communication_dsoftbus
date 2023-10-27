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
#include "legacy_ble_channel.h"

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

typedef struct {
    BleServerState serverState;
    GattService gattService;
} GattServiceContext;

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
        .name = (char *)("BleGattServerAsyncHandler"),
        .HandleMessage = BleGattServerMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BleCompareGattServerLooperEventFunc,
};
static ConnBleServerEventListener g_serverEventListener[GATT_SERVICE_MAX];
static GattServiceContext g_serviceContext[GATT_SERVICE_MAX];
static SoftBusMutex g_serviceContextLock = { 0 };
static bool g_isRegisterCallback = false;

static int32_t UpdateBleServerStateInOrder(enum GattServerState expectedState, enum GattServerState nextState,
    GattServiceType serviceId)
{
    int32_t status = SoftBusMutexLock(&g_serviceContextLock);
    if (status != SOFTBUS_OK) {
        CLOGE("try to get lock failed, err=%d", status);
        return SOFTBUS_LOCK_ERR;
    }
    enum GattServerState nowState = g_serviceContext[serviceId].serverState.state;
    if (nowState != expectedState) {
        CLOGE("update server state failed: actual state=%d, expected state=%d, next state=%d", nowState,
            expectedState, nextState);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        return SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR;
    }
    g_serviceContext[serviceId].serverState.state = nextState;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    return SOFTBUS_OK;
}

static void ClearServiceState(GattServiceType serviceId)
{
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! ble reset server state failed, try to lock failed");
    g_serviceContext[serviceId].serverState.state = BLE_SERVER_STATE_INITIAL;
    g_serviceContext[serviceId].serverState.serviceHandle = -1;
    g_serviceContext[serviceId].serverState.connCharacteristicHandle = -1;
    g_serviceContext[serviceId].serverState.connDescriptorHandle = -1;
    g_serviceContext[serviceId].serverState.netCharacteristicHandle = -1;
    g_serviceContext[serviceId].serverState.netDescriptorHandle = -1;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    SoftBusFree(&g_serviceContext[serviceId].gattService);
    bool isUnregisterCallback = true;
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.serviceHandle != -1) {
            isUnregisterCallback = false;
            break;
        }
    }
    if (isUnregisterCallback) {
        SoftBusUnRegisterGattsCallbacks();
    }
}

static void ResetServerState(GattServiceType serviceId)
{
    if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
        for (int i = 0; i < GATT_SERVICE_MAX; i++) {
            if (g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STARTING ||
                g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STOPPING) {
                ClearServiceState((GattServiceType)i);
            }
        }
    } else {
        ClearServiceState(serviceId);
    }
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! ble reset server state failed, try to lock failed");
    int32_t serviceHandle = g_serviceContext[serviceId].serverState.serviceHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    SoftBusGattsDeleteService(serviceHandle);

    ClearServiceState(serviceId);
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL);
}

static GattServiceType FindService(const SoftBusBtUuid *uuid)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService.serviceUuid.uuid != NULL &&
            g_serviceContext[i].gattService.serviceUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService.serviceUuid.uuid, uuid->uuidLen)) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByServiceHandle(int32_t serviceHandle)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.serviceHandle == serviceHandle) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByConnCharaHandle(int32_t connCharacteristicHandle)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.connCharacteristicHandle == connCharacteristicHandle) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByNetCharaHandle(int32_t netCharacteristicHandle)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.netCharacteristicHandle == netCharacteristicHandle) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByDescriptorHandle(int32_t descriptorHandle)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.netDescriptorHandle == descriptorHandle ||
            g_serviceContext[i].serverState.connDescriptorHandle == descriptorHandle) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindNetCharacteristic(const SoftBusBtUuid *uuid)
{
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService.netUuid.uuid != NULL &&
            g_serviceContext[i].gattService.netUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService.netUuid.uuid, uuid->uuidLen)) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindConnCharacteristic(const SoftBusBtUuid *uuid)
{
     for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService.connCharacteristicUuid.uuid != NULL &&
            g_serviceContext[i].gattService.connCharacteristicUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService.connCharacteristicUuid.uuid, uuid->uuidLen)) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindDescriptor(SoftBusBtUuid *uuid)
{
     for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService.descriptorUuid.uuid != NULL &&
            g_serviceContext[i].gattService.descriptorUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService.descriptorUuid.uuid, uuid->uuidLen)) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

int32_t ConnGattServerStartService(GattService *service, GattServiceType serviceId)
{
    if (serviceId <= GATT_SERVICE_TYPE_UNKOWN || serviceId >= GATT_SERVICE_MAX) {
        CLOGE("serviceType is unkown, servieId=%d", serviceId);
        return SOFTBUS_INVALID_PARAM;
    }
    CONN_CHECK_AND_RETURN_RET_LOG(service != NULL, SOFTBUS_INVALID_PARAM, "service is NULL");
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ATTENTION UNEXPECTED ERROR! ble server start service failed: try to lock failed");
    enum GattServerState state = g_serviceContext[serviceId].serverState.state;
    g_serviceContext[serviceId].gattService = *service;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    if (state == BLE_SERVER_STATE_SERVICE_STARTED) {
        return SOFTBUS_OK;
    }
    ResetServerState(serviceId);

    int32_t status = BleRegisterGattServerCallback();
    if (status != SOFTBUS_OK) {
        CLOGE("register underlayer callback failed, err=%d", status);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_REGISTER_CALLBACK_ERR;
    }
    g_isRegisterCallback = true;
    status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_INITIAL, BLE_SERVER_STATE_SERVICE_ADDING, serviceId);
    if (status != SOFTBUS_OK) {
        CLOGE("update server state failed, err=%d", status);
        return status;
    }

    status = SoftBusGattsAddService(service->serviceUuid, true, MAX_SERVICE_CHAR_NUM);
    if (status != SOFTBUS_OK) {
        CLOGE("underlayer add service failed, err=%d", status);
        ResetServerState(serviceId);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR;
    }
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL,
        SERVER_WAIT_START_SERVER_TIMEOUT_MILLIS);
    return SOFTBUS_OK;
}

static void BleServiceAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle)
{
    CLOGI("gatt server callback, server added, srvcHandle=%u, status=%d", srvcHandle, status);
    CONN_CHECK_AND_RETURN_LOG(uuid != NULL, "uuid is null");
    ServiceAddMsgContext *ctx = (ServiceAddMsgContext *)SoftBusCalloc(sizeof(ServiceAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "receive gatt server callback, server added handle failed: calloc service add msg context failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void NotifyServerStarted(GattServiceType serviceId, int32_t status)
{
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN && g_serverEventListener[serviceId].onServerStarted != NULL) {
        g_serverEventListener[serviceId].onServerStarted(BLE_GATT, status);
        return;
    }
    // if service type is unkown, notify starting service that start service failed
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STARTING &&
            g_serverEventListener[i].onServerStarted != NULL) {
            g_serverEventListener[i].onServerStarted(BLE_GATT, status);
        }
    }
}

static void BleServiceAddMsgHandler(const ServiceAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, err=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindService(&ctx->uuid);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_SERVICE_ERR;
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            break;
        }
        g_serviceContext[serviceId].serverState.serviceHandle = ctx->srvcHandle;
        SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService.netUuid;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (ctx->status != SOFTBUS_OK) {
            CLOGE("underlay returned status is not success, status=%d", ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_FAIL;
            break;
        }

        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDING, BLE_SERVER_STATE_SERVICE_ADDED, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
        int32_t properties = -1;
        if (serviceId == SOFTBUS_GATT_SERVICE) {
            properties = SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE;
        } else {
            properties = SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE;
        }
        rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid, properties,
            SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
        if (rc != SOFTBUS_OK) {
            CLOGE("underlayer add characteristic failed, err=%d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDED, BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static void BleCharacteristicAddCallback(
    int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t characteristicHandle)
{
    CLOGI("gatt server callback, characteristic added, srvcHandle=%u, characteristicHandle status=%d", srvcHandle,
        characteristicHandle, status);
    CharacteristicAddMsgContext *ctx =
        (CharacteristicAddMsgContext *)SoftBusCalloc(sizeof(CharacteristicAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL, "calloc characteristic add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->characteristicHandle = characteristicHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_CHARACTERISTIC_ADDED, 0, 0, ctx, 0) !=
        SOFTBUS_OK) {
        CLOGE("post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleCharacteristicAddMsgHandler(const CharacteristicAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        enum GattServerState expect;
        enum GattServerState next;
        enum GattServerState nextNext;
        bool isConnCharacterisic = false;
        bool isNeedAddDescriptor = true;

        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, err=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindNetCharacteristic(&ctx->uuid);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            isConnCharacterisic = true;
            serviceId = FindConnCharacteristic(&ctx->uuid);
        }
        
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_CHARACTERISTIC_ERR;
            CLOGE("unkown characteristic, err=%d", rc);
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            break;
        }
        if (isConnCharacterisic) {
            expect = BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING;
            next = BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDED;
            nextNext = BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING;
        } else {
            expect = BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING;
            next = BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDED;
            if (serviceId == LEGACY_GATT_SERVICE) {
                isNeedAddDescriptor = false;
                nextNext = BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING;
            } else {
                nextNext = BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING;
            }
        }
        if (ctx->srvcHandle != g_serviceContext[serviceId].serverState.serviceHandle) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("srvcHandle is different, serviceId=%d, context srvcHandle=%d, server srvcHandle=%d, error=%d", serviceId,
                ctx->srvcHandle, g_serviceContext[serviceId].serverState.serviceHandle, rc);
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            break;
        }
        if (isConnCharacterisic) {
            g_serviceContext[serviceId].serverState.connCharacteristicHandle = ctx->characteristicHandle;
        } else {
            g_serviceContext[serviceId].serverState.netCharacteristicHandle = ctx->characteristicHandle;
        }
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        rc = UpdateBleServerStateInOrder(expect, next, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
        if (isNeedAddDescriptor) {
            SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService.descriptorUuid;
            rc = SoftBusGattsAddDescriptor(
                ctx->srvcHandle, uuid, SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
            if (rc != SOFTBUS_OK) {
                CLOGE("underlayer add decriptor failed, err=%d", rc);
                rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_ERR;
                break;
            }
        } else {
            SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService.connCharacteristicUuid;
            rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid, SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE,
                SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
            if (rc != SOFTBUS_OK) {
                CLOGE("underlayer add characteristic failed, err=%d", rc);
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
                break;
            }
        }
        
        rc = UpdateBleServerStateInOrder(next, nextNext, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
    } while (false);
    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static void BleDescriptorAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t descriptorHandle)
{
    CLOGI("gatt server callback, descriptor added, srvcHandle=%u, descriptorHandle=%d, status=%d", srvcHandle,
        descriptorHandle, status);
    DescriptorAddMsgContext *ctx =
        (DescriptorAddMsgContext *)SoftBusCalloc(sizeof(DescriptorAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL, "calloc descriptor add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CLOGE("memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->descriptorHandle = descriptorHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_DESCRIPTOR_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, err=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        if (FindDescriptor(&ctx->uuid) == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_DESCRIPTOR_ERR;
            CLOGE("unkown descriptor");
            break;
        }
        bool isConnDescriptor = false;
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            CLOGE("underlayer srvcHandle mismatch, err=%d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            break;
        }

        if (g_serviceContext[serviceId].serverState.netDescriptorHandle == -1) {
            isConnDescriptor = false;
        } else if (g_serviceContext[serviceId].serverState.connDescriptorHandle == -1) {
            isConnDescriptor = true;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_HANDLE_MISMATCH_ERR;
        }
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("descriptor handle mismatch, err=%d", rc);
            break;
        }
        rc = isConnDescriptor ? BleConnDescriptorAddMsgHandler(ctx) : BleNetDescriptorAddMsgHandler(ctx);
    } while (false);
    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static int32_t BleNetDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CLOGE("underlayer return status is not success, status=%d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serviceContextLock);
    if (rc != SOFTBUS_OK) {
        CLOGE("try to lock failed, err=%d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    g_serviceContext[SOFTBUS_GATT_SERVICE].serverState.netDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING, BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED, SOFTBUS_GATT_SERVICE);
    if (rc != SOFTBUS_OK) {
        CLOGE("update server state failed, err=%d", ctx->status);
        return rc;
    }
    SoftBusBtUuid uuid = {
        .uuid = (char *)SOFTBUS_CHARA_BLECONN_UUID,
        .uuidLen = strlen(SOFTBUS_CHARA_BLECONN_UUID),
    };
    rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid,
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE,
        SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
    if (rc != SOFTBUS_OK) {
        CLOGE("underlayer add characteristic failed, err=%d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
    }
    rc =
        UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED, BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING, SOFTBUS_GATT_SERVICE);
    if (rc != SOFTBUS_OK) {
        CLOGE("update server state failed, err=%d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static int32_t BleConnDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CLOGE("underlayer return status is not success, status=%d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serviceContextLock);
    if (rc != SOFTBUS_OK) {
        CLOGE("try to lock failed, err=%d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    GattServiceType serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
    g_serviceContext[serviceId].serverState.connDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING, BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED, serviceId);
    if (rc != SOFTBUS_OK) {
        CLOGE("update server state failed, err=%d, serviceId", ctx->status, serviceId);
        return rc;
    }
    rc = SoftBusGattsStartService(ctx->srvcHandle);
    if (rc != SOFTBUS_OK) {
        CLOGE("underlayer start service failed, err=%d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_ERR;
    }
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED, BLE_SERVER_STATE_SERVICE_STARTING, serviceId);
    if (rc != SOFTBUS_OK) {
        CLOGE("update server state failed, err=%d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static void BleServiceStartCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("gatt server callback, service start, srvcHandle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL, "calloc service start status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STARTED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceStartMsgHandler(const CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_FAIL;
            CLOGE("underlayer return status is not success, status=%d", ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, err=%d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("underlayer srvcHandle mismatch, err=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTING, BLE_SERVER_STATE_SERVICE_STARTED, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d, serviceId=%d", rc, serviceId);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
    }
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL);
    NotifyServerStarted(serviceId, rc);
}

static void BleServerWaitStartServerTimeoutHandler(uint32_t serviceId)
{
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&g_serviceContextLock);
        if (status != SOFTBUS_OK) {
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        enum GattServerState state = g_serviceContext[serviceId].serverState.state;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (state != BLE_SERVER_STATE_SERVICE_STARTED) {
            status = SOFTBUS_CONN_BLE_SERVER_START_SERVER_TIMEOUT_ERR;
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ResetServerState(serviceId);
        g_serverEventListener[serviceId].onServerStarted(BLE_GATT, SOFTBUS_CONN_BLE_SERVER_START_SERVER_TIMEOUT_ERR);
    }
}

// server acceoped(be connected) not need switch thread, as it just save the connnection globally
static void BleConnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CLOGI("gatt server callback, server connected, underlayer handle=%u, address=%02X:*:*:*:%02X:%02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);

    char address[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(address, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("convert binary mac address to string failed, address=%02X:*:*:*:%02X:%02X, error=%d,", status,
            btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);

    ConnBleConnection *softbusConnection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    ConnBleConnection *legacyConnection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    if (softbusConnection != NULL || legacyConnection != NULL) {
        CLOGI("server connected handle trace, connection exist, ignore, address=%s", anomizeAddress);
        ConnBleReturnConnection(&softbusConnection);
        LegacyBleReturnConnection(&legacyConnection);
        return;
    }
    softbusConnection = ConnBleCreateConnection(address, BLE_GATT, CONN_SIDE_SERVER, underlayerHandle, false);
    legacyConnection = LegacyBleCreateConnection(address, CONN_SIDE_SERVER, underlayerHandle, false);
    if (softbusConnection == NULL || legacyConnection == NULL) {
        CLOGE("create connection failed, disconnect this connection, address=%s", anomizeAddress);
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        return;
    }
    status = ConnBleSaveConnection(softbusConnection);
    if (status != SOFTBUS_OK) {
        CLOGE("save softbus connection failed, disconnect this connection, address=%s, err=%d", anomizeAddress, status);
        ConnBleReturnConnection(&softbusConnection);
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        return;
    }

    status = LegacyBleSaveConnection(legacyConnection);
    if (status != SOFTBUS_OK) {
        CLOGE("save legacy connection failed, disconnect this connection, address=%s, err=%d", anomizeAddress, status);
        LegacyBleReturnConnection(&legacyConnection);
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        return;
    }
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, softbusConnection->connectionId,
        legacyConnection->connectionId, NULL, SERVER_WAIT_MTU_TIMEOUT_MILLIS);
    ConnBleReturnConnection(&softbusConnection);
    LegacyBleReturnConnection(&legacyConnection);
}

static void BleMtuChangeCallback(int32_t underlayerHandle, int32_t mtu)
{
    CLOGI("gatt server callback, mtu changed, underlayer handle=%d, mtu=%d", underlayerHandle, mtu);
    ConnBleConnection *softbusConnection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    ConnBleConnection *legacyConnection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    if (softbusConnection == NULL && legacyConnection != NULL) {
        CLOGI("softbus connection not exist, ignore");
        // clear legacy connection
        LegacyBleReturnConnection(&legacyConnection);
        return;
    }
    if (legacyConnection == NULL && softbusConnection != NULL) {
        CLOGI("legacy connection not exist, ignore");
        ConnBleReturnConnection(&softbusConnection);
        return;
    }
    ConnRemoveMsgFromLooper(
        &g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, softbusConnection->connectionId,
        legacyConnection->connectionId, NULL);
    GattServiceType serviceId = mtu == DEFAULT_MTU_SIZE ? SOFTBUS_GATT_SERVICE : LEGACY_GATT_SERVICE;
    ConnBleConnection *connection = NULL;
    if (serviceId == SOFTBUS_GATT_SERVICE) {
        connection = softbusConnection;
        LegacyBleRemoveConnection(legacyConnection);
        LegacyBleReturnConnection(&legacyConnection);
    } else {
        connection = legacyConnection;
        ConnBleRemoveConnection(softbusConnection);
        ConnBleReturnConnection(&softbusConnection);
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("try to lock failed, connId=%u, err=%d", connection->connectionId, status);
        if (ConnGattServerDisconnect(connection) != SOFTBUS_OK) {
            // if failed, notify connect disconnet directly, manager will remove connection
            g_serverEventListener[serviceId].onServerConnectionClosed(
                connection->connectionId, SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR);
            ReturnConnection(serviceId, connection);
            return;
        }
    }
    connection->mtu = (uint32_t)mtu;
    connection->state = BLE_CONNECTION_STATE_MTU_SETTED;
    (void)SoftBusMutexUnlock(&connection->lock);
    g_serverEventListener[serviceId].onServerAccepted(connection->connectionId);
    ReturnConnection(serviceId, connection);
}

static void BleServerWaitMtuTimeoutHandler(uint32_t softbusConnId, uint32_t legacyConnId)
{
    ConnBleConnection *softbusConnection = ConnBleGetConnectionById(softbusConnId);
    ConnBleConnection *legacyConnection = LegacyBleGetConnectionById(legacyConnId);
    if (softbusConnection == NULL && legacyConnection != NULL) {
        CLOGI("softbus connection not exist, connId=%d", softbusConnId);
        LegacyBleReturnConnection(&legacyConnection);
        return;
    }
    if (legacyConnection == NULL && softbusConnection != NULL) {
        CLOGI("legacy connection not exist, connId=%d", legacyConnId);
        ConnBleReturnConnection(&softbusConnection);
        return;
    }
    int32_t status = ConnGattServerDisconnect(softbusConnection);
    CLOGI("ble server wait mtu timeout, disconnect connection, connId=%u, status=%d", softbusConnId, status);
    ConnBleReturnConnection(&softbusConnection);
    LegacyBleRemoveConnection(legacyConnection);
    LegacyBleReturnConnection(&legacyConnection);
}

int32_t ConnGattServerStopService(GattServiceType serviceId)
{
    if (serviceId <= GATT_SERVICE_TYPE_UNKOWN || serviceId >= GATT_SERVICE_MAX) {
        CLOGE("serviceType is unkown, servieId=%d", serviceId);
        return SOFTBUS_INVALID_PARAM;
    }
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        "ATTENTION UNEXPECTED ERROR! ble server stop service failed, try to lock failed");
    enum GattServerState state = g_serviceContext[serviceId].serverState.state;
    int32_t serviceHandle = g_serviceContext[serviceId].serverState.serviceHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    if (state == BLE_SERVER_STATE_INITIAL) {
        return SOFTBUS_OK;
    }

    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, serviceId, 0, NULL,
        SERVER_WAIT_STOP_SERVER_TIMEOUT_MILLIS);

    int32_t status = SOFTBUS_OK;
    do {
        if (state == BLE_SERVER_STATE_SERVICE_STARTED) {
            status = SoftBusGattsStopService(serviceHandle);
            if (status != SOFTBUS_OK) {
                CLOGE("underlayer stop service failed, err=%d", status);
                status = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_ERR;
                break;
            }
            status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTED, BLE_SERVER_STATE_SERVICE_STOPPING, serviceId);
            if (status != SOFTBUS_OK) {
                CLOGE("update server state failed, err=%d", status);
                break;
            }
        } else {
            status = SoftBusGattsDeleteService(serviceHandle);
            if (status != SOFTBUS_OK) {
                CLOGE("underlayer delete service failed, err=%d", status);
                break;
            }
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL);
        ResetServerState(serviceId);
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, status);
        status = SOFTBUS_OK;
    }
    return status;
}

static void BleServiceStopCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("gatt server callback, service stop, srvcHandle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "receive gatt server callback, service stop handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STOPED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void NotifyServerClosed(GattServiceType serviceId, int32_t status)
{
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN && g_serverEventListener[serviceId].onServerClosed != NULL) {
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, status);
    }
    // if service type is unkown, notify all start service stoped
    for (int i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STOPPING &&
            g_serverEventListener[i].onServerClosed != NULL) {
            g_serverEventListener[i].onServerClosed(BLE_GATT, status);
        }
    }
}

static void BleServiceStopMsgHandler(CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_FAIL;
            CLOGE("underlayer return status is not success, status=%d", ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, status=%d", ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("underlayer srvcHandle mismatch, err=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPING, BLE_SERVER_STATE_SERVICE_STOPPED, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
        rc = SoftBusGattsDeleteService(ctx->srvcHandle);
        if (rc != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR;
            CLOGE("underlay delete service failed, err=%d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPED, BLE_SERVER_STATE_SERVICE_DELETING, serviceId);
        if (rc != SOFTBUS_OK) {
            CLOGE("update server state failed, err=%d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerClosed(serviceId, rc);
    }
}

static void BleServiceDeleteCallback(int32_t status, int32_t srvcHandle)
{
    CLOGI("gatt server callback, service deleted, srvcHandle=%u, status=%d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOG(
        ctx != NULL, "gatt server callback, service deleted handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_DELETED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CLOGE("gatt server callback, service deleted handle failed: post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void BleServiceDeleteMsgHandler(const CommonStatusMsgContext *ctx)
{
    int32_t rc = SOFTBUS_OK;
    GattServiceType serviceId = GATT_SERVICE_TYPE_UNKOWN;
    do {
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CLOGE("try to lock failed, status=%d", ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CLOGE("underlayer srvcHandle mismatch, err=%d", rc);
            break;
        }
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_FAIL;
            CLOGE("underlayer return status is not success, status=%d", ctx->status);
            break;
        }
        ClearServiceState(serviceId);
        
    } while (false);

    if (rc != SOFTBUS_OK) {
        ResetServerState(serviceId);
    }
    if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
    } else {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, serviceId, 0, NULL);
    }
    NotifyServerClosed(serviceId, rc);
}

static void BleServerWaitStopServerTimeoutHandler(int32_t serviceId)
{
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&g_serviceContextLock);
        if (status != SOFTBUS_OK) {
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        enum GattServerState state = g_serviceContext[serviceId].serverState.state;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (state != BLE_SERVER_STATE_INITIAL) {
            status = SOFTBUS_CONN_BLE_SERVER_STOP_SERVER_TIMEOUT_ERR;
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ResetServerState(serviceId);
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, SOFTBUS_CONN_BLE_SERVER_STOP_SERVER_TIMEOUT_ERR);
    }
}

static int32_t GetBleAttrHandle(int32_t module, GattServiceType serviceId)
{
    return (module == MODULE_BLE_NET) ? g_serviceContext[serviceId].serverState.netCharacteristicHandle
        : g_serviceContext[serviceId].serverState.connCharacteristicHandle;
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
        "ble server send data failed, try to get connection lock failed, connId=%u, err=%d", connection->connectionId,
        status);
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    SoftBusGattsNotify notify = {
        .connectId = underlayerHandle,
        .attrHandle = GetBleAttrHandle(module, connection->serviceId),
        .confirm = 0,
        .valueLen = dataLen,
        .value = (char *)data,
    };
    return SoftBusGattsSendNotify(&notify);
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, "invalid param, connection is null");
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server connection %u connect failed, try to lock failed, err=%d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        CLOGE("ble server connection %u connect failed, underlay handle is invalid", connection->connectionId);
        return SOFTBUS_ERR;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server connection %u connect failed: convert string mac to binary fail, err=%d",
            connection->connectionId, status);
        return status;
    }
    status = SoftBusGattsConnect(binaryAddr);
    CLOGI("ble server connection %u connect, underlayer handle=%d, status=%d", connection->connectionId,
        underlayerHandle, status);
    return status;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR,
        "ble server connection disconnect failed: invalid param, connection is null");
    if (connection->serviceId <= GATT_SERVICE_TYPE_UNKOWN || connection->serviceId >= GATT_SERVICE_MAX) {
        CLOGE("serviceType is unkown, servieId=%d", connection->serviceId);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CLOGE(
            "ble server connection %u disconnect failed, try to lock failed, err=%d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    GattServiceType serviceId = connection->serviceId;
    int32_t underlayerHandle = connection->underlayerHandle;
    connection->state =
        underlayerHandle == INVALID_UNDERLAY_HANDLE ? BLE_CONNECTION_STATE_CLOSED : BLE_CONNECTION_STATE_CLOSING;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        g_serverEventListener[serviceId].onServerConnectionClosed(connection->connectionId, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CLOGE("ble server connection %u disconnect failed: convert string mac to binary fail, err=%d",
            connection->connectionId, status);
        return status;
    }
    status = SoftBusGattsDisconnect(binaryAddr, underlayerHandle);
    if (status != SOFTBUS_OK && g_serverEventListener[serviceId].onServerConnectionClosed != NULL) {
        g_serverEventListener[serviceId].onServerConnectionClosed(
            connection->connectionId, SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR);
    } else {
        ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_DICONNECT_TIMEOUT, connection->connectionId,
            (uint64_t)serviceId, NULL, UNDERLAY_CONNECTION_DISCONNECT_TIMEOUT);
    }
    CLOGI("ble server connection %u disconnect, handle=%d, status=%d, serviceId=%d", connection->connectionId, underlayerHandle,
        status, connection->serviceId);
    return status;
}

static void BleDisconnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CLOGI("gatt server callback, server disconnected, handle=%u, address=%02X:*:*:*:%02X:%02X", underlayerHandle,
        btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
    GattServiceType serviceId = SOFTBUS_GATT_SERVICE;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection == NULL) {
        serviceId = LEGACY_GATT_SERVICE;
        connection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    }
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "connection not exist, serviceId=%d, handle=%u, address=%02X:*:*:*:%02X:%02X",
        serviceId, underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
    uint32_t connectionId = connection->connectionId;
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_DICONNECT_TIMEOUT, connectionId, serviceId, NULL);
    ReturnConnection(serviceId, connection);
    g_serverEventListener[serviceId].onServerConnectionClosed(connectionId, SOFTBUS_OK);
}

static void BleServerWaitDisconnectTimeoutHandler(uint32_t connectionId, uint32_t serviceId)
{
    CLOGI("server wait disconnect timeout, connId=%u", connectionId);
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "ble server wait disconnect timeout handler failed: connnection not exist, connId=%u", connectionId);
    ReturnConnection(serviceId, connection);
    g_serverEventListener[serviceId].onServerConnectionClosed(connectionId, SOFTBUS_CONN_BLE_DISCONNECT_WAIT_TIMEOUT_ERR);
}

static void BleRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    CLOGI("gatt server callback, request read, underlayer handle=%d, attribute handle=%d", readCbPara.connId,
        readCbPara.transId);
    SoftBusGattsResponse response = {
        .connectId = readCbPara.connId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = readCbPara.transId,
        .valueLen = strlen("not support!") + 1,
        .value = (char *)("not support!"),
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
    CLOGI("gatt server callback, request write, underlayer handle=%d, attribute handle=%d, need rsp=%d",
        writeCbPara.connId, writeCbPara.attrHandle, writeCbPara.needRsp);

    if (writeCbPara.needRsp) {
        BleSendGattRsp(&writeCbPara);
    }
    int32_t status = SoftBusMutexLock(&g_serviceContextLock);
    if (status != SOFTBUS_OK) {
        CLOGE("try to lock failed, underlayer handle=%d, err=%d", writeCbPara.attrHandle, status);
        return;
    }
    // ignore despriptor notify
    GattServiceType serviceId = FindServiceByDescriptorHandle(writeCbPara.attrHandle);
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN) {
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        return;
    }
    bool isConnCharacteristic = true;
    serviceId = FindServiceByConnCharaHandle(writeCbPara.attrHandle);
    if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
        isConnCharacteristic = false;
        serviceId = FindServiceByNetCharaHandle(writeCbPara.attrHandle);
    }
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
       CLOGE("request write failed: not NET or CONN characteristic");
    }
    int32_t underlayerHandle = writeCbPara.connId;
    uint32_t valueLen = 0;
    uint8_t *value = NULL;
    ConnBleConnection *connection = NULL;
    if (serviceId == SOFTBUS_GATT_SERVICE) {
        connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
        if (connection == NULL) {
            CLOGE("gatt server callback, softbus connection not exist,  underlayer handle=%d",
                underlayerHandle);
            return;
        }
        value = ConnGattTransRecv(
        connection->connectionId, writeCbPara.value, writeCbPara.length, &connection->buffer, &valueLen);
    } else {
        connection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
        if (connection == NULL) {
            CLOGE("gatt server callback, legacy connection not exist,  underlayer handle=%d",
                underlayerHandle);
            return;
        }
        value = SoftBusCalloc(sizeof(uint8_t) * writeCbPara.length);
        valueLen = writeCbPara.length;
        CONN_CHECK_AND_RETURN_LOG(value != NULL, "legacy malloc value failed, connId=%u, dataLen=%u",
            connection->connectionId, valueLen);
        if (memcpy_s(value, valueLen, writeCbPara.value, valueLen) != EOK) {
            CLOGE("legacy memcpy failed, connId=%u, dataLen=%u", connection->connectionId, valueLen);
            SoftBusFree(value);
            LegacyBleReturnConnection(&connection);
            return;
        }
    }
    
    if (value == NULL) {
        ReturnConnection(serviceId, connection);
        return;
    }
    g_serverEventListener[serviceId].onServerDataReceived(connection->connectionId, isConnCharacteristic, value, valueLen);
    ReturnConnection(serviceId, connection);
}

static void BleResponseConfirmationCallback(int32_t status, int32_t handle)
{
    CLOGI("gatt server callback, response confirmation, status=%d, handle=%d", status, handle);
}

static void BleNotifySentCallback(int32_t connId, int32_t status)
{
    CLOGI("gatt server callback, notify sent, connId=%d, status=%d", connId, status);
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
            BleServerWaitStartServerTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT:
            BleServerWaitStopServerTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_SERVER_WAIT_MTU_TIMEOUT:
            BleServerWaitMtuTimeoutHandler((uint32_t)msg->arg1, (uint32_t)msg->arg2);
            break;
        case MSG_SERVER_WAIT_DICONNECT_TIMEOUT:
            BleServerWaitDisconnectTimeoutHandler((uint32_t)msg->arg1, (uint32_t)msg->arg2);
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
        CLOGE("there is compare context value not use, forgot implement? "
              "compare failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t BleRegisterGattServerCallback(void)
{
    if (g_isRegisterCallback) {
        CLOGW("already register!");
        return SOFTBUS_OK;
    }
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

void RegisterServerListener(const ConnBleServerEventListener *listener, GattServiceType serviceId)
{
    g_serverEventListener[serviceId] = *listener;
    static BleServerState serverState = {
        .state = BLE_SERVER_STATE_INITIAL,
        .serviceHandle = -1,
        .connCharacteristicHandle = -1,
        .connDescriptorHandle = -1,
        .netCharacteristicHandle = -1,
        .netDescriptorHandle = -1,
    };
    g_serviceContext[serviceId].serverState = serverState;
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener, GattServiceType serviceId)
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

    int32_t status = SoftBusMutexInit(&g_serviceContextLock, NULL);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, status, "init ble server failed: init server state lock failed, err=%d", status);
    g_bleGattServerAsyncHandler.handler.looper = looper;
    return SOFTBUS_OK;
}