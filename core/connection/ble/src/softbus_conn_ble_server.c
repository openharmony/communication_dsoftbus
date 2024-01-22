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
#include "conn_log.h"
#include "message_handler.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
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
    GattService *gattService;
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

typedef struct {
    int32_t underHandle;
    char addr[BT_MAC_LEN];
    ListNode node;
} BleServerConnection;

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
static SoftBusList *g_bleServerConnections = { 0 };

static int32_t UpdateBleServerStateInOrder(enum GattServerState expectedState, enum GattServerState nextState,
    GattServiceType serviceId)
{
    int32_t status = SoftBusMutexLock(&g_serviceContextLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to get lock failed, err=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }
    enum GattServerState nowState = g_serviceContext[serviceId].serverState.state;
    if (nowState != expectedState) {
        CONN_LOGW(CONN_BLE,
            "update server state failed: actualState=%{public}d, expectedState=%{public}d, nextState=%{public}d",
            nowState, expectedState, nextState);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        return SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR;
    }
    g_serviceContext[serviceId].serverState.state = nextState;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    return SOFTBUS_OK;
}

static void ClearServiceState(GattServiceType serviceId)
{
    g_serviceContext[serviceId].serverState.state = BLE_SERVER_STATE_INITIAL;
    g_serviceContext[serviceId].serverState.serviceHandle = -1;
    g_serviceContext[serviceId].serverState.connCharacteristicHandle = -1;
    g_serviceContext[serviceId].serverState.connDescriptorHandle = -1;
    g_serviceContext[serviceId].serverState.netCharacteristicHandle = -1;
    g_serviceContext[serviceId].serverState.netDescriptorHandle = -1;
    SoftBusFree(g_serviceContext[serviceId].gattService);
    g_serviceContext[serviceId].gattService = NULL;
    bool isUnregisterCallback = true;
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.serviceHandle != -1) {
            isUnregisterCallback = false;
            break;
        }
    }
    if (isUnregisterCallback) {
        SoftBusUnRegisterGattsCallbacks();
        g_isRegisterCallback = false;
    }
    SoftBusFree(g_serviceContext[serviceId].gattService);
    g_serviceContext[serviceId].gattService = NULL;
}

static void ResetServerState(GattServiceType serviceId)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! ble reset server state failed, try to lock failed");
    int32_t serviceHandle = -1;
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN) {
        serviceHandle = g_serviceContext[serviceId].serverState.serviceHandle;
        ClearServiceState(serviceId);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (serviceHandle != -1) {
            SoftBusGattsDeleteService(serviceHandle);
        }
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL);
        return;
    }

    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STARTING ||
            g_serviceContext[i].serverState.state == BLE_SERVER_STATE_SERVICE_STOPPING) {
            ResetServerState((GattServiceType)i);
        }
    }
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
}

static GattServiceType FindService(const SoftBusBtUuid *uuid)
{
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService != NULL &&
            g_serviceContext[i].gattService->serviceUuid.uuid != NULL &&
            g_serviceContext[i].gattService->serviceUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService->serviceUuid.uuid, uuid->uuidLen) == 0) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByServiceHandle(int32_t serviceHandle)
{
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.serviceHandle == serviceHandle) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindServiceByDescriptorHandle(int32_t descriptorHandle)
{
    int32_t status = SoftBusMutexLock(&g_serviceContextLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock failed, err=%{public}d", status);
        return GATT_SERVICE_TYPE_UNKOWN;
    }
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].serverState.netDescriptorHandle == descriptorHandle ||
            g_serviceContext[i].serverState.connDescriptorHandle == descriptorHandle) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            return (GattServiceType)i;
        }
    }
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindNetCharacteristic(const SoftBusBtUuid *uuid)
{
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService !=  NULL &&
            g_serviceContext[i].gattService->netUuid.uuid != NULL &&
            g_serviceContext[i].gattService->netUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService->netUuid.uuid, uuid->uuidLen) == 0) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindConnCharacteristic(const SoftBusBtUuid *uuid)
{
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService !=  NULL &&
            g_serviceContext[i].gattService->connCharacteristicUuid.uuid != NULL &&
            g_serviceContext[i].gattService->connCharacteristicUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService->connCharacteristicUuid.uuid, uuid->uuidLen) == 0) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

static GattServiceType FindDescriptor(SoftBusBtUuid *uuid)
{
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        if (g_serviceContext[i].gattService !=  NULL &&
            g_serviceContext[i].gattService->descriptorUuid.uuid != NULL &&
            g_serviceContext[i].gattService->descriptorUuid.uuidLen == uuid->uuidLen &&
            memcmp(uuid->uuid, g_serviceContext[i].gattService->descriptorUuid.uuid, uuid->uuidLen) == 0) {
            return (GattServiceType)i;
        }
    }
    return GATT_SERVICE_TYPE_UNKOWN;
}

int32_t ConnGattServerStartService(GattService *service, GattServiceType serviceId)
{
    if (serviceId <= GATT_SERVICE_TYPE_UNKOWN || serviceId >= GATT_SERVICE_MAX) {
        CONN_LOGE(CONN_BLE, "serviceType is unkown, servieId=%{public}d", serviceId);
        return SOFTBUS_INVALID_PARAM;
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(service != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "service is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! ble server start service failed: try to lock failed");
    enum GattServerState state = g_serviceContext[serviceId].serverState.state;
    
    if (state == BLE_SERVER_STATE_SERVICE_STARTED) {
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        return SOFTBUS_OK;
    }
    ResetServerState(serviceId);
    g_serviceContext[serviceId].gattService = service;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);

    int32_t status = BleRegisterGattServerCallback();
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "register underlayer callback failed, err=%{public}d", status);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_REGISTER_CALLBACK_ERR;
    }
    g_isRegisterCallback = true;
    status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_INITIAL, BLE_SERVER_STATE_SERVICE_ADDING, serviceId);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", status);
        return status;
    }

    status = SoftBusGattsAddService(service->serviceUuid, true, MAX_SERVICE_CHAR_NUM);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "underlayer add service failed, err=%{public}d", status);
        ResetServerState(serviceId);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR;
    }
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL,
        SERVER_WAIT_START_SERVER_TIMEOUT_MILLIS);
    return SOFTBUS_OK;
}

static void BleServiceAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle)
{
    CONN_LOGI(CONN_BLE, "gatt server callback, server added, srvcHandle=%{public}u, status=%{public}d",
        srvcHandle, status);
    CONN_CHECK_AND_RETURN_LOGE(uuid != NULL, CONN_BLE, "uuid is null");
    ServiceAddMsgContext *ctx = (ServiceAddMsgContext *)SoftBusCalloc(sizeof(ServiceAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE,
        "receive gatt server callback, server added handle failed: calloc service add msg context failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void NotifyServerStarted(GattServiceType serviceId, int32_t status)
{
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN && g_serverEventListener[serviceId].onServerStarted != NULL) {
        if (status != SOFTBUS_OK) {
            ClearServiceState(serviceId);
        }
        g_serverEventListener[serviceId].onServerStarted(BLE_GATT, status);
        return;
    }
    // if service type is unkown, notify starting service that start service failed
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, CONN_BLE,
            "try to lock failed");
        enum GattServerState state = g_serviceContext[i].serverState.state;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (state <= BLE_SERVER_STATE_SERVICE_STARTING && state > BLE_SERVER_STATE_INITIAL) {
            NotifyServerStarted((GattServiceType)i, status);
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
            CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindService(&ctx->uuid);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            CONN_LOGE(CONN_BLE, "not find service");
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_SERVICE_ERR;
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            break;
        }
        g_serviceContext[serviceId].serverState.serviceHandle = ctx->srvcHandle;
        SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService->netUuid;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (ctx->status != SOFTBUS_OK) {
            CONN_LOGW(CONN_BLE, "underlay returned status is not success, status=%{public}d", ctx->status);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_FAIL;
            break;
        }

        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDING, BLE_SERVER_STATE_SERVICE_ADDED, serviceId);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", rc);
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
            CONN_LOGW(CONN_BLE, "underlayer add characteristic failed, err=%{public}d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_ADDED,
            BLE_SERVER_STATE_NET_CHARACTERISTIC_ADDING, serviceId);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static void BleCharacteristicAddCallback(
    int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t characteristicHandle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, characteristic added. "
        "srvcHandle=%{public}u, characteristicHandle=%{public}d, status=%{public}d",
        srvcHandle, characteristicHandle, status);
    CharacteristicAddMsgContext *ctx =
        (CharacteristicAddMsgContext *)SoftBusCalloc(sizeof(CharacteristicAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE, "calloc characteristic add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->characteristicHandle = characteristicHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_CHARACTERISTIC_ADDED, 0, 0, ctx, 0) !=
        SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post message to looper failed");
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
            CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
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
            CONN_LOGE(CONN_BLE, "unkown characteristic, err=%{public}d", rc);
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
                nextNext = BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING;
            }
        }
        if (ctx->srvcHandle != g_serviceContext[serviceId].serverState.serviceHandle) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CONN_LOGE(CONN_BLE, "srvcHandle is different, serviceId=%{public}d, "
                "contextSrvcHandle=%{public}d, serverSrvcHandle=%{public}d, error=%{public}d", serviceId,
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
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", rc);
            break;
        }

        if (isNeedAddDescriptor) {
            SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService->descriptorUuid;
            rc = SoftBusGattsAddDescriptor(
                ctx->srvcHandle, uuid, SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
            if (rc != SOFTBUS_OK) {
                CONN_LOGE(CONN_BLE, "underlayer add decriptor failed, err=%{public}d", rc);
                rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_ERR;
                break;
            }
        } else {
            SoftBusBtUuid uuid = g_serviceContext[serviceId].gattService->connCharacteristicUuid;
            rc = SoftBusGattsAddCharacteristic(ctx->srvcHandle, uuid, SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
                SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE,
                SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE);
            if (rc != SOFTBUS_OK) {
                CONN_LOGE(CONN_BLE, "underlayer add characteristic failed, err=%{public}d", rc);
                rc = SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
                break;
            }
        }
        
        rc = UpdateBleServerStateInOrder(next, nextNext, serviceId);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", rc);
            break;
        }
    } while (false);
    if (rc != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static void BleDescriptorAddCallback(int32_t status, SoftBusBtUuid *uuid, int32_t srvcHandle, int32_t descriptorHandle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, descriptor added, srvcHandle=%{public}u, descriptorHandle=%{public}d, status=%{public}d",
        srvcHandle, descriptorHandle, status);
    DescriptorAddMsgContext *ctx =
        (DescriptorAddMsgContext *)SoftBusCalloc(sizeof(DescriptorAddMsgContext) + uuid->uuidLen);
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE, "calloc descriptor add msg failed");
    ctx->status = status;
    ctx->srvcHandle = srvcHandle;
    ctx->uuid.uuidLen = uuid->uuidLen;
    char *copyUuid = (char *)(ctx + 1);
    if (memcpy_s(copyUuid, uuid->uuidLen, uuid->uuid, uuid->uuidLen) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy_s uuid failed");
        SoftBusFree(ctx);
        return;
    }
    ctx->uuid.uuid = copyUuid;
    ctx->descriptorHandle = descriptorHandle;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_DESCRIPTOR_ADDED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post message to looper failed");
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
            CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        if (FindDescriptor(&ctx->uuid) == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_DESCRIPTOR_ERR;
            CONN_LOGE(CONN_BLE, "unkown descriptor");
            break;
        }
        bool isConnDescriptor = false;
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            CONN_LOGE(CONN_BLE, "underlayer srvcHandle mismatch, err=%{public}d", rc);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            break;
        }

        if (serviceId == SOFTBUS_GATT_SERVICE && g_serviceContext[serviceId].serverState.netDescriptorHandle == -1) {
            isConnDescriptor = false;
        } else if (g_serviceContext[serviceId].serverState.connDescriptorHandle == -1) {
            isConnDescriptor = true;
        } else {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_HANDLE_MISMATCH_ERR;
        }
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "descriptor handle mismatch, err=%{public}d", rc);
            break;
        }
        rc = isConnDescriptor ? BleConnDescriptorAddMsgHandler(ctx) : BleNetDescriptorAddMsgHandler(ctx);
    } while (false);
    if (rc != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerStarted(serviceId, rc);
    }
}

static int32_t BleNetDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "underlayer return status is not success, status=%{public}d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serviceContextLock);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    g_serviceContext[SOFTBUS_GATT_SERVICE].serverState.netDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDING,
        BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED, SOFTBUS_GATT_SERVICE);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", ctx->status);
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
        CONN_LOGE(CONN_BLE, "underlayer add characteristic failed, err=%{public}d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
    }
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_NET_DISCRIPTOR_ADDED,
            BLE_SERVER_STATE_CONN_CHARACTERISTIC_ADDING, SOFTBUS_GATT_SERVICE);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static int32_t BleConnDescriptorAddMsgHandler(DescriptorAddMsgContext *ctx)
{
    if (ctx->status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "underlayer return status is not success, status=%{public}d", ctx->status);
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    int32_t rc = SoftBusMutexLock(&g_serviceContextLock);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
        return SOFTBUS_LOCK_ERR;
    }
    GattServiceType serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
    if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
        CONN_LOGE(CONN_BLE, "not find serviceId by handle");
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL;
    }
    g_serviceContext[serviceId].serverState.connDescriptorHandle = ctx->descriptorHandle;
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDING,
        BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED, serviceId);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", ctx->status);
        return rc;
    }
    rc = SoftBusGattsStartService(ctx->srvcHandle);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "underlayer start service failed, err=%{public}d", rc);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_ERR;
    }
    rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_CONN_DISCRIPTOR_ADDED,
        BLE_SERVER_STATE_SERVICE_STARTING, serviceId);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", ctx->status);
        return rc;
    }
    return SOFTBUS_OK;
}

static void BleServiceStartCallback(int32_t status, int32_t srvcHandle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, service start, srvcHandle=%{public}u, status=%{public}d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE, "calloc service start status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STARTED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post message to looper failed");
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
            CONN_LOGW(CONN_BLE, "underlayer return status is not success, status=%{public}d", ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, err=%{public}d", rc);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CONN_LOGE(CONN_BLE, "underlayer srvcHandle mismatch, err=%{public}d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTING,
            BLE_SERVER_STATE_SERVICE_STARTED, serviceId);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d, serviceId=%{public}d", rc, serviceId);
            break;
        }
    } while (false);

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
static BleServerConnection *GetServerConnectionByHandle(int32_t underlayerHandle)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleServerConnections->lock) == SOFTBUS_OK, NULL,
        CONN_BLE, "lock failed");
    BleServerConnection *it = NULL;
    BleServerConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleServerConnections->list, BleServerConnection, node) {
        if (it->underHandle == underlayerHandle) {
            target = it;
            break;
        }
    }
    SoftBusMutexUnlock(&g_bleServerConnections->lock);
    return target;
}

static int32_t GetServerConnectionAddrByHandle(int32_t underlayerHandle, char *addr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleServerConnections->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "lock failed");
    BleServerConnection *it = NULL;
    BleServerConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleServerConnections->list, BleServerConnection, node) {
        if (it->underHandle == underlayerHandle) {
            target = it;
            break;
        }
    }

    if (target == NULL || strcpy_s(addr, BT_MAC_LEN, target->addr) != EOK) {
        SoftBusMutexUnlock(&g_bleServerConnections->lock);
        return SOFTBUS_ERR;
    }
    SoftBusMutexUnlock(&g_bleServerConnections->lock);
    return SOFTBUS_OK;
}

static void RemoveServerConnection(int32_t underlayerHandle)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleServerConnections->lock) == SOFTBUS_OK, CONN_BLE,
        "lock failed");
    BleServerConnection *it = NULL;
    BleServerConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_bleServerConnections->list, BleServerConnection, node) {
        if (it->underHandle == underlayerHandle) {
            ListDelete(&it->node);
            SoftBusFree(it);
        }
    }
    SoftBusMutexUnlock(&g_bleServerConnections->lock);
}

static uint32_t BleCreateAndSaveConnection(char *address, int32_t mtu, int32_t underlayerHandle)
{
    ConnBleConnection *connection = NULL;
    uint32_t connectionId = 0;
    GattServiceType serviceId = mtu == DEFAULT_MTU_SIZE ? SOFTBUS_GATT_SERVICE : LEGACY_GATT_SERVICE;
    if (serviceId == SOFTBUS_GATT_SERVICE) {
        connection = ConnBleCreateConnection(address, BLE_GATT, CONN_SIDE_SERVER, underlayerHandle, false);
    } else {
        connection = LegacyBleCreateConnection(address, CONN_SIDE_SERVER, underlayerHandle, false);
    }
    if (connection == NULL) {
        CONN_LOGI(CONN_BLE, "create connection failed, handle=%{public}d", underlayerHandle);
        return connectionId;
    }
    connection->mtu = mtu;
    connection->state = BLE_CONNECTION_STATE_MTU_SETTED;
    int32_t status = serviceId == SOFTBUS_GATT_SERVICE ? ConnBleSaveConnection(connection) :
        LegacyBleSaveConnection(connection);
    if (status != SOFTBUS_OK) {
        ReturnConnection(serviceId, connection);
        CONN_LOGI(CONN_BLE, "save connection failed, handle=%{public}d", underlayerHandle);
        return connectionId;
    }
    connectionId = connection->connectionId;
    return connectionId;
}

// server accepted(be connected) not need switch thread, as it just save the connection globally
static void BleConnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, server connected, "
        "underlayerHandle=%{public}u, address=%{public}02X:*:*:*:%{public}02X:%{public}02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);

    char address[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(address, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE,
            "convert binary mac address to string failed, "
            "address=%{public}02X:*:*:*:%{public}02X:%{public}02X, error=%{public}d",
            status, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);

    ConnBleConnection *softbusConnection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    ConnBleConnection *legacyConnection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    if (softbusConnection != NULL || legacyConnection != NULL ||
        GetServerConnectionByHandle(underlayerHandle) != NULL) {
        CONN_LOGI(CONN_BLE,
            "server connected handle trace, connection exist, ignore, address=%{public}s", anomizeAddress);
        ConnBleReturnConnection(&softbusConnection);
        LegacyBleReturnConnection(&legacyConnection);
        return;
    }
    BleServerConnection *serverConnection = (BleServerConnection *)SoftBusCalloc(sizeof(BleServerConnection));
    CONN_CHECK_AND_RETURN_LOGE(serverConnection != NULL, CONN_BLE, "calloc service connection failed");
    serverConnection->underHandle = underlayerHandle;
    if (strcpy_s(serverConnection->addr, BT_MAC_LEN, address) != EOK) {
        SoftBusGattsDisconnect(*btAddr, underlayerHandle);
        SoftBusFree(serverConnection);
        return;
    }
    SoftBusMutexLock(&g_bleServerConnections->lock);
    ListAdd(&g_bleServerConnections->list, &serverConnection->node);
    SoftBusMutexUnlock(&g_bleServerConnections->lock);
    ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, (uint32_t)underlayerHandle,
        0, NULL, SERVER_WAIT_MTU_TIMEOUT_MILLIS);
}

static void BleMtuChangeCallback(int32_t underlayerHandle, int32_t mtu)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, mtu changed, underlayerHandle=%{public}d, mtu=%{public}d", underlayerHandle, mtu);
    char addr[BT_MAC_LEN] = {0};
    int status = GetServerConnectionAddrByHandle(underlayerHandle, addr);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "not find serverConnection");
        return;
    }
    ConnRemoveMsgFromLooper(
        &g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_MTU_TIMEOUT, (uint32_t)underlayerHandle, 0, NULL);
    GattServiceType serviceId = mtu == DEFAULT_MTU_SIZE ? SOFTBUS_GATT_SERVICE : LEGACY_GATT_SERVICE;

    uint32_t connectionId = BleCreateAndSaveConnection(addr, mtu, underlayerHandle);
    if (connectionId == 0) {
        CONN_LOGE(CONN_BLE, "create connection failed");
        RemoveServerConnection(underlayerHandle);
        return;
    };

    g_serverEventListener[serviceId].onServerAccepted(connectionId);
    RemoveServerConnection(underlayerHandle);
}

static void BleServerWaitMtuTimeoutHandler(int32_t underlayerHandle)
{
    char addr[BT_MAC_LEN] = {0};
    int32_t status = GetServerConnectionAddrByHandle(underlayerHandle, addr);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "not find serverConnection");
        return;
    }
    CONN_LOGI(CONN_BLE, "diconnect, underlayerHandle=%{public}d", underlayerHandle);
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != EOK) {
        CONN_LOGE(CONN_BLE, "convert string mac to binary fail, err=%{public}d", status);
        RemoveServerConnection(underlayerHandle);
        return;
    }
    status = SoftBusGattsDisconnect(binaryAddr, underlayerHandle);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "SoftBusGattsDisconnect fail, err=%{public}d", status);
    }
    RemoveServerConnection(underlayerHandle);
}

int32_t ConnGattServerStopService(GattServiceType serviceId)
{
    if (serviceId <= GATT_SERVICE_TYPE_UNKOWN || serviceId >= GATT_SERVICE_MAX) {
        CONN_LOGI(CONN_BLE, "serviceType is unkown, servieId=%{public}d", serviceId);
        return SOFTBUS_INVALID_PARAM;
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
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
        if (state != BLE_SERVER_STATE_SERVICE_STARTED) {
            status = SoftBusGattsDeleteService(serviceHandle);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_BLE, "delete service failed, err=%{public}d", status);
                status = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR;
            }
            break;
        }
        status = SoftBusGattsStopService(serviceHandle);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "stop service failed, err=%{public}d", status);
            status = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_ERR;
            break;
        }
        status = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STARTED,
            BLE_SERVER_STATE_SERVICE_STOPPING, serviceId);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update state failed, err=%{public}d", status);
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_START_SERVER_TIMEOUT, serviceId, 0, NULL);
        ResetServerState(serviceId);
        // After a service is forcibly stopped, the service is successfully stopped.
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, SOFTBUS_OK);
        if (status != SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR) {
            SoftBusGattsDeleteService(serviceHandle);
        }
        status = SOFTBUS_OK;
    }
    return status;
}

static void BleServiceStopCallback(int32_t status, int32_t srvcHandle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, service stop, srvcHandle=%{public}u, status=%{public}d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE,
        "receive gatt server callback, service stop handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_STOPED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post message to looper failed");
        SoftBusFree(ctx);
    }
}

static void NotifyServerClosed(GattServiceType serviceId, int32_t status)
{
    if (serviceId != GATT_SERVICE_TYPE_UNKOWN && g_serverEventListener[serviceId].onServerClosed != NULL) {
        if (status != SOFTBUS_OK) {
            ClearServiceState(serviceId);
        }
        // After a service is forcibly stopped, the service is successfully stopped.
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, SOFTBUS_OK);
        return;
    }
    // if service type is unkown, notify all stopping services stoped
    for (int32_t i = 0; i < GATT_SERVICE_MAX; i++) {
        CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, CONN_BLE,
            "try to lock failed");
        enum GattServerState state = g_serviceContext[i].serverState.state;
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (state >= BLE_SERVER_STATE_SERVICE_STOPPING && state < BLE_SERVER_STATE_SERVICE_DELETED) {
            NotifyServerClosed((GattServiceType)i, status);
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
            CONN_LOGW(CONN_BLE, "underlayer return status is not success, status=%{public}d", ctx->status);
            break;
        }
        rc = SoftBusMutexLock(&g_serviceContextLock);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, status=%{public}d", ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CONN_LOGE(CONN_BLE, "underlayer srvcHandle mismatch, err=%{public}d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPING,
            BLE_SERVER_STATE_SERVICE_STOPPED, serviceId);
        if (rc != SOFTBUS_OK) {
            // invoke to delete service even if the update fails
            CONN_LOGW(CONN_BLE, "update server state failed, err=%{public}d", rc);
        }
        rc = SoftBusGattsDeleteService(ctx->srvcHandle);
        if (rc != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR;
            CONN_LOGE(CONN_BLE, "underlay delete service failed, err=%{public}d", rc);
            break;
        }
        rc = UpdateBleServerStateInOrder(BLE_SERVER_STATE_SERVICE_STOPPED,
            BLE_SERVER_STATE_SERVICE_DELETING, serviceId);
        if (rc != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "update server state failed, err=%{public}d", rc);
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
        NotifyServerClosed(serviceId, rc);
    }
}

static void BleServiceDeleteCallback(int32_t status, int32_t srvcHandle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, service deleted, srvcHandle=%{public}u, status=%{public}d", srvcHandle, status);
    CommonStatusMsgContext *ctx = (CommonStatusMsgContext *)SoftBusCalloc(sizeof(CommonStatusMsgContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BLE,
        "gatt server callback, service deleted handle failed: calloc service stop status msg failed");
    ctx->srvcHandle = srvcHandle;
    ctx->status = status;
    if (ConnPostMsgToLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_SERVICE_DELETED, 0, 0, ctx, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "gatt server callback, service deleted handle failed: post message to looper failed");
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
            CONN_LOGE(CONN_BLE, "try to lock failed, status=%{public}d", ctx->status);
            rc = SOFTBUS_LOCK_ERR;
            break;
        }
        serviceId = FindServiceByServiceHandle(ctx->srvcHandle);
        if (serviceId == GATT_SERVICE_TYPE_UNKOWN) {
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR;
            CONN_LOGE(CONN_BLE, "underlayer srvcHandle mismatch, err=%{public}d", rc);
            break;
        }
        if (ctx->status != SOFTBUS_OK) {
            rc = SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_FAIL;
            CONN_LOGE(CONN_BLE, "underlayer return status is not success, status=%{public}d", ctx->status);
            (void)SoftBusMutexUnlock(&g_serviceContextLock);
            break;
        }

        ClearServiceState(serviceId);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
    } while (false);
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_STOP_SERVER_TIMEOUT, 0, 0, NULL);
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
        // After a service is forcibly stopped, the service is successfully stopped.
        g_serverEventListener[serviceId].onServerClosed(BLE_GATT, SOFTBUS_OK);
    }
}

static int32_t GetBleAttrHandle(int32_t module, GattServiceType serviceId)
{
    return (module == MODULE_BLE_NET) ? g_serviceContext[serviceId].serverState.netCharacteristicHandle
        : g_serviceContext[serviceId].serverState.connCharacteristicHandle;
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble server send data failed, invalia param, connection is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble server send data failed, invalia param, data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(dataLen != 0, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble server send data failed, invalia param, data len is 0");

    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "ble server send data failed, try to get connection lock failed, connId=%{public}u, err=%{public}d",
        connection->connectionId, status);
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);

    SoftBusGattsNotify notify = {
        .connectId = underlayerHandle,
        .attrHandle = GetBleAttrHandle(module, connection->serviceId),
        .confirm = 0,
        .valueLen = (int)dataLen,
        .value = (char *)data,
    };
    return SoftBusGattsSendNotify(&notify);
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "invalid param, connection is null");
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "ble server connect failed, try to lock failed, connId=%{public}u, err=%{public}d",
            connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (underlayerHandle == INVALID_UNDERLAY_HANDLE) {
        CONN_LOGE(CONN_BLE, "ble server connect failed, underlay handle is invalid. connId=%{public}u",
            connection->connectionId);
        return SOFTBUS_ERR;
    }
    SoftBusBtAddr binaryAddr = { 0 };
    status = ConvertBtMacToBinary(connection->addr, BT_MAC_LEN, binaryAddr.addr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "ble server connect failed: convert string mac to binary fail, connId=%{public}u, err=%{public}d",
            connection->connectionId, status);
        return status;
    }
    status = SoftBusGattsConnect(binaryAddr);
    CONN_LOGI(CONN_BLE,
        "ble server connect, connId=%{public}u, underlayerHandle=%{public}d, status=%{public}d",
        connection->connectionId, underlayerHandle, status);
    return status;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble server connection disconnect failed: invalid param, connection is null");
    if (connection->serviceId <= GATT_SERVICE_TYPE_UNKOWN || connection->serviceId >= GATT_SERVICE_MAX) {
        CONN_LOGE(CONN_BLE, "serviceType is unkown, servieId=%{public}d", connection->serviceId);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "ble server connection disconnect failed, try to lock failed, connectionId=%{public}u, err=%{public}d",
            connection->connectionId, status);
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
        CONN_LOGE(CONN_BLE,
            "ble server connection disconnect failed: convert string mac to binary fail, "
            "connectionId=%{public}u, err=%{public}d",
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
    CONN_LOGI(CONN_BLE,
        "ble server connection disconnect, connectionId=%{public}u, handle=%{public}d, status=%{public}d",
        connection->connectionId, underlayerHandle, status);
    return status;
}

static void BleDisconnectServerCallback(int32_t underlayerHandle, const SoftBusBtAddr *btAddr)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, server disconnected. "
        "handle=%{public}u, address=%{public}02X:*:*:*:%{public}02X:%{public}02X",
        underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
    GattServiceType serviceId = SOFTBUS_GATT_SERVICE;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection == NULL) {
        serviceId = LEGACY_GATT_SERVICE;
        connection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    }
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "connection not exist, serviceId=%{public}d, handle=%{public}u, "
        "address=%{public}02X:*:*:*:%{public}02X:%{public}02X",
        serviceId, underlayerHandle, btAddr->addr[0], btAddr->addr[4], btAddr->addr[5]);
    uint32_t connectionId = connection->connectionId;
    ConnRemoveMsgFromLooper(&g_bleGattServerAsyncHandler, MSG_SERVER_WAIT_DICONNECT_TIMEOUT,
        connectionId, serviceId, NULL);
    ReturnConnection(serviceId, connection);
    g_serverEventListener[serviceId].onServerConnectionClosed(connectionId, SOFTBUS_OK);
}

static void BleServerWaitDisconnectTimeoutHandler(uint32_t connectionId, uint32_t serviceId)
{
    CONN_LOGI(CONN_BLE, "server wait disconnect timeout, connId=%{public}u", connectionId);
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "ble server wait disconnect timeout handler failed: connnection not exist, connId=%{public}u", connectionId);
    ReturnConnection(serviceId, connection);
    g_serverEventListener[serviceId].onServerConnectionClosed(connectionId,
        SOFTBUS_CONN_BLE_DISCONNECT_WAIT_TIMEOUT_ERR);
}

static void BleRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    CONN_LOGI(CONN_BLE, "gatt server callback, request read, underlayerHandle=%{public}d, attributeHandle=%{public}d",
        readCbPara.connId, readCbPara.transId);
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
    CONN_LOGI(CONN_BLE, "send gatt response, handle=%{public}d, ret=%{public}d", request->attrHandle, ret);
}

static void BleRequestWriteCallback(SoftBusGattWriteRequest writeCbPara)
{
    CONN_LOGI(CONN_BLE, "gatt server callback, request write. "
                        "underlayerHandle=%{public}d, attributeHandle=%{public}d, needRsp=%{public}d",
        writeCbPara.connId, writeCbPara.attrHandle, writeCbPara.needRsp);

    if (writeCbPara.needRsp) {
        BleSendGattRsp(&writeCbPara);
    }
    CONN_CHECK_AND_RETURN_LOGE(FindServiceByDescriptorHandle(writeCbPara.attrHandle) == GATT_SERVICE_TYPE_UNKOWN,
        CONN_BLE, "ignore despriptor notify");
    int32_t underlayerHandle = writeCbPara.connId;
    GattServiceType serviceId = SOFTBUS_GATT_SERVICE;
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER, BLE_GATT);
    if (connection == NULL) {
        serviceId = LEGACY_GATT_SERVICE;
        connection = LegacyBleGetConnectionByHandle(underlayerHandle, CONN_SIDE_SERVER);
    }
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "not find conn by underlayer handle");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serviceContextLock) == SOFTBUS_OK, CONN_BLE,
        "try to lock failed");

    bool isConnCharacteristic = true;
    if (writeCbPara.attrHandle == g_serviceContext[serviceId].serverState.netCharacteristicHandle) {
        isConnCharacteristic = false;
    } else if (writeCbPara.attrHandle == g_serviceContext[serviceId].serverState.connCharacteristicHandle) {
        isConnCharacteristic = true;
    } else {
        CONN_LOGE(CONN_BLE,
            "not net or conn characteristic, connId=%{public}u, netHandle=%{public}d, connHandle=%{public}d",
            connection->connectionId, g_serviceContext[serviceId].serverState.netCharacteristicHandle,
            g_serviceContext[serviceId].serverState.connCharacteristicHandle);
        (void)SoftBusMutexUnlock(&g_serviceContextLock);
        ReturnConnection(serviceId, connection);
        return;
    }
    (void)SoftBusMutexUnlock(&g_serviceContextLock);
    uint32_t valueLen = 0;
    uint8_t *value = NULL;
    if (serviceId == SOFTBUS_GATT_SERVICE) {
        value = ConnGattTransRecv(
            connection->connectionId, writeCbPara.value, writeCbPara.length, &connection->buffer, &valueLen);
    } else {
        value = SoftBusCalloc(sizeof(uint8_t) * writeCbPara.length);
        valueLen = writeCbPara.length;
        if (value == NULL || memcpy_s(value, valueLen, writeCbPara.value, valueLen) != EOK) {
            CONN_LOGE(CONN_BLE, "legacy calloc or memcpy failed, connId=%{public}u, dataLen=%{public}u",
                connection->connectionId, valueLen);
            SoftBusFree(value);
            value = NULL;
        }
    }
    
    if (value == NULL) {
        ReturnConnection(serviceId, connection);
        return;
    }
    g_serverEventListener[serviceId].onServerDataReceived(connection->connectionId,
        isConnCharacteristic, value, valueLen);
    ReturnConnection(serviceId, connection);
}

static void BleResponseConfirmationCallback(int32_t status, int32_t handle)
{
    CONN_LOGI(CONN_BLE,
        "gatt server callback, response confirmation, status=%{public}d, handle=%{public}d", status, handle);
}

static void BleNotifySentCallback(int32_t connId, int32_t status)
{
    CONN_LOGI(CONN_BLE, "gatt server callback, notify sent, connId=%{public}d, status=%{public}d", connId, status);
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
            BleServerWaitMtuTimeoutHandler((int32_t)msg->arg1);
            break;
        case MSG_SERVER_WAIT_DICONNECT_TIMEOUT:
            BleServerWaitDisconnectTimeoutHandler((uint32_t)msg->arg1, (uint32_t)msg->arg2);
            break;
        default:
            CONN_LOGW(CONN_BLE,
                "ATTENTION, ble gatt server looper receive unexpected msg just ignore, FIX it quickly. "
                "what=%{public}d", msg->what);
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
        CONN_LOGE(CONN_BLE,
            "there is compare context value not use, forgot implement? "
            "compare failed to avoid fault silence, "
            "what=%{public}d, arg1=%{public}" PRIu64 ", arg2=%{public}" PRIu64 ", objIsNull=%{public}d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t BleRegisterGattServerCallback(void)
{
    if (g_isRegisterCallback) {
        CONN_LOGW(CONN_BLE, "already register!");
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

int32_t RegisterServerListener(const ConnBleServerEventListener *listener, GattServiceType serviceId)
{
    if (serviceId <= GATT_SERVICE_TYPE_UNKOWN || serviceId >= GATT_SERVICE_MAX) {
        CONN_LOGE(CONN_BLE, "serviceId is invalid. serviceId=%{public}d", serviceId);
        return SOFTBUS_INVALID_PARAM;
    }
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
    return SOFTBUS_OK;
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper,
    const ConnBleServerEventListener *listener, GattServiceType serviceId)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(looper != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, looper is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerStarted != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener onServerStarted is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerClosed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener onServerClosed is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerAccepted != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener onServerAccepted is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerDataReceived != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener onServerDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerConnectionClosed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble server failed, invalid param, listener onServerConnectionClosed is null");
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    int32_t status = SoftBusMutexInit(&g_serviceContextLock, &mutexAttr);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, status, CONN_INIT,
        "init ble server failed: init server state lock failed, err=%{public}d", status);
    g_bleGattServerAsyncHandler.handler.looper = looper;
    status = RegisterServerListener(listener, serviceId);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        status == SOFTBUS_OK, status, CONN_INIT, "init ble server failed: invalid param. err=%{public}d", status);
    g_bleServerConnections = CreateSoftBusList();
    return SOFTBUS_OK;
}