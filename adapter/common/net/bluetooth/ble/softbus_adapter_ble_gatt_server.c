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
#include "softbus_adapter_ble_gatt_server.h"

#include "securec.h"
#include <stdatomic.h>

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gatt_server.h"

#include "common_list.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"

#include "conn_log.h"
#include "softbus_adapter_ble_gatt_client.h"

#define WAIT_HAL_REG_TIME_MS 5 // ms
#define WAIT_HAL_REG_RETRY 3

static const char SOFTBUS_APP_UUID[BT_UUID_LEN] = {
    0x00, 0x00, 0xFE, 0x36, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
};

static void FindCallbackByHandle(int32_t handle, SoftBusGattsCallback *callback);
static void FindCallbackByConnId(int32_t connId, SoftBusGattsCallback *callback);
static void FindCallbackByUdidAndSetHandle(SoftBusBtUuid *serviceUuid, SoftBusGattsCallback *callback,
                                           int32_t srvcHandle);
static int32_t SetConnectionMtu(int connId, int mtu);
static int32_t SetConnIdAndAddr(int connId, int serverId, const SoftBusBtAddr *btAddr);

SoftBusGattsCallback *g_gattsCallback = NULL;
static BtGattServerCallbacks g_bleGattsHalCallback = { 0 };
static _Atomic int g_halServerId = -1;
static _Atomic int g_halRegFlag = -1; // -1:not registered or register failed; 0:registerring; 1:registered
static SoftBusGattsManager g_softBusGattsManager = { 0 };
static _Atomic bool g_isRegisterHalCallback = false;
static SoftBusBleSendSignal g_serverSendSignal = {0};

static bool IsGattsManagerEmpty(void)
{
    bool ret = true;
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK, CONN_BLE, ret,
                                   "try to lock failed");
    ret = IsListEmpty(&g_softBusGattsManager.services);
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
    return ret;
}

int CheckGattsStatus(void)
{
    if (IsGattsManagerEmpty()) {
        CONN_LOGE(CONN_BLE, "GattsManager isListEmpty");
        return SOFTBUS_LIST_EMPTY;
    }
    while (g_halRegFlag == 0) {
        CONN_LOGE(CONN_BLE, "ble hal registerring");
        static int tryTimes = WAIT_HAL_REG_RETRY;
        if (tryTimes > 0) {
            SoftBusSleepMs(WAIT_HAL_REG_TIME_MS);
            tryTimes--;
        } else {
            atomic_store_explicit(&g_halRegFlag, -1, memory_order_release);
            break;
        }
    }
    if (g_halRegFlag == -1) {
        CONN_LOGE(CONN_BLE, "g_halRegFlag == -1");
        return SOFTBUS_INVALID_NUM;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number)
{
    if ((srvcUuid.uuidLen == 0) || (srvcUuid.uuid == NULL) || (number <= 0)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    BtUuid uuid = {
        .uuid = srvcUuid.uuid,
        .uuidLen = srvcUuid.uuidLen
    };
    CONN_LOGI(CONN_BLE, "halServerId=%{public}d", g_halServerId);
    if (BleGattsAddService(g_halServerId, uuid, isPrimary, number) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddService return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions)
{
    if ((characUuid.uuidLen == 0) || (characUuid.uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    BtUuid uuid = {
        .uuid = characUuid.uuid,
        .uuidLen = characUuid.uuidLen
    };
    if (BleGattsAddCharacteristic(g_halServerId, srvcHandle, uuid, properties, permissions) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddCharacteristic return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
{
    if ((descUuid.uuidLen == 0) || (descUuid.uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    BtUuid uuid = {
        .uuid = descUuid.uuid,
        .uuidLen = descUuid.uuidLen
    };
    if (BleGattsAddDescriptor(g_halServerId, srvcHandle, uuid, permissions) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddDescriptor return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStartService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "halServerId = %{public}d, srvcHandle = %{public}d", g_halServerId, srvcHandle);
    if (BleGattsStartService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsStartService return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStopService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "halServerId = %{public}d, srvcHandle = %{public}d", g_halServerId, srvcHandle);
    if (BleGattsStopService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsStopService return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDeleteService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    if (BleGattsDeleteService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsDeleteService return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsConnect(SoftBusBtAddr btAddr)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    BdAddr addr;
    if (memcpy_s(addr.addr, BT_ADDR_LEN, btAddr.addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    CONN_LOGI(CONN_BLE, "BleGattsConnect start");
    if (BleGattsConnect(g_halServerId, addr) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsConnect return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_CONNECT_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    BdAddr addr;
    if (memcpy_s(addr.addr, BT_ADDR_LEN, btAddr.addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    CONN_LOGI(CONN_BLE, "BleGattsDisconnect start");
    if (BleGattsDisconnect(g_halServerId, addr, connId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsDisconnect return error");
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_DISCONNECT_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsSendResponse(SoftBusGattsResponse *param)
{
    if (param == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    CONN_LOGI(CONN_BLE, "connId=%{public}d", param->connectId);
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    GattsSendRspParam response = {
        .connectId = param->connectId,
        .status = param->status,
        .attrHandle = param->transId,
        .valueLen = param->valueLen,
        .value = param->value
    };
    if (BleGattsSendResponse(g_halServerId, &response) != SOFTBUS_OK) {
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_SEND_RESPONSE_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsSendNotify(SoftBusGattsNotify *param)
{
    if (param == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    CONN_LOGD(CONN_BLE, "enter");
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_CONN_BLE_CHECK_STATUS_ERR;
    }
    GattsSendIndParam notify = {
        .connectId = param->connectId,
        .attrHandle = param->attrHandle,
        .confirm = param->confirm,
        .valueLen = param->valueLen,
        .value = param->value
    };
    CONN_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_serverSendSignal.sendCondLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE, "lock fail!");
    if (!g_serverSendSignal.isWriteAvailable) {
        SoftBusSysTime waitTime = {0};
        SoftBusComputeWaitBleSendDataTime(BLE_WRITE_TIMEOUT_IN_MS, &waitTime);
        int32_t ret = SoftBusCondWait(&g_serverSendSignal.sendCond, &g_serverSendSignal.sendCondLock, &waitTime);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "SoftBusCondWait fail, ret=%{public}d, isWriteAvailable=%{public}d",
                ret, g_serverSendSignal.isWriteAvailable);
            // fall-through: The protocol stack in the blue zone on a signal framework may not be called back.
        }
    }
    g_serverSendSignal.isWriteAvailable = false;
    (void)SoftBusMutexUnlock(&g_serverSendSignal.sendCondLock);
    CONN_LOGI(CONN_BLE, "halconnId:%{public}d, attrHandle:%{public}d, confirm:%{public}d",
        notify.connectId, notify.attrHandle, notify.confirm);
    if (BleGattsSendIndication(g_halServerId, &notify) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsSendIndication failed");
        CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serverSendSignal.sendCondLock) == SOFTBUS_OK,
            SOFTBUS_LOCK_ERR, CONN_BLE, "lock fail!");
        g_serverSendSignal.isWriteAvailable = true;
        (void)SoftBusMutexUnlock(&g_serverSendSignal.sendCondLock);
        return SOFTBUS_CONN_BLE_UNDERLAY_SERVER_SEND_INDICATION_ERR;
    }
    return SOFTBUS_OK;
}

static void BleRegisterServerCallback(int status, int serverId, BtUuid *appUuid)
{
    CONN_LOGI(CONN_BLE, "status=%{public}d, severId=%{public}d", status, serverId);
    if ((appUuid == NULL) || (appUuid->uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "appUuid is null");
        return;
    }

    if (memcmp(appUuid->uuid, SOFTBUS_APP_UUID, appUuid->uuidLen) != 0) {
        CONN_LOGE(CONN_BLE, "unknown uuid");
        return;
    }

    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleRegisterServerCallback failed, status=%{public}d", status);
        atomic_store_explicit(&g_halRegFlag, -1, memory_order_release);
    } else {
        atomic_store_explicit(&g_halRegFlag, 1, memory_order_release);
        g_halServerId = serverId;
        CONN_LOGE(CONN_BLE, "g_halServerId:%{public}d)", g_halServerId);
    }
}

static void BleConnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    if (bdAddr == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }

    if (SoftbusGattcCheckExistConnectionByAddr((SoftBusBtAddr *)bdAddr)) {
        CONN_LOGW(CONN_BLE, "ble client exist connection by addr.");
        return;
    }

    CONN_LOGI(CONN_BLE, "ConnectServerCallback is coming, connId=%{public}d, serverId=%{public}d", connId, serverId);
    if (serverId != g_halServerId) {
        CONN_LOGI(CONN_BLE, "invalid serverId, halserverId=%{public}d", g_halServerId);
        return;
    }
    (void)SetConnIdAndAddr(connId, serverId, (SoftBusBtAddr *)bdAddr);
}

void RemoveConnId(int32_t connId)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    ServerConnection *it = NULL;
    ServerConnection *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_softBusGattsManager.connections, ServerConnection, node) {
        if (it->connId == connId) {
            ListDelete(&it->node);
            SoftBusFree(it);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
}

static void BleDisconnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    if (bdAddr == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }
    CONN_LOGI(CONN_BLE, "DisconnectServerCallback is coming, connId=%{public}d, severId=%{public}d", connId, serverId);
    if (serverId != g_halServerId) {
        CONN_LOGI(CONN_BLE, "invalid serverId, halserverId=%{public}d", g_halServerId);
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByConnId(connId, &callback);
    if (callback.disconnectServerCallback != NULL) {
        callback.disconnectServerCallback(connId, (SoftBusBtAddr *)bdAddr);
    }
    RemoveConnId(connId);
}

static void BleServiceAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle)
{
    if (uuid == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }

    (void)serverId;
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d", srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByUdidAndSetHandle((SoftBusBtUuid *)uuid, &callback, srvcHandle);
    if (callback.serviceAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by uuid failed");
        return;
    }
    callback.serviceAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle);
}

static void BleIncludeServiceAddCallback(int status, int serverId, int srvcHandle, int includeSrvcHandle)
{
    (void)serverId;
    (void)srvcHandle;
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d, includeSrvcHandle=%{public}d\n", srvcHandle, includeSrvcHandle);
}

static void BleCharacteristicAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d, charHandle=%{public}d\n", srvcHandle, characteristicHandle);
    if (serverId != g_halServerId) {
        CONN_LOGE(CONN_BLE, "bad server id");
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.characteristicAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    CONN_LOGI(CONN_BLE, "characteristicHandle:%{public}d)", characteristicHandle);
    callback.characteristicAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, characteristicHandle);
}

static void BleDescriptorAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle, int descriptorHandle)
{
    if (uuid == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
    }
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d, descriptorHandle=%{public}d", srvcHandle, descriptorHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.descriptorAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.descriptorAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, descriptorHandle);
}

static void BleServiceStartCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.serviceStartCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d", srvcHandle);
    callback.serviceStartCallback(status, srvcHandle);
}

static void BleServiceStopCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.serviceStopCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.serviceStopCallback(status, srvcHandle);
}

static void BleServiceDeleteCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.serviceDeleteCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.serviceDeleteCallback(status, srvcHandle);
}

static void BleRequestReadCallback(BtReqReadCbPara readCbPara)
{
    CONN_LOGI(CONN_BLE, "transId=%{public}d, attrHandle=%{public}d", readCbPara.transId, readCbPara.attrHandle);
    SoftBusGattReadRequest req = {
        .connId = readCbPara.connId,
        .transId = readCbPara.transId,
        .btAddr = (SoftBusBtAddr *)readCbPara.bdAddr,
        .attrHandle = readCbPara.attrHandle,
        .offset = readCbPara.offset,
        .isLong = readCbPara.isLong,
    };
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByConnId(readCbPara.connId, &callback);
    if (callback.requestReadCallback == NULL) {
        CONN_LOGI(CONN_BLE, "find callback by handle %{public}d failed", readCbPara.connId);
        return;
    }
    callback.requestReadCallback(req);
}

static ServerConnection *GetServerConnectionByConnIdUnsafe(int32_t connId)
{
    ServerConnection *it = NULL;
    ServerConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.connections, ServerConnection, node) {
        if (it->connId == connId) {
            target = it;
            break;
        }
    }
    return target;
}

static void FindCallbackAndNotifyConnected(int32_t connId, int32_t attrHandle, SoftBusGattsCallback *callback)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, handle=%{public}d", attrHandle);
    ServerService *it = NULL;
    ServerService *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.services, ServerService, node) {
        if (it->callback.isConcernedAttrHandle != NULL && it->callback.isConcernedAttrHandle(it->handle, attrHandle)) {
            target = it;
            break;
        }
    }
    if (target == NULL)  {
        CONN_LOGW(CONN_BLE, "unconcerned handle=%{public}d", attrHandle);
        (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
        return;
    }

    ServerConnection *connection = GetServerConnectionByConnIdUnsafe(connId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "conn is not exist, connId=%{public}d", connId);
        (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
        return;
    }

    connection->handle = target->handle; // Map connection to server
    if (!connection->notifyConnected && connection->mtu != 0) {
        if (target->callback.connectServerCallback != NULL) {
            target->callback.connectServerCallback(connId, &connection->btAddr);
        }
        if (target->callback.mtuChangeCallback != NULL) {
            target->callback.mtuChangeCallback(connId, connection->mtu);
        }
        connection->notifyConnected = true;
    }
    *callback = target->callback;
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
}

static void BleRequestWriteCallback(BtReqWriteCbPara writeCbPara)
{
    CONN_LOGI(CONN_BLE, "connId=%{public}d, attrHandle=%{public}d, req.needRsp=%{public}d", writeCbPara.connId,
              writeCbPara.attrHandle, writeCbPara.needRsp);

    SoftBusGattWriteRequest req = {
        .connId = writeCbPara.connId,
        .transId = writeCbPara.transId,
        .btAddr = (SoftBusBtAddr *)writeCbPara.bdAddr,
        .attrHandle = writeCbPara.attrHandle,
        .offset = writeCbPara.offset,
        .length = writeCbPara.length,
        .needRsp = writeCbPara.needRsp,
        .isPrep = writeCbPara.isPrep,
        .value = writeCbPara.value
    };
    SoftBusGattsCallback callback = { 0 };
    FindCallbackAndNotifyConnected(writeCbPara.connId, writeCbPara.attrHandle, &callback);
    if (callback.requestWriteCallback != NULL) {
        callback.requestWriteCallback(req);
        return;
    }
    // A response needs to be sent before the ACL is created.
    CONN_LOGI(CONN_BLE, "send response handle=%{public}d", writeCbPara.connId);
    if (writeCbPara.needRsp) {
        SoftBusGattsResponse response = {
            .connectId = writeCbPara.connId,
            .transId = writeCbPara.transId,
            .status = SOFTBUS_BT_STATUS_SUCCESS,
            .attrHandle = writeCbPara.attrHandle,
            .offset = writeCbPara.offset,
            .valueLen = writeCbPara.length,
            .value = (char *)writeCbPara.value,
        };
        SoftBusGattsSendResponse(&response);
    }
}

static void BleResponseConfirmationCallback(int status, int handle)
{
    CONN_LOGI(CONN_BLE, "status=%{public}d, handle=%{public}d\n", status, handle);
}

static void BleIndicationSentCallback(int connId, int status)
{
    CONN_LOGI(CONN_BLE, "status=%{public}d, connId=%{public}d\n", status, connId);
    CONN_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&g_serverSendSignal.sendCondLock) == SOFTBUS_OK, CONN_BLE, "lock fail!");
    g_serverSendSignal.isWriteAvailable = true;
    (void)SoftBusCondBroadcast(&g_serverSendSignal.sendCond);
    (void)SoftBusMutexUnlock(&g_serverSendSignal.sendCondLock);
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByConnId(connId, &callback);
    if (callback.notifySentCallback == NULL) {
        CONN_LOGI(CONN_BLE, "find callback by connId %{public}d failed", connId);
        return;
    }
    callback.notifySentCallback(connId, status);
}

static void BleMtuChangeCallback(int connId, int mtu)
{
    CONN_LOGI(CONN_BLE, "connId=%{public}d, mtu=%{public}d", connId, mtu);
    int32_t ret = SetConnectionMtu(connId, mtu);
    if (ret != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "SetConnectionMtu failed, err=%{public}d", ret);
    }
}

static int GattsRegisterHalCallback(void)
{
    g_bleGattsHalCallback.registerServerCb = BleRegisterServerCallback;
    g_bleGattsHalCallback.connectServerCb = BleConnectServerCallback;
    g_bleGattsHalCallback.disconnectServerCb = BleDisconnectServerCallback;
    g_bleGattsHalCallback.serviceAddCb = BleServiceAddCallback;
    g_bleGattsHalCallback.includeServiceAddCb = BleIncludeServiceAddCallback;
    g_bleGattsHalCallback.characteristicAddCb = BleCharacteristicAddCallback;
    g_bleGattsHalCallback.descriptorAddCb = BleDescriptorAddCallback;
    g_bleGattsHalCallback.serviceStartCb = BleServiceStartCallback;
    g_bleGattsHalCallback.serviceStopCb = BleServiceStopCallback;
    g_bleGattsHalCallback.serviceDeleteCb = BleServiceDeleteCallback;
    g_bleGattsHalCallback.requestReadCb = BleRequestReadCallback;
    g_bleGattsHalCallback.requestWriteCb = BleRequestWriteCallback;
    g_bleGattsHalCallback.responseConfirmationCb = BleResponseConfirmationCallback;
    g_bleGattsHalCallback.indicationSentCb = BleIndicationSentCallback;
    g_bleGattsHalCallback.mtuChangeCb = BleMtuChangeCallback;
    return BleGattsRegisterCallbacks(&g_bleGattsHalCallback);
}

static void FindCallbackByHandle(int32_t handle, SoftBusGattsCallback *callback)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, handle=%{public}d", handle);
    ServerService *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.services, ServerService, node) {
        if (it->handle == handle) {
            *callback = it->callback;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
}

static int32_t SetConnectionMtu(int connId, int mtu)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    ServerConnection *conn = GetServerConnectionByConnIdUnsafe(connId);
    if (conn == NULL) {
        CONN_LOGW(CONN_BLE, "conn is not exist, connId=%{public}d", connId);
        (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
        return SOFTBUS_NOT_FIND;
    }
    conn->mtu = mtu;
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
    return SOFTBUS_OK;
}

static int32_t SetConnIdAndAddr(int connId, int serverId, const SoftBusBtAddr *btAddr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    ServerConnection *it = NULL;
    ServerConnection *target =  NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.connections, ServerConnection, node) {
        if (it->connId == connId) {
            target = it;
            break;
        }
    }
    if (target == NULL) {
        target = (ServerConnection *)SoftBusCalloc(sizeof(ServerConnection));
        if (target == NULL) {
            CONN_LOGE(CONN_BLE, "calloc serverConnection failed");
            (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        ListInit(&target->node);
        ListAdd(&g_softBusGattsManager.connections, &target->node);
    }
    target->connId = connId;
    target->notifyConnected = false;
    target->handle = -1;
    (void)memcpy_s(&target->btAddr, sizeof(SoftBusBtAddr), btAddr, sizeof(SoftBusBtAddr));
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
    return SOFTBUS_OK;
}

static void FindCallbackByConnId(int32_t connId, SoftBusGattsCallback *callback)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    ServerConnection *conn = GetServerConnectionByConnIdUnsafe(connId);
    if (conn == NULL) {
        CONN_LOGI(CONN_BLE, "conn is not exist, connId=%{public}d", connId);
        (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
        return;
    }
    int32_t handle = conn->handle;
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
    FindCallbackByHandle(handle, callback);
}

static void FindCallbackByUdidAndSetHandle(
    SoftBusBtUuid *serviceUuid, SoftBusGattsCallback *callback, int32_t srvcHandle)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, srvcHandle=%{public}d", srvcHandle);
    ServerService *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.services, ServerService, node) {
        if (it->serviceUuid.uuidLen == serviceUuid->uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid->uuid, it->serviceUuid.uuidLen) == 0) {
            *callback = it->callback;
            it->handle = srvcHandle;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
}

static int32_t CreateAndAddGattsManager(SoftBusGattsCallback *callback, SoftBusBtUuid serviceUuid)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "try to lock failed");
    ServerService *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager.services, ServerService, node) {
        if (it->serviceUuid.uuidLen == serviceUuid.uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid.uuid, serviceUuid.uuidLen) == 0) {
            CONN_LOGW(CONN_BLE, "SoftBusRegisterGattsCallbacks register again");
            (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
            return SOFTBUS_OK;
        }
    }

    ServerService *service = (ServerService *)SoftBusCalloc(sizeof(ServerService));
    if (service == NULL) {
        CONN_LOGE(CONN_BLE, "calloc failed");
        (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
        return SOFTBUS_MALLOC_ERR;
    }
    service->serviceUuid = serviceUuid;
    service->callback = *callback;
    service->handle = -1;

    ListInit(&service->node);
    ListAdd(&g_softBusGattsManager.services, &service->node);
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
    return SOFTBUS_OK;
}

static void RemoveGattsManager(SoftBusBtUuid serviceUuid)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager.lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed");
    ServerService *it = NULL;
    ServerService *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_softBusGattsManager.services, ServerService, node) {
        if (it->serviceUuid.uuidLen == serviceUuid.uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid.uuid, it->serviceUuid.uuidLen) == 0) {
            ListDelete(&it->node);
            SoftBusFree(it);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager.lock);
}

int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback, SoftBusBtUuid serviceUuid)
{
    if (callback == NULL) {
        CONN_LOGE(CONN_BLE, "SoftBusRegisterGattsCallbacks fail:nullptr");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }

    int32_t ret = CreateAndAddGattsManager(callback, serviceUuid);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_BLE, "create and add gattsManager failed");

    if (!atomic_load_explicit(&g_isRegisterHalCallback, memory_order_acquire)) {
        CONN_LOGE(CONN_BLE, "GattsRegisterHalCallback");
        ret = GattsRegisterHalCallback();
    }
    if (ret != SOFTBUS_OK) {
        RemoveGattsManager(serviceUuid);
        CONN_LOGE(CONN_BLE, "GattsRegisterCallbacks failed:%{public}d", ret);
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    atomic_store_explicit(&g_isRegisterHalCallback, true, memory_order_release);
    if (g_halRegFlag == -1) {
        BtUuid uuid;
        uuid.uuid = (char *)SOFTBUS_APP_UUID;
        uuid.uuidLen = sizeof(SOFTBUS_APP_UUID);
        atomic_store_explicit(&g_halRegFlag, 0, memory_order_release);
        CONN_LOGI(CONN_BLE, "BleGattsRegister");
        ret = BleGattsRegister(uuid);
        if (ret != SOFTBUS_OK) {
            atomic_store_explicit(&g_halRegFlag, -1, memory_order_release);
            RemoveGattsManager(serviceUuid);
            CONN_LOGE(CONN_BLE, "BleGattsRegister failed:%{public}d", ret);
            return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
        }
    }
    return SOFTBUS_OK;
}

void SoftBusUnRegisterGattsCallbacks(SoftBusBtUuid serviceUuid)
{
    RemoveGattsManager(serviceUuid);
    if (g_halRegFlag == -1 || !IsGattsManagerEmpty()) {
        CONN_LOGI(CONN_BLE, "no need to unregist gatt server.");
        return;
    }
    CONN_LOGI(CONN_BLE, "UnRegister GattsCallbacks");
    if (BleGattsUnRegister(g_halServerId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsUnRegister error.");
        return;
    }
    atomic_store_explicit(&g_halServerId, -1, memory_order_release);
    atomic_store_explicit(&g_halRegFlag, -1, memory_order_release);
}

int InitSoftbusAdapterServer(void)
{
    ListInit(&g_softBusGattsManager.services);
    ListInit(&g_softBusGattsManager.connections);
    if (SoftBusMutexInit(&g_serverSendSignal.sendCondLock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "mutex init failed");
        ListDelInit(&g_softBusGattsManager.services);
        ListDelInit(&g_softBusGattsManager.connections);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusCondInit(&g_serverSendSignal.sendCond) != SOFTBUS_OK) {
        ListDelInit(&g_softBusGattsManager.services);
        ListDelInit(&g_softBusGattsManager.connections);
        (void)SoftBusMutexDestroy(&g_serverSendSignal.sendCondLock);
        return SOFTBUS_NO_INIT;
    }
    g_serverSendSignal.isWriteAvailable = true;
    return SoftBusMutexInit(&g_softBusGattsManager.lock, NULL);
}