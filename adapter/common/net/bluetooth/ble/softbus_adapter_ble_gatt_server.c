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

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gatt_server.h"

#include "common_list.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
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
static void FindCallbackByMtuAndSetConnId(int32_t mtu, SoftBusGattsCallback *callback, int32_t connId);

SoftBusGattsCallback *g_gattsCallback = NULL;
static BtGattServerCallbacks g_bleGattsHalCallback = { 0 };
static volatile int g_halServerId = -1;
static volatile int g_halRegFlag = -1; // -1:not registered or register failed; 0:registerring; 1:registered
static SoftBusList *g_softBusGattsManager = NULL;
bool g_isRegisterHalCallback = false;

static bool IsGattsManagerEmpty(void)
{
    bool ret = true;
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK, CONN_BLE, ret,
                                   "try to lock failed");
    ret = IsListEmpty(&g_softBusGattsManager->list);
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
    return ret;
}

int CheckGattsStatus(void)
{
    if (IsGattsManagerEmpty()) {
        CONN_LOGE(CONN_BLE, "GattsManager isListEmpty");
        return SOFTBUS_ERR;
    }
    while (g_halRegFlag == 0) {
        CONN_LOGE(CONN_BLE, "ble hal registerring");
        static int tryTimes = WAIT_HAL_REG_RETRY;
        if (tryTimes > 0) {
            SoftBusSleepMs(WAIT_HAL_REG_TIME_MS);
            tryTimes--;
        } else {
            g_halRegFlag = -1;
            break;
        }
    }
    if (g_halRegFlag == -1) {
        CONN_LOGE(CONN_BLE, "g_halRegFlag == -1");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number)
{
    if ((srvcUuid.uuidLen == 0) || (srvcUuid.uuid == NULL) || (number <= 0)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = srvcUuid.uuid,
        .uuidLen = srvcUuid.uuidLen
    };
    CONN_LOGI(CONN_BLE, "halServerId=%{public}d", g_halServerId);
    if (BleGattsAddService(g_halServerId, uuid, isPrimary, number) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddService return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions)
{
    if ((characUuid.uuidLen == 0) || (characUuid.uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = characUuid.uuid,
        .uuidLen = characUuid.uuidLen
    };
    if (BleGattsAddCharacteristic(g_halServerId, srvcHandle, uuid, properties, permissions) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddCharacteristic return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
{
    if ((descUuid.uuidLen == 0) || (descUuid.uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = descUuid.uuid,
        .uuidLen = descUuid.uuidLen
    };
    if (BleGattsAddDescriptor(g_halServerId, srvcHandle, uuid, permissions) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddDescriptor return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStartService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "halServerId = %{public}d, srvcHandle = %{public}d", g_halServerId, srvcHandle);
    if (BleGattsStartService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsStartService return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStopService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "halServerId = %{public}d, srvcHandle = %{public}d", g_halServerId, srvcHandle);
    if (BleGattsStopService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsStopService return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDeleteService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    if (BleGattsDeleteService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsDeleteService return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsConnect(SoftBusBtAddr btAddr)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    BdAddr addr;
    if (memcpy_s(addr.addr, BT_ADDR_LEN, btAddr.addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy fail");
        return SOFTBUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "BleGattsConnect start");
    if (BleGattsConnect(g_halServerId, addr) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsConnect return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "CheckGattsStatus return error");
        return SOFTBUS_ERR;
    }
    BdAddr addr;
    if (memcpy_s(addr.addr, BT_ADDR_LEN, btAddr.addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy fail");
        return SOFTBUS_ERR;
    }
    CONN_LOGI(CONN_BLE, "BleGattsDisconnect start");
    if (BleGattsDisconnect(g_halServerId, addr, connId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsDisconnect return error");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    GattsSendRspParam response = {
        .connectId = param->connectId,
        .status = param->status,
        .attrHandle = param->transId,
        .valueLen = param->valueLen,
        .value = param->value
    };
    if (BleGattsSendResponse(g_halServerId, &response) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    GattsSendIndParam notify = {
        .connectId = param->connectId,
        .attrHandle = param->attrHandle,
        .confirm = param->confirm,
        .valueLen = param->valueLen,
        .value = param->value
    };
    CONN_LOGI(CONN_BLE, "halconnId:%{public}d, attrHandle:%{public}d, confirm:%{public}d",
        notify.connectId, notify.attrHandle, notify.confirm);
    if (BleGattsSendIndication(g_halServerId, &notify) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsSendIndication failed");
        return SOFTBUS_ERR;
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
        g_halRegFlag = -1;
    } else {
        g_halRegFlag = 1;
        g_halServerId = serverId;
        CONN_LOGI(CONN_BLE, "g_halServerId:%{public}d)", g_halServerId);
    }
}

static int32_t GetAllManager(SoftBusGattsManager **node)
{
    if (g_softBusGattsManager == NULL) {
        CONN_LOGE(CONN_BLE, "list is null");
        return 0;
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK, CONN_BLE, 0,
                                   "try to lock failed");
    if (g_softBusGattsManager->cnt == 0) {
        CONN_LOGE(CONN_BLE, "list is empty");
        (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
        return 0;
    }
    *node = (SoftBusGattsManager *)SoftBusCalloc(g_softBusGattsManager->cnt * sizeof(SoftBusGattsManager));
    if (*node == NULL) {
        CONN_LOGE(CONN_BLE, "malloc failed");
        (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
        return 0;
    }

    int32_t i = 0;
    SoftBusGattsManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (memcpy_s(*node + i, sizeof(SoftBusGattsManager), it, sizeof(SoftBusGattsManager)) != EOK) {
            CONN_LOGE(CONN_BLE, "mem error");
            continue;
        }
        i++;
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
    return i;
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

    CONN_LOGI(CONN_BLE, "ConnectServerCallback is coming, connId=%{public}d, serverId=%{public}d\n", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsManager *nodes = NULL;
    int num = GetAllManager(&nodes);
    if (num == 0 || nodes == NULL) {
        CONN_LOGE(CONN_BLE, "get manager failed");
        return;
    }
    for (int i = 0; i < num; i++) {
        nodes[i].callback.ConnectServerCallback(connId, (SoftBusBtAddr *)bdAddr);
    }
    SoftBusFree(nodes);
}

static void RemoveConnId(int32_t connId)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    SoftBusGattsManager *manager = NULL;
    LIST_FOR_EACH_ENTRY(manager, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        ServerConnection *it = NULL;
        ServerConnection *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &manager->connections, ServerConnection, node) {
            if (it->connId == connId) {
                ListDelete(&it->node);
                SoftBusFree(it);
                break;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

static void BleDisconnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    if (bdAddr == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }
    CONN_LOGI(CONN_BLE, "DisconnectServerCallback is coming, connId=%{public}d, severId=%{public}d", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }

    SoftBusGattsManager *nodes = NULL;
    int num = GetAllManager(&nodes);
    if (num == 0 || nodes == NULL) {
        CONN_LOGE(CONN_BLE, "get manager failed");
        return;
    }
    for (int i = 0; i < num; i++) {
        nodes[i].callback.DisconnectServerCallback(connId, (SoftBusBtAddr *)bdAddr);
    }
    SoftBusFree(nodes);
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
    if (callback.ServiceAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by uuid failed");
        return;
    }
    callback.ServiceAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle);
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
    if (callback.CharacteristicAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    CONN_LOGI(CONN_BLE, "characteristicHandle:%{public}d)", characteristicHandle);
    callback.CharacteristicAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, characteristicHandle);
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
    if (callback.DescriptorAddCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.DescriptorAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, descriptorHandle);
}

static void BleServiceStartCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.ServiceStartCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d", srvcHandle);
    callback.ServiceStartCallback(status, srvcHandle);
}

static void BleServiceStopCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.ServiceStopCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.ServiceStopCallback(status, srvcHandle);
}

static void BleServiceDeleteCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByHandle(srvcHandle, &callback);
    if (callback.ServiceDeleteCallback == NULL) {
        CONN_LOGE(CONN_BLE, "find callback by handle %{public}d failed", srvcHandle);
        return;
    }
    callback.ServiceDeleteCallback(status, srvcHandle);
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
    if (callback.RequestReadCallback == NULL) {
        CONN_LOGI(CONN_BLE, "find callback by handle %{public}d failed", readCbPara.connId);
        return;
    }
    callback.RequestReadCallback(req);
}

static void BleRequestWriteCallback(BtReqWriteCbPara writeCbPara)
{
    CONN_LOGI(CONN_BLE, "transId=%{public}d, attrHandle=%{public}d, req.needRsp=%{public}d", writeCbPara.transId,
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
    FindCallbackByConnId(writeCbPara.connId, &callback);
    if (callback.RequestWriteCallback != NULL) {
        callback.RequestWriteCallback(req);
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
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByConnId(connId, &callback);
    if (callback.NotifySentCallback == NULL) {
        CONN_LOGI(CONN_BLE, "find callback by connId %{public}d failed", connId);
        return;
    }
    callback.NotifySentCallback(connId, status);
}

static void BleMtuChangeCallback(int connId, int mtu)
{
    CONN_LOGI(CONN_BLE, "connId=%{public}d, mtu=%{public}d", connId, mtu);
    SoftBusGattsCallback callback = { 0 };
    FindCallbackByMtuAndSetConnId(mtu, &callback, connId);
    if (callback.MtuChangeCallback == NULL) {
        CONN_LOGI(CONN_BLE, "find callback by connId %{public}d failed", connId);
        return;
    }
    callback.MtuChangeCallback(connId, mtu);
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
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, handle=%{public}d", handle);
    SoftBusGattsManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (it->handle == handle) {
            *callback = it->callback;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

static void FindCallbackByConnId(int32_t connId, SoftBusGattsCallback *callback)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, connId=%{public}d", connId);
    SoftBusGattsManager *it = NULL;
    ServerConnection *connections = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        LIST_FOR_EACH_ENTRY(connections, &it->connections, ServerConnection, node) {
            if (connections->connId == connId) {
                *callback = it->callback;
                break;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

static void FindCallbackByMtuAndSetConnId(int32_t mtu, SoftBusGattsCallback *callback, int32_t connId)
{
    FindCallbackByConnId(connId, callback);
    if (callback->MtuChangeCallback != NULL) {
        CONN_LOGW(CONN_BLE, "connId exist=%{public}d", connId);
        return;
    }
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK, CONN_BLE,
        "try to lock failed, mtu=%{public}d", mtu);
    SoftBusGattsManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (it->expectedMtu == mtu) {
            ServerConnection *serverConn = (ServerConnection *)SoftBusCalloc(sizeof(ServerConnection));
            if (serverConn == NULL) {
                CONN_LOGE(CONN_BLE, "calloc failed, connId=%{public}d", connId);
                break;
            }
            serverConn->connId = connId;
            ListInit(&serverConn->node);
            ListAdd(&it->connections, &serverConn->node);
            *callback = it->callback;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

static void FindCallbackByUdidAndSetHandle(
    SoftBusBtUuid *serviceUuid, SoftBusGattsCallback *callback, int32_t srvcHandle)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, srvcHandle=%{public}d", srvcHandle);
    SoftBusGattsManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (it->serviceUuid.uuidLen == serviceUuid->uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid->uuid, it->serviceUuid.uuidLen) == 0) {
            *callback = it->callback;
            it->handle = srvcHandle;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

static int32_t CreateAndAddGattsManager(SoftBusGattsCallback *callback, SoftBusBtUuid serviceUuid, int32_t expectedMtu)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK, SOFTBUS_ERR,
        CONN_BLE, "try to lock failed");
    SoftBusGattsManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (it->serviceUuid.uuidLen == serviceUuid.uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid.uuid, serviceUuid.uuidLen) == 0) {
            CONN_LOGW(CONN_BLE, "SoftBusRegisterGattsCallbacks register again");
            (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
            return SOFTBUS_OK;
        }
    }

    SoftBusGattsManager *gattsManager = (SoftBusGattsManager *)SoftBusCalloc(sizeof(SoftBusGattsManager));
    if (gattsManager == NULL) {
        CONN_LOGE(CONN_BLE, "calloc failed");
        (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
        return SOFTBUS_ERR;
    }
    gattsManager->serviceUuid = serviceUuid;
    gattsManager->callback = *callback;
    gattsManager->handle = -1;
    gattsManager->expectedMtu = expectedMtu;

    ListInit(&gattsManager->connections);
    ListInit(&gattsManager->node);
    ListAdd(&g_softBusGattsManager->list, &gattsManager->node);
    g_softBusGattsManager->cnt++;
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
    return SOFTBUS_OK;
}

static void RemoveGattsManager(SoftBusBtUuid serviceUuid)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattsManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed");
    SoftBusGattsManager *it = NULL;
    SoftBusGattsManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_softBusGattsManager->list, SoftBusGattsManager, node) {
        if (it->serviceUuid.uuidLen == serviceUuid.uuidLen &&
            memcmp(it->serviceUuid.uuid, serviceUuid.uuid, it->serviceUuid.uuidLen) == 0) {
            ListDelete(&it->node);
            g_softBusGattsManager->cnt--;
            SoftBusFree(it);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattsManager->lock);
}

int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback, SoftBusBtUuid serviceUuid, int32_t expectedMtu)
{
    if (callback == NULL) {
        CONN_LOGE(CONN_BLE, "SoftBusRegisterGattsCallbacks fail:nullptr");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }

    int32_t ret = CreateAndAddGattsManager(callback, serviceUuid, expectedMtu);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_BLE, "create and add gattsManager failed");

    if (!g_isRegisterHalCallback) {
        CONN_LOGE(CONN_BLE, "GattsRegisterHalCallback");
        ret = GattsRegisterHalCallback();
    }
    if (ret != SOFTBUS_OK) {
        RemoveGattsManager(serviceUuid);
        CONN_LOGE(CONN_BLE, "GattsRegisterCallbacks failed:%{public}d", ret);
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    g_isRegisterHalCallback = true;
    if (g_halRegFlag == -1) {
        BtUuid uuid;
        uuid.uuid = (char *)SOFTBUS_APP_UUID;
        uuid.uuidLen = sizeof(SOFTBUS_APP_UUID);
        g_halRegFlag = 0;
        CONN_LOGI(CONN_BLE, "BleGattsRegister");
        ret = BleGattsRegister(uuid);
        if (ret != SOFTBUS_OK) {
            g_halRegFlag = -1;
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
    g_halServerId = -1;
    g_halRegFlag = -1;
}

int InitSoftbusAdapterServer(void)
{
    g_softBusGattsManager = CreateSoftBusList();
    if (g_softBusGattsManager == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}