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
#include "softbus_adapter_ble_gatt_client.h"

#include "securec.h"
#include <stdbool.h>

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gatt_client.h"

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

#include "conn_log.h"
#include "softbus_type_def.h"

#include "adapter_bt_utils.h"
#define APP_UUID_LEN 2
#define INVALID_ID   (-1)

static void GetGattcCallback(int32_t clientId, SoftBusGattcCallback *cb);

static BtGattClientCallbacks g_btGattClientCallbacks = { 0 };
static SoftBusList *g_softBusGattcManager = NULL;

static void GattcConnectionStateChangedCallback(int clientId, int connectionState, int status)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, state=%{public}d, status=%{public}d", clientId, connectionState, status);
    if (connectionState != OHOS_STATE_CONNECTED && connectionState != OHOS_STATE_DISCONNECTED) {
        CONN_LOGI(CONN_BLE, "ignore connection state");
        return;
    }

    SoftBusGattcCallback cb = { 0 };
    GetGattcCallback(clientId, &cb);
    if (cb.ConnectionStateCallback == NULL) {
        CONN_LOGE(CONN_BLE, "get callback failed");
        return;
    }
    cb.ConnectionStateCallback(clientId, connectionState, status);
}

static void GattcConnectParaUpdateCallback(int clientId, int interval, int latency, int timeout, int status)
{
    (void)clientId;
    (void)interval;
    (void)latency;
    (void)timeout;
    (void)status;
    CONN_LOGI(CONN_BLE, "ParaUpdateCallback");
}

static void GattcSearchServiceCompleteCallback(int clientId, int status)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
    SoftBusGattcCallback cb = { 0 };
    GetGattcCallback(clientId, &cb);
    if (cb.ServiceCompleteCallback == NULL) {
        CONN_LOGE(CONN_BLE, "get callback failed");
        return;
    }
    cb.ServiceCompleteCallback(clientId, status);
}

static void GattcReadCharacteristicCallback(int clientId, BtGattReadData *readData, int status)
{
    (void)readData;
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
}

static void GattcWriteCharacteristicCallback(int clientId, BtGattCharacteristic *characteristic, int status)
{
    (void)characteristic;
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
}

static void GattcReadDescriptorCallback(int clientId, BtGattReadData *readData, int status)
{
    (void)readData;
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
}

static void GattcWriteDescriptorCallback(int clientId, BtGattDescriptor *descriptor, int status)
{
    (void)descriptor;
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
}

static void GattcConfigureMtuSizeCallback(int clientId, int mtuSize, int status)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, mtusize=%{public}d, status=%{public}d", clientId, mtuSize, status);
    SoftBusGattcCallback cb = { 0 };
    GetGattcCallback(clientId, &cb);
    if (cb.ConfigureMtuSizeCallback == NULL) {
        CONN_LOGE(CONN_BLE, "get callback failed");
        return;
    }
    cb.ConfigureMtuSizeCallback(clientId, mtuSize, status);
}

static void GattcRegisterNotificationCallback(int clientId, int status)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
    SoftBusGattcCallback cb = { 0 };
    GetGattcCallback(clientId, &cb);
    if (cb.RegistNotificationCallback == NULL) {
        CONN_LOGE(CONN_BLE, "get callback failed");
        return;
    }
    cb.RegistNotificationCallback(clientId, status);
}

static void GattcNotificationCallback(int clientId, BtGattReadData *notifyData, int status)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d, status=%{public}d", clientId, status);
    if (notifyData == NULL) {
        return;
    }
    SoftBusGattcNotify notify;
    notify.dataLen = notifyData->dataLen;
    notify.charaUuid.uuidLen = notifyData->attribute.characteristic.characteristicUuid.uuidLen;
    notify.data = notifyData->data;
    notify.charaUuid.uuid = notifyData->attribute.characteristic.characteristicUuid.uuid;

    SoftBusGattcCallback cb = { 0 };
    GetGattcCallback(clientId, &cb);
    if (cb.NotificationReceiveCallback == NULL) {
        CONN_LOGE(CONN_BLE, "get callback failed");
        return;
    }
    cb.NotificationReceiveCallback(clientId, &notify, status);
}

int32_t SoftbusGattcRegisterCallback(SoftBusGattcCallback *cb, int32_t clientId)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(cb != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "cb is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(cb->ConnectionStateCallback != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ConnectionStateCallback is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(cb->ConfigureMtuSizeCallback != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ConfigureMtuSizeCallback is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(cb->NotificationReceiveCallback != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "NotificationReceiveCallback is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(cb->RegistNotificationCallback != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "RegistNotificationCallback is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(cb->ServiceCompleteCallback != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ServiceCompleteCallback is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(clientId >= 0, SOFTBUS_INVALID_PARAM, CONN_BLE, "clientId < 0");
    CONN_CHECK_AND_RETURN_RET_LOGE(g_softBusGattcManager != NULL, SOFTBUS_ERR, CONN_BLE, "GattcManager is null");

    SoftBusGattcManager *gattcManager = (SoftBusGattcManager *)SoftBusCalloc(sizeof(SoftBusGattcManager));
    if (gattcManager == NULL) {
        CONN_LOGE(CONN_BLE, "calloc failed");
        return SOFTBUS_ERR;
    }

    gattcManager->callback = *cb;
    gattcManager->clientId = clientId;
    ListInit(&gattcManager->node);
    if (SoftBusMutexLock(&g_softBusGattcManager->lock) != SOFTBUS_OK) {
        SoftBusFree(gattcManager);
        CONN_LOGE(CONN_BLE, "try to lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_softBusGattcManager->list, &gattcManager->node);
    (void)SoftBusMutexUnlock(&g_softBusGattcManager->lock);
    CONN_LOGI(CONN_BLE, "clientId=%{public}d", gattcManager->clientId);
    return SOFTBUS_OK;
}

static void GetGattcCallback(int32_t clientId, SoftBusGattcCallback *cb)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_softBusGattcManager->lock) == SOFTBUS_OK,
        CONN_BLE, "try to lock failed, clientId=%{public}d", clientId);
    SoftBusGattcManager *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_softBusGattcManager->list, SoftBusGattcManager, node) {
        if (it->clientId == clientId) {
            *cb = it->callback;
            break;
        }
    }

    (void)SoftBusMutexUnlock(&g_softBusGattcManager->lock);
}

int32_t SoftbusGattcRegister(void)
{
    BtUuid appId;
    char uuid[APP_UUID_LEN] = { 0xEE, 0xFD };
    appId.uuid = uuid;
    appId.uuidLen = APP_UUID_LEN;
    int32_t clientId = BleGattcRegister(appId);
    if (clientId <= 0) {
        CONN_LOGE(CONN_BLE, "BleGattcRegister error");
        return INVALID_ID;
    }
    CONN_LOGI(CONN_BLE, "clientId=%{public}d", clientId);
    return clientId;
}

int32_t SoftbusGattcUnRegister(int32_t clientId)
{
    CONN_LOGI(CONN_BLE, "clientId=%{public}d", clientId);
    int32_t ret = SOFTBUS_OK;
    if (BleGattcUnRegister(clientId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattcUnRegister error");
        ret = SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_softBusGattcManager->lock) == SOFTBUS_OK, SOFTBUS_ERR,
        CONN_BLE, "try to lock failed, clientId=%{public}d", clientId);
    SoftBusGattcManager *it = NULL;
    SoftBusGattcManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_softBusGattcManager->list, SoftBusGattcManager, node) {
        if (it->clientId == clientId) {
            ListDelete(&it->node);
            SoftBusFree(it);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_softBusGattcManager->lock);
    return ret;
}

int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr)
{
    BdAddr bdAddr;
    if (memcpy_s(bdAddr.addr, OHOS_BD_ADDR_LEN, addr->addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy error");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t status = BleOhosStatusToSoftBus(
        BleGattcConnect(clientId, &g_btGattClientCallbacks, &bdAddr, false, OHOS_BT_TRANSPORT_TYPE_LE));
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "status=%{public}d", status);
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }

    return SOFTBUS_OK;
}

int32_t SoftbusBleGattcDisconnect(int32_t clientId, bool refreshGatt)
{
    (void)refreshGatt;
    if (BleGattcDisconnect(clientId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattcDisconnect error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSearchServices(int32_t clientId)
{
    CONN_LOGI(CONN_BLE, "input param clientId = %{public}d", clientId);
    int32_t status = BleOhosStatusToSoftBus(BleGattcSearchServices(clientId));
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "status = %{public}d", status);
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcRefreshServices(int32_t clientId)
{
    CONN_LOGI(CONN_BLE, "input param clientId = %{public}d", clientId);
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid)
{
    if (clientId <= 0) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    BtUuid btUuid;
    btUuid.uuid = serverUuid->uuid;
    btUuid.uuidLen = serverUuid->uuidLen;
    if (!BleGattcGetService(clientId, btUuid)) {
        CONN_LOGE(CONN_BLE, "BleGattcGetService error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}


int32_t SoftbusGattcRegisterNotification(
    int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid, SoftBusBtUuid *descriptorUuid)
{
    (void)descriptorUuid;
    BtGattCharacteristic btCharaUuid;
    btCharaUuid.serviceUuid.uuid = serverUuid->uuid;
    btCharaUuid.serviceUuid.uuidLen = serverUuid->uuidLen;
    btCharaUuid.characteristicUuid.uuid = charaUuid->uuid;
    btCharaUuid.characteristicUuid.uuidLen = charaUuid->uuidLen;
    int32_t status = BleOhosStatusToSoftBus(BleGattcRegisterNotification(clientId, btCharaUuid, true));
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "RegisterNotification error = %{public}d", status);
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int mtuSize)
{
    if (clientId <= 0) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (BleGattcConfigureMtuSize(clientId, mtuSize) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattcConfigureMtuSize error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData)
{
    if (clientId <= 0 || clientData == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    CONN_LOGI(CONN_BLE, "clientId = %{public}d", clientId);
    BtGattCharacteristic characteristic;
    characteristic.serviceUuid.uuid = clientData->serviceUuid.uuid;
    characteristic.serviceUuid.uuidLen = clientData->serviceUuid.uuidLen;
    characteristic.characteristicUuid.uuid = clientData->characterUuid.uuid;
    characteristic.characteristicUuid.uuidLen = clientData->characterUuid.uuidLen;
    if (BleGattcWriteCharacteristic(clientId, characteristic, OHOS_GATT_WRITE_NO_RSP, clientData->valueLen,
        (const char *)clientData->value) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSetFastestConn(int32_t clientId)
{
    if (clientId <= 0) {
        CONN_LOGE(CONN_BLE, "invalid param, clientId = %{public}d", clientId);
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = BleGattcSetFastestConn(clientId, true);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        CONN_LOGE(CONN_BLE, "BleGattcSetFastestConn failed, return code = %{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSetPriority(int32_t clientId, SoftBusBtAddr *addr, SoftbusBleGattPriority priority)
{
    if (clientId <= 0 || addr == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param, clientId = %{public}d", clientId);
        return SOFTBUS_INVALID_PARAM;
    }
    BdAddr bdAddr = { 0 };
    if (memcpy_s(bdAddr.addr, OHOS_BD_ADDR_LEN, addr->addr, BT_ADDR_LEN) != EOK) {
        CONN_LOGE(CONN_BLE, "addr memory copy failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = BleGattcSetPriority(clientId, &bdAddr, (BtGattPriority)priority);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        CONN_LOGE(CONN_BLE, "BleGattcSetPriority failed, return code = %{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t InitSoftbusAdapterClient(void)
{
    g_softBusGattcManager = CreateSoftBusList();
    if (g_softBusGattcManager == NULL) {
        return SOFTBUS_ERR;
    }
    g_btGattClientCallbacks.ConnectionStateCb = GattcConnectionStateChangedCallback;
    g_btGattClientCallbacks.connectParaUpdateCb = GattcConnectParaUpdateCallback;
    g_btGattClientCallbacks.searchServiceCompleteCb = GattcSearchServiceCompleteCallback;
    g_btGattClientCallbacks.readCharacteristicCb = GattcReadCharacteristicCallback;
    g_btGattClientCallbacks.writeCharacteristicCb = GattcWriteCharacteristicCallback;
    g_btGattClientCallbacks.readDescriptorCb = GattcReadDescriptorCallback;
    g_btGattClientCallbacks.writeDescriptorCb = GattcWriteDescriptorCallback;
    g_btGattClientCallbacks.configureMtuSizeCb = GattcConfigureMtuSizeCallback;
    g_btGattClientCallbacks.registerNotificationCb = GattcRegisterNotificationCallback;
    g_btGattClientCallbacks.notificationCb = GattcNotificationCallback;
    return SOFTBUS_OK;
}