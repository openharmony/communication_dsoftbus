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

#include "adapter_bt_utils.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

#include "ohos_bt_def.h"
#include "ohos_bt_gatt_client.h"

#define APP_UUID_LEN 2
#define INVALID_ID   (-1)

static BtGattClientCallbacks g_btGattClientCallbacks = { 0 };
static SoftBusGattcCallback *g_softBusGattcCallback = NULL;

NO_SANITIZE("cfi") static void GattcConnectionStateChangedCallback(int clientId, int connectionState, int status)
{
    CLOGI("StateChangedCallback id=%d, state=%d, status=%d", clientId, connectionState, status);
    if (connectionState != OHOS_STATE_CONNECTED && connectionState != OHOS_STATE_DISCONNECTED) {
        CLOGI("GattcConnectionStateChangedCallback ignore");
        return;
    }

    g_softBusGattcCallback->ConnectionStateCallback(clientId, connectionState, status);
}

NO_SANITIZE("cfi")
static void GattcConnectParaUpdateCallback(int clientId, int interval, int latency, int timeout, int status)
{
    CLOGI("ParaUpdateCallback");
}

NO_SANITIZE("cfi") static void GattcSearchServiceCompleteCallback(int clientId, int status)
{
    CLOGI("SearchServiceCompleteCallback, id=%d, status=%d", clientId, status);
    g_softBusGattcCallback->ServiceCompleteCallback(clientId, status);
}

NO_SANITIZE("cfi") static void GattcReadCharacteristicCallback(int clientId, BtGattReadData *readData, int status)
{
    CLOGI("ReadCharacteristicCallback, id=%d, status=%d", clientId, status);
}

NO_SANITIZE("cfi")
static void GattcWriteCharacteristicCallback(int clientId, BtGattCharacteristic *characteristic, int status)
{
    CLOGI("WriteCharacteristicCallback, id=%d, status=%d", clientId, status);
}

NO_SANITIZE("cfi") static void GattcReadDescriptorCallback(int clientId, BtGattReadData *readData, int status)
{
    CLOGI("ReadDescriptorCallback, id=%d, status=%d", clientId, status);
}

NO_SANITIZE("cfi") static void GattcWriteDescriptorCallback(int clientId, BtGattDescriptor *descriptor, int status)
{
    CLOGI("WriteDescriptorCallback, id=%d, status=%d", clientId, status);
}

NO_SANITIZE("cfi") static void GattcConfigureMtuSizeCallback(int clientId, int mtuSize, int status)
{
    CLOGI("ConfigureMtuSizeCallback, id=%d, mtusize=%d, status=%d", clientId, mtuSize, status);
    g_softBusGattcCallback->ConfigureMtuSizeCallback(clientId, mtuSize, status);
}

NO_SANITIZE("cfi") static void GattcRegisterNotificationCallback(int clientId, int status)
{
    CLOGI("RegisterNotificationCallback, id=%d, status=%d", clientId, status);
    g_softBusGattcCallback->RegistNotificationCallback(clientId, status);
}

static void GattcNotificationCallback(int clientId, BtGattReadData *notifyData, int status)
{
    CLOGI("GattcNotificationCallback, id=%d, status=%d", clientId, status);
    if (notifyData == NULL) {
        return;
    }
    SoftBusGattcNotify notify;
    notify.dataLen = notifyData->dataLen;
    notify.charaUuid.uuidLen = notifyData->attribute.characteristic.characteristicUuid.uuidLen;
    notify.data = notifyData->data;
    notify.charaUuid.uuid = notifyData->attribute.characteristic.characteristicUuid.uuid;

    CLOGI("GattcNotificationCallback, id=%d, status=%d", clientId, status);
    g_softBusGattcCallback->NotificationReceiveCallback(clientId, &notify, status);
}

NO_SANITIZE("cfi") void SoftbusGattcRegisterCallback(SoftBusGattcCallback *cb)
{
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
    g_softBusGattcCallback = cb;
}
NO_SANITIZE("cfi") int32_t SoftbusGattcRegister(void)
{
    BtUuid appId;
    char uuid[APP_UUID_LEN] = { 0xEE, 0xFD };
    appId.uuid = uuid;
    appId.uuidLen = APP_UUID_LEN;
    int32_t clientId = BleGattcRegister(appId);
    if (clientId <= 0) {
        CLOGE("BleGattcRegister error");
        return INVALID_ID;
    }
    CLOGI("BleGattcRegister %d", clientId);
    return clientId;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcUnRegister(int32_t clientId)
{
    if (BleGattcUnRegister(clientId) != SOFTBUS_OK) {
        CLOGE("BleGattcUnRegister error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr)
{
    BdAddr bdAddr;
    if (memcpy_s(bdAddr.addr, OHOS_BD_ADDR_LEN, addr->addr, BT_ADDR_LEN) != EOK) {
        CLOGE("SoftbusGattcConnect memcpy error");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t status = BleOhosStatusToSoftBus(
        BleGattcConnect(clientId, &g_btGattClientCallbacks, &bdAddr, false, OHOS_BT_TRANSPORT_TYPE_LE));
    if (status != SOFTBUS_OK) {
        CLOGE("BleGattcConnect error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }

    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusBleGattcDisconnect(int32_t clientId)
{
    if (BleGattcDisconnect(clientId) != SOFTBUS_OK) {
        CLOGE("BleGattcDisconnect error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcSearchServices(int32_t clientId)
{
    CLOGI("SoftbusGattcSearchServices %d", clientId);
    int32_t status = BleOhosStatusToSoftBus(BleGattcSearchServices(clientId));
    if (status != SOFTBUS_OK) {
        CLOGE("BleGattcSearchServices error, status = %d", status);
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid)
{
    if (clientId <= 0) {
        CLOGE("SoftbusGattcGetService invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    BtUuid btUuid;
    btUuid.uuid = serverUuid->uuid;
    btUuid.uuidLen = serverUuid->uuidLen;
    if (!BleGattcGetService(clientId, btUuid)) {
        CLOGE("BleGattcGetService error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi")
int32_t SoftbusGattcRegisterNotification(int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid)
{
    BtGattCharacteristic btCharaUuid;
    btCharaUuid.serviceUuid.uuid = serverUuid->uuid;
    btCharaUuid.serviceUuid.uuidLen = serverUuid->uuidLen;
    btCharaUuid.characteristicUuid.uuid = charaUuid->uuid;
    btCharaUuid.characteristicUuid.uuidLen = charaUuid->uuidLen;
    int32_t status = BleOhosStatusToSoftBus(BleGattcRegisterNotification(clientId, btCharaUuid, true));
    if (status != SOFTBUS_OK) {
        CLOGE("BleGattcRegisterNotification error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int mtuSize)
{
    if (BleGattcConfigureMtuSize(clientId, mtuSize) != SOFTBUS_OK) {
        CLOGE("BleGattcConfigureMtuSize error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData)
{
    if (clientId <= 0 || clientData == NULL) {
        CLOGE("SoftbusGattcWriteCharacteristic invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    CLOGI("SoftbusGattcRegisterNotification clientId = %d", clientId);
    BtGattCharacteristic characteristic;
    characteristic.serviceUuid.uuid = clientData->serviceUuid.uuid;
    characteristic.serviceUuid.uuidLen = clientData->serviceUuid.uuidLen;
    characteristic.characteristicUuid.uuid = clientData->characterUuid.uuid;
    characteristic.characteristicUuid.uuidLen = clientData->characterUuid.uuidLen;
    if (BleGattcWriteCharacteristic(
            clientId, characteristic, OHOS_GATT_WRITE_NO_RSP, clientData->valueLen, clientData->value) != SOFTBUS_OK) {
        CLOGE("SoftbusGattcWriteCharacteristic error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSetFastestConn(int32_t clientId)
{
    if (clientId <= 0) {
        CLOGE("invalid param, '%d'", clientId);
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = BleGattcSetFastestConn(clientId, true);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        CLOGE("BleGattcSetFastestConn failed, return code '%d'", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSetPriority(int32_t clientId, SoftBusBtAddr *addr, SoftbusGattPriority priority)
{
    if (clientId <= 0 || addr == NULL) {
        CLOGE("invalid param, '%d'", clientId);
        return SOFTBUS_INVALID_PARAM;
    }
    BdAddr bdAddr = { 0 };
    if (memcpy_s(bdAddr.addr, OHOS_BD_ADDR_LEN, addr->addr, BT_ADDR_LEN) != EOK) {
        CLOGE("addr memory copy failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = BleGattcSetPriority(clientId, &bdAddr, (BtGattPriority)priority);
    if (ret != OHOS_BT_STATUS_SUCCESS) {
        CLOGE("BleGattcSetPriority failed, return code '%d'", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
