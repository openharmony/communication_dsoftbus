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

#include <stdbool.h>
#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

#include "ohos_bt_def.h"
#include "ohos_bt_gatt_client.h"

#define APP_UUID_LEN 2
#define INVALID_ID (-1)

static BtGattClientCallbacks g_btGattClientCallbacks = {0};
static SoftBusGattcCallback *g_softBusGattcCallback = NULL;

static void GattcConnectionStateChangedCallback(int clientId, int connectionState, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StateChangedCallback id=%d, state=%d, status=%d",
        clientId, connectionState, status);
    if (connectionState != OHOS_STATE_CONNECTED && connectionState != OHOS_STATE_DISCONNECTED) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GattcConnectionStateChangedCallback ignore");
        return;
    }
    g_softBusGattcCallback->ConnectionStateCallback(clientId, connectionState, status);
}

static void GattcConnectParaUpdateCallback(int clientId, int interval, int latency, int timeout, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ParaUpdateCallback");
}

static void GattcSearchServiceCompleteCallback(int clientId, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SearchServiceCompleteCallback, id=%d, status=%d",
        clientId, status);
    g_softBusGattcCallback->ServiceCompleteCallback(clientId, status);
}

static void GattcReadCharacteristicCallback(int clientId, BtGattReadData *readData, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ReadCharacteristicCallback, id=%d, status=%d", clientId, status);
}

static void GattcWriteCharacteristicCallback(int clientId, BtGattCharacteristic *characteristic, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WriteCharacteristicCallback, id=%d, status=%d", clientId, status);
}

static void GattcReadDescriptorCallback(int clientId, BtGattReadData *readData, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ReadDescriptorCallback, id=%d, status=%d", clientId, status);
}

static void GattcWriteDescriptorCallback(int clientId, BtGattDescriptor *descriptor, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WriteDescriptorCallback, id=%d, status=%d", clientId, status);
}

static void GattcConfigureMtuSizeCallback(int clientId, int mtuSize, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConfigureMtuSizeCallback, id=%d, mtusize=%d, status=%d",
        clientId, mtuSize, status);
    g_softBusGattcCallback->ConfigureMtuSizeCallback(clientId, mtuSize, status);
}

static void GattcRegisterNotificationCallback(int clientId, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RegisterNotificationCallback, id=%d, status=%d", clientId, status);
    g_softBusGattcCallback->RegistNotificationCallback(clientId, status);
}

static void GattcNotificationCallback(int clientId, BtGattReadData *notifyData, int status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GattcNotificationCallback, id=%d, status=%d", clientId, status);
    if (notifyData == NULL) {
        return;
    }
    SoftBusGattcNotify notify;
    notify.dataLen = notifyData->dataLen;
    notify.charaUuid.uuidLen = notifyData->attribute.characteristic.characteristicUuid.uuidLen;
    notify.data = notifyData->data;
    notify.charaUuid.uuid = notifyData->attribute.characteristic.characteristicUuid.uuid;

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GattcNotificationCallback, id=%d, status=%d", clientId, status);
    g_softBusGattcCallback->NotificationReceiveCallback(clientId, &notify, status);
}


void SoftbusGattcRegisterCallback(SoftBusGattcCallback *cb)
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
int32_t SoftbusGattcRegister(void)
{
    BtUuid appId;
    char uuid[APP_UUID_LEN] = {0xEE, 0xFD};
    appId.uuid = uuid;
    appId.uuidLen = APP_UUID_LEN;
    int32_t clientId = BleGattcRegister(appId);
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcRegister error");
        return INVALID_ID;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleGattcRegister %d", clientId);
    return clientId;
}

int32_t SoftbusGattcUnRegister(int32_t clientId)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcUnRegister invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (BleGattcUnRegister(clientId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcUnRegister error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcConnect invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    BdAddr bdAddr;
    if (memcpy_s(bdAddr.addr, OHOS_BD_ADDR_LEN, addr->addr, BT_ADDR_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcConnect memcpy error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (BleGattcConnect(clientId, &g_btGattClientCallbacks, &bdAddr, false, OHOS_BT_TRANSPORT_TYPE_LE) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcConnect error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBleGattcDisconnect(int32_t clientId)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusBleGattcDisconnect invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (BleGattcDisconnect(clientId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcDisconnect error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcSearchServices(int32_t clientId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftbusGattcSearchServices %d", clientId);
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcSearchServices invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = BleGattcSearchServices(clientId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcSearchServices error, ret = %d", ret);
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcGetService invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    BtUuid btUuid;
    btUuid.uuid = serverUuid->uuid;
    btUuid.uuidLen = serverUuid->uuidLen;
    if (BleGattcGetService(clientId, btUuid) == false) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcGetService error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcRegisterNotification(int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcRegisterNotification invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    BtGattCharacteristic btCharaUuid;
    btCharaUuid.serviceUuid.uuid = serverUuid->uuid;
    btCharaUuid.serviceUuid.uuidLen = serverUuid->uuidLen;
    btCharaUuid.characteristicUuid.uuid = charaUuid->uuid;
    btCharaUuid.characteristicUuid.uuidLen = charaUuid->uuidLen;
    if (BleGattcRegisterNotification(clientId, btCharaUuid, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcRegisterNotification error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int mtuSize)
{
    if (clientId <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcConfigureMtuSize invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (BleGattcConfigureMtuSize(clientId, mtuSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleGattcConfigureMtuSize error");
        return SOFTBUS_GATTC_INTERFACE_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData)
{
    if (clientId <= 0 || clientData == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcWriteCharacteristic invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftbusGattcRegisterNotification clientId = %d", clientId);
    BtGattCharacteristic characteristic;
    characteristic.serviceUuid.uuid = clientData->serviceUuid.uuid;
    characteristic.serviceUuid.uuidLen = clientData->serviceUuid.uuidLen;
    characteristic.characteristicUuid.uuid = clientData->characterUuid.uuid;
    characteristic.characteristicUuid.uuidLen = clientData->characterUuid.uuidLen;
    if (BleGattcWriteCharacteristic(clientId, characteristic, OHOS_GATT_WRITE_NO_RSP,
        clientData->valueLen, clientData->value) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftbusGattcWriteCharacteristic error");
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
