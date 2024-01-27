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

#include "conn_log.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"

#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gatt_server.h"

#define WAIT_HAL_REG_TIME_MS 5 // ms
#define WAIT_HAL_REG_RETRY 3

static const char SOFTBUS_APP_UUID[BT_UUID_LEN] = {
    0x00, 0x00, 0xFE, 0x36, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
};

SoftBusGattsCallback *g_gattsCallback = NULL;
static BtGattServerCallbacks g_bleGattsHalCallback = {0};
static volatile int g_halServerId = -1;
static volatile int g_halRegFlag = -1; // -1:not registered or register failed; 0:registerring; 1:registered

int CheckGattsStatus(void)
{
    if (g_gattsCallback == NULL) {
        CONN_LOGE(CONN_BLE, "g_gattsCallback is NULL");
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
    if (BleGattsAddService(g_halServerId, uuid, isPrimary, number) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsAddService return error");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties,
    int permissions)
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
    CONN_LOGI(CONN_BLE, "BLEINFOPRTINT:BleGattsStartService, halServerId=%{public}d, srvcHandle=%{public}d",
        g_halServerId, srvcHandle);
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
    CONN_LOGI(CONN_BLE, "BLEINFOPRTINT:SoftBusGattsStopService, halServerId=%{public}d, srvcHandle=%{public}d",
        g_halServerId, srvcHandle);
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
    CONN_LOGI(CONN_BLE, "enter");
    if (param == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
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
    CONN_LOGI(CONN_BLE, "call BleGattsSendIndication halconnId=%{public}d, attrHandle=%{public}d, confirm=%{public}d",
        notify.connectId, notify.attrHandle, notify.confirm);
    if (BleGattsSendIndication(g_halServerId, &notify) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsSendIndication return failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void BleRegisterServerCallback(int status, int serverId, BtUuid *appUuid)
{
    CONN_LOGI(CONN_BLE, "status=%{public}d, severId=%{public}d", status, serverId);
    if ((appUuid == NULL) || (appUuid->uuid == NULL)) {
        CONN_LOGE(CONN_BLE, "BleRegisterServerCallback appUuid is null");
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
        CONN_LOGI(CONN_BLE, "BLEINFOPRTINT:BleRegisterServerCallback g_halServerId=%{public}d)", g_halServerId);
    }
}

static void BleConnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    if (bdAddr == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }
    CONN_LOGI(CONN_BLE, "ConnectServerCallback is coming, connId=%{public}d, serverId=%{public}d\n", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ConnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
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
    g_gattsCallback->DisconnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
}

static void BleServiceAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle)
{
    if (uuid == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }
    (void)serverId;
    CONN_LOGI(CONN_BLE, "ServiceAddCallback srvcHandle=%{public}d\n", srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d", srvcHandle);
    g_gattsCallback->ServiceAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle);
}

static void BleIncludeServiceAddCallback(int status, int serverId, int srvcHandle,
    int includeSrvcHandle)
{
    (void)serverId;
    (void)srvcHandle;
    CONN_LOGI(CONN_BLE, "IncludeServiceAddCallback srvcHandle=%{public}d, includeSrvcHandle=%{public}d\n", srvcHandle,
        includeSrvcHandle);
}

static void BleCharacteristicAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    CONN_LOGI(CONN_BLE, "CharacteristicAddCallback srvcHandle=%{public}d, charHandle=%{public}d\n",
        srvcHandle, characteristicHandle);
    if (serverId != g_halServerId) {
        CONN_LOGE(CONN_BLE, "bad server id");
        return;
    }
    CONN_LOGI(CONN_BLE, "characteristicHandle=%{public}d", characteristicHandle);
    g_gattsCallback->CharacteristicAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, characteristicHandle);
}

static void BleDescriptorAddCallback(int status, int serverId, BtUuid *uuid,
    int srvcHandle, int descriptorHandle)
{
    if (uuid == NULL) {
        CONN_LOGE(CONN_BLE, "invalid param");
        return;
    }

    CONN_LOGI(CONN_BLE, "DescriptorAddCallback srvcHandle=%{public}d, descriptorHandle=%{public}d",
        srvcHandle, descriptorHandle);
    if (serverId != g_halServerId) {
        CONN_LOGE(CONN_BLE, "serverId error");
        return;
    }
    CONN_LOGI(CONN_BLE, "descriptorHandle=%{public}d", descriptorHandle);
    g_gattsCallback->DescriptorAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, descriptorHandle);
}

static void BleServiceStartCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    CONN_LOGI(CONN_BLE, "srvcHandle=%{public}d", srvcHandle);
    g_gattsCallback->ServiceStartCallback(status, srvcHandle);
}

static void BleServiceStopCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "ServiceStopCallback serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceStopCallback(status, srvcHandle);
}

static void BleServiceDeleteCallback(int status, int serverId, int srvcHandle)
{
    CONN_LOGI(CONN_BLE, "serverId=%{public}d, srvcHandle=%{public}d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceDeleteCallback(status, srvcHandle);
}

static void BleRequestReadCallback(BtReqReadCbPara readCbPara)
{
    CONN_LOGI(CONN_BLE, "RequestReadCallback transId=%{public}d, attrHandle=%{public}d\n",
        readCbPara.transId, readCbPara.attrHandle);
    SoftBusGattReadRequest req = {
        .connId = readCbPara.connId,
        .transId = readCbPara.transId,
        .btAddr = (SoftBusBtAddr *)readCbPara.bdAddr,
        .attrHandle = readCbPara.attrHandle,
        .offset = readCbPara.offset,
        .isLong = readCbPara.isLong
    };
    g_gattsCallback->RequestReadCallback(req);
}

static void BleRequestWriteCallback(BtReqWriteCbPara writeCbPara)
{
    CONN_LOGI(CONN_BLE, "RequestWriteCallback transId=%{public}d, attrHandle=%{public}d\n", writeCbPara.transId,
        writeCbPara.attrHandle);
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
    g_gattsCallback->RequestWriteCallback(req);
}

static void BleResponseConfirmationCallback(int status, int handle)
{
    CONN_LOGI(CONN_BLE, "ResponseConfirmationCallback status=%{public}d, handle=%{public}d\n", status, handle);
    g_gattsCallback->ResponseConfirmationCallback(status, handle);
}

static void BleIndicationSentCallback(int connId, int status)
{
    CONN_LOGI(CONN_BLE, "IndicationSentCallback status=%{public}d, connId=%{public}d\n", status, connId);
    g_gattsCallback->NotifySentCallback(connId, status);
}

static void BleMtuChangeCallback(int connId, int mtu)
{
    CONN_LOGI(CONN_BLE, "MtuChangeCallback connId=%{public}d, mtu=%{public}d\n", connId, mtu);
    g_gattsCallback->MtuChangeCallback(connId, mtu);
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

int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback)
{
    if (callback == NULL) {
        CONN_LOGE(CONN_BLE, "fail:nullptr");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    if (g_gattsCallback != NULL) {
        CONN_LOGW(CONN_BLE, "register again");
    } else {
        g_gattsCallback = callback;
    }
    int ret = GattsRegisterHalCallback();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "GattsRegisterCallbacks failed. ret=%{public}d", ret);
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    if (g_halRegFlag == -1) {
        BtUuid uuid;
        uuid.uuid = (char *)SOFTBUS_APP_UUID;
        uuid.uuidLen = sizeof(SOFTBUS_APP_UUID);
        g_halRegFlag = 0;
        ret = BleGattsRegister(uuid);
        if (ret != SOFTBUS_OK) {
            g_halRegFlag = -1;
            CONN_LOGE(CONN_BLE, "BleGattsRegister failed, ret=%{public}d", ret);
            return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
        }
    }
    return SOFTBUS_OK;
}

void SoftBusUnRegisterGattsCallbacks(void)
{
    if (g_gattsCallback == NULL) {
        CONN_LOGI(CONN_BLE, "no need to unregist gatts callback.");
        return;
    }
    if (g_halRegFlag == -1) {
        CONN_LOGI(CONN_BLE, "no need to unregist gatt server.");
        return;
    }
    if (BleGattsUnRegister(g_halServerId) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "BleGattsUnRegister error.");
        return;
    }
    g_halServerId = -1;
    g_halRegFlag = -1;
}
