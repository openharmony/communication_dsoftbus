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

#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

#include "ohos_bt_def.h"
#include "ohos_bt_gatt_server.h"

#define WAIT_HAL_REG_TIME 5 // ms
#define WAIT_HAL_REG_RETRY 3

static const char SOFTBUS_APP_UUID[BT_UUID_LEN] = {
    0x00, 0x00, 0xFE, 0x36, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
};

SoftBusGattsCallback *g_gattsCallback = NULL;
static BtGattServerCallbacks g_bleGattsHalCallback = { 0 };
static int g_halServerId = -1;
static int g_halRegFlag = -1; // -1:not registered or register failed; 0:registerring; 1:registered

int CheckGattsStatus(void)
{
    if (g_gattsCallback == NULL) {
        return SOFTBUS_ERR;
    }
    while (g_halRegFlag == 0) {
        LOG_ERR("ble hal registerring");
        static int tryTimes = WAIT_HAL_REG_RETRY;
        if (tryTimes > 0) {
            SoftBusSleepMs(WAIT_HAL_REG_TIME);
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
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = srvcUuid.uuid,
        .uuidLen = srvcUuid.uuidLen
    };
    LOG_ERR("BLEINFOPRTINT:BleGattsAddService(%{public}d, %{public}s, %{public}d, %{public}d)", g_halServerId, uuid.uuid, isPrimary, number);
    if (BleGattsAddService(g_halServerId, uuid, isPrimary, number) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions)
{
    if ((characUuid.uuidLen == 0) || (characUuid.uuid == NULL)) {
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = characUuid.uuid,
        .uuidLen = characUuid.uuidLen
    };
    LOG_ERR("BLEINFOPRTINT:BleGattsAddCharacteristic(%{public}d, %{public}d, %{public}s, %{public}d, %{public}d)", g_halServerId, srvcHandle, uuid.uuid, properties, permissions);
    if (BleGattsAddCharacteristic(g_halServerId, srvcHandle, uuid, properties, permissions) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
{
    if ((descUuid.uuidLen == 0) || (descUuid.uuid == NULL)) {
        return SOFTBUS_ERR;
    }
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    BtUuid uuid = {
        .uuid = descUuid.uuid,
        .uuidLen = descUuid.uuidLen
    };
    LOG_ERR("BLEINFOPRTINT:BleGattsAddDescriptor(%{public}d, %{public}d, %{public}s, %{public}d)", g_halServerId, srvcHandle, uuid.uuid, permissions);
    if (BleGattsAddDescriptor(g_halServerId, srvcHandle, uuid, permissions) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStartService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LOG_ERR("BLEINFOPRTINT:BleGattsStartService(%{public}d, %{public}d)", g_halServerId, srvcHandle);
    if (BleGattsStartService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsStopService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (BleGattsStopService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDeleteService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (BleGattsDeleteService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusGattsSendResponse(SoftBusGattsResponse *param)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    GattsSendRspParam response = {
        .connectId = param->connectId,
        .status = param->status,
        .attrHandle = param->attrHandle,
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
    LOG_INFO("SoftBusGattsSendNotify enter");
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
    LOG_INFO("SoftBusGattsSendNotify call BleGattsSendIndication halconnId:%{public}d attrHandle:%{public}d confirm:%{public}d",
        notify.connectId, notify.attrHandle, notify.confirm);
    if (BleGattsSendIndication(g_halServerId, &notify) != SOFTBUS_OK) {
        LOG_INFO("SoftBusGattsSendNotify failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void BleRegisterServerCallback(int status, int serverId, BtUuid *appUuid)
{
    LOG_INFO("BleRegisterServerCallback status=%d severId=%d", status, serverId);
    if ((appUuid == NULL) || (appUuid->uuid == NULL)) {
        LOG_ERR("BleRegisterServerCallback appUuid is null");
        return;
    }

    if (memcmp(appUuid->uuid, SOFTBUS_APP_UUID, appUuid->uuidLen) != 0) {
        LOG_ERR("BleRegisterServerCallback unknown uuid");
        return;
    }

    if (status != SOFTBUS_OK) {
        LOG_ERR("BleRegisterServerCallback failed, status=%d", status);
        g_halRegFlag = -1;
    } else {
        g_halRegFlag = 1;
        g_halServerId = serverId;
        LOG_ERR("BLEINFOPRTINT:BleRegisterServerCallback g_halServerId:%{public}d)", g_halServerId);
    }
}

static void BleConnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    LOG_INFO("ConnectServerCallback is coming, connId=%d serverId=%d\n", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ConnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
}

static void BleDisconnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    LOG_INFO("DisconnectServerCallback is coming, connId=%d severId=%d", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->DisconnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
}

static void BleServiceAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle)
{
    LOG_INFO("ServiceAddCallback srvcHandle=%d\n", srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    LOG_ERR("BLEINFOPRTINT:BleServiceAddCallback srvcHandle:%{public}d)", srvcHandle);
    g_gattsCallback->ServiceAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle);
}

static void BleIncludeServiceAddCallback(int status, int serverId, int srvcHandle, int includeSrvcHandle)
{
    (void)serverId;
    (void)srvcHandle;
    LOG_INFO("IncludeServiceAddCallback srvcHandle=%d,includeSrvcHandle=%d\n", srvcHandle,
        includeSrvcHandle);
}

static void BleCharacteristicAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    LOG_INFO("CharacteristicAddCallback srvcHandle=%d,charHandle=%d\n", srvcHandle,
        characteristicHandle);
    if (serverId != g_halServerId) {
        LOG_ERR("bad server id");
        return;
    }
    LOG_ERR("BLEINFOPRTINT:BleCharacteristicAddCallback characteristicHandle:%{public}d)", characteristicHandle);
    g_gattsCallback->CharacteristicAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, characteristicHandle);
}

static void BleDescriptorAddCallback(int status, int serverId, BtUuid *uuid,
    int srvcHandle, int descriptorHandle)
{
    LOG_INFO("DescriptorAddCallback srvcHandle=%d,descriptorHandle=%d\n",
        srvcHandle, descriptorHandle);
    if (serverId != g_halServerId) {
        return;
    }
    LOG_ERR("BLEINFOPRTINT:BleDescriptorAddCallback descriptorHandle:%{public}d)", descriptorHandle);
    g_gattsCallback->DescriptorAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, descriptorHandle);
}

static void BleServiceStartCallback(int status, int serverId, int srvcHandle)
{
    LOG_INFO("ServiceStartCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    LOG_ERR("BLEINFOPRTINT:BleServiceStartCallback srvcHandle:%{public}d)", srvcHandle);
    g_gattsCallback->ServiceStartCallback(status, srvcHandle);
}

static void BleServiceStopCallback(int status, int serverId, int srvcHandle)
{
    LOG_INFO("ServiceStopCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceStopCallback(status, srvcHandle);
}

static void BleServiceDeleteCallback(int status, int serverId, int srvcHandle)
{
    LOG_INFO("ServiceDeleteCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceDeleteCallback(status, srvcHandle);
}

static void BleRequestReadCallback(BtReqReadCbPara readCbPara)
{
    LOG_INFO("RequestReadCallback transId=%d, attrHandle=%d\n", readCbPara.transId,
        readCbPara.attrHandle);
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
    LOG_INFO("RequestWriteCallback transId=%d, attrHandle=%d\n", writeCbPara.transId,
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
    LOG_INFO("ResponseConfirmationCallback status=%d, handle=%d\n", status, handle);
    g_gattsCallback->ResponseConfirmationCallback(status, handle);
}

static void BleIndicationSentCallback(int connId, int status)
{
    LOG_INFO("IndicationSentCallback status=%d, connId=%d\n", status, connId);
    g_gattsCallback->NotifySentCallback(connId, status);
}

static void BleMtuChangeCallback(int connId, int mtu)
{
    LOG_INFO("MtuChangeCallback connId=%d, mtu=%d\n", connId, mtu);
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
        LOG_ERR("SoftBusRegisterGattsCallbacks fail:nullptr");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    if (g_gattsCallback != NULL) {
        LOG_ERR("SoftBusRegisterGattsCallbacks fail:callback exist");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    int ret = GattsRegisterHalCallback();
    if (ret != SOFTBUS_OK) {
        LOG_ERR("SoftBusRegisterGattsCallbacks GattsRegisterCallbacks failed:%d", ret);
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    if (g_halRegFlag == -1) {
        BtUuid uuid;
        uuid.uuid = (char *)SOFTBUS_APP_UUID;
        uuid.uuidLen = sizeof(SOFTBUS_APP_UUID);
        ret = BleGattsRegister(uuid);
        if (ret != SOFTBUS_OK) {
            LOG_ERR("BleGattsRegister failed%d", ret);
            return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
        }
    }
    g_gattsCallback = callback;
    return SOFTBUS_OK;
}
