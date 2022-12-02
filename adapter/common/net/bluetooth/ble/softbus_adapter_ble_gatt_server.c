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
static BtGattServerCallbacks g_bleGattsHalCallback = {0};
static volatile int g_halServerId = -1;
static volatile int g_halRegFlag = -1; // -1:not registered or register failed; 0:registerring; 1:registered

NO_SANITIZE("cfi") int CheckGattsStatus(void)
{
    if (g_gattsCallback == NULL) {
        return SOFTBUS_ERR;
    }
    while (g_halRegFlag == 0) {
        CLOGE("ble hal registerring");
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

NO_SANITIZE("cfi") int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number)
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
    if (BleGattsAddService(g_halServerId, uuid, isPrimary, number) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties,
    int permissions)
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
    if (BleGattsAddCharacteristic(g_halServerId, srvcHandle, uuid, properties, permissions) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
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
    if (BleGattsAddDescriptor(g_halServerId, srvcHandle, uuid, permissions) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsStartService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    CLOGI("BLEINFOPRTINT:BleGattsStartService(%d, %d)", g_halServerId, srvcHandle);
    if (BleGattsStartService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsStopService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    CLOGI("BLEINFOPRTINT:SoftBusGattsStopService(%d, %d)", g_halServerId, srvcHandle);
    if (BleGattsStopService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsDeleteService(int srvcHandle)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (BleGattsDeleteService(g_halServerId, srvcHandle) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId)
{
    if (CheckGattsStatus() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    BdAddr addr;
    if (memcpy_s(addr.addr, BT_ADDR_LEN, btAddr.addr, BT_ADDR_LEN) != EOK) {
        CLOGE("SoftBusGattsDisconnect memcpy fail");
        return SOFTBUS_ERR;
    }
    if (BleGattsDisconnect(g_halServerId, addr, connId) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int SoftBusGattsSendResponse(SoftBusGattsResponse *param)
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

NO_SANITIZE("cfi") int SoftBusGattsSendNotify(SoftBusGattsNotify *param)
{
    CLOGI("SoftBusGattsSendNotify enter");
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
    CLOGI("SoftBusGattsSendNotify call BleGattsSendIndication halconnId:%d attrHandle:%d confirm:%d",
        notify.connectId, notify.attrHandle, notify.confirm);
    if (BleGattsSendIndication(g_halServerId, &notify) != SOFTBUS_OK) {
        CLOGE("SoftBusGattsSendNotify failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void BleRegisterServerCallback(int status, int serverId, BtUuid *appUuid)
{
    CLOGI("BleRegisterServerCallback status=%d severId=%d", status, serverId);
    if ((appUuid == NULL) || (appUuid->uuid == NULL)) {
        CLOGE("BleRegisterServerCallback appUuid is null");
        return;
    }

    if (memcmp(appUuid->uuid, SOFTBUS_APP_UUID, appUuid->uuidLen) != 0) {
        CLOGE("BleRegisterServerCallback unknown uuid");
        return;
    }

    if (status != SOFTBUS_OK) {
        CLOGE("BleRegisterServerCallback failed, status=%d", status);
        g_halRegFlag = -1;
    } else {
        g_halRegFlag = 1;
        g_halServerId = serverId;
        CLOGI("BLEINFOPRTINT:BleRegisterServerCallback g_halServerId:%d)", g_halServerId);
    }
}

NO_SANITIZE("cfi") static void BleConnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    CLOGI("ConnectServerCallback is coming, connId=%d serverId=%d\n", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ConnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
}

NO_SANITIZE("cfi") static void BleDisconnectServerCallback(int connId, int serverId, const BdAddr *bdAddr)
{
    CLOGI("DisconnectServerCallback is coming, connId=%d severId=%d", connId, serverId);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->DisconnectServerCallback(connId, (const SoftBusBtAddr*)bdAddr);
}

NO_SANITIZE("cfi") static void BleServiceAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle)
{
    (void)serverId;
    CLOGI("ServiceAddCallback srvcHandle=%d\n", srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    CLOGI("BLEINFOPRTINT:BleServiceAddCallback srvcHandle:%d)", srvcHandle);
    g_gattsCallback->ServiceAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle);
}

NO_SANITIZE("cfi") static void BleIncludeServiceAddCallback(int status, int serverId, int srvcHandle,
    int includeSrvcHandle)
{
    (void)serverId;
    (void)srvcHandle;
    CLOGI("IncludeServiceAddCallback srvcHandle=%d,includeSrvcHandle=%d\n", srvcHandle, includeSrvcHandle);
}

NO_SANITIZE("cfi") static void BleCharacteristicAddCallback(int status, int serverId, BtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    CLOGI("CharacteristicAddCallback srvcHandle=%d,charHandle=%d\n", srvcHandle, characteristicHandle);
    if (serverId != g_halServerId) {
        CLOGE("bad server id");
        return;
    }
    CLOGI("BLEINFOPRTINT:BleCharacteristicAddCallback characteristicHandle:%d)", characteristicHandle);
    g_gattsCallback->CharacteristicAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, characteristicHandle);
}

NO_SANITIZE("cfi") static void BleDescriptorAddCallback(int status, int serverId, BtUuid *uuid,
    int srvcHandle, int descriptorHandle)
{
    CLOGI("DescriptorAddCallback srvcHandle=%d,descriptorHandle=%d", srvcHandle, descriptorHandle);
    if (serverId != g_halServerId) {
        return;
    }
    CLOGI("BLEINFOPRTINT:BleDescriptorAddCallback descriptorHandle:%d)", descriptorHandle);
    g_gattsCallback->DescriptorAddCallback(status, (SoftBusBtUuid *)uuid, srvcHandle, descriptorHandle);
}

NO_SANITIZE("cfi") static void BleServiceStartCallback(int status, int serverId, int srvcHandle)
{
    CLOGI("ServiceStartCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    CLOGI("BLEINFOPRTINT:BleServiceStartCallback srvcHandle:%d)", srvcHandle);
    g_gattsCallback->ServiceStartCallback(status, srvcHandle);
}

NO_SANITIZE("cfi") static void BleServiceStopCallback(int status, int serverId, int srvcHandle)
{
    CLOGI("ServiceStopCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceStopCallback(status, srvcHandle);
}

NO_SANITIZE("cfi") static void BleServiceDeleteCallback(int status, int serverId, int srvcHandle)
{
    CLOGI("ServiceDeleteCallback serverId=%d,srvcHandle=%d\n", serverId, srvcHandle);
    if (serverId != g_halServerId) {
        return;
    }
    g_gattsCallback->ServiceDeleteCallback(status, srvcHandle);
}

NO_SANITIZE("cfi") static void BleRequestReadCallback(BtReqReadCbPara readCbPara)
{
    CLOGI("RequestReadCallback transId=%d, attrHandle=%d\n", readCbPara.transId, readCbPara.attrHandle);
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

NO_SANITIZE("cfi") static void BleRequestWriteCallback(BtReqWriteCbPara writeCbPara)
{
    CLOGI("RequestWriteCallback transId=%d, attrHandle=%d\n", writeCbPara.transId, writeCbPara.attrHandle);
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

NO_SANITIZE("cfi") static void BleResponseConfirmationCallback(int status, int handle)
{
    CLOGI("ResponseConfirmationCallback status=%d, handle=%d\n", status, handle);
    g_gattsCallback->ResponseConfirmationCallback(status, handle);
}

NO_SANITIZE("cfi") static void BleIndicationSentCallback(int connId, int status)
{
    CLOGI("IndicationSentCallback status=%d, connId=%d\n", status, connId);
    g_gattsCallback->NotifySentCallback(connId, status);
}

NO_SANITIZE("cfi") static void BleMtuChangeCallback(int connId, int mtu)
{
    CLOGI("MtuChangeCallback connId=%d, mtu=%d\n", connId, mtu);
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

NO_SANITIZE("cfi") int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback)
{
    if (callback == NULL) {
        CLOGE("SoftBusRegisterGattsCallbacks fail:nullptr");
        return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
    }
    if (g_gattsCallback != NULL) {
        CLOGW("SoftBusRegisterGattsCallbacks register again");
    } else {
        g_gattsCallback = callback;
    }
    int ret = GattsRegisterHalCallback();
    if (ret != SOFTBUS_OK) {
        CLOGE("SoftBusRegisterGattsCallbacks GattsRegisterCallbacks failed:%d", ret);
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
            CLOGE("BleGattsRegister failed%d", ret);
            return SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL;
        }
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void SoftBusUnRegisterGattsCallbacks(void)
{
    if (g_gattsCallback == NULL) {
        CLOGI("no need to unregist gatts callback.");
        return;
    }
    if (g_halRegFlag == -1) {
        CLOGI("no need to unregist gatt server.");
        return;
    }
    if (BleGattsUnRegister(g_halServerId) != SOFTBUS_OK) {
        CLOGE("BleGattsUnRegister error.");
        return;
    }
    g_halServerId = -1;
    g_halRegFlag = -1;
}
