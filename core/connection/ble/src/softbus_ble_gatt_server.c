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

#include "softbus_ble_gatt_server.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>

#include "cJSON.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_connection_inner.h"
#include "softbus_ble_queue.h"
#include "softbus_ble_trans_manager.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hisysevt_connreporter.h"

#define BLE_GATT_SERVICE "bleGattService"

typedef enum {
    BLE_GATT_SERVICE_INITIAL = 0,
    BLE_GATT_SERVICE_ADDING,
    BLE_GATT_SERVICE_ADDED,
    BLE_GATT_SERVICE_STARTING,
    BLE_GATT_SERVICE_STARTED,
    BLE_GATT_SERVICE_STOPPING,
    BLE_GATT_SERVICE_DELETING,
    BLE_GATT_SERVICE_INVALID
} GattServiceState;

typedef struct {
    GattServiceState state;
    int32_t svcId;
    int32_t bleConnCharaId;
    int32_t bleConnDesId;
    int32_t bleNetCharaId;
    int32_t bleNetDesId;
} SoftBusGattService;

typedef enum {
    ADD_SERVICE_MSG,
    ADD_CHARA_MSG,
    ADD_DESCRIPTOR_MSG,
} BleConnLoopMsg;

static const int MAX_SERVICE_CHAR_NUM = 8;

static SoftBusHandler g_bleAsyncHandler = {
    .name ="g_bleAsyncHandler"
};
static SoftBusGattsCallback g_bleGattsCallback = {0};
static SoftBusBleConnCalback *g_softBusBleConnCb = NULL;
static SoftBusMutex g_serviceStateLock;
static int32_t BleGattServiceDump(int fd);
static SoftBusGattService g_gattService = {
    .state = BLE_GATT_SERVICE_INITIAL,
    .svcId = -1,
    .bleConnCharaId = -1,
    .bleConnDesId = -1,
    .bleNetCharaId = -1,
    .bleNetDesId = -1
};

static SoftBusMessage *BleConnCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, const char *data)
{
    SoftBusMessage *msg = NULL;
    msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        CLOGE("BleConnCreateLoopMsg SoftBusCalloc failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_bleAsyncHandler;
    msg->FreeMessage = NULL;
    msg->obj = (void *)data;
    return msg;
}

NO_SANITIZE("cfi") int32_t GetBleAttrHandle(int32_t module)
{
    return (module == MODULE_BLE_NET) ? g_gattService.bleNetCharaId : g_gattService.bleConnCharaId;
}

NO_SANITIZE("cfi") int32_t SoftBusGattServerSend(int32_t halConnId, const char *data, int32_t len, int32_t module)
{
    SoftBusGattsNotify notify = {
        .connectId = halConnId,
        .attrHandle =  GetBleAttrHandle(module),
        .confirm = 0,
        .valueLen = len,
        .value = (char *)data
    };
    CLOGI("SoftBusGattServerSend halconnId:%d attrHandle:%d confirm:%d",
        notify.connectId, notify.attrHandle, notify.confirm);
    return SoftBusGattsSendNotify(&notify);
}

NO_SANITIZE("cfi") int32_t SoftBusGattServerStartService(void)
{
    if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
        CLOGE("SoftBusGattServerStartService lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    if ((g_gattService.state == BLE_GATT_SERVICE_STARTED) ||
        (g_gattService.state == BLE_GATT_SERVICE_STARTING)) {
        CLOGI("Ble service already started or is starting");
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        return SOFTBUS_OK;
    }
    if (g_gattService.state == BLE_GATT_SERVICE_ADDED) {
        g_gattService.state = BLE_GATT_SERVICE_STARTING;
        int ret = SoftBusGattsStartService(g_gattService.svcId);
        if (ret != SOFTBUS_OK) {
            CLOGE("SoftBusGattsStartService failed");
            SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTSERVER_START_FAIL);
            g_gattService.state = BLE_GATT_SERVICE_ADDED;
        }
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        return (ret == SOFTBUS_OK) ? ret : SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
    CLOGE("start gatt service wrong state:%d", g_gattService.state);
    return SOFTBUS_ERR;
}

NO_SANITIZE("cfi") int32_t SoftBusGattServerStopService(void)
{
    if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
        CLOGE("SoftBusGattServerStopService lock mutex failed");
        return SOFTBUS_BLECONNECTION_MUTEX_LOCK_ERROR;
    }
    if ((g_gattService.state == BLE_GATT_SERVICE_ADDED) ||
        (g_gattService.state == BLE_GATT_SERVICE_STOPPING)) {
        CLOGI("Ble service already stopped or is stopping");
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        return SOFTBUS_OK;
    }
    if (g_gattService.state == BLE_GATT_SERVICE_STARTED) {
        g_gattService.state = BLE_GATT_SERVICE_STOPPING;
        int ret = SoftBusGattsStopService(g_gattService.svcId);
        if (ret != SOFTBUS_OK) {
            g_gattService.state = BLE_GATT_SERVICE_STARTED;
        }
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        return (ret == SOFTBUS_OK) ? ret : SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
    CLOGE("stop gatt service wrong state:%d", g_gattService.state);
    SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTSERVER_STOP_FAIL);
    return SOFTBUS_ERR;
}

static void UpdateGattService(SoftBusGattService *service, int status)
{
    if (service == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
        CLOGE("lock mutex failed");
        return;
    }
    switch (service->state) {
        case BLE_GATT_SERVICE_ADDING:
            if ((service->svcId != -1) &&
                (service->bleConnCharaId != -1) &&
                (service->bleNetCharaId != -1) &&
                (service->bleConnDesId != -1) &&
                (service->bleNetDesId != -1)) {
                service->state = BLE_GATT_SERVICE_ADDED;
                if (SoftBusGattServerStartService() != SOFTBUS_OK) {
                    CLOGE("BleStartLocalListening failed");
                }
                break;
            }
            if (service->svcId != -1) {
                service->state = BLE_GATT_SERVICE_DELETING;
                int ret = SoftBusGattsDeleteService(service->svcId);
                if (ret != SOFTBUS_OK) {
                    service->state = BLE_GATT_SERVICE_INVALID;
                }
            } else {
                service->state = BLE_GATT_SERVICE_INITIAL;
            }
            break;
        case BLE_GATT_SERVICE_STARTING:
            service->state = (status == SOFTBUS_OK) ? BLE_GATT_SERVICE_STARTED :
                BLE_GATT_SERVICE_ADDED;
            break;
        case BLE_GATT_SERVICE_STOPPING:
            service->state = (status == SOFTBUS_OK) ? BLE_GATT_SERVICE_ADDED :
                BLE_GATT_SERVICE_STARTED;
            break;
        case BLE_GATT_SERVICE_DELETING:
            service->state = (status == SOFTBUS_OK) ? BLE_GATT_SERVICE_INITIAL :
                BLE_GATT_SERVICE_INVALID;
            break;
        default:
            break;
    }
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
}

static void ResetGattService(SoftBusGattService *service)
{
    if (service == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
        CLOGE("lock mutex failed");
        return;
    }
    if (service->svcId != -1) {
        service->state = BLE_GATT_SERVICE_DELETING;
        int ret = SoftBusGattsDeleteService(service->svcId);
        if (ret != SOFTBUS_OK) {
            service->state = BLE_GATT_SERVICE_INVALID;
        }
    } else {
        // clean up adapter status
        SoftBusUnRegisterGattsCallbacks();
        service->state = BLE_GATT_SERVICE_INITIAL;
    }
    service->svcId = -1;
    service->bleConnCharaId = -1;
    service->bleConnDesId = -1;
    service->bleNetCharaId = -1;
    service->bleNetDesId = -1;
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
}

NO_SANITIZE("cfi") static void BleServiceAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle)
{
    CLOGI("ServiceAddCallback srvcHandle=%d\n", srvcHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        CLOGE("BleServiceAddCallback appUuid is null");
        return;
    }

    if (memcmp(uuid->uuid, SOFTBUS_SERVICE_UUID, uuid->uuidLen) == 0) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            CLOGE("BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
            CLOGE("lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            CLOGE("g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)SoftBusMutexUnlock(&g_serviceStateLock);
            return;
        }
        g_gattService.svcId = srvcHandle;
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        SoftBusMessage *msg = BleConnCreateLoopMsg(ADD_CHARA_MSG,
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE, SOFTBUS_GATT_PERMISSION_READ |
            SOFTBUS_GATT_PERMISSION_WRITE, SOFTBUS_CHARA_BLENET_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);

        msg = BleConnCreateLoopMsg(ADD_DESCRIPTOR_MSG, 0,
            SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);

        msg = BleConnCreateLoopMsg(ADD_CHARA_MSG,
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
            SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE, SOFTBUS_GATT_PERMISSION_READ |
            SOFTBUS_GATT_PERMISSION_WRITE, SOFTBUS_CHARA_BLECONN_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);
    } else {
        CLOGE("BleServiceAddCallback unknown uuid");
    }
}

NO_SANITIZE("cfi") static void BleCharacteristicAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle,
    int characteristicHandle)
{
    CLOGI("CharacteristicAddCallback srvcHandle=%d,charHandle=%d\n", srvcHandle, characteristicHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        CLOGE("BleServiceAddCallback appUuid is null");
        return;
    }
    if ((srvcHandle == g_gattService.svcId) && (memcmp(uuid->uuid, SOFTBUS_CHARA_BLENET_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            CLOGE("BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            CLOGE("g_gattService state not equal BLE_GATT_SERVICE_ADDING");
            (void)SoftBusMutexUnlock(&g_serviceStateLock);
            return;
        }
        g_gattService.bleNetCharaId = characteristicHandle;
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        return;
    }
    if ((srvcHandle == g_gattService.svcId) && (memcmp(uuid->uuid, SOFTBUS_CHARA_BLECONN_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            CLOGE("BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            (void)SoftBusMutexUnlock(&g_serviceStateLock);
            return;
        }
        g_gattService.bleConnCharaId = characteristicHandle;
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
        SoftBusMessage *msg = BleConnCreateLoopMsg(ADD_DESCRIPTOR_MSG, 0,
            SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);
    }
}

NO_SANITIZE("cfi") static void BleDescriptorAddCallback(int status, SoftBusBtUuid *uuid,
    int srvcHandle, int descriptorHandle)
{
    CLOGI("DescriptorAddCallback srvcHandle=%d,descriptorHandle=%d", srvcHandle, descriptorHandle);
    if ((uuid == NULL) || (uuid->uuid == NULL)) {
        CLOGE("BleServiceAddCallback appUuid is null");
        return;
    }

    if ((srvcHandle == g_gattService.svcId) &&
        (memcmp(uuid->uuid, SOFTBUS_DESCRIPTOR_CONFIGURE_UUID, uuid->uuidLen) == 0)) {
        if (status != SOFTBUS_OK) {
            ResetGattService(&g_gattService);
            CLOGE("BleRegisterServerCallback failed, status=%d", status);
            return;
        }
        if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
            CLOGE("lock mutex failed");
            return;
        }
        if (g_gattService.state != BLE_GATT_SERVICE_ADDING) {
            CLOGE("g_gattService wrong state, should be BLE_GATT_SERVICE_ADDING");
            (void)SoftBusMutexUnlock(&g_serviceStateLock);
            return;
        }
        if (g_gattService.bleNetDesId == -1) {
            g_gattService.bleNetDesId = descriptorHandle;
        } else {
            g_gattService.bleConnDesId = descriptorHandle;
            UpdateGattService(&g_gattService, 0);
        }
        (void)SoftBusMutexUnlock(&g_serviceStateLock);
    } else {
        CLOGE("BleDescriptorAddCallback unknown srvcHandle or uuid");
    }
}

NO_SANITIZE("cfi") static void BleServiceStartCallback(int status, int srvcHandle)
{
    CLOGI("ServiceStartCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        CLOGE("BleServiceStartCallback start failed");
    }
    UpdateGattService(&g_gattService, status);
    CLOGI("BleServiceStartCallback start success");
}

NO_SANITIZE("cfi") static void BleServiceStopCallback(int status, int srvcHandle)
{
    CLOGI("ServiceStopCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        CLOGE("BleServiceStopCallback stop failed");
    }
    UpdateGattService(&g_gattService, status);
}

NO_SANITIZE("cfi") static void BleServiceDeleteCallback(int status, int srvcHandle)
{
    CLOGI("ServiceDeleteCallback srvcHandle=%d\n", srvcHandle);
    if (srvcHandle != g_gattService.svcId) {
        return;
    }
    if (status != SOFTBUS_OK) {
        CLOGE("BleServiceStopCallback stop failed");
    }
    UpdateGattService(&g_gattService, status);
    SoftBusUnRegisterGattsCallbacks();
}

NO_SANITIZE("cfi") static void BleConnectServerCallback(int halConnId, const SoftBusBtAddr *btAddr)
{
    CLOGI("ConnectServerCallback is coming, halConnId=%d\n", halConnId);
    if (btAddr == NULL) {
        CLOGE("btAddr is null");
        return;
    }
    char bleStrMac[BT_MAC_LEN];
    int ret = ConvertBtMacToStr(bleStrMac, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (ret != SOFTBUS_OK) {
        CLOGE("Convert ble addr failed:%d", ret);
        return;
    }
    g_softBusBleConnCb->BleConnectCallback(halConnId, bleStrMac, btAddr);
}

NO_SANITIZE("cfi") static void BleDisconnectServerCallback(int halConnId, const SoftBusBtAddr *btAddr)
{
    CLOGI("DisconnectServerCallback is coming, halconnId=%d", halConnId);
    if (btAddr == NULL) {
        CLOGE("btAddr is null");
        return;
    }
    char bleStrMac[BT_MAC_LEN];
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = halConnId;
    halConnInfo.isServer = BLE_SERVER_TYPE;
    int ret = ConvertBtMacToStr(bleStrMac, BT_MAC_LEN, btAddr->addr, BT_ADDR_LEN);
    if (ret != SOFTBUS_OK) {
        CLOGE("Convert ble addr failed:%d", ret);
        return;
    }
    g_softBusBleConnCb->BleDisconnectCallback(halConnInfo, SOFTBUS_BLECONNECTION_SERVER_DISCONNECT);
}

NO_SANITIZE("cfi") static void SoftBusGattServerOnDataReceived(int32_t handle, int32_t halConnId, uint32_t len,
    const char *value)
{
    if (value == NULL) {
        CLOGE("GattServerOnDataReceived invalid data");
        return;
    }
    bool isBleConn = handle == g_gattService.bleConnCharaId;
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = halConnId;
    halConnInfo.isServer = BLE_SERVER_TYPE;
    g_softBusBleConnCb->BleOnDataReceived(isBleConn, halConnInfo, len, value);
}

NO_SANITIZE("cfi") static void BleRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    CLOGI("RequestReadCallback transId=%d, attrHandle=%d", readCbPara.transId, readCbPara.attrHandle);
    SoftBusGattsResponse response = {
        .connectId = readCbPara.connId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = readCbPara.transId,
        .valueLen = strlen("not support!") + 1,
        .value = "not support!"
    };
    CLOGI("BleRequestReadCallback sendresponse");
    SoftBusGattsSendResponse(&response);
}

static void BleSendGattRsp(SoftBusGattWriteRequest *request)
{
    if (!request->needRsp) {
        return;
    }
    SoftBusGattsResponse response = {
        .connectId = request->connId,
        .status = SOFTBUS_BT_STATUS_SUCCESS,
        .attrHandle = request->transId,
        .valueLen = request->length,
        .value = (char *)request->value
    };
    int ret = SoftBusGattsSendResponse(&response);
    CLOGI("send gatt response, handle: %d, ret: %d", request->attrHandle, ret);
}

static void BleRequestCharacteristicWriteCallback(SoftBusGattWriteRequest *request)
{
    BleSendGattRsp(request);

    uint32_t len = 0;
    int32_t index = -1;
    BleHalConnInfo halConnInfo = {
        .halConnId = request->connId,
        .isServer = BLE_SERVER_TYPE
    };
    char *value = BleTransRecv(halConnInfo, (char *)request->value, (uint32_t)request->length, &len, &index);
    if (value == NULL) {
        return;
    }
    SoftBusGattServerOnDataReceived(request->attrHandle, request->connId, len, (const char *)value);
    if (index != -1) {
        BleTransCacheFree(halConnInfo, index);
    }
}

NO_SANITIZE("cfi") static void BleRequestWriteCallback(SoftBusGattWriteRequest writeCbPara)
{
    CLOGI("RequestWriteCallback halconnId: %d, transId: %d, attrHandle: %d, value length: %d, need rsp: %d",
        writeCbPara.connId, writeCbPara.transId, writeCbPara.attrHandle, writeCbPara.length, writeCbPara.needRsp);

    if (writeCbPara.attrHandle == g_gattService.bleConnDesId ||
        writeCbPara.attrHandle == g_gattService.bleNetDesId) {
        BleSendGattRsp(&writeCbPara);
        return;
    }
    if (writeCbPara.attrHandle == g_gattService.bleConnCharaId ||
        writeCbPara.attrHandle == g_gattService.bleNetCharaId) {
        BleRequestCharacteristicWriteCallback(&writeCbPara);
        return;
    }
    CLOGW("BleRequestWriteCallback receive unexpectedly notify, handle: %d, expect: [%d, %d, %d, %d]",
        writeCbPara.attrHandle, g_gattService.bleConnDesId, g_gattService.bleNetDesId,
        g_gattService.bleConnCharaId, g_gattService.bleNetCharaId);
}

NO_SANITIZE("cfi") static void BleResponseConfirmationCallback(int status, int handle)
{
    CLOGI("ResponseConfirmationCallback status=%d, handle=%d", status, handle);
}

static void BleNotifySentCallback(int connId, int status)
{
    CLOGI("IndicationSentCallback status=%d, connId=%d", status, connId);
}

NO_SANITIZE("cfi") static void BleMtuChangeCallback(int connId, int mtu)
{
    CLOGI("MtuChangeCallback connId=%d, mtu=%d", connId, mtu);
    BleHalConnInfo halConnInfo;
    halConnInfo.halConnId = connId;
    halConnInfo.isServer = BLE_SERVER_TYPE;
    BleConnectionInfo *connInfo = g_softBusBleConnCb->GetBleConnInfoByHalConnId(halConnInfo);
    if (connInfo == NULL) {
        CLOGE("BleMtuChangeCallback GetBleConnInfo failed");
        return;
    }
    connInfo->mtu = mtu;
}

static int GattsRegisterCallback(void)
{
    g_bleGattsCallback.ServiceAddCallback = BleServiceAddCallback;
    g_bleGattsCallback.CharacteristicAddCallback = BleCharacteristicAddCallback;
    g_bleGattsCallback.DescriptorAddCallback = BleDescriptorAddCallback;
    g_bleGattsCallback.ServiceStartCallback = BleServiceStartCallback;
    g_bleGattsCallback.ServiceStopCallback = BleServiceStopCallback;
    g_bleGattsCallback.ServiceDeleteCallback = BleServiceDeleteCallback;
    g_bleGattsCallback.ConnectServerCallback = BleConnectServerCallback;
    g_bleGattsCallback.DisconnectServerCallback = BleDisconnectServerCallback;
    g_bleGattsCallback.RequestReadCallback = BleRequestReadCallback;
    g_bleGattsCallback.RequestWriteCallback = BleRequestWriteCallback;
    g_bleGattsCallback.ResponseConfirmationCallback = BleResponseConfirmationCallback;
    g_bleGattsCallback.NotifySentCallback = BleNotifySentCallback;
    g_bleGattsCallback.MtuChangeCallback = BleMtuChangeCallback;
    return SoftBusRegisterGattsCallbacks(&g_bleGattsCallback);
}

static void BleConnAddSerMsgHandler(const SoftBusMessage *msg)
{
    CLOGI("call GattsRegisterCallback");
    int32_t ret = GattsRegisterCallback();
    if (ret != SOFTBUS_OK) {
        CLOGE("GattsRegisterCallbacks failed: %d", ret);
        return;
    }
    if (SoftBusMutexLock(&g_serviceStateLock) != 0) {
        CLOGE("lock mutex failed");
        return;
    }
    g_gattService.state = BLE_GATT_SERVICE_ADDING;
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
    SoftBusBtUuid uuid;
    uuid.uuid = (char *)msg->obj;
    uuid.uuidLen = strlen(uuid.uuid);
    ret = SoftBusGattsAddService(uuid, true, MAX_SERVICE_CHAR_NUM);
    if (ret != SOFTBUS_OK) {
        CLOGE("BleGattsAddService failed:%d", ret);
        return;
    }
}

NO_SANITIZE("cfi") static void BleConnMsgHandler(SoftBusMessage *msg)
{
    SoftBusBtUuid uuid;
    int properties, permissions;
    if (msg == NULL) {
        return;
    }
    CLOGI("ble conn loop process msg type %d", msg->what);
    switch (msg->what) {
        case ADD_SERVICE_MSG:
            BleConnAddSerMsgHandler(msg);
            break;
        case ADD_CHARA_MSG:
            uuid.uuid = (char *)msg->obj;
            uuid.uuidLen = strlen(uuid.uuid);
            properties = (int32_t)msg->arg1;
            permissions = (int32_t)msg->arg2;
            int32_t ret = SoftBusGattsAddCharacteristic(g_gattService.svcId, uuid, properties, permissions);
            if (ret != SOFTBUS_OK) {
                CLOGE("BleGattsAddCharacteristic  failed:%d", ret);
                return;
            }
            break;
        case ADD_DESCRIPTOR_MSG:
            uuid.uuid = (char *)msg->obj;
            uuid.uuidLen = strlen(uuid.uuid);
            permissions = (int32_t)msg->arg2;
            ret = SoftBusGattsAddDescriptor(g_gattService.svcId, uuid, permissions);
            if (ret != SOFTBUS_OK) {
                CLOGE("BleGattsAddDescriptor  failed:%d", ret);
                return;
            }
            break;
        default:
            break;
    }
}

static int BleConnLooperInit(void)
{
    g_bleAsyncHandler.looper = CreateNewLooper("ble_looper");
    if (g_bleAsyncHandler.looper == NULL) {
        return SOFTBUS_ERR;
    }
    g_bleAsyncHandler.HandleMessage = BleConnMsgHandler;
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void SoftBusGattServerOnBtStateChanged(int state)
{
    if (state != SOFTBUS_BT_STATE_TURN_ON && state != SOFTBUS_BT_STATE_TURN_OFF) {
        return;
    }
    CLOGI("SoftBusGattServerOnBtStateChanged state:%d", state);
    if (state == SOFTBUS_BT_STATE_TURN_ON) {
        SoftBusMessage *msg = BleConnCreateLoopMsg(ADD_SERVICE_MSG, 0, 0, SOFTBUS_SERVICE_UUID);
        if (msg == NULL) {
            return;
        }
        g_bleAsyncHandler.looper->PostMessage(g_bleAsyncHandler.looper, msg);
        return;
    }
    ResetGattService(&g_gattService);
}

NO_SANITIZE("cfi") int32_t SoftBusGattServerInit(SoftBusBleConnCalback *cb)
{
    int ret = BleConnLooperInit();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    g_softBusBleConnCb = cb;
    SoftBusMutexAttr attr;
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&g_serviceStateLock, &attr);
    SoftBusRegConnVarDump(BLE_GATT_SERVICE, &BleGattServiceDump);
    return ret;
}

static int32_t BleGattServiceDump(int fd)
{
    if (SoftBusMutexLock(&g_serviceStateLock) != SOFTBUS_OK) {
        CLOGE("lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    SOFTBUS_DPRINTF(fd, "\n-----------------BLEGattService Info-------------------\n");
    SOFTBUS_DPRINTF(fd, "GattService state               : %u\n", g_gattService.state);
    SOFTBUS_DPRINTF(fd, "BleGattService svcId            : %d\n", g_gattService.svcId);
    SOFTBUS_DPRINTF(fd, "BleGattService bleConnChardId   : %d\n", g_gattService.bleConnCharaId);
    SOFTBUS_DPRINTF(fd, "BleGattService bleConnDesId     : %d\n", g_gattService.bleConnDesId);
    SOFTBUS_DPRINTF(fd, "BleGattService bleNetCharaId    : %d\n", g_gattService.bleNetCharaId);
    SOFTBUS_DPRINTF(fd, "BleGattService bleNetDesId      : %d\n", g_gattService.bleNetDesId);
    (void)SoftBusMutexUnlock(&g_serviceStateLock);
    return SOFTBUS_OK;
}